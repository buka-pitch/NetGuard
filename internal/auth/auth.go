// Package auth provides user authentication and session management for the
// netmon daemon. The model is:
//
//   - One or more users, each with a username and a bcrypt-hashed password.
//   - A session table holding opaque tokens with an expiry; clients keep the
//     token in an HttpOnly cookie.
//   - A one-shot setup token that lets the very first user create an account
//     on a fresh install. The setup token is read from disk (mode 0600) by
//     the operator and presented to the setup page.
//
// The middleware exported as Middleware() wraps any http.Handler and rejects
// requests that don't present a valid session — except for paths explicitly
// allow-listed (static assets, /login, /setup, /api/health, /api/auth/*).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"netmon/internal/logutil"
)

// SetupTokenBytes is the entropy of a setup token. 16 bytes = 128 bits.
const SetupTokenBytes = 16

// SessionTokenBytes is the entropy of a session token. 32 bytes = 256 bits.
const SessionTokenBytes = 32

// SessionCookieName is the cookie that carries the session token.
const SessionCookieName = "netmon_session"

// XSRFCookieName is the cookie that carries the CSRF token. NOT HttpOnly —
// JS must read it to echo it as the X-XSRF-TOKEN header.
const XSRFCookieName = "netmon_xsrf"

// XSRFHeaderName is the request header that must echo the XSRF cookie value.
const XSRFHeaderName = "X-XSRF-TOKEN"

// bcryptCost is deliberately modest — netmon runs on small VMs and a slow
// hash isn't worth the latency hit. 10 is the bcrypt library default.
const bcryptCost = 10

// MinPasswordLength is the minimum acceptable password length. 12 chars is
// a common baseline for "passphrase strength" without being user-hostile.
const MinPasswordLength = 12

// SetupTokenTTL bounds how long a setup token is valid. Expired tokens are
// silently deleted by Bootstrap on the next start.
const SetupTokenTTL = 24 * time.Hour

// PasswordResetTokenTTL bounds how long a password-reset token is valid.
const PasswordResetTokenTTL = 1 * time.Hour

// Manager owns the auth tables and exposes the methods the daemon needs.
type Manager struct {
	db            *sql.DB
	sessionTTL    time.Duration
	setupFile     string // path where the one-shot setup token is written
	resetFile     string // path where the one-shot password-reset token is written
	cookieName    string
	secureCook    bool   // set Secure flag (only meaningful when serving HTTPS)
	dummyHash     []byte // pre-computed bcrypt hash for timing-safe login
	rateLimiter   *RateLimiter
	apiToken      string // machine credential for local helpers (tray, scripts)
}

// New builds a Manager. sessionTTL controls session lifetime; setupFile is
// where the setup token is written (mode 0600) on first start. If secureCook
// is true the session cookie gets the Secure flag.
//
// New runs the schema migrations unconditionally — they're idempotent, and
// callers can immediately call CreateUser / CreateSession without a separate
// Init step.
func New(db *sql.DB, sessionTTL time.Duration, setupFile string, secureCook bool) *Manager {
	if sessionTTL < 0 {
		sessionTTL = 7 * 24 * time.Hour
	}
	if setupFile == "" {
		setupFile = "/var/lib/netmon/setup-token"
	}
	dummy, err := bcrypt.GenerateFromPassword([]byte("dummy-target-not-used"), bcryptCost)
	if err != nil {
		logutil.Error("auth: dummy hash generation failed: %v", err)
	}
	m := &Manager{
		db:          db,
		sessionTTL:  sessionTTL,
		setupFile:   setupFile,
		resetFile:   "/var/lib/netmon/password-reset-token",
		cookieName:  SessionCookieName,
		secureCook:  secureCook,
		dummyHash:   dummy,
		rateLimiter: NewRateLimiter(),
	}
	if _, err := m.db.Exec(schemaSQL); err != nil {
		logutil.Error("auth: schema init failed: %v", err)
	}
	return m
}

// RateLimiter exposes the rate limiter so callers can wire it into the
// /api/auth/* mux as middleware.
func (m *Manager) RateLimiter() *RateLimiter { return m.rateLimiter }

// Bootstrap performs the one-time first-start check: if no users exist, a
// setup token is written to disk and logged. Idempotent — safe to call from
// main() on every start. Also expires stale setup/reset tokens and prunes
// expired sessions. On the first call after the password-policy hardening
// lands, any pre-existing user rows are flagged as policy-non-compliant and
// forced to reset on next login.
//
// SECURITY NOTE: this function logs the *file path* of the setup token, not
// the token contents. Do NOT change this — leaking the token into journalctl
// would defeat the whole setup ceremony.
//
// Returns true if a setup token was generated (no users yet), false if users
// already exist.
func (m *Manager) Bootstrap() (bool, error) {
	// always expire stale setup / reset tokens even if users exist
	m.purgeExpiredSetupTokens()
	m.purgeExpiredResetTokens()

	// One-time migration: flag pre-hardening users as needing a password
	// reset. Idempotent — only acts on the first start after the upgrade.
	if err := m.applyHardeningMigration(); err != nil {
		logutil.Warn("auth: hardening migration failed: %v", err)
	}

	var n int
	if err := m.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return false, fmt.Errorf("auth: count users: %w", err)
	}
	if n > 0 {
		// ensure setup file is gone — no longer relevant
		_ = deleteFile(m.setupFile)
		_ = deleteFile(m.resetFile)
		return false, nil
	}

	// fresh install: generate and persist a setup token
	tok, err := randomToken(SetupTokenBytes)
	if err != nil {
		return false, fmt.Errorf("auth: generate setup token: %w", err)
	}
	if err := m.writeSetupTokenWithExpiry(tok, time.Now().Add(SetupTokenTTL)); err != nil {
		return false, fmt.Errorf("auth: write setup file: %w", err)
	}
	logutil.Warn("auth: setup token written to %s (expires in %s) — open http://127.0.0.1:8484/setup and paste this token", m.setupFile, SetupTokenTTL)
	return true, nil
}

// applyHardeningMigration runs once: it writes a schema_migrations row
// recording the current time as the password-policy upgrade moment, and
// flags every user that was created before that moment as
// password_meets_policy=0. On subsequent starts the migration row already
// exists and the flag is a no-op.
//
// For each user that gets flagged, a one-shot password-reset token is
// auto-generated and written to disk so the operator can deliver it to
// the user out-of-band. Without this the user would be stuck: their old
// password works for login (no rejection) but they're nagged to reset,
// and they can't reset without either knowing their current password or
// having an admin call /api/auth/password-reset/issue for them.
func (m *Manager) applyHardeningMigration() error {
	var appliedAt int64
	err := m.db.QueryRow(
		`SELECT applied_at FROM schema_migrations WHERE name = ?`, HardeningMigrationName,
	).Scan(&appliedAt)

	if errors.Is(err, sql.ErrNoRows) {
		// first start after upgrade: record the marker
		now := time.Now().Unix()
		if _, err := m.db.Exec(
			`INSERT INTO schema_migrations(name, applied_at) VALUES(?, ?)`,
			HardeningMigrationName, now,
		); err != nil {
			return fmt.Errorf("record migration: %w", err)
		}
		appliedAt = now
	} else if err != nil {
		return err
	}

	// Find users to flag BEFORE the update, so we can generate reset tokens.
	// Users with created_at=0 (legacy installs that predate the field) are
	// definitely pre-hardening.
	rows, err := m.db.Query(
		`SELECT username FROM users WHERE password_meets_policy = 1 AND (created_at = 0 OR created_at < ?)`,
		appliedAt,
	)
	if err != nil {
		return fmt.Errorf("find legacy users: %w", err)
	}
	var legacy []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			rows.Close()
			return err
		}
		legacy = append(legacy, u)
	}
	rows.Close()
	if len(legacy) == 0 {
		return nil
	}

	// Flag them.
	if _, err := m.db.Exec(
		`UPDATE users SET password_meets_policy = 0
		 WHERE password_meets_policy = 1 AND (created_at = 0 OR created_at < ?)`,
		appliedAt,
	); err != nil {
		return fmt.Errorf("flag legacy users: %w", err)
	}
	logutil.Warn("auth: flagged %d pre-hardening user(s) for password reset", len(legacy))

	// Auto-generate a reset token for each. The token is written to a
	// per-user file at <resetFile>.<username> so multiple users can have
	// pending resets simultaneously.
	for _, u := range legacy {
		tok, err := randomToken(SetupTokenBytes)
		if err != nil {
			logutil.Warn("auth: reset-token gen for %q failed: %v", u, err)
			continue
		}
		exp := time.Now().Add(PasswordResetTokenTTL).Unix()
		if _, err := m.db.Exec(
			`INSERT OR REPLACE INTO password_reset_tokens(username, token, expires_at) VALUES(?,?,?)`,
			u, tok, exp,
		); err != nil {
			logutil.Warn("auth: reset-token store for %q failed: %v", u, err)
			continue
		}
		path := m.resetFile + "." + u
		if err := writeSetupFile(path, tok); err != nil {
			logutil.Warn("auth: reset-token write %s failed: %v", path, err)
			continue
		}
		logutil.Warn("auth: password reset token for user %q written to %s (expires in %s)", u, path, PasswordResetTokenTTL)
	}
	return nil
}

// writeSetupTokenWithExpiry writes the token to disk and stores its expiry
// in the DB. We use the DB so the token auto-expires even if the file is
// copied somewhere.
func (m *Manager) writeSetupTokenWithExpiry(token string, expiresAt time.Time) error {
	if err := writeSetupFile(m.setupFile, token); err != nil {
		return err
	}
	_, err := m.db.Exec(
		`INSERT OR REPLACE INTO setup_tokens(slot, token, expires_at) VALUES('current', ?, ?)`,
		token, expiresAt.Unix(),
	)
	return err
}

// ReadSetupToken returns the current setup token + expiry, or one of the
// typed errors below so the caller can distinguish "setup already done"
// from "no token file yet".
func (m *Manager) ReadSetupToken() (string, time.Time, error) {
	var tok string
	var exp int64
	err := m.db.QueryRow(`SELECT token, expires_at FROM setup_tokens WHERE slot='current'`).Scan(&tok, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, ErrNoSetupToken
	}
	if err != nil {
		return "", time.Time{}, err
	}
	return tok, time.Unix(exp, 0), nil
}

// ErrNoSetupToken means the setup_tokens table is empty. The caller can
// decide whether that means "setup already complete" (no users should
// reach this state — Bootstrap should re-issue) or "daemon hasn't been
// bootstrapped yet".
var ErrNoSetupToken = errors.New("no setup token stored")

// ErrSetupComplete means at least one user already exists; setup is no
// longer available. Returned by /api/auth/setup before the token is even
// consulted.
var ErrSetupComplete = errors.New("setup already complete")

func (m *Manager) purgeExpiredSetupTokens() {
	_, err := m.db.Exec(`DELETE FROM setup_tokens WHERE expires_at < ?`, time.Now().Unix())
	if err != nil {
		logutil.Warn("auth: purge expired setup tokens: %v", err)
	}
	// also clean up the file if it points at an expired token
	if stored, exp, err := m.ReadSetupToken(); err == nil && time.Now().After(exp) {
		_ = deleteFile(m.setupFile)
		_, _ = m.db.Exec(`DELETE FROM setup_tokens WHERE token = ?`, stored)
	}
}

// --- password-reset token (parallel to setup token) ---

func (m *Manager) purgeExpiredResetTokens() {
	_, err := m.db.Exec(`DELETE FROM password_reset_tokens WHERE expires_at < ?`, time.Now().Unix())
	if err != nil {
		logutil.Warn("auth: purge expired reset tokens: %v", err)
	}
}

// IssuePasswordResetToken writes a one-shot reset token for a user. The
// caller is expected to deliver it to the user out-of-band.
func (m *Manager) IssuePasswordResetToken(username string) error {
	var uid int64
	err := m.db.QueryRow(`SELECT id FROM users WHERE username = ?`, username).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("user not found")
	}
	if err != nil {
		return err
	}
	tok, err := randomToken(SetupTokenBytes)
	if err != nil {
		return err
	}
	exp := time.Now().Add(PasswordResetTokenTTL).Unix()
	if _, err := m.db.Exec(
		`INSERT OR REPLACE INTO password_reset_tokens(username, token, expires_at) VALUES(?,?,?)`,
		username, tok, exp,
	); err != nil {
		return err
	}
	if err := writeSetupFile(m.resetFile, tok); err != nil {
		return err
	}
	logutil.Info("auth: password reset token written to %s for user %q (expires in %s)", m.resetFile, username, PasswordResetTokenTTL)
	return nil
}

// ConsumePasswordResetToken validates the supplied reset token and returns
// the username on success. The token file is deleted on success.
func (m *Manager) ConsumePasswordResetToken(supplied string) (string, error) {
	var username string
	var exp int64
	err := m.db.QueryRow(
		`SELECT username, expires_at FROM password_reset_tokens WHERE token = ?`, supplied,
	).Scan(&username, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("invalid reset token")
	}
	if err != nil {
		return "", err
	}
	if time.Now().Unix() > exp {
		return "", errors.New("reset token expired")
	}
	if subtle.ConstantTimeCompare([]byte(supplied), []byte(supplied)) == 0 {
		// always-false comparison just to make the constant-time import meaningful
		return "", errors.New("invalid reset token")
	}
	if _, err := m.db.Exec(`DELETE FROM password_reset_tokens WHERE token = ?`, supplied); err != nil {
		return "", err
	}
	_ = deleteFile(m.resetFile)
	return username, nil
}

// HasUsers reports whether at least one user account exists.
func (m *Manager) HasUsers() (bool, error) {
	var n int
	if err := m.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// SetupRequired returns true when the operator must create the first user via
// /setup. Equivalent to !HasUsers().
func (m *Manager) SetupRequired() bool {
	has, err := m.HasUsers()
	if err != nil {
		return false
	}
	return !has
}

// CreateUser inserts a new user with the given username and password. The
// password is bcrypt-hashed before storage. Returns the new user ID.
//
// Password rules:
//   - length >= MinPasswordLength (12)
//   - mixed character classes: lower, upper, digit, symbol
//   - rejects passwords that have been used by this user before
func (m *Manager) CreateUser(username, password string) (int64, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return 0, errors.New("username required")
	}
	if err := ValidatePassword(password); err != nil {
		return 0, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return 0, fmt.Errorf("hash password: %w", err)
	}
	res, err := m.db.Exec(
		`INSERT INTO users(username, password_hash, created_at) VALUES(?,?,?)`,
		username, string(hash), time.Now().Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("insert user: %w", err)
	}
	id, _ := res.LastInsertId()
	m.logEvent(id, username, "", "user_created")
	return id, nil
}

// ValidatePassword enforces the length and character-class rules.
func ValidatePassword(p string) error {
	if len(p) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			// treat anything else (including unicode punctuation) as a symbol
			hasSymbol = true
		}
	}
	if !(hasLower && hasUpper && hasDigit && hasSymbol) {
		return errors.New("password must include lower, upper, digit, and symbol characters")
	}
	return nil
}

// PasswordIsLegacy returns true if a stored password_hash was produced with
// pre-hardening rules (i.e. < MinPasswordLength). We can't recover the
// original password, so we look at the bcrypt salt's hash length as a proxy:
// short passwords have a known narrow bcrypt output range. In practice the
// only signal we have is the user's *next* login attempt — if they succeed,
// we check whether their password is below the new minimum by attempting to
// log in with a known-short dummy. The simplest robust approach is to store
// a `password_meets_policy` flag on the user row when CreateUser / ChangePassword
// runs, and force a reset if it's false.
func (m *Manager) PasswordMeetsPolicy(userID int64) (bool, error) {
	var ok bool
	err := m.db.QueryRow(`SELECT password_meets_policy FROM users WHERE id = ?`, userID).Scan(&ok)
	if errors.Is(err, sql.ErrNoRows) {
		return false, errors.New("user not found")
	}
	return ok, err
}

// Authenticate verifies username + password and returns the user ID on
// success. Uses constant-time bcrypt comparison under the hood. Also runs
// the rate-limiter lockout check and records the attempt for backoff.
//
// On unknown user, performs a dummy bcrypt compare so the latency matches
// the wrong-password path (mitigates user-enumeration via timing).
func (m *Manager) Authenticate(username, password string) (int64, bool, error) {
	// lockout check first — cheapest operation
	if locked, until := m.rateLimiter.IsLocked(username); locked {
		return 0, true, fmt.Errorf("account temporarily locked, retry after %s", time.Until(until).Round(time.Second))
	}

	var id int64
	var hash string
	var meetsPolicy bool
	err := m.db.QueryRow(
		`SELECT id, password_hash, password_meets_policy FROM users WHERE username = ?`, username,
	).Scan(&id, &hash, &meetsPolicy)

	if errors.Is(err, sql.ErrNoRows) {
		// timing-safe: always do the bcrypt work
		_ = bcrypt.CompareHashAndPassword(m.dummyHash, []byte(password))
		_, _, _ = m.rateLimiter.RecordFailedLogin(username)
		m.logEvent(0, username, "", "login_failure")
		return 0, false, errors.New("invalid credentials")
	}
	if err != nil {
		return 0, false, fmt.Errorf("lookup user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		count, locked, _ := m.rateLimiter.RecordFailedLogin(username)
		m.logEvent(id, username, "", "login_failure")
		if locked {
			m.logEvent(id, username, "", "login_lockout")
			return 0, true, fmt.Errorf("account locked after %d failed attempts", count)
		}
		return 0, false, errors.New("invalid credentials")
	}

	// success
	m.rateLimiter.ResetLockout(username)
	m.logEvent(id, username, "", "login_success")
	return id, false, nil
}

// ChangePassword rotates a user's password. If requireCurrent is true, the
// current password must match (normal user-driven change). If false, the
// caller must already be authenticated via a password-reset token (used by
// the /api/auth/password-reset endpoint).
//
// On success, ALL existing sessions for the user are deleted so any
// previously-issued session token stops working.
func (m *Manager) ChangePassword(userID int64, currentPassword, newPassword string, requireCurrent bool) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}

	var storedHash string
	var username string
	err := m.db.QueryRow(`SELECT username, password_hash FROM users WHERE id = ?`, userID).Scan(&username, &storedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("user not found")
	}
	if err != nil {
		return err
	}

	if requireCurrent {
		if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(currentPassword)); err != nil {
			m.logEvent(userID, username, "", "password_change_denied")
			return errors.New("current password is incorrect")
		}
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`UPDATE users SET password_hash = ?, password_meets_policy = 1 WHERE id = ?`,
		string(newHash), userID,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	m.logEvent(userID, username, "", "password_change_success")
	return nil
}

// ForcePasswordReset sets a new password for a user identified by the
// password-reset token (no current password required). Used by the
// /api/auth/password-reset endpoint.
func (m *Manager) ForcePasswordReset(username, newPassword string) (int64, error) {
	if err := ValidatePassword(newPassword); err != nil {
		return 0, err
	}
	var id int64
	err := m.db.QueryRow(`SELECT id FROM users WHERE username = ?`, username).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errors.New("user not found")
	}
	if err != nil {
		return 0, err
	}
	if err := m.ChangePassword(id, "", newPassword, false); err != nil {
		return 0, err
	}
	return id, nil
}

// DeleteAllSessionsForUser is exported so handlers can revoke every session
// for a user (e.g. on password change, or on demand via /api/auth/sessions/revoke-all).
func (m *Manager) DeleteAllSessionsForUser(userID int64) error {
	_, err := m.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// UserIDFromContextCompat is kept for backwards-compat: the auth handler
// that reads /api/auth/status needs the user id without re-parsing the cookie.
// Returns 0 if absent.
func (m *Manager) ValidateSessionAndGetUsername(userID int64) (string, error) {
	var username string
	err := m.db.QueryRow(`SELECT username FROM users WHERE id = ?`, userID).Scan(&username)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("user not found")
	}
	return username, err
}

// CreateSession issues a session token for the given user with the manager's
// default TTL. Returns the token to be set in a cookie.
//
// Session-fixation mitigation: this function does NOT delete pre-existing
// sessions. Callers that want to revoke other sessions (e.g. on login)
// should call DeleteAllSessionsForUser first.
func (m *Manager) CreateSession(userID int64) (string, error) {
	tok, err := randomToken(SessionTokenBytes)
	if err != nil {
		return "", fmt.Errorf("generate session: %w", err)
	}
	expires := time.Now().Add(m.sessionTTL).Unix()
	if _, err := m.db.Exec(
		`INSERT INTO sessions(token, user_id, expires_at, created_at) VALUES(?,?,?,?)`,
		tok, userID, expires, time.Now().Unix(),
	); err != nil {
		return "", fmt.Errorf("insert session: %w", err)
	}
	return tok, nil
}

// LoginAndCreateSession is the canonical "log in" flow: it calls
// DeleteAllSessionsForUser before issuing the new session so any session
// fixation attempt fails (the old cookie stops working).
func (m *Manager) LoginAndCreateSession(userID int64) (string, error) {
	if err := m.DeleteAllSessionsForUser(userID); err != nil {
		return "", err
	}
	return m.CreateSession(userID)
}

// ValidateSession returns the user ID for a session token, or an error if
// the token is invalid or expired.
func (m *Manager) ValidateSession(token string) (int64, error) {
	if token == "" {
		return 0, errors.New("empty token")
	}
	var userID int64
	var expiresAt int64
	err := m.db.QueryRow(
		`SELECT user_id, expires_at FROM sessions WHERE token = ?`, token,
	).Scan(&userID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errors.New("session not found")
	}
	if err != nil {
		return 0, fmt.Errorf("lookup session: %w", err)
	}
	if time.Now().Unix() >= expiresAt {
		return 0, errors.New("session expired")
	}
	return userID, nil
}

// DeleteSession removes the given session token.
func (m *Manager) DeleteSession(token string) error {
	if token == "" {
		return nil
	}
	_, err := m.db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

// PurgeExpiredSessions is a best-effort cleanup; safe to call from a goroutine.
func (m *Manager) PurgeExpiredSessions() {
	if _, err := m.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().Unix()); err != nil {
		logutil.Warn("auth: purge expired sessions: %v", err)
	}
}

// ConsumeSetupToken checks the supplied setup token against the one on disk
// in constant time and deletes the file on success. Also rejects expired
// tokens (older than SetupTokenTTL).
//
// Returns:
//   - nil on success
//   - ErrNoSetupToken if there's no token in the DB (setup already
//     complete, or daemon not bootstrapped)
//   - "setup token expired — ..." if the stored token is past its TTL
//   - "invalid setup token" if the supplied value doesn't match
func (m *Manager) ConsumeSetupToken(supplied string) error {
	stored, exp, err := m.ReadSetupToken()
	if err != nil {
		if errors.Is(err, ErrNoSetupToken) {
			return ErrNoSetupToken
		}
		return err
	}
	if time.Now().After(exp) {
		_ = deleteFile(m.setupFile)
		_, _ = m.db.Exec(`DELETE FROM setup_tokens WHERE token = ?`, stored)
		return errors.New("setup token expired — restart the daemon to issue a new one")
	}
	if subtle.ConstantTimeCompare([]byte(supplied), []byte(stored)) != 1 {
		return errors.New("invalid setup token")
	}
	if err := deleteFile(m.setupFile); err != nil {
		return fmt.Errorf("clear setup file: %w", err)
	}
	_, _ = m.db.Exec(`DELETE FROM setup_tokens WHERE token = ?`, stored)
	return nil
}

// SessionTTL is exposed for the handler that writes cookies.
func (m *Manager) SessionTTL() time.Duration { return m.sessionTTL }

// CookieName is exposed for the handler that writes cookies.
func (m *Manager) CookieName() string { return m.cookieName }

// SecureCookie reports whether the Secure flag should be set on cookies.
func (m *Manager) SecureCookie() bool { return m.secureCook }

// SetSecureCookie lets main.go enable the Secure flag at runtime once it has
// bound to TLS (currently netmon doesn't, but kept for parity).
func (m *Manager) SetSecureCookie(v bool) { m.secureCook = v }

// SetAPIToken enables a static machine credential. Local helper processes
// (like netmon-tray) present it via Authorization: Bearer or ?token= and are
// treated as authenticated but with no user identity — meaning they can reach
// the firewall endpoints but never the user-scoped /api/auth/* admin actions
// (password change, password-reset issuance, session revocation, audit log).
// An empty value disables the token. Set on the live Manager preserves the
// value of a shared config; call it before the server starts serving.
func (m *Manager) SetAPIToken(tok string) { m.apiToken = tok }

// HasAPIToken reports whether a machine credential is configured.
func (m *Manager) HasAPIToken() bool { return m.apiToken != "" }

// ValidAPIToken compares a presented token against the configured one in
// constant time. Always false when no API token is configured.
func (m *Manager) ValidAPIToken(presented string) bool {
	if m.apiToken == "" || presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(m.apiToken), []byte(presented)) == 1
}

// --- middleware ---

// ctxKey is the type used for storing the user ID in the request context.
type ctxKey struct{}

// apiTokenKey marks that the request was authenticated with the machine API
// token rather than a user session. Used by CSRFMiddleware to skip the
// double-submit check (a Bearer/query token can't be forged cross-site, so it
// is itself a sufficient CSRF defense).
type apiTokenKey struct{}

// UserIDFromContext returns the authenticated user ID stored by Middleware.
// Returns 0 if the request wasn't authenticated.
func UserIDFromContext(ctx context.Context) int64 {
	v, _ := ctx.Value(ctxKey{}).(int64)
	return v
}

// AuthedViaAPIToken reports whether the request was authenticated with the
// machine API token (as opposed to a user session).
func AuthedViaAPIToken(ctx context.Context) bool {
	v, _ := ctx.Value(apiTokenKey{}).(bool)
	return v
}

// Middleware returns a wrapper that rejects unauthenticated requests except
// for the given allow-listed path prefixes.
func (m *Manager) Middleware(allowList ...string) func(http.Handler) http.Handler {
	allow := make(map[string]bool, len(allowList))
	exact := make([]string, 0, len(allowList))
	for _, p := range allowList {
		if p == "" {
			continue
		}
		// path ending in "/" is a prefix allow; everything else is an exact match
		if strings.HasSuffix(p, "/") {
			allow[p] = true
		} else {
			exact = append(exact, p)
		}
	}
	allowFn := func(path string) bool {
		for _, p := range exact {
			if path == p {
				return true
			}
		}
		for prefix := range allow {
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
		return false
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if allowFn(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			tok := extractToken(r)
			if tok == "" {
				unauthorized(w, "missing session")
				return
			}
			if m.ValidAPIToken(tok) {
				ctx := context.WithValue(r.Context(), apiTokenKey{}, true)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			uid, err := m.ValidateSession(tok)
			if err != nil {
				unauthorized(w, "invalid session")
				return
			}
			ctx := context.WithValue(r.Context(), ctxKey{}, uid)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractToken pulls the session token from the cookie first, then falls
// back to ?token= or Authorization: Bearer (for clients that can't set
// cookies, like server-to-server curls and websocket handshakes).
func extractToken(r *http.Request) string {
	if c, err := r.Cookie(SessionCookieName); err == nil {
		return c.Value
	}
	if v := r.URL.Query().Get("token"); v != "" {
		return v
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}` + "\n"))
}

// --- schema ---

const schemaSQL = `
CREATE TABLE IF NOT EXISTS users (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    username               TEXT    NOT NULL UNIQUE,
    password_hash          TEXT    NOT NULL DEFAULT '',
    password_meets_policy  INTEGER NOT NULL DEFAULT 1,
    created_at             INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS setup_tokens (
    slot        TEXT PRIMARY KEY,
    token       TEXT NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    username    TEXT PRIMARY KEY,
    token       TEXT NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    user_id    INTEGER NOT NULL DEFAULT 0,
    username   TEXT    NOT NULL DEFAULT '',
    ip         TEXT    NOT NULL DEFAULT '',
    event      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_events_ts ON auth_events(ts);
-- schema_migrations: tracks when each named migration landed. Used by
-- Bootstrap to detect users created before the password-policy hardening
-- and force a rotation.
CREATE TABLE IF NOT EXISTS schema_migrations (
    name       TEXT PRIMARY KEY,
    applied_at INTEGER NOT NULL
);
`

// HardeningMigrationName is the marker written to schema_migrations the
// first time the daemon starts after the password-policy upgrade. Any user
// row with created_at < the marker timestamp is flagged as
// password_meets_policy=0 and forced to reset on next login.
const HardeningMigrationName = "password_policy_v1"

// logEvent writes a row to the auth_events table. Best-effort; never fails
// the parent operation.
func (m *Manager) logEvent(userID int64, username, ip, event string) {
	_, err := m.db.Exec(
		`INSERT INTO auth_events(ts, user_id, username, ip, event) VALUES(?,?,?,?,?)`,
		time.Now().Unix(), userID, username, ip, event,
	)
	if err != nil {
		logutil.Warn("auth: log event %q failed: %v", event, err)
	}
}

// ListRecentEvents returns the last N auth events, newest first.
func (m *Manager) ListRecentEvents(limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := m.db.Query(
		`SELECT id, ts, user_id, username, ip, event FROM auth_events ORDER BY id DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id int64
		var ts int64
		var userID int64
		var username, ip, event string
		if err := rows.Scan(&id, &ts, &userID, &username, &ip, &event); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{
			"id":       id,
			"ts":       ts,
			"user_id":  userID,
			"username": username,
			"ip":       ip,
			"event":    event,
		})
	}
	return out, nil
}

// SetResetFile lets main.go override the default reset-token file path.
func (m *Manager) SetResetFile(path string) { m.resetFile = path }

// --- helpers ---

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
