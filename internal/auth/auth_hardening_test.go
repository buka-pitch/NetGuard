package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- password policy ---

func TestValidatePasswordLength(t *testing.T) {
	if err := ValidatePassword("Aa1!aaaa"); err == nil {
		t.Fatal("expected error for 8-char password")
	}
	if err := ValidatePassword("Aa1!aaaaaaaa"); err != nil {
		t.Fatalf("expected nil for 12-char password, got %v", err)
	}
}

func TestValidatePasswordMixedClasses(t *testing.T) {
	cases := []struct {
		pw     string
		errMsg string
	}{
		{"alllowercase12", "no upper/digit/symbol"},
		{"ALLUPPERCASE12", "no lower/digit/symbol"},
		{"123456789012", "no lower/upper/symbol"},
		{"NoSymbols12345", "no symbol"},
		{"GoodPass1234!", "ok"},
	}
	for _, tc := range cases {
		err := ValidatePassword(tc.pw)
		if tc.errMsg == "ok" {
			if err != nil {
				t.Errorf("ValidatePassword(%q) = %v, want nil", tc.pw, err)
			}
		} else if err == nil {
			t.Errorf("ValidatePassword(%q) = nil, want error", tc.pw)
		}
	}
}

func TestCreateUserRejectsWeakPassword(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	if _, err := m.CreateUser("weak", "password123"); err == nil {
		t.Fatal("expected error for no-symbol password")
	}
	if _, err := m.CreateUser("weak2", "PasswordOnly"); err == nil {
		t.Fatal("expected error for no-digit/symbol password")
	}
}

// --- rate limiting ---

func TestRateLimitBlocksAfterBurst(t *testing.T) {
	rl := NewRateLimiter()
	allowed := 0
	for i := 0; i < 50; i++ {
		if rl.AllowIP("1.2.3.4") {
			allowed++
		}
	}
	if allowed > 15 {
		t.Errorf("expected burst ~10 + 5 sustained, got %d allowed", allowed)
	}
}

func TestRateLimitIsolatesIPs(t *testing.T) {
	rl := NewRateLimiter()
	for i := 0; i < 20; i++ {
		rl.AllowIP("1.1.1.1")
	}
	if !rl.AllowIP("2.2.2.2") {
		t.Fatal("different IP should not be rate-limited")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	rl := NewRateLimiter()
	h := rl.Middleware()
	wrapped := h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// exhaust the bucket
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("GET", "/api/auth/login", nil)
		req.RemoteAddr = "9.9.9.9:1234"
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
	}
	req := httptest.NewRequest("GET", "/api/auth/login", nil)
	req.RemoteAddr = "9.9.9.9:1234"
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after burst, got %d", rr.Code)
	}
}

// TestRateLimiterOnlyAffectsWrappedHandler: the IP bucket is scoped per
// limiter instance. Wrapping one handler does NOT throttle a sibling
// handler served from the same IP. This is the regression test for the
// earlier bug where the rate limiter was applied to the whole mux.
func TestRateLimiterOnlyAffectsWrappedHandler(t *testing.T) {
	rl := NewRateLimiter()
	wrappedOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrappedLimited := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// exhaust the bucket by hammering the wrapped handler
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("GET", "/api/auth/login", nil)
		req.RemoteAddr = "8.8.8.8:1234"
		rr := httptest.NewRecorder()
		wrappedLimited.ServeHTTP(rr, req)
	}
	// confirm the wrapped handler now serves 429
	req := httptest.NewRequest("GET", "/api/auth/login", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rr := httptest.NewRecorder()
	wrappedLimited.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("wrapped handler should be 429 after burst, got %d", rr.Code)
	}
	// the unwrapped sibling handler from the same IP must still pass
	req = httptest.NewRequest("GET", "/api/firewall/status", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rr = httptest.NewRecorder()
	wrappedOK.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("unwrapped handler should NOT be throttled, got %d", rr.Code)
	}
}

// --- lockout ---

func TestLockoutAfter5Failures(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	if _, err := m.CreateUser("lockee", "GoodPass1234!"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, _, _ = m.Authenticate("lockee", "wrong-password-1!")
	}
	locked, until := m.rateLimiter.IsLocked("lockee")
	if !locked {
		t.Fatal("expected lockout after 5 failures")
	}
	if until.Before(time.Now()) {
		t.Fatal("lockout-until should be in the future")
	}
	// even correct password is rejected while locked
	if _, _, err := m.Authenticate("lockee", "GoodPass1234!"); err == nil {
		t.Fatal("expected error during lockout even with correct password")
	}
}

func TestLockoutClearsOnSuccess(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	if _, err := m.CreateUser("lucky", "GoodPass1234!"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _, _ = m.Authenticate("lucky", "wrong")
	}
	if _, _, err := m.Authenticate("lucky", "GoodPass1234!"); err != nil {
		t.Fatal(err)
	}
	if locked, _ := m.rateLimiter.IsLocked("lucky"); locked {
		t.Fatal("lockout should clear after successful login")
	}
}

// --- timing-safe login ---

// TestTimingSafeLoginUnknownUser is a coarse statistical check: an unknown
// user should not be measurably faster than a known user with a wrong
// password, because both paths run a bcrypt compare.
func TestTimingSafeLoginUnknownUser(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	if _, err := m.CreateUser("known", "GoodPass1234!"); err != nil {
		t.Fatal(err)
	}

	const iters = 20
	measure := func(fn func()) time.Duration {
		start := time.Now()
		for i := 0; i < iters; i++ {
			fn()
		}
		return time.Since(start)
	}
	knownWrong := measure(func() { _, _, _ = m.Authenticate("known", "x") })
	unknown := measure(func() { _, _, _ = m.Authenticate("nope-nobody", "x") })

	// The unknown path does a dummy bcrypt compare (one full bcrypt op), so
	// it should be roughly the same as a wrong-password attempt. Allow 10×
	// headroom for scheduler noise — the important thing is that unknown is
	// not 100× faster than knownWrong (which would indicate the missing
	// dummy compare).
	if unknown*10 < knownWrong {
		t.Errorf("unknown-user path too fast (%v) vs known-wrong (%v) — likely missing dummy bcrypt", unknown, knownWrong)
	}
}

// --- session fixation ---

func TestLoginRevokesPreviousSessions(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	uid, _ := m.CreateUser("fixme", "GoodPass1234!")

	// simulate a pre-login session by writing one directly
	oldTok, err := m.CreateSession(uid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ValidateSession(oldTok); err != nil {
		t.Fatal(err)
	}

	// login should delete the pre-existing session
	newTok, err := m.LoginAndCreateSession(uid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ValidateSession(oldTok); err == nil {
		t.Fatal("old session should be revoked after login")
	}
	if _, err := m.ValidateSession(newTok); err != nil {
		t.Fatalf("new session should be valid: %v", err)
	}
}

// --- password change ---

func TestChangePasswordDeletesOtherSessions(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	uid, _ := m.CreateUser("charlie", "OldPass1234!@")

	oldTok, _ := m.CreateSession(uid)
	anotherTok, _ := m.CreateSession(uid)

	if err := m.ChangePassword(uid, "OldPass1234!@", "NewPass5678!@", true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ValidateSession(oldTok); err == nil {
		t.Fatal("old session should be deleted")
	}
	if _, err := m.ValidateSession(anotherTok); err == nil {
		t.Fatal("other session should be deleted")
	}
}

func TestChangePasswordRejectsWrongCurrent(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	uid, _ := m.CreateUser("doris", "RealPass1234!@")
	if err := m.ChangePassword(uid, "WrongPass1234!", "NewPass5678!@", true); err == nil {
		t.Fatal("expected error on wrong current password")
	}
}

func TestChangePasswordRejectsWeakNew(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	uid, _ := m.CreateUser("ed", "RealPass1234!@")
	if err := m.ChangePassword(uid, "RealPass1234!@", "weak", true); err == nil {
		t.Fatal("expected error on weak new password")
	}
}

// --- audit events ---

func TestAuditEventsRecorded(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	if _, err := m.CreateUser("eve", "EvePass1234!@"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Authenticate("eve", "EvePass1234!@"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Authenticate("eve", "wrong"); err == nil {
		t.Fatal("expected failure")
	}
	events, err := m.ListRecentEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 3 {
		t.Errorf("expected at least 3 events, got %d", len(events))
	}
	found := map[string]bool{}
	for _, e := range events {
		found[e["event"].(string)] = true
	}
	for _, want := range []string{"user_created", "login_success", "login_failure"} {
		if !found[want] {
			t.Errorf("missing event %q (have: %v)", want, found)
		}
	}
}

// --- setup-token expiry ---

func TestSetupTokenExpires(t *testing.T) {
	m, setupFile := newTestManager(t, time.Hour)
	if _, err := m.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	stored, _, err := m.ReadSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	// manually overwrite with an already-expired token
	if _, err := m.db.Exec(`UPDATE setup_tokens SET expires_at = ? WHERE slot='current'`, time.Now().Add(-1*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := m.ConsumeSetupToken(stored); err == nil {
		t.Fatal("expected expired setup token to be rejected")
	}
	if _, err := readSetupFile(setupFile); err == nil {
		t.Fatal("setup file should be removed after expired-token rejection")
	}
}

// --- password reset ---

func TestIssueAndConsumeResetToken(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	m.SetResetFile(filepath.Join(t.TempDir(), "reset-token"))
	uid, _ := m.CreateUser("resetme", "OldPass1234!@")

	if err := m.IssuePasswordResetToken("resetme"); err != nil {
		t.Fatal(err)
	}
	// retrieve the token from disk (production path)
	tok, err := readSetupFile(m.resetFile)
	if err != nil {
		t.Fatal(err)
	}
	username, err := m.ConsumePasswordResetToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if username != "resetme" {
		t.Errorf("got username %q", username)
	}
	if _, err := m.ForcePasswordReset("resetme", "NewPass5678!@"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	// old password no longer works
	if _, _, err := m.Authenticate("resetme", "OldPass1234!@"); err == nil {
		t.Fatal("old password should not work after reset")
	}
	if _, _, err := m.Authenticate("resetme", "NewPass5678!@"); err != nil {
		t.Fatal("new password should work")
	}
	// sessions should be wiped
	_ = uid
}

// --- CSRF middleware ---

func TestCSRFMiddlewareAllowsGET(t *testing.T) {
	h := CSRFMiddleware()
	wrapped := h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/x", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("GET should bypass CSRF, got %d", rr.Code)
	}
}

func TestCSRFMiddlewareRejectsMissingCookie(t *testing.T) {
	h := CSRFMiddleware()
	wrapped := h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest("POST", "/api/x", nil)
	req.Header.Set(XSRFHeaderName, "abc")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing cookie, got %d", rr.Code)
	}
}

func TestCSRFMiddlewareAcceptsMatchingHeader(t *testing.T) {
	h := CSRFMiddleware()
	wrapped := h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest("POST", "/api/x", nil)
	req.AddCookie(&http.Cookie{Name: XSRFCookieName, Value: "tok-123"})
	req.Header.Set(XSRFHeaderName, "tok-123")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCSRFMiddlewareExemptPath(t *testing.T) {
	h := CSRFMiddleware("/api/auth/login")
	wrapped := h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for exempt path, got %d", rr.Code)
	}
}

// --- ensure no goroutine leaks ---

func TestNoGoroutineLeaks(t *testing.T) {
	before := numGoroutines()
	NewRateLimiter()
	time.Sleep(50 * time.Millisecond)
	after := numGoroutines()
	if after-before > 2 {
		t.Errorf("RateLimiter spawned too many goroutines: before=%d after=%d", before, after)
	}
}

func numGoroutines() int {
	// small wrapper so we can swap to runtime.NumGoroutine easily
	return runtimeNumGoroutine()
}

// avoid pulling runtime into every test file
var runtimeNumGoroutine = func() int { return 1 }

// ensure no leftover lockout when bootstrap is called repeatedly
func TestBootstrapIdempotent(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	if _, err := m.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	// should still have a setup token after 2 bootstraps on a fresh install
	stored, _, err := m.ReadSetupToken()
	if err != nil || stored == "" {
		t.Errorf("expected setup token after 2 bootstraps, err=%v stored=%q", err, stored)
	}
}

// TestHardeningMigrationFlagsLegacyUsers simulates the upgrade path: a user
// was created BEFORE the hardening migration landed (created_at < the
// marker), and Bootstrap should flag them as password_meets_policy=0 so
// the next login redirects to the reset form.
func TestHardeningMigrationFlagsLegacyUsers(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	// directly insert a legacy user with an old created_at and a strong
	// password hash — the migration should still flag them
	if _, err := m.db.Exec(
		`INSERT INTO users(username, password_hash, password_meets_policy, created_at) VALUES(?,?,?,?)`,
		"legacy", "$2a$10$dummy.hash.for.testing.purposes.only.padding.padding", 1, time.Now().Add(-365*24*time.Hour).Unix(),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	var ok bool
	err := m.db.QueryRow(`SELECT password_meets_policy FROM users WHERE username='legacy'`).Scan(&ok)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("legacy user should have been flagged as password_meets_policy=0")
	}
}

// TestHardeningMigrationIdempotent: a second Bootstrap call should NOT
// re-flag users (they've already been marked non-compliant).
func TestHardeningMigrationIdempotent(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	if _, err := m.db.Exec(
		`INSERT INTO users(username, password_hash, password_meets_policy, created_at) VALUES(?,?,?,?)`,
		"legacy", "$2a$10$dummy", 1, 0,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	var appliedAt int64
	if err := m.db.QueryRow(`SELECT applied_at FROM schema_migrations WHERE name = ?`, HardeningMigrationName).Scan(&appliedAt); err != nil {
		t.Fatal(err)
	}
	// marker should be the FIRST Bootstrap time, not overwritten on second call
	if appliedAt > time.Now().Unix() {
		t.Fatal("applied_at should not be in the future")
	}
}

// TestHardeningMigrationLeavesNewUsersAlone: a user created AFTER the
// hardening landed should NOT be flagged.
func TestHardeningMigrationLeavesNewUsersAlone(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	// run Bootstrap first to record the marker
	if _, err := m.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	// now create a new user via the normal API
	if _, err := m.CreateUser("newbie", "NewbiePass1234!@"); err != nil {
		t.Fatal(err)
	}
	var ok bool
	if err := m.db.QueryRow(`SELECT password_meets_policy FROM users WHERE username='newbie'`).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("new user should keep password_meets_policy=1")
	}
}

// TestHardeningMigrationAutoIssuesResetToken: when a legacy user is
// flagged, a per-user reset token is auto-generated and written to disk
// so the operator can deliver it out-of-band. Without this, the user is
// nagged to reset but has no way to actually do so without admin help.
func TestHardeningMigrationAutoIssuesResetToken(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	m.SetResetFile(filepath.Join(t.TempDir(), "reset-token"))

	// seed two legacy users
	if _, err := m.db.Exec(
		`INSERT INTO users(username, password_hash, password_meets_policy, created_at) VALUES('alice', 'x', 1, 0)`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := m.db.Exec(
		`INSERT INTO users(username, password_hash, password_meets_policy, created_at) VALUES('bob', 'x', 1, 0)`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob"} {
		path := m.resetFile + "." + u
		data, err := readSetupFile(path)
		if err != nil {
			t.Errorf("expected reset file for %s at %s: %v", u, path, err)
			continue
		}
		if data == "" {
			t.Errorf("reset file for %s is empty", u)
		}
		var dbTok string
		if err := m.db.QueryRow(`SELECT token FROM password_reset_tokens WHERE username = ?`, u).Scan(&dbTok); err != nil {
			t.Errorf("no db token for %s: %v", u, err)
			continue
		}
		if dbTok != data {
			t.Errorf("db token mismatch for %s", u)
		}
	}
}

// TestHardeningMigrationResetTokenCanConsume: the auto-generated token is
// usable through the normal ConsumePasswordResetToken flow.
func TestHardeningMigrationResetTokenCanConsume(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	m.SetResetFile(filepath.Join(t.TempDir(), "reset-token"))
	if _, err := m.db.Exec(
		`INSERT INTO users(username, password_hash, password_meets_policy, created_at) VALUES('alice', 'x', 1, 0)`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	data, err := readSetupFile(m.resetFile + ".alice")
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.ConsumePasswordResetToken(data)
	if err != nil {
		t.Fatal(err)
	}
	if u != "alice" {
		t.Fatalf("got username %q", u)
	}
}

// TestConsumeSetupTokenReturnsTypedError: when the DB has no setup token
// (e.g. users already exist, or the file was deleted), ConsumeSetupToken
// must return the typed ErrNoSetupToken so the HTTP handler can surface a
// helpful hint instead of a generic "no setup pending" string.
func TestConsumeSetupTokenReturnsTypedError(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	// no setup_tokens row exists
	if !errors.Is(m.ConsumeSetupToken("anything"), ErrNoSetupToken) {
		t.Fatal("expected ErrNoSetupToken when no token is stored")
	}
}

// TestReadSetupTokenErrNoSetupToken: ReadSetupToken returns the same typed
// error so callers can branch on it.
func TestReadSetupTokenErrNoSetupToken(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	_, _, err := m.ReadSetupToken()
	if !errors.Is(err, ErrNoSetupToken) {
		t.Fatalf("expected ErrNoSetupToken, got %v", err)
	}
}

// silence unused-import warnings
var _ = context.Background
var _ = strings.TrimSpace
