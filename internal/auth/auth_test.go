package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestManager(t *testing.T, ttl time.Duration) (*Manager, string) {
	t.Helper()
	f, err := os.CreateTemp("", "netmon-auth-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()); f.Close() })
	f.Close()

	db, err := sql.Open("sqlite", f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	setupFile := filepath.Join(t.TempDir(), "setup-token")
	m := New(db, ttl, setupFile, false)
	return m, setupFile
}

func TestInitWritesSetupTokenWhenNoUsers(t *testing.T) {
	m, setupFile := newTestManager(t, time.Hour)
	created, err := m.Bootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected setup token to be created")
	}
	data, err := os.ReadFile(setupFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("setup file is empty")
	}
	// hex of 16 bytes = 32 chars
	if got := len(strings.TrimSpace(string(data))); got != SetupTokenBytes*2 {
		t.Errorf("setup token length = %d, want %d", got, SetupTokenBytes*2)
	}
}

func TestInitSkipsSetupWhenUsersExist(t *testing.T) {
	m, setupFile := newTestManager(t, time.Hour)
	if _, err := m.CreateUser("admin", "Sup3rSecretPwd!"); err != nil {
		t.Fatal(err)
	}
	created, err := m.Bootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("expected NO setup token when users already exist")
	}
	if _, err := os.Stat(setupFile); !os.IsNotExist(err) {
		t.Errorf("setup file should be removed, stat err=%v", err)
	}
}

func TestConsumeSetupTokenSuccess(t *testing.T) {
	m, setupFile := newTestManager(t, time.Hour)
	if _, err := m.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(setupFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConsumeSetupToken(strings.TrimSpace(string(stored))); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if _, err := os.Stat(setupFile); !os.IsNotExist(err) {
		t.Error("setup file should be deleted after consume")
	}
}

func TestConsumeSetupTokenWrongValue(t *testing.T) {
	m, setupFile := newTestManager(t, time.Hour)
	if _, err := m.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := m.ConsumeSetupToken("deadbeef"); err == nil {
		t.Fatal("expected error on wrong token")
	}
	if _, err := os.Stat(setupFile); err != nil {
		t.Error("setup file should still exist after failed consume")
	}
}

func TestCreateAndAuthenticateUser(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	if _, err := m.CreateUser("alice", "Sup3rSecretPwd!"); err != nil {
		t.Fatal(err)
	}
	id, _, err := m.Authenticate("alice", "Sup3rSecretPwd!")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero user id")
	}
	if _, _, err := m.Authenticate("alice", "wrongpass"); err == nil {
		t.Fatal("expected error on wrong password")
	}
	if _, _, err := m.Authenticate("nobody", "Sup3rSecretPwd!"); err == nil {
		t.Fatal("expected error on unknown user")
	}
}

func TestCreateUserRejectsShortPassword(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	if _, err := m.CreateUser("bob", "short"); err == nil {
		t.Fatal("expected error on password <8 chars")
	}
}

func TestCreateAndValidateSession(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	uid, err := m.CreateUser("cathy", "Sup3rSecretPwd!")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := m.CreateSession(uid)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != SessionTokenBytes*2 {
		t.Errorf("session token length = %d, want %d", len(tok), SessionTokenBytes*2)
	}
	got, err := m.ValidateSession(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got != uid {
		t.Errorf("user id mismatch: got %d want %d", got, uid)
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	m, _ := newTestManager(t, 0) // zero TTL — session expires the instant it's created
	uid, _ := m.CreateUser("dave", "Sup3rSecretPwd!")
	tok, _ := m.CreateSession(uid)
	if _, err := m.ValidateSession(tok); err == nil {
		t.Fatal("expected expired session rejection")
	}
}

func TestDeleteSession(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	uid, _ := m.CreateUser("erin", "Sup3rSecretPwd!")
	tok, _ := m.CreateSession(uid)
	if err := m.DeleteSession(tok); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ValidateSession(tok); err == nil {
		t.Fatal("expected error after delete")
	}
}

// --- Middleware ---

func TestMiddlewareAllowsPublicPaths(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	h := m.Middleware("/login", "/setup", "/api/health", "/static/")
	wrapped := h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, path := range []string{"/login", "/setup", "/api/health", "/static/x.css"} {
		req := httptest.NewRequest("GET", path, nil)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("%s: got %d, want 200", path, rr.Code)
		}
	}
}

// TestMiddlewareExactVsPrefix — a bare path (no trailing "/") must match the
// exact route only, so sibling subpaths still require auth. Without this,
// allow-listing "/api/auth/password-reset" would also exempt the admin-only
// "/api/auth/password-reset/issue" from session validation.
func TestMiddlewareExactVsPrefix(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	h := m.Middleware("/api/auth/password-reset", "/static/")
	wrapped := h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	exact := httptest.NewRequest("GET", "/api/auth/password-reset", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, exact)
	if rr.Code != http.StatusOK {
		t.Errorf("exact public path: got %d, want 200", rr.Code)
	}

	sibling := httptest.NewRequest("GET", "/api/auth/password-reset/issue", nil)
	rr2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rr2, sibling)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("sibling subpath should require auth: got %d, want 401", rr2.Code)
	}

	prefix := httptest.NewRequest("GET", "/static/x.css", nil)
	rr3 := httptest.NewRecorder()
	wrapped.ServeHTTP(rr3, prefix)
	if rr3.Code != http.StatusOK {
		t.Errorf("trailing-slash prefix: got %d, want 200", rr3.Code)
	}
}

func TestMiddlewareRejectsUnauthenticated(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	h := m.Middleware()
	wrapped := h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/firewall/status", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rr.Code)
	}
}

func TestMiddlewareAcceptsCookieSession(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	uid, _ := m.CreateUser("frank", "Sup3rSecretPwd!")
	tok, _ := m.CreateSession(uid)

	var seenUID int64
	h := m.Middleware()
	wrapped := h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUID = UserIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/firewall/status", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("got %d, want 200", rr.Code)
	}
	if seenUID != uid {
		t.Errorf("user id: got %d, want %d", seenUID, uid)
	}
}

func TestMiddlewareAcceptsBearerAndQueryToken(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	uid, _ := m.CreateUser("gina", "Sup3rSecretPwd!")
	tok, _ := m.CreateSession(uid)
	h := m.Middleware()

	for _, setReq := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) },
		func(r *http.Request) { r.URL.RawQuery = "token=" + tok },
	} {
		req := httptest.NewRequest("GET", "/api/firewall/status", nil)
		setReq(req)
		rr := httptest.NewRecorder()
		h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("got %d, want 200", rr.Code)
		}
	}
}

func TestMiddlewareRejectsExpiredSession(t *testing.T) {
	m, _ := newTestManager(t, 0) // zero TTL — session expires the instant it's created
	uid, _ := m.CreateUser("harry", "Sup3rSecretPwd!")
	tok, _ := m.CreateSession(uid)
	h := m.Middleware()
	wrapped := h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rr.Code)
	}
}

func TestSetXSRFCookieTTLAlignsWithSessionLifetime(t *testing.T) {
	rr := httptest.NewRecorder()
	SetXSRFCookieTTL(rr, "tok123", false, 7*24*time.Hour)

	cookies := rr.Result().Cookies()
	var xsrf *http.Cookie
	for _, c := range cookies {
		if c.Name == XSRFCookieName {
			xsrf = c
		}
	}
	if xsrf == nil {
		t.Fatal("expected netmon_xsrf cookie to be set")
	}
	if xsrf.HttpOnly {
		t.Error("xsrf cookie must be readable by JS (not HttpOnly)")
	}
	if xsrf.Expires.IsZero() {
		t.Fatal("xsrf cookie must carry an expiry (session-aligned), otherwise it dies on browser restart while the session cookie survives")
	}
	// ~7 days out, generous 1h skew for test scheduling
	if d := time.Until(xsrf.Expires); d < 6*24*time.Hour || d > 8*24*time.Hour {
		t.Errorf("xsrf expiry should be ~7d, got %v", d)
	}
}
