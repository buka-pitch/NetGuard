package auth

import (
	"crypto/subtle"
	"net/http"
)

// CSRFMiddleware returns a wrapper that enforces a double-submit-cookie CSRF
// check on all mutating requests (POST/PUT/DELETE/PATCH). Safe methods
// (GET/HEAD/OPTIONS) are allowed through.
//
// The first time a session is created (login / setup / password-reset) the
// caller must also write a netmon_xsrf cookie. On every subsequent mutating
// request the JS client must echo that cookie's value as the X-XSRF-TOKEN
// header; the middleware compares the two in constant time.
//
// exempt lists path prefixes that bypass the check entirely — typically the
// login/setup endpoints themselves which mint the initial cookie.
func CSRFMiddleware(exempt ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range exempt {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			method := r.Method
			if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			for p := range set {
				if len(r.URL.Path) >= len(p) && r.URL.Path[:len(p)] == p {
					next.ServeHTTP(w, r)
					return
				}
			}
			cookie, err := r.Cookie(XSRFCookieName)
			if err != nil || cookie.Value == "" {
				http.Error(w, `{"error":"missing csrf cookie"}`, http.StatusForbidden)
				return
			}
			header := r.Header.Get(XSRFHeaderName)
			if header == "" {
				http.Error(w, `{"error":"missing csrf header"}`, http.StatusForbidden)
				return
			}
			if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
				http.Error(w, `{"error":"csrf mismatch"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NewXSRFToken generates a fresh 32-byte hex token for the XSRF cookie.
func NewXSRFToken() (string, error) {
	return randomToken(SessionTokenBytes)
}

// SetXSRFCookie writes the non-HttpOnly XSRF cookie. Path=/ so it's sent on
// every request from this origin.
func SetXSRFCookie(w http.ResponseWriter, value string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     XSRFCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: false, // JS must read this
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}
