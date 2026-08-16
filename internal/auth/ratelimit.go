package auth

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter enforces two complementary limits on the auth endpoints:
//   - per-IP request rate (sustained + burst)
//   - per-username failed-login backoff
type RateLimiter struct {
	ipBuckets    sync.Map // string -> *ipBucket
	ipRate       rate.Limit
	ipBurst      int
	mu           sync.Mutex
	loginFails   map[string]*loginAttempt // keyed by lowercased username
	lockoutAfter int                      // number of failed attempts before lockout
	lockoutFor   time.Duration
}

type ipBucket struct {
	lim  *rate.Limiter
	seen time.Time
}

type loginAttempt struct {
	count      int
	lockedTill time.Time
}

// NewRateLimiter constructs a limiter with sensible defaults:
//   - 5 requests / minute sustained per IP, burst 10
//   - 5 failed login attempts per username triggers a 15-minute lockout
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		ipRate:       rate.Limit(5.0 / 60.0), // 5 per minute
		ipBurst:      10,
		loginFails:   map[string]*loginAttempt{},
		lockoutAfter: 5,
		lockoutFor:   15 * time.Minute,
	}
	go rl.gc()
	return rl
}

// AllowIP reports whether a request from the given IP is permitted right now.
// It updates the token bucket.
func (rl *RateLimiter) AllowIP(remoteAddr string) bool {
	ip := clientIP(remoteAddr)
	if ip == "" {
		ip = "unknown"
	}
	v, ok := rl.ipBuckets.Load(ip)
	if !ok {
		v, _ = rl.ipBuckets.LoadOrStore(ip, &ipBucket{lim: rate.NewLimiter(rl.ipRate, rl.ipBurst), seen: time.Now()})
	}
	b := v.(*ipBucket)
	b.seen = time.Now()
	return b.lim.Allow()
}

// RecordFailedLogin increments the failure counter for a username and returns
// the new count + whether the account is now locked.
func (rl *RateLimiter) RecordFailedLogin(username string) (count int, locked bool, until time.Time) {
	key := strings.ToLower(username)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	a, ok := rl.loginFails[key]
	if !ok {
		a = &loginAttempt{}
		rl.loginFails[key] = a
	}
	now := time.Now()
	if now.Before(a.lockedTill) {
		return a.count, true, a.lockedTill
	}
	a.count++
	a.lockedTill = time.Time{}
	if a.count >= rl.lockoutAfter {
		a.lockedTill = now.Add(rl.lockoutFor)
		return a.count, true, a.lockedTill
	}
	return a.count, false, time.Time{}
}

// IsLocked reports whether a username is currently locked out without
// incrementing the counter.
func (rl *RateLimiter) IsLocked(username string) (bool, time.Time) {
	key := strings.ToLower(username)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	a, ok := rl.loginFails[key]
	if !ok {
		return false, time.Time{}
	}
	if time.Now().Before(a.lockedTill) {
		return true, a.lockedTill
	}
	return false, time.Time{}
}

// ResetLockout clears the failure counter after a successful login.
func (rl *RateLimiter) ResetLockout(username string) {
	key := strings.ToLower(username)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.loginFails, key)
}

// gc drops IP buckets and login-attempt records that haven't been seen for
// a while. Keeps memory bounded.
func (rl *RateLimiter) gc() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-1 * time.Hour)
		rl.ipBuckets.Range(func(k, v any) bool {
			if v.(*ipBucket).seen.Before(cutoff) {
				rl.ipBuckets.Delete(k)
			}
			return true
		})
		rl.mu.Lock()
		for k, a := range rl.loginFails {
			if !time.Now().Before(a.lockedTill) && a.count == 0 {
				delete(rl.loginFails, k)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP extracts the host from r.RemoteAddr, stripping the port.
func clientIP(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// Middleware returns an http middleware that rejects requests above the IP
// rate with 429. Exempt paths bypass the limit.
func (rl *RateLimiter) Middleware(exempt ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range exempt {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if set[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			if !rl.AllowIP(r.RemoteAddr) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
