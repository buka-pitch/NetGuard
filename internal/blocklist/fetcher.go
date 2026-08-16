// Package blocklist fetches and parses remote IP/CIDR blocklists and pushes
// them into the SQLite blocklist table. Designed for additive-only behaviour:
// IPs added via the URL feed are never auto-removed.
package blocklist

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"modernc.org/sqlite"

	"netmon/internal/logutil"
)

// MaxResponseBytes caps the size of a single fetched blocklist to avoid OOM
// from a malicious or misconfigured source.
const MaxResponseBytes = 5 * 1024 * 1024

// Store is the minimal persistence surface the Fetcher needs.
type Store interface {
	BlocklistIP(ip, source string) error
}

// Fetcher periodically downloads a remote blocklist and merges the parsed
// IPs/CIDRs into the store.
type Fetcher struct {
	URL     string
	Source  string // label written into the blocklist.source column
	Every   time.Duration
	Client  *http.Client
	Store   Store
}

// New builds a Fetcher with safe defaults applied.
func New(rawURL, source string, every time.Duration, st Store) (*Fetcher, error) {
	if rawURL == "" {
		return nil, errors.New("blocklist: empty URL")
	}
	if st == nil {
		return nil, errors.New("blocklist: nil store")
	}
	if every <= 0 {
		every = 6 * time.Hour
	}
	if source == "" {
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			source = "url"
		} else {
			source = "url:" + u.Host
		}
	}
	return &Fetcher{
		URL:    rawURL,
		Source: source,
		Every:  every,
		Client: &http.Client{Timeout: 30 * time.Second},
		Store:  st,
	}, nil
}

// Run blocks until ctx is cancelled. It performs one fetch immediately, then
// fetches every `f.Every` afterwards.
func (f *Fetcher) Run(ctx context.Context) {
	if err := f.FetchOnce(ctx); err != nil {
		logutil.Warn("blocklist: initial fetch failed: %v", err)
	}

	t := time.NewTicker(f.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := f.FetchOnce(ctx); err != nil {
				logutil.Warn("blocklist: fetch failed: %v", err)
			}
		}
	}
}

// FetchOnce does a single HTTP GET + parse + insert cycle.
func (f *Fetcher) FetchOnce(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "netmon-blocklist/1.0")

	resp, err := f.Client.Do(req)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http status %d", resp.StatusCode)
	}

	body := io.LimitReader(resp.Body, MaxResponseBytes+1)
	entries, err := Parse(body)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	added := 0
	for _, ip := range entries {
		if err := f.Store.BlocklistIP(ip, f.Source); err != nil {
			// Unique-constraint violation just means the IP is already in the
			// table — that's the desired outcome of additive-only behaviour.
			if isUniqueViolation(err) {
				continue
			}
			logutil.Warn("blocklist: insert %s failed: %v", ip, err)
			continue
		}
		added++
	}
	logutil.Info("blocklist: fetched %d entries from %s (%d new)", len(entries), f.URL, added)
	return nil
}

// Parse reads a blocklist in plain-text form. Supported entry shapes:
//   - bare IPv4:  "1.2.3.4"
//   - bare IPv6:  "2001:db8::1"
//   - CIDR:       "10.0.0.0/8"
//   - hostnames are NOT supported.
//
// Lines starting with '#' (after trimming whitespace) and blank lines are
// ignored. Anything that fails IP/CIDR parsing is skipped silently.
func Parse(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	// Allow long lines (some feeds include >64KiB single lines for IPv6 ranges).
	scanner.Buffer(make([]byte, 0, 64*1024), MaxResponseBytes)

	seen := make(map[string]struct{})
	var out []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments (# to end of line) — some feeds embed them.
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		if !validIPOrCIDR(line) {
			continue
		}
		// Defensive filter: drop private/loopback/multicast/link-local ranges
		// so a misconfigured or hostile feed can't lock the host out of itself.
		if !isSafeRange(line) {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func validIPOrCIDR(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

// isSafeRange rejects anything that could match local traffic.
func isSafeRange(s string) bool {
	var ip net.IP
	var cidr *net.IPNet
	if strings.Contains(s, "/") {
		var err error
		ip, cidr, err = net.ParseCIDR(s)
		if err != nil {
			return false
		}
	} else {
		ip = net.ParseIP(s)
		if ip == nil {
			return false
		}
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	if cidr != nil {
		// Re-check the network address itself.
		if cidr.IP.IsLoopback() || cidr.IP.IsPrivate() || cidr.IP.IsMulticast() || cidr.IP.IsLinkLocalUnicast() || cidr.IP.IsLinkLocalMulticast() {
			return false
		}
	}
	return true
}

// isUniqueViolation returns true when the error from BlocklistIP is the
// "UNIQUE constraint failed" condition (the IP is already in the table).
// Overridable in tests via the package-level hook below.
var isUniqueViolation = func(err error) bool {
	if err == nil {
		return false
	}
	var sqlErr *sqlite.Error
	if errors.As(err, &sqlErr) {
		// 19 == SQLITE_CONSTRAINT
		if sqlErr.Code() == 19 {
			return true
		}
	}
	// Fallback string match — modernc sometimes wraps the error.
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
