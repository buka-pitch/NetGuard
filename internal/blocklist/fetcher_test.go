package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubStore records every IP/source the fetcher inserts.
type stubStore struct {
	mu      sync.Mutex
	entries map[string]string // ip -> source
}

func newStubStore() *stubStore {
	return &stubStore{entries: map[string]string{}}
}

func (s *stubStore) BlocklistIP(ip, source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[ip]; ok {
		// mimic sqlite UNIQUE violation
		return errUnique
	}
	s.entries[ip] = source
	return nil
}

func (s *stubStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// errUnique is a stand-in for the sqlite UNIQUE constraint error.
type fakeUniqueErr struct{}

func (fakeUniqueErr) Error() string { return "UNIQUE constraint failed: blocklist.ip" }

// we set the package-level hook used by the fetcher to identify uniqueness.
var errUnique = fakeUniqueErr{}

// withIsUnique swaps isUniqueViolation for the duration of the test.
func withIsUnique(t *testing.T) {
	t.Helper()
	orig := isUniqueViolation
	isUniqueViolation = func(err error) bool {
		_, ok := err.(fakeUniqueErr)
		return ok
	}
	t.Cleanup(func() { isUniqueViolation = orig })
}

// --- Parse ---

func TestParseBasic(t *testing.T) {
	in := `# a comment
1.2.3.4
5.6.7.8

2001:db8::1
10.0.0.0/24  # comment after
not_an_ip
`
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.2.3.4", "5.6.7.8", "2001:db8::1"}
	if !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseDropsPrivateRanges(t *testing.T) {
	in := `# these should be dropped
127.0.0.1
10.0.0.5
172.16.0.1
192.168.1.1
169.254.0.1
224.0.0.1
::1
fc00::1
fe80::1

# these should pass
8.8.8.8
1.1.1.1
`
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"8.8.8.8", "1.1.1.1"}
	if !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseDeduplicates(t *testing.T) {
	in := "1.2.3.4\n1.2.3.4\n1.2.3.4\n"
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("got %v, want [1.2.3.4]", got)
	}
}

func TestParseEmptyAndComments(t *testing.T) {
	in := "# header\n\n\n# more\n"
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestParseCIDR(t *testing.T) {
	in := "8.8.0.0/16\n# private\n10.0.0.0/8\n1.0.0.0/8\n"
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"8.8.0.0/16", "1.0.0.0/8"}
	if !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// --- FetchOnce end-to-end via httptest ---

func TestFetchOnceInsertsViaStore(t *testing.T) {
	withIsUnique(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1.2.3.4\n5.6.7.8\n8.8.8.8\n"))
	}))
	defer srv.Close()

	st := newStubStore()
	f := &Fetcher{
		URL:    srv.URL,
		Source: "url:test",
		Every:  0,
		Client: srv.Client(),
		Store:  st,
	}
	if err := f.FetchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.count() != 3 {
		t.Errorf("expected 3 inserts, got %d", st.count())
	}
}

func TestFetchOnceIdempotent(t *testing.T) {
	withIsUnique(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1.2.3.4\n5.6.7.8\n"))
	}))
	defer srv.Close()

	st := newStubStore()
	f := &Fetcher{URL: srv.URL, Source: "url:test", Client: srv.Client(), Store: st}

	if err := f.FetchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.FetchOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.count() != 2 {
		t.Errorf("expected 2 inserts across two fetches, got %d", st.count())
	}
}

func TestFetchOnceNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	st := newStubStore()
	f := &Fetcher{URL: srv.URL, Client: srv.Client(), Store: st}
	if err := f.FetchOnce(context.Background()); err == nil {
		t.Fatal("expected error on 500 response")
	}
	if st.count() != 0 {
		t.Errorf("expected no inserts on error, got %d", st.count())
	}
}

func TestFetchOnceBadURL(t *testing.T) {
	st := newStubStore()
	f := &Fetcher{URL: "http://127.0.0.1:1/does-not-exist", Client: &http.Client{}, Store: st}
	if err := f.FetchOnce(context.Background()); err == nil {
		t.Fatal("expected network error")
	}
}

// --- Run loop context cancellation ---

func TestRunStopsOnContextCancel(t *testing.T) {
	withIsUnique(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1.1.1.1\n"))
	}))
	defer srv.Close()

	st := newStubStore()
	f := &Fetcher{
		URL:    srv.URL,
		Source: "url:test",
		Every:  50 * time.Millisecond,
		Client: srv.Client(),
		Store:  st,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		f.Run(ctx)
		close(done)
	}()

	// let it run a tick
	time.Sleep(120 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fetcher.Run did not return after ctx cancel")
	}
}

// --- helpers ---

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
