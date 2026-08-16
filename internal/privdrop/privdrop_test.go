package privdrop

import (
	"os"
	"syscall"
	"testing"
)

func TestParseInt(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"0", 0},
		{"123", 123},
		{"999", 999},
		{"", 0},
		{"abc", 0},
		{"12abc", 12},
	}
	for _, tc := range tests {
		got := parseInt(tc.input)
		if got != tc.want {
			t.Errorf("parseInt(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestSplitLines(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", []string{}},
		{"a\nb\nc", []string{"a", "b", "c"}},
		{"a\nb\nc\n", []string{"a", "b", "c"}},
		{"single", []string{"single"}},
		{"\nleading", []string{"leading"}},
	}
	for _, tc := range tests {
		got := splitLines(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("splitLines(%q) = %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitLines(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

func TestSplitN(t *testing.T) {
	tests := []struct {
		s   string
		sep string
		n   int
		want []string
	}{
		{"a:b:c", ":", 3, []string{"a", "b", "c"}},
		{"a:b:c", ":", 2, []string{"a", "b:c"}},
		{"a:b:c", ":", 1, []string{"a:b:c"}},
		{"abc", ":", 3, []string{"abc"}},
	}
	for _, tc := range tests {
		got := splitN(tc.s, tc.sep, tc.n)
		if len(got) != len(tc.want) {
			t.Errorf("splitN(%q, %q, %d) = %v, want %v", tc.s, tc.sep, tc.n, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitN(%q, %q, %d)[%d] = %q, want %q", tc.s, tc.sep, tc.n, i, got[i], tc.want[i])
			}
		}
	}
}

func TestLookupUser(t *testing.T) {
	// Look up root — should always exist
	uid, gid, err := LookupUser("root")
	if err != nil {
		t.Fatalf("LookupUser(root) failed: %v", err)
	}
	if uid != 0 {
		t.Errorf("expected root uid 0, got %d", uid)
	}
	if gid != 0 {
		t.Errorf("expected root gid 0, got %d", gid)
	}

	// Look up nonexistent user
	_, _, err = LookupUser("thisuserdoesnotexist_xyz")
	if err != syscall.ENOENT {
		t.Errorf("expected ENOENT, got %v", err)
	}
}

func TestLookupUserCurrent(t *testing.T) {
	// Look up the current user
	current := os.Getenv("USER")
	if current == "" {
		t.Skip("USER env not set")
	}
	uid, gid, err := LookupUser(current)
	if err != nil {
		t.Fatalf("LookupUser(%s) failed: %v", current, err)
	}
	if uid < 0 || gid < 0 {
		t.Errorf("invalid uid/gid: %d/%d", uid, gid)
	}
	t.Logf("user %s: uid=%d gid=%d", current, uid, gid)
}

func TestMaybeDropUserInvalid(t *testing.T) {
	// Should return false for invalid UID/GID
	if MaybeDropUser(-1, -1) {
		t.Error("expected false for invalid uid/gid")
	}
}

func TestDropToUserNonRoot(t *testing.T) {
	// This should fail since we're not root
	err := DropToUser(1000, 1000)
	if err == nil {
		t.Log("DropToUser succeeded (running as root?)")
	}
}
