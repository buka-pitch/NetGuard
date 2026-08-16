package privdrop

import (
	"os"
	"syscall"
)

const (
	prSetKeepCaps    = 8
	prCapBSetDrop    = 0x11
	prSetNoNewPrivs  = 0x26

	capDACOverride   = 1
	capNetAdmin      = 12
	capNetRaw        = 13
	capSysPtrace     = 19
	capLast          = 40
)

func prctl(option, arg2, arg3 uintptr) error {
	_, _, err := syscall.Syscall(syscall.SYS_PRCTL, option, arg2, arg3)
	if err != 0 {
		return err
	}
	return nil
}

// KeepCaps drops all capabilities from the bounding set except those listed
// in keep. Must be called after all privileged setup is done.
func KeepCaps(keep ...int) error {
	// Build a set of capabilities to keep
	keepSet := make(map[int]bool)
	for _, c := range keep {
		keepSet[c] = true
	}

	// Set keepcaps flag in case we switch UID later
	if err := prctl(prSetKeepCaps, 1, 0); err != nil {
		return err
	}

	// Drop capabilities from bounding set
	for c := 0; c <= capLast; c++ {
		if keepSet[c] {
			continue
		}
		// Ignore errors for caps that don't exist on this kernel
		prctl(prCapBSetDrop, uintptr(c), 0)
	}

	return nil
}

// NoNewPrivs prevents the process and its children from gaining new privileges
// via execve (e.g. setuid binaries).
func NoNewPrivs() error {
	return prctl(prSetNoNewPrivs, 1, 0)
}

// DropToUser changes to the given UID/GID after capability drop.
func DropToUser(uid, gid int) error {
	if err := syscall.Setgroups([]int{}); err != nil {
		return err
	}
	if err := syscall.Setresgid(gid, gid, gid); err != nil {
		return err
	}
	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		return err
	}
	return nil
}

// MaybeDropUser drops privileges to the configured user if the config has one
// set. Returns true if privileges were dropped.
func MaybeDropUser(uid, gid int) bool {
	if uid < 0 || gid < 0 {
		return false
	}
	KeepCaps(capDACOverride, capNetAdmin, capNetRaw, capSysPtrace)
	NoNewPrivs()
	if err := DropToUser(uid, gid); err != nil {
		return false
	}
	return true
}

// LookupUser finds the UID/GID for a given username from /etc/passwd.
func LookupUser(username string) (uid, gid int, err error) {
	return lookupUser(username)
}

// lookupUser is a platform-specific implementation.
func lookupUser(username string) (uid, gid int, err error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return -1, -1, err
	}
	for _, line := range splitLines(string(data)) {
		fields := splitN(line, ":", 7)
		if len(fields) >= 3 && fields[0] == username {
			return parseInt(fields[2]), parseInt(fields[3]), nil
		}
	}
	return -1, -1, syscall.ENOENT
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				lines = append(lines, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func splitN(s, sep string, n int) []string {
	var out []string
	start := 0
	count := 0
	for i := 0; i < len(s)-len(sep)+1 && count < n-1; i++ {
		if s[i:i+len(sep)] == sep {
			out = append(out, s[start:i])
			start = i + len(sep)
			count++
		}
	}
	out = append(out, s[start:])
	return out
}

func parseInt(s string) int {
	var v int
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			v = v*10 + int(s[i]-'0')
		} else {
			break
		}
	}
	return v
}
