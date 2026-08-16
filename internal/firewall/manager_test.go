package firewall

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	f, err := os.CreateTemp("", "netmon-test-*.db")
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
	return db
}

func newTestManager(t *testing.T) *Manager {
	db := newTestDB(t)
	m := New(db)
	m.InitDB()
	m.PreSeed()
	return m
}

// --- Direction-aware blocking ---

func TestIsBlockedIn(t *testing.T) {
	m := newTestManager(t)
	if !m.IsBlockedIn(0, "", "", "1.2.3.4", "tcp", 22) {
		t.Error("expected blocked (no rules)")
	}
	m.AddRule(Rule{
		ExePath: "/usr/sbin/sshd", Process: "sshd",
		IP: "1.2.3.4", Port: 22, Proto: "tcp",
		Direction: "in", Mode: "always",
	})
	if m.IsBlockedIn(0, "/usr/sbin/sshd", "sshd", "1.2.3.4", "tcp", 22) {
		t.Error("expected allowed after rule")
	}
	if !m.IsBlockedIn(0, "/usr/sbin/sshd", "sshd", "5.6.7.8", "tcp", 22) {
		t.Error("expected blocked for different source")
	}
	if !m.IsBlockedIn(0, "/usr/sbin/sshd", "sshd", "1.2.3.4", "tcp", 443) {
		t.Error("expected blocked for different port")
	}
}

func TestIsBlockedInWildcard(t *testing.T) {
	m := newTestManager(t)
	m.AddRule(Rule{
		ExePath: "/usr/sbin/sshd", Process: "sshd",
		IP: "0.0.0.0/0", Port: 22, Proto: "tcp",
		Direction: "in", Mode: "always",
	})
	if m.IsBlockedIn(0, "sshd", "", "9.9.9.9", "tcp", 22) {
		t.Error("wildcard should match any source")
	}
}

func TestIsBlockedDirectionIsolation(t *testing.T) {
	m := newTestManager(t)
	m.AddRule(Rule{
		ExePath: "/usr/sbin/sshd", Process: "sshd",
		IP: "1.2.3.4", Port: 22, Proto: "tcp",
		Direction: "in", Mode: "always",
	})
	if !m.IsBlocked(0, "/usr/sbin/sshd", "sshd", "1.2.3.4", "tcp", 22) {
		t.Error("outgoing IsBlocked should not match incoming rule")
	}
	m.AddRule(Rule{
		ExePath: "/usr/bin/curl", Process: "curl",
		IP: "1.2.3.4", Port: 80, Proto: "tcp",
		Direction: "out", Mode: "always",
	})
	if !m.IsBlockedIn(0, "/usr/bin/curl", "curl", "1.2.3.4", "tcp", 80) {
		t.Error("incoming IsBlockedIn should not match outgoing rule")
	}
}

func TestIsBlockedOutgoing(t *testing.T) {
	m := newTestManager(t)
	// preseed DNS rules only apply to systemd-resolved
	if m.IsBlocked(0, "/usr/lib/systemd/systemd-resolved", "systemd-resolved", "0.0.0.0/0", "tcp", 53) {
		t.Error("preseed DNS should be allowed")
	}
	if m.IsBlocked(0, "/usr/lib/systemd/systemd-resolved", "systemd-resolved", "0.0.0.0/0", "udp", 53) {
		t.Error("preseed DNS should be allowed")
	}
	if !m.IsBlocked(0, "/usr/bin/nc", "nc", "9.9.9.9", "tcp", 9999) {
		t.Error("unknown destination should be blocked")
	}
}

func TestBlocklistOverridesAllowlist(t *testing.T) {
	m := newTestManager(t)
	m.AddRule(Rule{
		ExePath:   "/usr/bin/curl",
		Process:   "curl",
		IP:        "1.2.3.4",
		Port:      443,
		Proto:     "tcp",
		Direction: "out",
		Mode:      "always",
	})
	if _, err := m.db.Exec("INSERT INTO blocklist(ip, source, added_at) VALUES(?,?,?)", "1.2.3.4", "test", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if !m.IsBlocked(0, "/usr/bin/curl", "curl", "1.2.3.4", "tcp", 443) {
		t.Fatal("blocklist should override outgoing allowlist")
	}
}

// --- Pending direction isolation ---

func TestAlreadyPendingIn(t *testing.T) {
	m := newTestManager(t)
	if m.AlreadyPendingIn("/usr/sbin/sshd", "1.2.3.4", "tcp", 22) {
		t.Error("expected no duplicate initially")
	}
	m.QueuePending(Pending{
		ExePath: "/usr/sbin/sshd", Process: "sshd",
		IP: "1.2.3.4", Port: 22, Proto: "tcp",
		Direction: "in",
	})
	if !m.AlreadyPendingIn("/usr/sbin/sshd", "1.2.3.4", "tcp", 22) {
		t.Error("expected duplicate after queuing")
	}
	if m.AlreadyPending("/usr/sbin/sshd", "1.2.3.4", "tcp", 22) {
		t.Error("out-direction check should not match in-direction pending")
	}
}

func TestPendingDirectionIsolation(t *testing.T) {
	m := newTestManager(t)
	m.QueuePending(Pending{
		ExePath: "/usr/sbin/sshd", Process: "sshd",
		IP: "1.2.3.4", Port: 22, Proto: "tcp",
		Direction: "in",
	})
	if m.AlreadyPending("/usr/sbin/sshd", "1.2.3.4", "tcp", 22) {
		t.Error("out check should not match in pending")
	}
	if !m.AlreadyPendingIn("/usr/sbin/sshd", "1.2.3.4", "tcp", 22) {
		t.Error("in check should match in pending")
	}
}

func TestPendingExpiry(t *testing.T) {
	m := newTestManager(t)
	id, err := m.QueuePending(Pending{
		ExePath: "test", Process: "test",
		IP: "1.2.3.4", Port: 99, Proto: "udp",
		Direction: "out",
	})
	if err != nil {
		t.Fatal(err)
	}
	// force old timestamp
	m.db.Exec("UPDATE pending_approvals SET created_at=? WHERE id=?", time.Now().Add(-10*time.Minute).Unix(), id)

	pendings, _ := m.GetPending()
	for _, p := range pendings {
		if p.ID == id {
			t.Error("expired pending should have been cleaned")
		}
	}
}

// --- Approve / Deny ---

func TestApproveDirection(t *testing.T) {
	m := newTestManager(t)
	id, err := m.QueuePending(Pending{
		ExePath: "/usr/sbin/sshd", Process: "sshd",
		IP: "1.2.3.4", Port: 22, Proto: "tcp",
		Direction: "in",
	})
	if err != nil {
		t.Fatal(err)
	}
	m.Approve(id, "always")

	if m.IsBlockedIn(0, "/usr/sbin/sshd", "sshd", "1.2.3.4", "tcp", 22) {
		t.Error("expected allowed after approval")
	}
	rule, err := m.getRuleByIPPort("1.2.3.4", 22)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Direction != "in" {
		t.Errorf("expected direction in, got %s", rule.Direction)
	}
	if rule.Mode != "always" {
		t.Errorf("expected mode always, got %s", rule.Mode)
	}
	// pending removed
	pendings, _ := m.GetPending()
	for _, p := range pendings {
		if p.ID == id {
			t.Error("pending should be removed after approve")
		}
	}
}

func TestApproveOnce(t *testing.T) {
	m := newTestManager(t)
	id, _ := m.QueuePending(Pending{
		ExePath: "curl", Process: "curl",
		IP: "1.2.3.4", Port: 443, Proto: "tcp",
		Direction: "out",
	})
	m.Approve(id, "once")

	rule, err := m.getRuleByIPPort("1.2.3.4", 443)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Mode != "once" {
		t.Errorf("expected mode once, got %s", rule.Mode)
	}
	if rule.TTLSecs != 300 {
		t.Errorf("expected TTL 300 for once mode, got %d", rule.TTLSecs)
	}
}

func TestDenyDirection(t *testing.T) {
	m := newTestManager(t)
	id, _ := m.QueuePending(Pending{
		ExePath: "nc", Process: "nc",
		IP: "5.6.7.8", Port: 4444, Proto: "tcp",
		Direction: "out",
	})
	if err := m.Deny(id); err != nil {
		t.Fatal(err)
	}
	pendings, _ := m.GetPending()
	for _, p := range pendings {
		if p.ID == id {
			t.Error("pending should be removed after deny")
		}
	}
	// IP should be in blocklist
	var count int
	m.db.QueryRow("SELECT COUNT(*) FROM blocklist WHERE ip='5.6.7.8'").Scan(&count)
	if count != 1 {
		t.Error("denied IP should be in blocklist")
	}
}

func TestApproveTwice(t *testing.T) {
	m := newTestManager(t)
	id1, _ := m.QueuePending(Pending{
		ExePath: "curl", Process: "curl",
		IP: "1.2.3.4", Port: 443, Proto: "tcp",
	})
	m.Approve(id1, "always")

	// second queue+approve for same IP/port — should succeed (dedup at config level)
	id2, _ := m.QueuePending(Pending{
		ExePath: "wget", Process: "wget",
		IP: "1.2.3.4", Port: 443, Proto: "tcp",
	})
	m.Approve(id2, "always")

	var count int
	m.db.QueryRow("SELECT COUNT(*) FROM allowlist WHERE ip='1.2.3.4' AND port=443").Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 rules (separate exe), got %d", count)
	}
}

func TestDenyNonExistent(t *testing.T) {
	m := newTestManager(t)
	// denying a non-existent pending should not panic
	err := m.Deny(99999)
	if err == nil {
		t.Log("deny of non-existent id returned nil (expected in some cases)")
	}
}

// --- App allowlist ---

func TestAllowApp(t *testing.T) {
	m := newTestManager(t)

	if m.IsAppAllowed("/usr/bin/curl", "curl") {
		t.Error("should not be allowed initially")
	}

	if err := m.AllowApp("/usr/bin/curl", "curl"); err != nil {
		t.Fatal(err)
	}
	if !m.IsAppAllowed("/usr/bin/curl", "curl") {
		t.Error("should be allowed after AllowApp")
	}
	// match by exe
	if !m.IsAppAllowed("/usr/bin/curl", "anything") {
		t.Error("should match by exe_path")
	}
	// match by process name
	if !m.IsAppAllowed("/different/path", "curl") {
		t.Error("should match by process name")
	}
}

func TestAllowAppIdempotent(t *testing.T) {
	m := newTestManager(t)
	m.AllowApp("/usr/bin/curl", "curl")
	m.AllowApp("/usr/bin/curl", "curl") // should not error
	m.AllowApp("/usr/bin/curl", "curl") // should not error

	apps, _ := m.ListAllowedApps()
	if len(apps) != 1 {
		t.Errorf("expected 1 app entry, got %d", len(apps))
	}
}

func TestRemoveApp(t *testing.T) {
	m := newTestManager(t)
	m.AllowApp("/usr/bin/curl", "curl")
	if err := m.RemoveApp(1); err != nil {
		t.Fatal(err)
	}
	if m.IsAppAllowed("/usr/bin/curl", "curl") {
		t.Error("should not be allowed after remove")
	}
}

func TestRemoveAppNotFound(t *testing.T) {
	m := newTestManager(t)
	err := m.RemoveApp(999)
	if err == nil {
		t.Fatal("expected error for non-existent ID")
	}
}

func TestListAllowedAppsEmpty(t *testing.T) {
	m := newTestManager(t)
	apps, _ := m.ListAllowedApps()
	if len(apps) != 0 {
		t.Errorf("expected empty list, got %d", len(apps))
	}
}

func TestListAllowedApps(t *testing.T) {
	m := newTestManager(t)
	m.AllowApp("/usr/bin/curl", "curl")
	m.AllowApp("/usr/bin/wget", "wget")
	m.AllowApp("/usr/sbin/sshd", "sshd")

	apps, _ := m.ListAllowedApps()
	if len(apps) != 3 {
		t.Fatalf("expected 3 apps, got %d", len(apps))
	}
	// most recent first
	if apps[0].Process != "sshd" {
		t.Errorf("expected sshd first (most recent), got %s", apps[0].Process)
	}
}

// --- Preseed ---

func TestPreSeedDedup(t *testing.T) {
	m := newTestManager(t)
	// PreSeed is called in newTestManager — calling again should not duplicate
	m.PreSeed()

	var count int
	m.db.QueryRow("SELECT COUNT(*) FROM allowlist WHERE proto='udp' AND port=53").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 DNS rule after duplicate preseed, got %d", count)
	}
}

func TestPreSeedRulesPresent(t *testing.T) {
	m := newTestManager(t)
	rules, _ := m.LoadAllowlist()
	t.Logf("preseed has %d rules", len(rules))

	// make sure key preseed rules exist
	preseedPorts := map[int]bool{53: true, 123: true, 67: true, 68: true, 546: true}
	for _, r := range rules {
		delete(preseedPorts, r.Port)
	}
	for port := range preseedPorts {
		t.Errorf("preseed missing port %d", port)
	}
}

// --- Allowlist CRUD ---

func TestAddRule(t *testing.T) {
	m := newTestManager(t)
	id, err := m.AddRule(Rule{
		ExePath: "test", Process: "test",
		IP: "1.2.3.4", Port: 443, Proto: "tcp",
		Mode: "always",
	})
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("expected non-zero ID")
	}
}

func TestRemoveRule(t *testing.T) {
	m := newTestManager(t)
	id, _ := m.AddRule(Rule{
		ExePath: "test", Process: "test",
		IP: "1.2.3.4", Port: 443, Proto: "tcp", Mode: "always",
	})
	if err := m.RemoveRule(id); err != nil {
		t.Fatal(err)
	}
	var count int
	m.db.QueryRow("SELECT COUNT(*) FROM allowlist WHERE id=?", id).Scan(&count)
	if count != 0 {
		t.Error("rule should be gone after remove")
	}
}

func TestDeleteRule(t *testing.T) {
	m := newTestManager(t)
	id, _ := m.AddRule(Rule{
		ExePath: "test", Process: "test",
		IP: "1.2.3.4", Port: 443, Proto: "tcp", Mode: "once",
		Direction: "in",
	})
	if err := m.DeleteRule(id); err != nil {
		t.Fatal(err)
	}
	var count int
	m.db.QueryRow("SELECT COUNT(*) FROM allowlist WHERE id=?", id).Scan(&count)
	if count != 0 {
		t.Error("rule should be deleted")
	}
}

// --- CleanExpired ---

func TestCleanExpiredDirection(t *testing.T) {
	m := newTestManager(t)

	inID, _ := m.AddRule(Rule{
		ExePath: "/usr/sbin/sshd", Process: "sshd",
		IP: "1.2.3.4", Port: 22, Proto: "tcp",
		Direction: "in", Mode: "once",
	})
	m.db.Exec("UPDATE allowlist SET created_at=? WHERE id=?", time.Now().Add(-600*time.Second).Unix(), inID)

	outID, _ := m.AddRule(Rule{
		ExePath: "/usr/bin/curl", Process: "curl",
		IP: "5.6.7.8", Port: 443, Proto: "tcp",
		Direction: "out", Mode: "once",
	})
	m.db.Exec("UPDATE allowlist SET created_at=? WHERE id=?", time.Now().Add(-600*time.Second).Unix(), outID)

	m.CleanExpired()

	var count int
	m.db.QueryRow("SELECT COUNT(*) FROM allowlist WHERE id=? OR id=?", inID, outID).Scan(&count)
	if count > 0 {
		t.Errorf("expected both expired rules removed, got %d", count)
	}
}

func TestCleanExpiredOnlyOnce(t *testing.T) {
	m := newTestManager(t)

	// always mode should NOT be expired
	alwaysID, _ := m.AddRule(Rule{
		ExePath: "test", Process: "test",
		IP: "1.2.3.4", Port: 443, Proto: "tcp",
		Mode: "always",
	})
	// but it's old
	m.db.Exec("UPDATE allowlist SET created_at=? WHERE id=?", time.Now().Add(-86400*time.Second).Unix(), alwaysID)

	m.CleanExpired()

	var count int
	m.db.QueryRow("SELECT COUNT(*) FROM allowlist WHERE id=?", alwaysID).Scan(&count)
	if count != 1 {
		t.Error("always mode rules should never expire")
	}
}

func TestCleanExpiredCustomTTL(t *testing.T) {
	m := newTestManager(t)

	id, _ := m.AddRule(Rule{
		ExePath: "test", Process: "test",
		IP: "1.2.3.4", Port: 80, Proto: "tcp",
		Mode: "once", TTLSecs: 10,
	})
	m.db.Exec("UPDATE allowlist SET created_at=? WHERE id=?", time.Now().Add(-20*time.Second).Unix(), id)

	m.CleanExpired()

	var count int
	m.db.QueryRow("SELECT COUNT(*) FROM allowlist WHERE id=?", id).Scan(&count)
	if count != 0 {
		t.Error("custom TTL should expire")
	}
}

// --- Status ---

func TestStatus(t *testing.T) {
	m := newTestManager(t)
	// We use an in-memory/ file DB — nftables won't be running,
	// so IsEnabled() returns false
	s := m.Status()
	if s.Enabled {
		t.Log("status: nftables enabled (running as root?)")
	} else {
		t.Log("status: nftables disabled (expected in unit test)")
	}
	// pending should be 0 initially
	if s.Pending != 0 {
		t.Errorf("expected 0 pending, got %d", s.Pending)
	}
	if s.PanicMode {
		t.Error("should not be in panic mode initially")
	}
}

func TestStatusWithPending(t *testing.T) {
	m := newTestManager(t)
	m.QueuePending(Pending{
		ExePath: "test", Process: "test",
		IP: "1.2.3.4", Port: 80, Proto: "tcp",
	})
	s := m.Status()
	if s.Pending != 1 {
		t.Errorf("expected 1 pending, got %d", s.Pending)
	}
}

// --- Panic ---

func TestPanicMode(t *testing.T) {
	m := newTestManager(t)
	m.PanicMode(1 * time.Second)

	s := m.Status()
	if !s.PanicMode {
		t.Error("expected panic mode active")
	}
	if s.PanicUntil == 0 {
		t.Error("expected non-zero panic_until")
	}
	// After a short wait, panic should have expired
	time.Sleep(1100 * time.Millisecond)
	s = m.Status()
	if s.PanicMode {
		t.Error("expected panic mode ended")
	}
}

func TestClearPanic(t *testing.T) {
	m := newTestManager(t)
	m.PanicMode(1 * time.Hour)
	m.ClearPanic()

	s := m.Status()
	if s.PanicMode {
		t.Error("expected panic cleared")
	}
}

// --- LoadAllowlist ---

func TestLoadAllowlistOnlyAlways(t *testing.T) {
	m := newTestManager(t)

	m.AddRule(Rule{
		ExePath: "perm", Process: "perm",
		IP: "1.2.3.4", Port: 80, Proto: "tcp", Mode: "always",
	})
	m.AddRule(Rule{
		ExePath: "temp", Process: "temp",
		IP: "5.6.7.8", Port: 443, Proto: "tcp", Mode: "once",
	})

	rules, _ := m.LoadAllowlist()
	for _, r := range rules {
		if r.Mode != "always" {
			t.Errorf("LoadAllowlist returned mode=%s, expected always only", r.Mode)
		}
	}
}

func TestLoadAllowlistEmpty(t *testing.T) {
	// fresh manager without preseed
	db := newTestDB(t)
	m := New(db)
	m.InitDB()

	rules, _ := m.LoadAllowlist()
	if len(rules) != 0 {
		t.Errorf("expected empty allowlist, got %d", len(rules))
	}
}

func TestQueuePendingSourceDefault(t *testing.T) {
	m := newTestManager(t)
	id, err := m.QueuePending(Pending{ExePath: "/usr/bin/curl", Process: "curl", IP: "1.1.1.1", Port: 443, Proto: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("expected non-zero id")
	}

	list, err := m.GetPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(list))
	}
	if list[0].Source != "new" {
		t.Errorf("expected default source='new', got %q", list[0].Source)
	}
}

func TestQueuePendingSourcePreexisting(t *testing.T) {
	m := newTestManager(t)
	id, err := m.QueuePending(Pending{ExePath: "/usr/bin/firefox", Process: "firefox", IP: "9.9.9.9", Port: 443, Proto: "tcp", Source: "preexisting"})
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("expected non-zero id")
	}

	list, err := m.GetPending()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(list))
	}
	if list[0].Source != "preexisting" {
		t.Errorf("expected source='preexisting', got %q", list[0].Source)
	}
}

// helpers

func (m *Manager) getRuleByIPPort(ip string, port int) (*Rule, error) {
	row := m.db.QueryRow("SELECT id, exe_path, process, ip, port, proto, mode, direction, ttl_secs, created_at FROM allowlist WHERE ip=? AND port=? LIMIT 1", ip, port)
	var r Rule
	err := row.Scan(&r.ID, &r.ExePath, &r.Process, &r.IP, &r.Port, &r.Proto, &r.Mode, &r.Direction, &r.TTLSecs, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}
