package store

import (
	"database/sql"
	"net"
	"os"
	"testing"
	"time"

	"netmon/internal/capture"
	"netmon/internal/detect"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	f, err := os.CreateTemp("", "netmon-store-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()); f.Close() })

	s, err := New(f.Name(), 100)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mkEvent(typ capture.EventType, pid int, comm, localIP string, localPort int, remoteIP string, remotePort int, proto string, state string) capture.ConnectionEvent {
	return capture.ConnectionEvent{
		Type: typ,
		Connection: capture.Connection{
			PID:        pid,
			UID:        1000,
			Comm:       comm,
			Cmdline:    "/usr/bin/" + comm,
			Exe:        "/usr/bin/" + comm,
			PPID:       1,
			PComm:      "init",
			LocalAddr:  net.ParseIP(localIP),
			LocalPort:  localPort,
			RemoteAddr: net.ParseIP(remoteIP),
			RemotePort: remotePort,
			Protocol:   proto,
			State:      state,
			Inode:      uint64(pid * 1000),
			CreatedAt:  time.Now().UnixMilli(),
		},
	}
}

func TestQueryConns_All(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	for i := 0; i < 5; i++ {
		ev := mkEvent(capture.EventNew, 1000+i, "proc", "10.0.0.1", 80, "10.0.0.2", 80+i, "tcp", "ESTABLISHED")
		s.Insert(ev)
	}
	s.flush()

	results, err := s.QueryConns(ConnFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}
}

func TestQueryConns_FilterByProcess(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	s.Insert(mkEvent(capture.EventNew, 2001, "firefox", "10.0.0.1", 40000, "93.184.216.34", 443, "tcp", "ESTABLISHED"))
	s.Insert(mkEvent(capture.EventNew, 2002, "curl", "10.0.0.1", 40001, "93.184.216.35", 80, "tcp", "ESTABLISHED"))
	s.Insert(mkEvent(capture.EventNew, 2003, "firefox", "10.0.0.1", 40002, "93.184.216.36", 443, "tcp", "TIME_WAIT"))
	s.flush()

	results, err := s.QueryConns(ConnFilter{Process: "firefox", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 firefox connections, got %d", len(results))
	}
	for _, r := range results {
		if r.Comm != "firefox" {
			t.Errorf("expected comm firefox, got %s", r.Comm)
		}
	}
}

func TestQueryConns_FilterByRemotePort(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	s.Insert(mkEvent(capture.EventNew, 3001, "curl", "10.0.0.1", 40000, "1.1.1.1", 80, "tcp", "ESTABLISHED"))
	s.Insert(mkEvent(capture.EventNew, 3002, "curl", "10.0.0.1", 40001, "1.1.1.2", 443, "tcp", "ESTABLISHED"))
	s.Insert(mkEvent(capture.EventNew, 3003, "ssh", "10.0.0.1", 40002, "1.1.1.3", 22, "tcp", "ESTABLISHED"))
	s.flush()

	results, err := s.QueryConns(ConnFilter{RemotePort: 443, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for port 443, got %d", len(results))
	}
	if results[0].RemotePort != 443 {
		t.Errorf("expected port 443, got %d", results[0].RemotePort)
	}
}

func TestQueryConns_FilterByRemoteIP(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	s.Insert(mkEvent(capture.EventNew, 4001, "wget", "10.0.0.1", 40000, "93.184.216.34", 80, "tcp", "ESTABLISHED"))
	s.Insert(mkEvent(capture.EventNew, 4002, "wget", "10.0.0.1", 40001, "8.8.8.8", 53, "udp", "CLOSE"))
	s.flush()

	results, err := s.QueryConns(ConnFilter{RemoteIP: "93.184.216.34", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestQueryConns_FilterByState(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	s.Insert(mkEvent(capture.EventNew, 5001, "curl", "10.0.0.1", 40000, "1.1.1.1", 80, "tcp", "ESTABLISHED"))
	s.Insert(mkEvent(capture.EventNew, 5002, "curl", "10.0.0.1", 40001, "1.1.1.2", 80, "tcp", "SYN_SENT"))
	s.flush()

	results, err := s.QueryConns(ConnFilter{State: "ESTABLISHED", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 established conn, got %d", len(results))
	}
}

func TestQueryConns_FilterByProtocol(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	s.Insert(mkEvent(capture.EventNew, 6001, "dig", "10.0.0.1", 40000, "8.8.8.8", 53, "udp", "CLOSE"))
	s.Insert(mkEvent(capture.EventNew, 6002, "curl", "10.0.0.1", 40001, "1.1.1.1", 80, "tcp", "ESTABLISHED"))
	s.flush()

	results, err := s.QueryConns(ConnFilter{Protocol: "udp", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 udp conn, got %d", len(results))
	}
	if results[0].Comm != "dig" {
		t.Errorf("expected comm dig, got %s", results[0].Comm)
	}
}

func TestQueryConns_CombinedFilters(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	s.Insert(mkEvent(capture.EventNew, 7001, "firefox", "10.0.0.1", 40000, "93.184.216.34", 443, "tcp", "ESTABLISHED"))
	s.Insert(mkEvent(capture.EventNew, 7002, "curl", "10.0.0.1", 40001, "93.184.216.34", 443, "tcp", "ESTABLISHED"))
	s.Insert(mkEvent(capture.EventNew, 7003, "firefox", "10.0.0.1", 40002, "1.1.1.1", 443, "tcp", "ESTABLISHED"))
	s.flush()

	results, err := s.QueryConns(ConnFilter{
		Process:    "firefox",
		RemoteIP:   "93.184.216.34",
		RemotePort: 443,
		Limit:      100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for firefox→93.184.216.34:443, got %d", len(results))
	}
}

func TestQueryConns_EmptyResult(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	s.Insert(mkEvent(capture.EventNew, 8001, "curl", "10.0.0.1", 40000, "1.1.1.1", 80, "tcp", "ESTABLISHED"))
	s.flush()

	results, err := s.QueryConns(ConnFilter{Process: "nonexistent", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestQueryConns_Limit(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	for i := 0; i < 10; i++ {
		ev := mkEvent(capture.EventNew, 9000+i, "proc", "10.0.0.1", 80, "10.0.0.2", 80+i, "tcp", "ESTABLISHED")
		s.Insert(ev)
	}
	s.flush()

	results, err := s.QueryConns(ConnFilter{Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
}

func TestQueryAlerts(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	for i := 0; i < 3; i++ {
		s.insertAlert("test_rule", "critical", 1000+i, "proc", "10.0.0.1", 80, "test alert")
	}
	s.flush()

	results, err := s.QueryAlerts(AlertFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 alerts, got %d", len(results))
	}
}

func TestQueryAlerts_FilterBySeverity(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	s.insertAlert("rule1", "critical", 1001, "proc1", "1.1.1.1", 80, "critical alert")
	s.insertAlert("rule2", "warning", 1002, "proc2", "1.1.1.2", 80, "warning alert")
	s.insertAlert("rule3", "info", 1003, "proc3", "1.1.1.3", 80, "info alert")
	s.flush()

	results, err := s.QueryAlerts(AlertFilter{Severity: "critical", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 critical alert, got %d", len(results))
	}
}

func TestGetConnHistory(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	s.Insert(mkEvent(capture.EventNew, 2001, "firefox", "10.0.0.1", 40000, "93.184.216.34", 443, "tcp", "ESTABLISHED"))
	s.Insert(mkEvent(capture.EventNew, 2001, "firefox", "10.0.0.1", 40001, "93.184.216.34", 443, "tcp", "TIME_WAIT"))
	s.Insert(mkEvent(capture.EventNew, 2002, "curl", "10.0.0.1", 40002, "93.184.216.34", 443, "tcp", "ESTABLISHED"))
	s.flush()

	// history for IP 93.184.216.34
	results, err := s.GetConnHistory("93.184.216.34", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 connections to that IP, got %d", len(results))
	}
}

func TestGetAnalysisContext(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	// insert a connection
	s.Insert(mkEvent(capture.EventNew, 3001, "suspicious", "10.0.0.1", 40000, "203.0.113.5", 8443, "tcp", "ESTABLISHED"))
	// insert related alerts
	s.insertAlert("blocklist_match", "critical", 3001, "suspicious", "203.0.113.5", 8443, "blocklisted IP")
	// insert historical connections for same process
	s.Insert(mkEvent(capture.EventNew, 3001, "suspicious", "10.0.0.1", 40001, "203.0.113.5", 443, "tcp", "CLOSE"))
	s.flush()

	ctx, err := s.GetAnalysisContext("203.0.113.5", 8443)
	if err != nil {
		t.Fatal(err)
	}
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if len(ctx.CurrentConns) == 0 {
		t.Error("expected at least 1 current connection")
	}
	if len(ctx.Alerts) == 0 {
		t.Error("expected at least 1 alert")
	}
	if ctx.TotalHistory == 0 {
		t.Error("expected non-zero total history count")
	}
}

func TestRuleUsage(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	rs := detect.NewRuleStore(s.DB())
	idA, err := rs.Add("rule-a", detect.SevHigh, detect.RuleConditions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = rs.Add("rule-b", detect.SevMedium, detect.RuleConditions{})
	if err != nil {
		t.Fatal(err)
	}

	s.insertAlert("rule-a", "high", 1111, "curl", "1.1.1.1", 443, "hit one", idA)
	s.insertAlert("rule-a", "high", 1111, "curl", "1.1.1.1", 443, "hit two", idA)
	s.insertAlert("rule-b", "medium", 2222, "wget", "2.2.2.2", 80, "legacy hit")
	s.flush()

	usage, err := s.RuleUsage()
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(usage))
	}

	var gotA, gotB *RuleUsage
	for i := range usage {
		switch usage[i].Name {
		case "rule-a":
			gotA = &usage[i]
		case "rule-b":
			gotB = &usage[i]
		}
	}
	if gotA == nil || gotB == nil {
		t.Fatalf("missing analytics rows: %#v", usage)
	}
	if gotA.HitCount != 2 {
		t.Fatalf("expected rule-a hit count 2, got %d", gotA.HitCount)
	}
	if gotB.HitCount != 1 {
		t.Fatalf("expected rule-b hit count 1, got %d", gotB.HitCount)
	}
	if gotA.LastAlertAt == 0 || gotB.LastAlertAt == 0 {
		t.Fatal("expected last alert timestamps to be populated")
	}
	if gotB.LastRemote != "2.2.2.2" || gotB.LastRemotePort != 80 {
		t.Fatalf("unexpected last endpoint for rule-b: %s:%d", gotB.LastRemote, gotB.LastRemotePort)
	}
}

func TestNewMigratesLegacyAlertsSchema(t *testing.T) {
	f, err := os.CreateTemp("", "netmon-legacy-alerts-*.db")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE alerts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_name TEXT NOT NULL,
			severity TEXT NOT NULL,
			pid INTEGER NOT NULL DEFAULT 0,
			comm TEXT NOT NULL DEFAULT '',
			remote_addr TEXT NOT NULL DEFAULT '',
			remote_port INTEGER NOT NULL DEFAULT 0,
			message TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL
		)
	`)
	if err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}
	db.Close()

	s, err := New(path, 10)
	if err != nil {
		t.Fatalf("expected migration to succeed, got %v", err)
	}
	defer s.Close()

	if _, err := s.DB().Exec(`
		INSERT INTO alerts(rule_id, rule_name, severity, pid, comm, remote_addr, remote_port, message, created_at)
		VALUES(?,?,?,?,?,?,?,?,?)
	`, 12, "rule", "high", 1001, "proc", "1.1.1.1", 443, "ok", time.Now().UnixMilli()); err != nil {
		t.Fatalf("expected migrated schema to accept rule_id inserts, got %v", err)
	}
}

func TestInsertEventClose(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	ev := mkEvent(capture.EventNew, 1002, "wget", "192.168.1.10", 54322, "93.184.216.34", 443, "tcp", "ESTABLISHED")
	s.Insert(ev)
	s.flush()

	evClose := mkEvent(capture.EventClose, 1002, "wget", "192.168.1.10", 54322, "93.184.216.34", 443, "tcp", "CLOSE")
	s.Insert(evClose)
	s.flush()

	var closedAt int64
	err := s.db.QueryRow("SELECT closed_at FROM connections WHERE pid=1002").Scan(&closedAt)
	if err != nil {
		t.Fatal(err)
	}
	if closedAt == 0 {
		t.Error("expected closed_at to be set after close event")
	}
}

func TestInsertEventUpdate(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	ev := mkEvent(capture.EventNew, 1003, "ssh", "192.168.1.10", 22, "10.0.0.1", 54321, "tcp", "SYN_SENT")
	s.Insert(ev)
	s.flush()

	evUpd := mkEvent(capture.EventUpdate, 1003, "ssh", "192.168.1.10", 22, "10.0.0.1", 54321, "tcp", "ESTABLISHED")
	s.Insert(evUpd)
	s.flush()

	var state string
	s.db.QueryRow("SELECT state FROM connections WHERE pid=1003").Scan(&state)
	if state != "ESTABLISHED" {
		t.Errorf("expected state ESTABLISHED after update, got %s", state)
	}
}

func TestInsertUDP(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	ev := mkEvent(capture.EventNew, 1004, "dig", "192.168.1.10", 43251, "8.8.8.8", 53, "udp", "CLOSE")
	s.Insert(ev)
	s.flush()

	var proto string
	s.db.QueryRow("SELECT protocol FROM connections WHERE pid=1004").Scan(&proto)
	if proto != "udp" {
		t.Errorf("expected proto udp, got %s", proto)
	}
}

func TestInsertRaw(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	ev := mkEvent(capture.EventNew, 1005, "ping", "192.168.1.10", 0, "8.8.8.8", 0, "icmp", "CLOSE")
	s.Insert(ev)
	s.flush()

	var proto string
	s.db.QueryRow("SELECT protocol FROM connections WHERE pid=1005").Scan(&proto)
	if proto != "icmp" {
		t.Errorf("expected proto icmp, got %s", proto)
	}
}

func TestFlushBatching(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	// insert 50 events without flushing
	for i := 0; i < 50; i++ {
		ev := mkEvent(capture.EventNew, 2000+i, "batch", "10.0.0.1", 80, "10.0.0.2", 80+i, "tcp", "SYN_SENT")
		s.Insert(ev)
	}

	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM connections").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 before flush, got %d", count)
	}

	// now flush
	s.flush()
	s.db.QueryRow("SELECT COUNT(*) FROM connections").Scan(&count)
	if count != 50 {
		t.Errorf("expected 50 after flush, got %d", count)
	}
}

func TestInsertCloseForNonexistent(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	// close event for a conn that was never inserted should not error
	ev := mkEvent(capture.EventClose, 9999, "ghost", "10.0.0.1", 1, "10.0.0.2", 1, "tcp", "CLOSE")
	s.Insert(ev)
	s.flush()

	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM connections").Scan(&count)
	if count != 0 {
		t.Errorf("close on nonexistent should not create rows, got %d", count)
	}
}

func TestMultipleConnsSameKey(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	ev1 := mkEvent(capture.EventNew, 3001, "proc1", "10.0.0.1", 10000, "10.0.0.2", 80, "tcp", "ESTABLISHED")
	ev2 := mkEvent(capture.EventNew, 3002, "proc2", "10.0.0.1", 10001, "10.0.0.2", 80, "tcp", "ESTABLISHED")
	s.Insert(ev1)
	s.Insert(ev2)
	s.flush()

	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM connections").Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 distinct conns, got %d", count)
	}
}

func TestInsertIncoming(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	ev := mkEvent(capture.EventNew, 4001, "sshd", "10.0.0.1", 22, "192.168.1.50", 54321, "tcp", "ESTABLISHED")
	ev.Incoming = true
	s.Insert(ev)
	s.flush()

	var remoteAddr string
	s.db.QueryRow("SELECT remote_addr FROM connections WHERE pid=4001").Scan(&remoteAddr)
	if remoteAddr != "192.168.1.50" {
		t.Errorf("expected remote 192.168.1.50, got %s", remoteAddr)
	}
}

func TestDBConcurrentAccess(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			for j := 0; j < 10; j++ {
				ev := mkEvent(capture.EventNew, 5000+n*100+j, "conc", "10.0.0.1", 80, "10.0.0.2", 80+j, "udp", "CLOSE")
				s.Insert(ev)
			}
			done <- true
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	s.flush()

	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM connections").Scan(&count)
	if count != 100 {
		t.Errorf("expected 100 concurrent inserts, got %d", count)
	}
}
