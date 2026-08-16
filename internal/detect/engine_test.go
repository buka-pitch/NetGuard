package detect

import (
	"net"
	"testing"
	"time"

	"netmon/internal/capture"
)

func mkEvent(typ capture.EventType, pid int, comm, remoteIP string, remotePort int, state string) capture.ConnectionEvent {
	return capture.ConnectionEvent{
		Type: typ,
		Connection: capture.Connection{
			PID:        pid,
			Comm:       comm,
			RemoteAddr: net.ParseIP(remoteIP),
			RemotePort: remotePort,
			State:      state,
			CreatedAt:  time.Now().UnixMilli(),
		},
	}
}

// --- BeaconRule ---

func TestBeaconRuleFires(t *testing.T) {
	eng := NewEngine()
	r := &BeaconRule{}

	for i := 0; i < 5; i++ {
		ev := mkEvent(capture.EventNew, 1001, "trojan", "10.0.0.1", 4444, "SYN_SENT")
		ev.CreatedAt = time.Now().UnixMilli() + int64(i*1000)
		alert := r.Eval(ev, eng)
		if i < 4 && alert != nil {
			t.Fatalf("unexpected alert at event %d", i)
		}
		if i == 4 {
			if alert == nil {
				t.Fatal("expected beacon alert at 5th event")
			}
			if alert.Severity != SevHigh {
				t.Errorf("expected severity high, got %s", alert.Severity)
			}
			if alert.PID != 1001 {
				t.Errorf("expected PID 1001, got %d", alert.PID)
			}
			if alert.RemoteAddr != "10.0.0.1" {
				t.Errorf("expected IP 10.0.0.1, got %s", alert.RemoteAddr)
			}
			if alert.RemotePort != 4444 {
				t.Errorf("expected port 4444, got %d", alert.RemotePort)
			}
		}
	}
}

func TestBeaconRuleRandomIntervals(t *testing.T) {
	eng := NewEngine()
	r := &BeaconRule{}
	for i := 0; i < 6; i++ {
		ev := mkEvent(capture.EventNew, 1002, "normal", "10.0.0.2", 80, "SYN_SENT")
		ev.CreatedAt = time.Now().UnixMilli() + int64(i*100+i*i*500)
		if alert := r.Eval(ev, eng); alert != nil {
			t.Fatal("random intervals should not trigger beacon")
		}
	}
}

func TestBeaconRuleLowVolume(t *testing.T) {
	eng := NewEngine()
	r := &BeaconRule{}
	for i := 0; i < 4; i++ {
		ev := mkEvent(capture.EventNew, 1003, "low", "10.0.0.3", 53, "SYN_SENT")
		ev.CreatedAt = time.Now().UnixMilli() + int64(i*1000)
		if alert := r.Eval(ev, eng); alert != nil {
			t.Fatal("beacon needs >=5 events")
		}
	}
}

func TestBeaconRuleOnlyNew(t *testing.T) {
	eng := NewEngine()
	r := &BeaconRule{}

	ev := mkEvent(capture.EventUpdate, 1004, "u", "10.0.0.4", 443, "ESTABLISHED")
	if alert := r.Eval(ev, eng); alert != nil {
		t.Fatal("EventUpdate should not trigger beacon")
	}
	ev.Type = capture.EventClose
	if alert := r.Eval(ev, eng); alert != nil {
		t.Fatal("EventClose should not trigger beacon")
	}
}

func TestBeaconRuleLoopback(t *testing.T) {
	eng := NewEngine()
	r := &BeaconRule{}
	for i := 0; i < 6; i++ {
		ev := mkEvent(capture.EventNew, 1005, "local", "127.0.0.1", 8080, "SYN_SENT")
		ev.CreatedAt = time.Now().UnixMilli() + int64(i*1000)
		if alert := r.Eval(ev, eng); alert != nil {
			t.Fatal("loopback should not trigger beacon")
		}
	}
}

func TestBeaconRuleWideVariance(t *testing.T) {
	eng := NewEngine()
	r := &BeaconRule{}
	// variance > 15% of mean — should not fire
	for i := 0; i < 6; i++ {
		ev := mkEvent(capture.EventNew, 1006, "jittery", "10.0.0.6", 80, "SYN_SENT")
		ev.CreatedAt = time.Now().UnixMilli() + int64(i*1000) + int64(i%2)*500
		if alert := r.Eval(ev, eng); alert != nil {
			t.Fatal("high variance should not trigger beacon")
		}
	}
}

// --- BlocklistRule ---

func TestBlocklistRuleFires(t *testing.T) {
	eng := NewEngine()
	eng.AddBlocklist([]string{"5.5.5.5", "6.6.6.6"})
	r := &BlocklistRule{}

	ev := mkEvent(capture.EventNew, 2001, "bad", "5.5.5.5", 443, "SYN_SENT")
	alert := r.Eval(ev, eng)
	if alert == nil {
		t.Fatal("expected blocklist alert")
	}
	if alert.Severity != SevCritical {
		t.Errorf("expected critical, got %s", alert.Severity)
	}
	if alert.RemoteAddr != "5.5.5.5" {
		t.Errorf("expected 5.5.5.5, got %s", alert.RemoteAddr)
	}
}

func TestBlocklistRuleNonMatching(t *testing.T) {
	eng := NewEngine()
	eng.AddBlocklist([]string{"5.5.5.5"})
	r := &BlocklistRule{}
	ev := mkEvent(capture.EventNew, 2002, "good", "8.8.8.8", 443, "SYN_SENT")
	if alert := r.Eval(ev, eng); alert != nil {
		t.Fatal("non-blocklisted IP should not alert")
	}
}

func TestBlocklistRuleNonNew(t *testing.T) {
	eng := NewEngine()
	eng.AddBlocklist([]string{"5.5.5.5"})
	r := &BlocklistRule{}
	ev := mkEvent(capture.EventUpdate, 2003, "upd", "5.5.5.5", 443, "ESTABLISHED")
	if alert := r.Eval(ev, eng); alert != nil {
		t.Fatal("EventUpdate should not trigger blocklist")
	}
}

func TestBlocklistRuleNilAddr(t *testing.T) {
	eng := NewEngine()
	eng.AddBlocklist([]string{"5.5.5.5"})
	r := &BlocklistRule{}
	ev := capture.ConnectionEvent{
		Type: capture.EventNew,
		Connection: capture.Connection{
			PID:  2004,
			Comm: "null",
		},
	}
	if alert := r.Eval(ev, eng); alert != nil {
		t.Fatal("nil addr should not trigger blocklist")
	}
}

// --- AnomalyPortRule ---

func TestAnomalyPortRule(t *testing.T) {
	eng := NewEngine()
	r := &AnomalyPortRule{}

	tests := []struct {
		port     int
		wantSev Severity
		desc     string
	}{
		{4444, SevHigh, "metasploit"},
		{1337, SevHigh, "leet"},
		{31337, SevHigh, "back orifice"},
		{22, SevMedium, "ssh"},
		{3389, SevMedium, "rdp"},
		{443, "", "https - clean"},
		{80, "", "http - clean"},
		{8080, SevMedium, "alt http"},
		{53, "", "dns - clean"},
		{123, "", "ntp - clean"},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			ev := mkEvent(capture.EventNew, 3001, "app", "10.0.0.1", tc.port, "SYN_SENT")
			alert := r.Eval(ev, eng)
			if tc.wantSev == "" {
				if alert != nil {
					t.Errorf("port %d: unexpected alert", tc.port)
				}
			} else {
				if alert == nil {
					t.Errorf("port %d: expected alert", tc.port)
				} else if alert.Severity != tc.wantSev {
					t.Errorf("port %d: severity %s, want %s", tc.port, alert.Severity, tc.wantSev)
				}
			}
		})
	}
}

func TestAnomalyPortLoopback(t *testing.T) {
	eng := NewEngine()
	r := &AnomalyPortRule{}
	ev := mkEvent(capture.EventNew, 3002, "local", "127.0.0.1", 4444, "ESTABLISHED")
	if alert := r.Eval(ev, eng); alert != nil {
		t.Fatal("loopback should not trigger")
	}
}

func TestAnomalyPortNonNew(t *testing.T) {
	eng := NewEngine()
	r := &AnomalyPortRule{}
	ev := mkEvent(capture.EventUpdate, 3003, "upd", "10.0.0.1", 4444, "ESTABLISHED")
	if alert := r.Eval(ev, eng); alert != nil {
		t.Fatal("EventUpdate should not trigger")
	}
}

// --- DetectTrends (jitter analysis) ---

func TestDetectTrendsFires(t *testing.T) {
	eng := NewEngine()
	key := beaconKey{PID: 4001, RemoteAddr: "10.0.0.100", RemotePort: 9999}
	now := time.Now().UnixMilli()
	for i := 0; i < 15; i++ {
		eng.mu.Lock()
		eng.beaconTrack[key] = append(eng.beaconTrack[key], now+int64(i*5000))
		eng.mu.Unlock()
	}
	alerts := eng.DetectTrends()
	found := false
	for _, a := range alerts {
		if a.RuleName == "jitter_analysis" && a.PID == 4001 && a.RemoteAddr == "10.0.0.100" && a.RemotePort == 9999 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected jitter alert for low-jitter data")
	}
}

func TestDetectTrendsHighJitter(t *testing.T) {
	eng := NewEngine()
	key := beaconKey{PID: 4002, RemoteAddr: "10.0.0.101", RemotePort: 80}
	now := time.Now().UnixMilli()
	for i := 0; i < 15; i++ {
		eng.mu.Lock()
		eng.beaconTrack[key] = append(eng.beaconTrack[key], now+int64(i*5000)+int64(i%2)*2000)
		eng.mu.Unlock()
	}
	for _, a := range eng.DetectTrends() {
		if a.PID == 4002 {
			t.Fatal("high jitter should not trigger")
		}
	}
}

func TestDetectTrendsInsufficientData(t *testing.T) {
	eng := NewEngine()
	key := beaconKey{PID: 4003, RemoteAddr: "10.0.0.102", RemotePort: 22}
	now := time.Now().UnixMilli()
	for i := 0; i < 5; i++ {
		eng.mu.Lock()
		eng.beaconTrack[key] = append(eng.beaconTrack[key], now+int64(i*1000))
		eng.mu.Unlock()
	}
	for _, a := range eng.DetectTrends() {
		if a.PID == 4003 {
			t.Fatal("<10 points should not trigger")
		}
	}
}

func TestDetectTrendsSlowInterval(t *testing.T) {
	eng := NewEngine()
	key := beaconKey{PID: 4004, RemoteAddr: "10.0.0.104", RemotePort: 443}
	now := time.Now().UnixMilli()
	// intervals > 3600000ms (1h) should not trigger
	for i := 0; i < 15; i++ {
		eng.mu.Lock()
		eng.beaconTrack[key] = append(eng.beaconTrack[key], now+int64(i*7200000))
		eng.mu.Unlock()
	}
	for _, a := range eng.DetectTrends() {
		if a.PID == 4004 {
			t.Fatal(">1h intervals should not trigger")
		}
	}
}

// --- Engine integration ---

func TestEngineEval(t *testing.T) {
	eng := NewEngine()
	eng.AddBlocklist([]string{"1.1.1.1"})

	// blocklist hit
	ev := mkEvent(capture.EventNew, 5001, "bad", "1.1.1.1", 22, "SYN_SENT")
	if alert := eng.Eval(ev); alert == nil {
		t.Fatal("expected alert for blocklisted IP")
	}
	if eng.AlertCount() != 1 {
		t.Errorf("expected 1 alert, got %d", eng.AlertCount())
	}

	// clean
	ev2 := mkEvent(capture.EventNew, 5002, "good", "8.8.8.8", 443, "SYN_SENT")
	if alert := eng.Eval(ev2); alert != nil {
		t.Fatal("unexpected alert for clean IP")
	}
	if eng.AlertCount() != 1 {
		t.Errorf("expected still 1 alert, got %d", eng.AlertCount())
	}
}

func TestRecentAlerts(t *testing.T) {
	eng := NewEngine()
	eng.AddBlocklist([]string{"1.1.1.1"})
	for i := 0; i < 10; i++ {
		ev := mkEvent(capture.EventNew, 6001, "bad", "1.1.1.1", 22, "SYN_SENT")
		eng.Eval(ev)
	}
	recent := eng.RecentAlerts(3)
	if len(recent) != 3 {
		t.Errorf("expected 3 recent, got %d", len(recent))
	}
	all := eng.RecentAlerts(100)
	if len(all) != 10 {
		t.Errorf("expected 10 total, got %d", len(all))
	}
}

func TestAddBlocklist(t *testing.T) {
	eng := NewEngine()
	if eng.IsBlocked("1.2.3.4") {
		t.Fatal("should not be blocked initially")
	}
	eng.AddBlocklist([]string{"1.2.3.4"})
	if !eng.IsBlocked("1.2.3.4") {
		t.Fatal("should be blocked after add")
	}
}

func TestAddRule(t *testing.T) {
	eng := NewEngine()
	eng.AddRule(&BlocklistRule{})
	if len(eng.rules) != 4 {
		t.Errorf("expected 4 rules, got %d", len(eng.rules))
	}
}
