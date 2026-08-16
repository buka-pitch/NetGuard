package suricata

import (
	"database/sql"
	"encoding/json"
	"net"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"netmon/internal/capture"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open db: %v", err)
	}
	return db
}

func TestCmpNum(t *testing.T) {
	tests := []struct {
		expr string
		val  int
		want bool
	}{
		{"", 5, true},
		{"5", 5, true},
		{"5", 6, false},
		{">5", 6, true},
		{">5", 5, false},
		{">=5", 5, true},
		{">=5", 4, false},
		{"<5", 4, true},
		{"<5", 5, false},
		{"<=5", 5, true},
		{"<=5", 6, false},
		{"!5", 4, true},
		{"!5", 5, false},
		{"=5", 5, true},
		{"=5", 6, false},
	}
	for _, tc := range tests {
		got := cmpNum(tc.expr, tc.val)
		if got != tc.want {
			t.Errorf("cmpNum(%q, %d) = %v, want %v", tc.expr, tc.val, got, tc.want)
		}
	}
}

func TestMatchAlert(t *testing.T) {
	alert := &Alert{
		Timestamp: "2024-01-01T00:00:00Z",
		SrcIP:     "10.0.0.1",
		DstIP:     "203.0.113.5",
		Proto:     "TCP",
		Action:    "alert",
		Signature: "ET MALWARE Known Bad",
		Category:  "Malware",
		Comm:      "curl",
		Cmdline:   "curl http://evil.com",
		Severity:  2,
	}

	tests := []struct {
		name string
		f    *AlertFilter
		want bool
	}{
		{"nil filter", nil, true},
		{"empty filter", &AlertFilter{}, true},
		{"Q match signature", &AlertFilter{Q: "bad"}, true},
		{"Q match ip", &AlertFilter{Q: "203.0.113"}, true},
		{"Q no match", &AlertFilter{Q: "nonexistent"}, false},
		{"Severity exact", &AlertFilter{Severity: "2"}, true},
		{"Severity wrong", &AlertFilter{Severity: "3"}, false},
		{"Severity >", &AlertFilter{Severity: ">1"}, true},
		{"Severity > wrong", &AlertFilter{Severity: ">3"}, false},
		{"IP match src", &AlertFilter{IP: "10.0.0.1"}, true},
		{"IP match dst", &AlertFilter{IP: "203.0.113"}, true},
		{"IP no match", &AlertFilter{IP: "192.168"}, false},
		{"Comm match", &AlertFilter{Comm: "curl"}, true},
		{"Comm no match", &AlertFilter{Comm: "wget"}, false},
		{"Proto match", &AlertFilter{Proto: "tcp"}, true},
		{"Proto no match", &AlertFilter{Proto: "udp"}, false},
		{"Action match", &AlertFilter{Action: "alert"}, true},
		{"Action no match", &AlertFilter{Action: "drop"}, false},
		{"Sig match", &AlertFilter{Sig: "Known Bad"}, true},
		{"Sig no match", &AlertFilter{Sig: "Unknown"}, false},
		{"Combined filter all match", &AlertFilter{Q: "bad", Severity: "2", IP: "203.0.113", Comm: "curl", Proto: "tcp", Action: "alert", Sig: "Known"}, true},
		{"Combined filter one fails", &AlertFilter{Q: "bad", Severity: "1"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchAlert(alert, tc.f)
			if got != tc.want {
				t.Errorf("matchAlert = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHandleAlert(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	r := NewReader(100, nil, db)

	flow := &eveFlow{
		Timestamp: "2024-01-01T00:00:00Z",
		SrcIP:     "10.0.0.1",
		SrcPort:   12345,
		DestIP:    "203.0.113.5",
		DestPort:  80,
		Proto:     "TCP",
		Alert: &struct {
			Action    string `json:"action"`
			GID       int    `json:"gid"`
			Signature string `json:"signature"`
			Category  string `json:"category"`
			Severity  int    `json:"severity"`
		}{
			Action: "alert", GID: 1,
			Signature: "ET POLICY Suspicious",
			Category:  "Policy Violation",
			Severity:  2,
		},
		HTTP: &struct {
			Hostname  string `json:"hostname"`
			URL       string `json:"url"`
			UserAgent string `json:"ua"`
			Method    string `json:"method"`
			Status    int    `json:"status"`
			Mime      string `json:"mime"`
			Length    int    `json:"length"`
		}{
			Hostname: "evil.com", URL: "/payload", Method: "GET", Status: 200,
		},
		TLS: &struct {
			Subject     string `json:"subject"`
			IssuerDN    string `json:"issuerdn"`
			Fingerprint string `json:"fingerprint"`
			SNI         string `json:"sni"`
			Version     string `json:"version"`
		}{
			SNI: "evil.com", Version: "TLSv1.3",
		},
	}

	r.handleAlert(flow)

	alerts := r.RecentAlerts(10)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Signature != "ET POLICY Suspicious" {
		t.Errorf("signature: %s", a.Signature)
	}
	if a.HTTP == nil || a.HTTP.Hostname != "evil.com" {
		t.Error("HTTP hostname missing")
	}
	if a.TLS == nil || a.TLS.SNI != "evil.com" {
		t.Error("TLS SNI missing")
	}
	if a.DstIP != "203.0.113.5" {
		t.Errorf("dst_ip: %s", a.DstIP)
	}
}

func TestHandleAlertHTTPTLS(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	r := NewReader(100, nil, db)

	flow := &eveFlow{
		Timestamp: "2024-01-01T00:00:00Z",
		SrcIP:     "10.0.0.2",
		SrcPort:   54321,
		DestIP:    "1.2.3.4",
		DestPort:  443,
		Proto:     "TCP",
		Alert: &struct {
			Action    string `json:"action"`
			GID       int    `json:"gid"`
			Signature string `json:"signature"`
			Category  string `json:"category"`
			Severity  int    `json:"severity"`
		}{
			Action: "alert", GID: 2,
			Signature: "ET MALWARE CobaltStrike",
			Category:  "Malware",
			Severity:  1,
		},
		TLS: &struct {
			Subject     string `json:"subject"`
			IssuerDN    string `json:"issuerdn"`
			Fingerprint string `json:"fingerprint"`
			SNI         string `json:"sni"`
			Version     string `json:"version"`
		}{
			SNI: "malware-c2.example.com", Subject: "CN=malware-c2.example.com",
		},
	}

	r.handleAlert(flow)

	alerts := r.RecentAlerts(10)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.TLS == nil || a.TLS.SNI != "malware-c2.example.com" {
		t.Error("TLS SNI missing or wrong")
	}
	if a.HTTP != nil {
		t.Error("HTTP should be nil")
	}
}

func TestHandleAlertDNS(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	r := NewReader(100, nil, db)

	flow := &eveFlow{
		Timestamp: "2024-01-01T00:00:00Z",
		SrcIP:     "10.0.0.1",
		DestIP:    "8.8.8.8",
		DestPort:  53,
		Proto:     "UDP",
		DNS: &struct {
			Type    string `json:"type"`
			Query   string `json:"query"`
			RCode   string `json:"rcode"`
			Answers []struct {
				Name string `json:"name"`
				Type string `json:"type"`
				Data string `json:"data"`
			} `json:"answers"`
		}{
			Type: "query", Query: "example.com", RCode: "NOERROR",
			Answers: []struct {
				Name string `json:"name"`
				Type string `json:"type"`
				Data string `json:"data"`
			}{
				{Name: "example.com", Type: "A", Data: "93.184.216.34"},
			},
		},
	}

	r.handleAlert(flow)

	alerts := r.RecentAlerts(10)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.DNS == nil || a.DNS.Query != "example.com" {
		t.Error("DNS query missing")
	}
	if len(a.DNS.Answers) != 1 || a.DNS.Answers[0].Data != "93.184.216.34" {
		t.Error("DNS answer missing")
	}
}

func TestHandleStats(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	r := NewReader(100, nil, db)

	flow := &eveFlow{
		EventType: "stats",
		Stats: &struct {
			Uptime  int `json:"uptime"`
			Capture *struct {
				KernelPackets int64 `json:"kernel_packets"`
				KernelDrops   int64 `json:"kernel_drops"`
			} `json:"capture"`
			Detect *struct {
				Alert int64 `json:"alert"`
			} `json:"detect"`
			Flow *struct {
				Memuse int64 `json:"memuse"`
			} `json:"flow"`
			Tcp *struct {
				Memuse int64 `json:"memuse"`
			} `json:"tcp"`
		}{
			Uptime: 3600,
			Capture: &struct {
				KernelPackets int64 `json:"kernel_packets"`
				KernelDrops   int64 `json:"kernel_drops"`
			}{
				KernelPackets: 1000000,
				KernelDrops:   500,
			},
			Detect: &struct {
				Alert int64 `json:"alert"`
			}{
				Alert: 42,
			},
			Flow: &struct {
				Memuse int64 `json:"memuse"`
			}{
				Memuse: 1048576,
			},
			Tcp: &struct {
				Memuse int64 `json:"memuse"`
			}{
				Memuse: 2097152,
			},
		},
	}

	r.handleStats(flow)

	s := r.GetStats()
	if s.PacketsTotal != 1000000 {
		t.Errorf("PacketsTotal: %d", s.PacketsTotal)
	}
	if s.PacketsDrop != 500 {
		t.Errorf("PacketsDrop: %d", s.PacketsDrop)
	}
	if s.AlertsTotal != 42 {
		t.Errorf("AlertsTotal: %d", s.AlertsTotal)
	}
	if s.MemUsage != 3145728 {
		t.Errorf("MemUsage: %d", s.MemUsage)
	}
	if s.Uptime != "3600s" {
		t.Errorf("Uptime: %s", s.Uptime)
	}
	if s.AlertsPerSec <= 0 {
		t.Errorf("AlertsPerSec: %f", s.AlertsPerSec)
	}
}

func TestHandleStatsNil(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	r := NewReader(100, nil, db)

	// Should not panic
	r.handleStats(&eveFlow{})
	r.handleStats(&eveFlow{Stats: &struct {
		Uptime  int `json:"uptime"`
		Capture *struct {
			KernelPackets int64 `json:"kernel_packets"`
			KernelDrops   int64 `json:"kernel_drops"`
		} `json:"capture"`
		Detect *struct {
			Alert int64 `json:"alert"`
		} `json:"detect"`
		Flow *struct {
			Memuse int64 `json:"memuse"`
		} `json:"flow"`
		Tcp *struct {
			Memuse int64 `json:"memuse"`
		} `json:"tcp"`
	}{}})
}

func TestRecentAlerts(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	r := NewReader(10, nil, db)

	for i := 0; i < 15; i++ {
		r.handleAlert(&eveFlow{
			Timestamp: "2024-01-01T00:00:00Z",
			SrcIP:     "10.0.0.1",
			DestIP:    "203.0.113.5",
			Proto:     "TCP",
		})
	}

	alerts := r.RecentAlerts(5)
	if len(alerts) != 5 {
		t.Errorf("expected 5 alerts, got %d", len(alerts))
	}

	alerts = r.RecentAlerts(20)
	if len(alerts) != 10 {
		t.Errorf("expected 10 alerts (maxAlert), got %d", len(alerts))
	}
}

func TestQueryAlertsNoDB(t *testing.T) {
	r := &Reader{
		maxAlert: 100,
		alerts:   []Alert{},
		stats:    &Stats{},
	}

	for i := 0; i < 10; i++ {
		r.alerts = append(r.alerts, Alert{
			Signature: "Alert",
			Severity:  1,
		})
	}

	alerts, total := r.QueryAlerts(5, 0, nil)
	if len(alerts) != 5 {
		t.Errorf("expected 5, got %d", len(alerts))
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}

	alerts, total = r.QueryAlerts(20, 0, nil)
	if len(alerts) != 10 {
		t.Errorf("expected 10, got %d", len(alerts))
	}
	if total != 10 {
		t.Errorf("expected total 10, got %d", total)
	}

	// With filter
	alerts, total = r.QueryAlerts(10, 0, &AlertFilter{Q: "Nonexistent"})
	if len(alerts) != 0 || total != 0 {
		t.Errorf("expected 0, got %d / %d", len(alerts), total)
	}
}

func TestEnrich(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create a snapshot function returning a matching connection
	snapshot := func() []capture.Connection {
		return []capture.Connection{
			{
				PID:        1234,
				Comm:       "curl",
				Cmdline:    "curl https://evil.com",
				Exe:        "/usr/bin/curl",
				PPID:       1,
				PComm:      "systemd",
				RemoteAddr: net.ParseIP("203.0.113.5"),
				RemotePort: 443,
				LocalAddr:  net.ParseIP("10.0.0.5"),
				LocalPort:  54321,
				CreatedAt:  int64(time.Now().UnixMilli()),
			},
		}
	}
	_ = snapshot

	r := NewReader(100, func() []capture.Connection {
		return []capture.Connection{
			{
				PID:        1234,
				Comm:       "curl",
				Cmdline:    "curl https://evil.com",
				Exe:        "/usr/bin/curl",
				PPID:       1,
				PComm:      "systemd",
				RemoteAddr: net.ParseIP("203.0.113.5"),
				RemotePort: 443,
				LocalAddr:  net.ParseIP("10.0.0.5"),
				LocalPort:  54321,
				CreatedAt:  int64(time.Now().UnixMilli()),
			},
		}
	}, db)

	alert := &Alert{
		DstIP:   "203.0.113.5",
		DstPort: 443,
	}

	r.enrich(alert)

	if alert.PID != 1234 {
		t.Errorf("PID: %d", alert.PID)
	}
	if alert.Comm != "curl" {
		t.Errorf("Comm: %s", alert.Comm)
	}
	if alert.Cmdline != "curl https://evil.com" {
		t.Errorf("Cmdline: %s", alert.Cmdline)
	}
	if alert.Duration == "" {
		t.Error("Duration should be set")
	}
}

func TestEnrichNoMatch(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	r := NewReader(100, func() []capture.Connection {
		return []capture.Connection{
			{
				RemoteAddr: net.ParseIP("1.2.3.4"),
				RemotePort: 80,
			},
		}
	}, db)

	alert := &Alert{
		DstIP:   "5.6.7.8",
		DstPort: 443,
	}

	r.enrich(alert)

	if alert.PID != 0 {
		t.Error("should not match")
	}
}

func TestOffsetPersistence(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	r := NewReader(100, nil, db)

	r.saveOffset(12345, 67890)

	off, inode := r.loadOffset()
	if off != 12345 {
		t.Errorf("offset: %d", off)
	}
	if inode != 67890 {
		t.Errorf("inode: %d", inode)
	}
}

func TestPersistAlert(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	r := NewReader(100, nil, db)

	alert := &Alert{
		Timestamp: "2024-01-01T00:00:00Z",
		SrcIP:     "10.0.0.1",
		SrcPort:   12345,
		DstIP:     "203.0.113.5",
		DstPort:   80,
		Proto:     "TCP",
		Action:    "alert",
		Signature: "ET MALWARE Test",
		Category:  "Malware",
		Severity:  1,
		GID:       1,
		PID:       100,
		Comm:      "test",
		Cmdline:   "test",
	}

	r.persistAlert(alert)

	var count int
	db.QueryRow("SELECT COUNT(*) FROM suricata_alerts").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 persisted alert, got %d", count)
	}

	var sig string
	db.QueryRow("SELECT signature FROM suricata_alerts WHERE dst_ip='203.0.113.5'").Scan(&sig)
	if sig != "ET MALWARE Test" {
		t.Errorf("signature: %s", sig)
	}
}

func TestPersistAlertWithHTTPTLS(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	r := NewReader(100, nil, db)

	alert := &Alert{
		Timestamp: "2024-01-01T00:00:00Z",
		SrcIP:     "10.0.0.1",
		DstIP:     "203.0.113.5",
		DstPort:   443,
		Proto:     "TCP",
		Signature: "Test",
		HTTP: &HTTP{
			Hostname: "evil.com",
			URL:      "/payload",
		},
		TLS: &TLS{
			SNI: "evil.com",
		},
		DNS: &DNS{
			Query: "evil.com",
		},
	}

	r.persistAlert(alert)

	var httpData, tlsData, dnsData string
	db.QueryRow("SELECT http_data, tls_data, dns_data FROM suricata_alerts LIMIT 1").Scan(&httpData, &tlsData, &dnsData)
	if httpData == "" {
		t.Error("http_data should not be empty")
	}
	if tlsData == "" {
		t.Error("tls_data should not be empty")
	}
	if dnsData == "" {
		t.Error("dns_data should not be empty")
	}

	var httpParsed HTTP
	json.Unmarshal([]byte(httpData), &httpParsed)
	if httpParsed.Hostname != "evil.com" {
		t.Errorf("HTTP hostname: %s", httpParsed.Hostname)
	}
}

func TestQueryAlertsWithDB(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	r := NewReader(100, nil, db)

	// Insert some alerts directly
	for i := 0; i < 5; i++ {
		alert := &Alert{
			Timestamp: "2024-01-01T00:00:00Z",
			SrcIP:     "10.0.0.1",
			DstIP:     "203.0.113.5",
			Proto:     "TCP",
			Signature: "Alert",
			Comm:      "curl",
		}
		r.persistAlert(alert)
	}

	alerts, total := r.QueryAlerts(10, 0, nil)
	if len(alerts) != 5 {
		t.Errorf("expected 5, got %d", len(alerts))
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}

	// With filter
	alerts, total = r.QueryAlerts(10, 0, &AlertFilter{Comm: "curl"})
	if len(alerts) != 5 {
		t.Errorf("expected 5 with filter, got %d", len(alerts))
	}

	alerts, total = r.QueryAlerts(10, 0, &AlertFilter{Comm: "wget"})
	if len(alerts) != 0 {
		t.Errorf("expected 0, got %d", len(alerts))
	}
}

func TestInitDB(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	NewReader(100, nil, db)

	// Tables should exist
	var count int
	db.QueryRow("SELECT COUNT(*) FROM suricata_alerts").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}

	db.QueryRow("SELECT COUNT(*) FROM reader_state").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestNoCaptFn(t *testing.T) {
	r := &Reader{
		maxAlert: 100,
		alerts:   []Alert{},
		stats:    &Stats{},
	}

	// Should not panic when cap is nil
	r.enrich(&Alert{})
}

func TestGetStats(t *testing.T) {
	r := &Reader{
		stats: &Stats{
			PacketsTotal: 100,
			AlertsTotal:  50,
		},
	}

	s := r.GetStats()
	if s.PacketsTotal != 100 {
		t.Errorf("PacketsTotal: %d", s.PacketsTotal)
	}
	if s.AlertsTotal != 50 {
		t.Errorf("AlertsTotal: %d", s.AlertsTotal)
	}
}

func TestEnrichPrefersExactTupleMatch(t *testing.T) {
	r := &Reader{
		cap: func() []capture.Connection {
			return []capture.Connection{
				{
					PID:        111,
					Comm:       "wrong",
					Cmdline:    "wrong --scan",
					Exe:        "/usr/bin/wrong",
					LocalAddr:  net.ParseIP("10.0.0.5"),
					LocalPort:  55555,
					RemoteAddr: net.ParseIP("8.8.8.8"),
					RemotePort: 443,
				},
				{
					PID:        222,
					Comm:       "right",
					Cmdline:    "right --fetch",
					Exe:        "/usr/bin/right",
					LocalAddr:  net.ParseIP("10.0.0.5"),
					LocalPort:  44444,
					RemoteAddr: net.ParseIP("8.8.8.8"),
					RemotePort: 443,
				},
			}
		},
	}

	alert := &Alert{
		SrcIP:   "10.0.0.5",
		SrcPort: 44444,
		DstIP:   "8.8.8.8",
		DstPort: 443,
		Proto:   "TCP",
	}

	r.enrich(alert)

	if alert.PID != 222 {
		t.Fatalf("expected exact match PID 222, got %d", alert.PID)
	}
	if alert.Comm != "right" {
		t.Fatalf("expected exact match comm right, got %s", alert.Comm)
	}
	if alert.Cmdline != "right --fetch" {
		t.Fatalf("expected cmdline from exact match, got %s", alert.Cmdline)
	}
}

// TestReaderStopContract: Stop() must be safe to call multiple times and
// must close the done channel so any spawned tail() goroutine can exit.
// We test the contract directly without standing up NewReader (which
// touches the filesystem via initDB) by constructing a Reader literal.
func TestReaderStopContract(t *testing.T) {
	r := &Reader{done: make(chan struct{})}
	r.Stop()
	r.Stop() // must not panic
	select {
	case <-r.done:
	default:
		t.Fatal("done channel should be closed after Stop()")
	}
}
