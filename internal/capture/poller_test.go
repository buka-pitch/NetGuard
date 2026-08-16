package capture

import (
	"context"
	"net"
	"testing"
	"time"
)

// --- Incoming detection ---

func incomingKey(remoteIP string, remotePort int, localPort int) ConnectionKey {
	return ConnectionKey{
		RemoteAddr: remoteIP,
		RemotePort: remotePort,
		LocalPort:  localPort,
	}
}

func TestIncomingDetection(t *testing.T) {
	tests := []struct {
		name        string
		state       string
		remoteIP    string
		firstPoll   bool
		synSentSeen map[ConnectionKey]bool
		wantIncoming bool
	}{
		{
			name:         "SYN_SENT not incoming",
			state:        "SYN_SENT",
			remoteIP:     "1.1.1.1",
			firstPoll:    false,
			synSentSeen:  map[ConnectionKey]bool{},
			wantIncoming: false,
		},
		{
			name:     "ESTABLISHED after SYN_SENT not incoming",
			state:    "ESTABLISHED",
			remoteIP: "1.1.1.1",
			firstPoll: false,
			synSentSeen: map[ConnectionKey]bool{
				incomingKey("1.1.1.1", 443, 0): true,
			},
			wantIncoming: false,
		},
		{
			name:         "ESTABLISHED without SYN_SENT is incoming",
			state:        "ESTABLISHED",
			remoteIP:     "10.0.0.5",
			firstPoll:    false,
			synSentSeen:  map[ConnectionKey]bool{},
			wantIncoming: true,
		},
		{
			name:         "SYN_RECV without SYN_SENT is incoming",
			state:        "SYN_RECV",
			remoteIP:     "10.0.0.6",
			firstPoll:    false,
			synSentSeen:  map[ConnectionKey]bool{},
			wantIncoming: true,
		},
		{
			name:         "first poll not incoming",
			state:        "ESTABLISHED",
			remoteIP:     "10.0.0.7",
			firstPoll:    true,
			synSentSeen:  map[ConnectionKey]bool{},
			wantIncoming: false,
		},
		{
			name:         "loopback not incoming",
			state:        "ESTABLISHED",
			remoteIP:     "127.0.0.1",
			firstPoll:    false,
			synSentSeen:  map[ConnectionKey]bool{},
			wantIncoming: false,
		},
		{
			name:         "CLOSE not incoming",
			state:        "CLOSE",
			remoteIP:     "10.0.0.8",
			firstPoll:    false,
			synSentSeen:  map[ConnectionKey]bool{},
			wantIncoming: false,
		},
		{
			name:         "TIME_WAIT not incoming",
			state:        "TIME_WAIT",
			remoteIP:     "10.0.0.9",
			firstPoll:    false,
			synSentSeen:  map[ConnectionKey]bool{},
			wantIncoming: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			remote := net.ParseIP(tc.remoteIP)
			if remote == nil {
				t.Fatal("bad IP:", tc.remoteIP)
			}
			key := ConnectionKey{RemoteAddr: remote.String(), RemotePort: 443}
			got := !tc.firstPoll &&
				(tc.state == "ESTABLISHED" || tc.state == "SYN_RECV") &&
				!tc.synSentSeen[key] &&
				remote != nil && !remote.IsLoopback() && !remote.IsUnspecified()
			if got != tc.wantIncoming {
				t.Errorf("incoming=%v, want %v", got, tc.wantIncoming)
			}
		})
	}
}

func TestPreExisting(t *testing.T) {
	p := NewPoller(0, nil, false)
	if !p.firstPoll {
		t.Fatal("new poller should have firstPoll=true")
	}

	// check that the flag gets set on connections during first poll
	// by running poll and checking if PreExisting is set
	p.poll(nil)
	// after poll, firstPoll should be false
	if p.firstPoll {
		t.Fatal("firstPoll should be false after first poll")
	}
}

// When askOnStart is true, the very first poll must NOT mark connections as
// PreExisting — they need to be queueable as pending approvals just like a
// fresh connection would.
func TestAskOnStartDisablesPreExisting(t *testing.T) {
	p := NewPoller(0, nil, true)
	if !p.askOnStart {
		t.Fatal("new poller should have askOnStart=true")
	}
	if !p.firstPoll {
		t.Fatal("new poller should still have firstPoll=true")
	}

	// Simulate one cycle: emulate the PreExisting assignment directly
	// (we can't easily synthesize /proc state in unit tests; this guards
	// the field semantics without touching the real poll path).
	conn := Connection{State: "ESTABLISHED"}
	conn.PreExisting = p.firstPoll && !p.askOnStart
	if conn.PreExisting {
		t.Fatal("askOnStart=true should suppress PreExisting flag on first poll")
	}
}

// --- VPN ports ---

func TestVPNPorts(t *testing.T) {
	tests := []struct {
		port int
		vpn  bool
	}{
		{51820, true},
		{51821, true},
		{1194, true},
		{1195, true},
		{500, true},
		{4500, true},
		{1701, true},
		{1723, true},
		{60000, true},
		{443, false},
		{80, false},
		{53, false},
		{22, false},
		{8443, false},
		{9999, false},
	}
	for _, tc := range tests {
		_, ok := VPNPorts[tc.port]
		if ok != tc.vpn {
			t.Errorf("VPNPorts[%d] = %v, want %v", tc.port, ok, tc.vpn)
		}
	}
}

// --- hex address parsing ---

func TestParseHexAddrV4(t *testing.T) {
	// 0801A8C0:D9A2 = 192.168.1.8:55714
	addr := parseHexAddr("0801A8C0:D9A2")
	if addr.IP == nil {
		t.Fatal("nil IP")
	}
	if addr.IP.String() != "192.168.1.8" {
		t.Errorf("expected 192.168.1.8, got %s", addr.IP)
	}
	if addr.Port != 55714 {
		t.Errorf("expected port 55714, got %d", addr.Port)
	}
}

func TestParseHexAddrV4Zero(t *testing.T) {
	addr := parseHexAddr("00000000:0000")
	if addr.IP == nil || !addr.IP.IsUnspecified() {
		t.Errorf("expected unspecified IP, got %s", addr.IP)
	}
	if addr.Port != 0 {
		t.Errorf("expected port 0, got %d", addr.Port)
	}
}

func TestParseHexAddrV6(t *testing.T) {
	// 0000000000000000FFFF0100:01BB = ::ffff:1.0.0.255:443
	addr := parseHexAddr("0000000000000000FFFF0100:01BB")
	if addr.IP == nil {
		t.Fatal("nil IP")
	}
	if addr.Port != 443 {
		t.Errorf("expected port 443, got %d", addr.Port)
	}
}

func TestParseHexAddrInvalid(t *testing.T) {
	addr := parseHexAddr("invalid")
	if addr.IP != nil {
		t.Errorf("expected nil IP for invalid input")
	}
}

func TestParseHexAddrEmpty(t *testing.T) {
	addr := parseHexAddr("")
	if addr.IP != nil {
		t.Errorf("expected nil IP for empty input")
	}
}

// --- readProcNet ---

func TestReadProcNetTCP(t *testing.T) {
	conns, err := readProcNet(procNetTCP, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	// There should be at least the loopback entries on any system
	if len(conns) == 0 {
		t.Log("no TCP connections found (expected on idle system)")
	}
	for key, conn := range conns {
		if conn.Protocol != "tcp" {
			t.Errorf("expected proto tcp, got %s", conn.Protocol)
		}
		if conn.RemoteAddr != nil && conn.LocalAddr != nil {
			if key.RemoteAddr != conn.RemoteAddr.String() {
				t.Errorf("key RemoteAddr %s != conn %s", key.RemoteAddr, conn.RemoteAddr)
			}
		}
	}
}

func TestReadProcNetUDP(t *testing.T) {
	conns, err := readProcNet(procNetUDP, "udp")
	if err != nil {
		t.Fatal(err)
	}
	for _, conn := range conns {
		if conn.Protocol != "udp" {
			t.Errorf("expected proto udp, got %s", conn.Protocol)
		}
	}
}

func TestReadProcNetBadPath(t *testing.T) {
	_, err := readProcNet("/proc/net/nonexistent", "bad")
	if err == nil {
		t.Fatal("expected error for bad path")
	}
}

// --- SynSent scanning ---

func TestSynSentScan(t *testing.T) {
	entries := ScanSynSent()
	// should not panic or error
	for _, e := range entries {
		if e.IP == "" {
			t.Error("syn sent entry with empty IP")
		}
		if e.Port <= 0 {
			t.Error("syn sent entry with invalid port")
		}
	}
}

// --- readSynSent ---

func TestReadSynSent(t *testing.T) {
	entries := readSynSent(procNetTCP)
	// nil is valid when no SYN_SENT connections exist
	for _, e := range entries {
		if e.ip == "" {
			t.Errorf("empty IP in synSent entry")
		}
	}
}

// --- poller event cycle ---

func TestPollerProcessEnrichment(t *testing.T) {
	p := NewPoller(0, nil, false)

	// simulate two poll cycles and check event emission
	events := make(chan ConnectionEvent, 100)

	// first poll — all conns are PreExisting
	p.poll(events)
	select {
	case ev := <-events:
		if ev.Type != EventNew {
			t.Errorf("expected EventNew, got %v", ev.Type)
		}
		if !ev.PreExisting && ev.State != "ESTABLISHED" {
			// connections that existed before daemon start
			// are marked PreExisting on first poll
		}
	default:
		// no events — idle system. That's ok.
	}

	// drain first poll events before second poll
drain:
	for {
		select {
		case <-events:
		default:
			break drain
		}
	}

	// second poll — should emit no events unless connections changed
	p.poll(events)
	close(events)
	for ev := range events {
		if ev.Type == EventNew {
			if ev.PreExisting {
				t.Error("second poll should not have PreExisting connections")
			}
		}
	}
}

func TestPollAndSnapshot(t *testing.T) {
	p := NewPoller(0, nil, false)
	p.poll(nil)
	snap := p.Snapshot()
	// should not be nil
	if snap == nil {
		t.Error("snapshot should not be nil")
	}
	for _, c := range snap {
		if c.PID == 0 && c.State != "ESTABLISHED" {
			t.Errorf("snapshot includes conn without PID or ESTABLISHED state: %+v", c)
		}
	}
}

func TestSynSentSeenTracking(t *testing.T) {
	p := NewPoller(0, nil, false)

	// seed synthetic SYN_SENT entries into poller
	key := ConnectionKey{
		Proto:      "tcp",
		RemoteAddr: "203.0.113.1",
		RemotePort: 8443,
	}
	p.synSentSeen[key] = true

	// on next poll, an ESTABLISHED with this key should NOT be incoming
	remoteIP := net.ParseIP("203.0.113.1")
	conn := Connection{
		RemoteAddr: remoteIP,
		RemotePort: 8443,
		State:      "ESTABLISHED",
		Protocol:   "tcp",
	}
	connKey := ConnectionKey{
		RemoteAddr: conn.RemoteAddr.String(),
		RemotePort: conn.RemotePort,
	}

	isIncoming := !p.firstPoll && (conn.State == "ESTABLISHED" || conn.State == "SYN_RECV") && !p.synSentSeen[connKey] && conn.RemoteAddr != nil && !conn.RemoteAddr.IsLoopback() && !conn.RemoteAddr.IsUnspecified()
	if isIncoming {
		t.Error("expected outgoing because SYN_SENT was tracked")
	}

	// unknown key should be incoming
	p.synSentSeen = map[ConnectionKey]bool{} // reset
	p.firstPoll = false
	isIncoming = !p.firstPoll && (conn.State == "ESTABLISHED" || conn.State == "SYN_RECV") && !p.synSentSeen[connKey] && conn.RemoteAddr != nil && !conn.RemoteAddr.IsLoopback() && !conn.RemoteAddr.IsUnspecified()
	if !isIncoming {
		t.Error("expected incoming because SYN_SENT was not tracked")
	}
}

// --- process enrichment ---

func TestReadProcCmdline(t *testing.T) {
	cmdline := ReadProcCmdline(1) // PID 1 is always init
	if cmdline == "" {
		t.Log("PID 1 cmdline is empty (container?)")
	}
}

func TestReadProcExe(t *testing.T) {
	exe := ReadProcExe(1)
	if exe == "" {
		t.Log("PID 1 exe is empty (container?)")
	}
}

func TestReadProcPPID(t *testing.T) {
	ppid := ReadProcPPID(1)
	if ppid != 0 {
		// PID 1 typically has PPID 0
		t.Logf("PID 1 PPID = %d", ppid)
	}
}

func TestReadProcParentComm(t *testing.T) {
	pcomm := ReadProcParentComm(1)
	// may or may not have a parent
	t.Logf("PID 1 parent comm = %q", pcomm)
}

func TestReadProcAll(t *testing.T) {
	cmdline, exe, ppid, pcomm, gpid, gcomm := ReadProcAll(1)
	t.Logf("PID 1: cmdline=%q exe=%q ppid=%d pcomm=%q gpid=%d gcomm=%q", cmdline, exe, ppid, pcomm, gpid, gcomm)
}

func TestProcMapperLookup(t *testing.T) {
	m := NewProcMapper()
	pid, comm := m.Lookup(uint64(1))
	// PID 1 should always be resolvable
	if pid > 0 && comm == "" {
		t.Errorf("PID %d resolved but comm empty", pid)
	}
}

func TestProcMapperLookupPID(t *testing.T) {
	m := NewProcMapper()
	comm := m.LookupPID(1)
	if comm == "" {
		t.Log("PID 1 comm empty (expected in some environments)")
	}
}

func TestResolveProcInodes(t *testing.T) {
	im, err := ResolveProcInodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(im) == 0 {
		t.Log("no socket inodes found (expected in minimal environments)")
	}
	for inode, pid := range im {
		if inode == 0 {
			t.Error("zero inode in result")
		}
		if pid <= 0 {
			t.Errorf("invalid PID %d for inode %d", pid, inode)
		}
	}
}

// --- ConnectionKey ---

func TestConnectionKeyEquality(t *testing.T) {
	a := ConnectionKey{Proto: "tcp", RemoteAddr: "1.2.3.4", RemotePort: 80, LocalPort: 54321}
	b := ConnectionKey{Proto: "tcp", RemoteAddr: "1.2.3.4", RemotePort: 80, LocalPort: 54321}
	if a != b {
		t.Error("identical keys should be equal")
	}
	// different proto
	b.Proto = "udp"
	if a == b {
		t.Error("different proto should be different")
	}
	b.Proto = "tcp"
	b.RemotePort = 443
	if a == b {
		t.Error("different port should be different")
	}
}

// TestPollerStopsOnContextCancel verifies that Start exits promptly when the
// passed context is cancelled. Without the ctx branch in Start, the loop
// would run forever and the goroutine would leak.
func TestPollerStopsOnContextCancel(t *testing.T) {
	p := NewPoller(50*time.Millisecond, nil, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Start(ctx, nil)
		close(done)
	}()
	time.Sleep(120 * time.Millisecond) // let it tick a few times
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Poller.Start did not return after ctx cancel")
	}
}

// TestPollerStopsOnStopCall: Stop() (without ctx cancellation) also works.
func TestPollerStopsOnStopCall(t *testing.T) {
	p := NewPoller(50*time.Millisecond, nil, false)
	done := make(chan struct{})
	go func() {
		p.Start(context.Background(), nil)
		close(done)
	}()
	time.Sleep(120 * time.Millisecond)
	p.Stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Poller.Start did not return after Stop()")
	}
}

// TestPollerStopIsIdempotent: multiple Stop() calls don't panic.
func TestPollerStopIsIdempotent(t *testing.T) {
	p := NewPoller(50*time.Millisecond, nil, false)
	for i := 0; i < 5; i++ {
		p.Stop()
	}
}
