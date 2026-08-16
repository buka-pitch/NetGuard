package ai

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"netmon/internal/store"
)

type Store interface {
	QueryConns(store.ConnFilter) ([]store.ConnResult, error)
	QueryAlerts(store.AlertFilter) ([]store.AlertResult, error)
	GetAnalysisContext(remoteIP string, remotePort int) (*store.AnalysisContext, error)
	GetConnHistory(remoteIP string, limit int) ([]store.ConnResult, error)
	Stats() store.Stats
	BlocklistIP(ip string, source string) error
	GetAlert(id int64) (*store.AlertResult, error)
}

type PcapLister interface {
	ListCaptures() ([]CaptureInfo, error)
	ReadCapture(filename string, maxLines int, filter string) (string, error)
}

type CaptureInfo struct {
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	CreatedAt int64  `json:"created_at"`
}

type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type ToolHandler func(args json.RawMessage) (string, error)

type Registry struct {
	store    Store
	pcap     PcapLister
	handlers map[string]ToolHandler
	defs     []ToolDef
}

func NewRegistry(s Store) *Registry {
	return NewRegistryWithPcap(s, nil)
}

func NewRegistryWithPcap(s Store, p PcapLister) *Registry {
	r := &Registry{store: s, pcap: p, handlers: make(map[string]ToolHandler)}
	r.register("query_connections",
		"Query historical connections with optional filters. Returns process, IP, port, protocol, state for each matching connection.",
		`{"type":"object","properties":{"process":{"type":"string","description":"Filter by process name (e.g. firefox, curl)"},"remote_ip":{"type":"string","description":"Filter by remote IP address"},"remote_port":{"type":"integer","description":"Filter by remote port"},"local_port":{"type":"integer","description":"Filter by local port"},"protocol":{"type":"string","description":"Filter by protocol (tcp, udp, icmp)"},"state":{"type":"string","description":"Filter by connection state (ESTABLISHED, SYN_SENT, CLOSE, TIME_WAIT)"},"limit":{"type":"integer","default":20,"description":"Max results to return"}}}`,
		r.handleQueryConns)

	r.register("get_stats",
		"Get aggregate network statistics including total connections, active connections, alert count, top processes and top destinations.",
		`{"type":"object","properties":{}}`,
		r.handleGetStats)

	r.register("get_analysis_context",
		"Get comprehensive security analysis context for a connection to a specific remote IP and port. Returns current connections, historical data, and related alerts. Use this before deciding to allow or deny a connection.",
		`{"type":"object","properties":{"remote_ip":{"type":"string","description":"Remote IP address to analyze"},"remote_port":{"type":"integer","description":"Remote port to analyze"}},"required":["remote_ip","remote_port"]}`,
		r.handleGetAnalysisContext)

	r.register("analyze_ip",
		"Look up all historical connections and alerts involving a specific remote IP address.",
		`{"type":"object","properties":{"remote_ip":{"type":"string","description":"IP address to look up"},"limit":{"type":"integer","default":20}},"required":["remote_ip"]}`,
		r.handleAnalyzeIP)

	r.register("list_alerts",
		"List security alerts with optional severity filter. Returns recent alerts including rule name, severity, process, remote address, and message.",
		`{"type":"object","properties":{"severity":{"type":"string","description":"Filter by severity (critical, high, medium, low, info)"},"limit":{"type":"integer","default":30,"description":"Max alerts to return"}}}`,
		r.handleListAlerts)

	r.register("inspect_alert",
		"Get comprehensive details about a specific alert by its ID. Returns the full alert data plus related network connections, process information, and historical context for the involved remote address.",
		`{"type":"object","properties":{"alert_id":{"type":"integer","description":"Alert ID to inspect"}},"required":["alert_id"]}`,
		r.handleInspectAlert)

	r.register("block_ip",
		"Block a remote IP address by adding it to the blocklist. Future connections from this IP will be denied.",
		`{"type":"object","properties":{"remote_ip":{"type":"string","description":"IP address to block"},"reason":{"type":"string","description":"Optional reason for blocking"}},"required":["remote_ip"]}`,
		r.handleBlockIP)

	r.register("run_diagnostics",
		"Run network diagnostics against a target IP or hostname. Performs DNS resolution, ping, and port connectivity checks.",
		`{"type":"object","properties":{"target":{"type":"string","description":"IP address or hostname to diagnose"},"port":{"type":"integer","description":"Optional port to check"}},"required":["target"]}`,
		r.handleRunDiagnostics)

	if r.pcap != nil {
		r.register("list_captures",
			"List available packet capture files with their sizes and creation times.",
			`{"type":"object","properties":{}}`,
			r.handleListCaptures)

		r.register("read_capture",
			"Read and analyze a packet capture file. Returns tcpdump output for the given capture. Use list_captures first to find available files.",
			`{"type":"object","properties":{"filename":{"type":"string","description":"Capture filename (e.g. capture_pid123_1234567890.pcap)"},"max_lines":{"type":"integer","default":50,"description":"Max lines of output to return. Use small values for summaries, larger for detailed analysis."},"filter":{"type":"string","description":"Optional tcpdump filter expression (e.g. 'port 80', 'host 1.2.3.4')"}},"required":["filename"]}`,
			r.handleReadCapture)
	}

	return r
}

func (r *Registry) register(name, desc, paramsJSON string, handler ToolHandler) {
	r.defs = append(r.defs, ToolDef{
		Name: name, Description: desc, Parameters: json.RawMessage(paramsJSON),
	})
	r.handlers[name] = handler
}

func (r *Registry) Definitions() []ToolDef {
	return r.defs
}

func (r *Registry) Dispatch(name string, args json.RawMessage) (string, error) {
	h, ok := r.handlers[name]
	if !ok {
		return "", fmt.Errorf("unknown tool: %s", name)
	}
	return h(args)
}

func (r *Registry) handleQueryConns(args json.RawMessage) (string, error) {
	if r.store == nil {
		return "store not available", nil
	}
	var params struct {
		Process    string `json:"process"`
		RemoteIP   string `json:"remote_ip"`
		RemotePort int    `json:"remote_port"`
		LocalPort  int    `json:"local_port"`
		Protocol   string `json:"protocol"`
		State      string `json:"state"`
		Limit      int    `json:"limit"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid args: %w", err)
	}
	if params.Limit <= 0 {
		params.Limit = 20
	}
	conns, err := r.store.QueryConns(store.ConnFilter{
		Process:    params.Process,
		RemoteIP:   params.RemoteIP,
		RemotePort: params.RemotePort,
		LocalPort:  params.LocalPort,
		Protocol:   params.Protocol,
		State:      params.State,
		Limit:      params.Limit,
	})
	if err != nil {
		return "", err
	}
	return formatConns(conns), nil
}

func (r *Registry) handleGetStats(args json.RawMessage) (string, error) {
	if r.store == nil {
		return "store not available", nil
	}
	s := r.store.Stats()
	var b strings.Builder
	fmt.Fprintf(&b, "Total connections: %d\n", s.TotalConns)
	fmt.Fprintf(&b, "Active connections: %d\n", s.ActiveConns)
	fmt.Fprintf(&b, "Alert count: %d\n", s.AlertCount)
	if len(s.TopProcesses) > 0 {
		b.WriteString("Top processes:\n")
		for _, p := range s.TopProcesses {
			fmt.Fprintf(&b, "  %s: %d\n", p.Comm, p.Count)
		}
	}
	if len(s.TopIPs) > 0 {
		b.WriteString("Top destinations:\n")
		for _, i := range s.TopIPs {
			fmt.Fprintf(&b, "  %s: %d\n", i.IP, i.Count)
		}
	}
	return b.String(), nil
}

func (r *Registry) handleGetAnalysisContext(args json.RawMessage) (string, error) {
	if r.store == nil {
		return "store not available", nil
	}
	var params struct {
		RemoteIP   string `json:"remote_ip"`
		RemotePort int    `json:"remote_port"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid args: %w", err)
	}
	ctx, err := r.store.GetAnalysisContext(params.RemoteIP, params.RemotePort)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("=== Connection Analysis ===\n")

	b.WriteString("\nCurrent connections to this IP:port:\n")
	b.WriteString(formatConns(ctx.CurrentConns))

	b.WriteString("\nHistorical connections to this IP:port:\n")
	b.WriteString(fmt.Sprintf("Total historical connections: %d\n", ctx.TotalHistory))

	if len(ctx.Alerts) > 0 {
		b.WriteString("\nRelated alerts:\n")
		b.WriteString(formatAlerts(ctx.Alerts))
	} else {
		b.WriteString("\nNo related alerts.\n")
	}
	return b.String(), nil
}

func (r *Registry) handleAnalyzeIP(args json.RawMessage) (string, error) {
	if r.store == nil {
		return "store not available", nil
	}
	var params struct {
		RemoteIP string `json:"remote_ip"`
		Limit    int    `json:"limit"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid args: %w", err)
	}
	if params.Limit <= 0 {
		params.Limit = 20
	}
	conns, err := r.store.GetConnHistory(params.RemoteIP, params.Limit)
	if err != nil {
		return "", err
	}
	alerts, _ := r.store.QueryAlerts(store.AlertFilter{Limit: 50})
	var related []store.AlertResult
	for _, a := range alerts {
		if a.RemoteAddr == params.RemoteIP {
			related = append(related, a)
		}
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Connections to %s:\n", params.RemoteIP))
	b.WriteString(formatConns(conns))
	if len(related) > 0 {
		b.WriteString("\nAlerts involving this IP:\n")
		b.WriteString(formatAlerts(related))
	}
	return b.String(), nil
}

func (r *Registry) handleListAlerts(args json.RawMessage) (string, error) {
	if r.store == nil {
		return "store not available", nil
	}
	var params struct {
		Severity string `json:"severity"`
		Limit    int    `json:"limit"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid args: %w", err)
	}
	if params.Limit <= 0 {
		params.Limit = 30
	}
	alerts, err := r.store.QueryAlerts(store.AlertFilter{
		Severity: params.Severity,
		Limit:    params.Limit,
	})
	if err != nil {
		return "", err
	}
	if len(alerts) == 0 {
		return "No alerts found.", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Found %d alerts:\n\n", len(alerts))
	b.WriteString(formatAlerts(alerts))
	return b.String(), nil
}

func (r *Registry) handleInspectAlert(args json.RawMessage) (string, error) {
	if r.store == nil {
		return "store not available", nil
	}
	var params struct {
		AlertID int64 `json:"alert_id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid args: %w", err)
	}
	if params.AlertID <= 0 {
		return "", fmt.Errorf("valid alert_id is required")
	}

	alert, err := r.store.GetAlert(params.AlertID)
	if err != nil {
		return "", fmt.Errorf("get alert: %w", err)
	}
	if alert == nil {
		return fmt.Sprintf("Alert %d not found.", params.AlertID), nil
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("=== Alert #%d ===\n", alert.ID))
	fmt.Fprintf(&b, "Rule: %s\n", alert.RuleName)
	fmt.Fprintf(&b, "Severity: %s\n", alert.Severity)
	fmt.Fprintf(&b, "Process: %s (PID %d)\n", alert.Comm, alert.PID)
	fmt.Fprintf(&b, "Remote: %s:%d\n", alert.RemoteAddr, alert.RemotePort)
	fmt.Fprintf(&b, "Message: %s\n", alert.Message)
	t := time.UnixMilli(alert.CreatedAt)
	fmt.Fprintf(&b, "Time: %s\n\n", t.Format("2006-01-02 15:04:05"))

	// Related connections
	ctx, err := r.store.GetAnalysisContext(alert.RemoteAddr, alert.RemotePort)
	if err == nil && ctx != nil {
		b.WriteString("--- Current connections to this IP:port ---\n")
		b.WriteString(formatConns(ctx.CurrentConns))
		b.WriteString("\n\n--- Recent connections to this IP:port ---\n")
		b.WriteString(fmt.Sprintf("Total: %d connections\n", ctx.TotalHistory))
		b.WriteString(formatConns(ctx.HistoryConns))
	}

	// Alerts for this IP
	alerts, err := r.store.QueryAlerts(store.AlertFilter{Limit: 20})
	if err == nil {
		var related []store.AlertResult
		for _, a := range alerts {
			if a.RemoteAddr == alert.RemoteAddr && a.ID != alert.ID {
				related = append(related, a)
			}
		}
		if len(related) > 0 {
			b.WriteString("\n\n--- Other alerts for this IP ---\n")
			b.WriteString(formatAlerts(related))
		}
	}

	return b.String(), nil
}

func (r *Registry) handleBlockIP(args json.RawMessage) (string, error) {
	if r.store == nil {
		return "store not available", nil
	}
	var params struct {
		RemoteIP string `json:"remote_ip"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid args: %w", err)
	}
	if params.RemoteIP == "" {
		return "", fmt.Errorf("remote_ip is required")
	}
	source := "ai-tool"
	if params.Reason != "" {
		source = "ai-tool: " + params.Reason
	}
	if err := r.store.BlocklistIP(params.RemoteIP, source); err != nil {
		return "", fmt.Errorf("failed to block IP: %w", err)
	}
	return fmt.Sprintf("Blocked %s. The IP has been added to the blocklist. Future connections from this address will be denied.", params.RemoteIP), nil
}

func (r *Registry) handleRunDiagnostics(args json.RawMessage) (string, error) {
	var params struct {
		Target string `json:"target"`
		Port   int    `json:"port"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid args: %w", err)
	}
	if params.Target == "" {
		return "", fmt.Errorf("target is required")
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("=== Diagnostics for %s ===\n\n", params.Target))

	// DNS resolution
	b.WriteString("DNS resolution:\n")
	addrs, err := netLookupHost(params.Target)
	if err != nil {
		fmt.Fprintf(&b, "  FAILED: %v\n", err)
	} else {
		for _, a := range addrs {
			fmt.Fprintf(&b, "  → %s\n", a)
		}
	}

	// Ping
	if !isPrivate(params.Target) {
		b.WriteString("\nPing (1 packet):\n")
		out, err := runPing(params.Target)
		if err != nil {
			fmt.Fprintf(&b, "  FAILED: %v\n", err)
		} else {
			fmt.Fprintf(&b, "  %s\n", out)
		}
	} else {
		b.WriteString("\nPing: skipped (private/local address)\n")
	}

	if params.Port > 0 {
		fmt.Fprintf(&b, "\nPort %d connectivity:\n", params.Port)
		if checkPort(params.Target, params.Port) {
			fmt.Fprintf(&b, "  Port %d is OPEN\n", params.Port)
		} else {
			fmt.Fprintf(&b, "  Port %d is CLOSED or filtered\n", params.Port)
		}
	}

	return b.String(), nil
}

func (r *Registry) handleListCaptures(args json.RawMessage) (string, error) {
	if r.pcap == nil {
		return "pcap capture system not available", nil
	}
	caps, err := r.pcap.ListCaptures()
	if err != nil {
		return "", fmt.Errorf("list captures: %w", err)
	}
	if len(caps) == 0 {
		return "No capture files found.", nil
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Found %d capture files:\n\n", len(caps)))
	for i, c := range caps {
		t := time.Unix(c.CreatedAt, 0).Format("15:04:05")
		sizeStr := fmt.Sprintf("%.1f KB", float64(c.Size)/1024)
		if c.Size > 1024*1024 {
			sizeStr = fmt.Sprintf("%.1f MB", float64(c.Size)/(1024*1024))
		}
		fmt.Fprintf(&b, "%d. %s (%s, %s)\n", i+1, c.Filename, sizeStr, t)
	}
	return b.String(), nil
}

func (r *Registry) handleReadCapture(args json.RawMessage) (string, error) {
	if r.pcap == nil {
		return "pcap capture system not available", nil
	}
	var params struct {
		Filename string `json:"filename"`
		MaxLines int    `json:"max_lines"`
		Filter   string `json:"filter"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid args: %w", err)
	}
	if params.Filename == "" {
		return "", fmt.Errorf("filename is required")
	}
	if params.MaxLines <= 0 {
		params.MaxLines = 50
	}

	text, err := r.pcap.ReadCapture(params.Filename, params.MaxLines, params.Filter)
	if err != nil {
		return "", fmt.Errorf("read capture: %w", err)
	}
	if strings.TrimSpace(text) == "" {
		return "Capture file is empty (no packets).", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "=== %s ===\n\n", params.Filename)

	// Check if it has packets by looking for lines beyond the header
	lines := strings.SplitN(text, "\n", 3)
	if len(lines) <= 1 || (len(lines) == 2 && strings.TrimSpace(lines[1]) == "") {
		b.WriteString("No packets in this capture.\n")
	} else {
		b.WriteString(text)
	}
	return b.String(), nil
}

// net helpers (overridable for testing)
var netLookupHost = net.LookupHost
var runPing = runPingImpl
var checkPort = checkPortImpl
var isPrivate = isPrivateImpl

func runPingImpl(target string) (string, error) {
	cmd := exec.Command("ping", "-c", "1", "-W", "3", target)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ping failed: %w", err)
	}
	lines := strings.SplitN(string(out), "\n", 2)
	if len(lines) > 1 {
		return strings.TrimSpace(lines[len(lines)-1]), nil
	}
	return strings.TrimSpace(string(out)), nil
}

func checkPortImpl(host string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

func isPrivateImpl(host string) bool {
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	return false
}

func formatConns(conns []store.ConnResult) string {
	if len(conns) == 0 {
		return "no connections found"
	}
	var b strings.Builder
	for i, c := range conns {
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "%d. [%s] %s (%s:%d) → %s:%d proto=%s pid=%d",
			i+1, c.State, c.Comm, c.LocalAddr, c.LocalPort,
			c.RemoteAddr, c.RemotePort, c.Protocol, c.PID)
	}
	return b.String()
}

func formatAlerts(alerts []store.AlertResult) string {
	if len(alerts) == 0 {
		return "no alerts"
	}
	var b strings.Builder
	for i, a := range alerts {
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "%d. [%s] %s: %s (%s:%d)", i+1, a.Severity, a.RuleName, a.Message, a.RemoteAddr, a.RemotePort)
	}
	return b.String()
}
