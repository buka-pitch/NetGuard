package ai

import (
	"encoding/json"
	"testing"

	"netmon/internal/store"
)

func TestToolDefinitions_ValidJSON(t *testing.T) {
	reg := NewRegistry(nil)
	defs := reg.Definitions()
	for _, d := range defs {
		var tmp interface{}
		if err := json.Unmarshal(d.Parameters, &tmp); err != nil {
			t.Errorf("tool %s has invalid parameters JSON: %v", d.Name, err)
		}
	}
}

func TestToolDefinitions_HaveExpectedTools(t *testing.T) {
	reg := NewRegistry(nil)
	defs := reg.Definitions()
	names := make(map[string]bool)
	for _, d := range defs {
		names[d.Name] = true
	}
	for _, want := range []string{"query_connections", "get_stats", "analyze_ip", "get_analysis_context", "block_ip", "run_diagnostics", "list_alerts", "inspect_alert"} {
		if !names[want] {
			t.Errorf("missing tool: %s", want)
		}
	}
}

func TestToolDispatch_QueryConnections(t *testing.T) {
	mock := &mockStore{}
	reg := NewRegistry(mock)
	result, err := reg.Dispatch("query_connections", json.RawMessage(`{"remote_ip":"1.1.1.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(result) == 0 {
		t.Error("expected non-empty result")
	}
}

func TestToolDispatch_GetStats(t *testing.T) {
	mock := &mockStore{}
	reg := NewRegistry(mock)
	result, err := reg.Dispatch("get_stats", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestToolDispatch_UnknownTool(t *testing.T) {
	reg := NewRegistry(nil)
	_, err := reg.Dispatch("nonexistent_tool", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
}

func TestFormatConns_Empty(t *testing.T) {
	result := formatConns(nil)
	if result != "no connections found" {
		t.Errorf("expected 'no connections found', got %q", result)
	}
}

func TestFormatConns_WithData(t *testing.T) {
	conns := []store.ConnResult{
		{Comm: "curl", RemoteAddr: "1.1.1.1", RemotePort: 80, Protocol: "tcp", State: "ESTABLISHED", PID: 1001},
		{Comm: "firefox", RemoteAddr: "93.184.216.34", RemotePort: 443, Protocol: "tcp", State: "ESTABLISHED", PID: 2002, LocalPort: 40000},
	}
	result := formatConns(conns)
	if result == "" {
		t.Fatal("expected non-empty result")
	}
}

func TestFormatAlerts_Empty(t *testing.T) {
	result := formatAlerts(nil)
	if result != "no alerts" {
		t.Errorf("expected 'no alerts', got %q", result)
	}
}

type mockStore struct{}

func (m *mockStore) QueryConns(f store.ConnFilter) ([]store.ConnResult, error) {
	return []store.ConnResult{
		{Comm: "curl", RemoteAddr: "1.1.1.1", RemotePort: 80, Protocol: "tcp", State: "ESTABLISHED", PID: 1001, LocalAddr: "10.0.0.1", LocalPort: 40000, CreatedAt: 1000000},
		{Comm: "firefox", RemoteAddr: "93.184.216.34", RemotePort: 443, Protocol: "tcp", State: "ESTABLISHED", PID: 2002, LocalAddr: "10.0.0.1", LocalPort: 40001, CreatedAt: 1000001},
	}, nil
}

func (m *mockStore) QueryAlerts(f store.AlertFilter) ([]store.AlertResult, error) {
	return []store.AlertResult{
		{RuleName: "test_rule", Severity: "critical", Message: "test alert", RemoteAddr: "1.1.1.1", RemotePort: 80, CreatedAt: 1000000},
	}, nil
}

func (m *mockStore) GetAnalysisContext(remoteIP string, remotePort int) (*store.AnalysisContext, error) {
	return &store.AnalysisContext{
		CurrentConns: []store.ConnResult{
			{Comm: "curl", RemoteAddr: "1.1.1.1", RemotePort: 80, Protocol: "tcp", State: "ESTABLISHED", PID: 1001},
		},
		Alerts: []store.AlertResult{
			{RuleName: "test_rule", Severity: "critical", Message: "test alert"},
		},
		TotalHistory: 5,
	}, nil
}

func (m *mockStore) GetConnHistory(remoteIP string, limit int) ([]store.ConnResult, error) {
	return nil, nil
}

func (m *mockStore) Stats() store.Stats {
	return store.Stats{TotalConns: 50, ActiveConns: 12, AlertCount: 3}
}

func (m *mockStore) BlocklistIP(ip string, source string) error {
	return nil
}

func (m *mockStore) GetAlert(id int64) (*store.AlertResult, error) {
	return &store.AlertResult{
		ID: id, RuleName: "test_rule", Severity: "critical",
		Message: "test alert", RemoteAddr: "1.1.1.1", RemotePort: 80,
		PID: 1001, Comm: "curl", CreatedAt: 1000000,
	}, nil
}
