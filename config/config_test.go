package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.PollInterval != 3*time.Second {
		t.Errorf("expected 3s poll interval, got %v", cfg.PollInterval)
	}
	if cfg.ListenAddr != "127.0.0.1:8484" {
		t.Errorf("expected 127.0.0.1:8484, got %s", cfg.ListenAddr)
	}
	if !cfg.SuricataEnabled {
		t.Error("expected suricata enabled by default")
	}
	if !cfg.AskOnStart {
		t.Error("expected AskOnStart enabled by default")
	}
}

func TestLoadNonExistent(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.json")
	if err != nil {
		t.Fatalf("Load should not error on missing file: %v", err)
	}
	if cfg == nil {
		t.Fatal("cfg should not be nil")
	}
}

func TestLoadFullConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
		"poll_interval": "2s",
		"db_path": "/tmp/test.db",
		"buffer_size": 200,
		"alert_limit": 50,
		"blocklist_url": "https://example.com/blocklist",
		"blocklist": ["1.2.3.4", "5.6.7.8"],
		"listen_addr": "0.0.0.0:9090",
		"run_as": "netmon",
		"suricata_enabled": false,
		"suricata_conf_path": "/etc/suricata/suricata.yaml",
		"suricata_eve_path": "/var/log/suricata/eve.json"
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.PollInterval != 2*time.Second {
		t.Errorf("expected 2s, got %v", cfg.PollInterval)
	}
	if cfg.DBPath != "/tmp/test.db" {
		t.Errorf("expected /tmp/test.db, got %s", cfg.DBPath)
	}
	if cfg.BufSize != 200 {
		t.Errorf("expected 200, got %d", cfg.BufSize)
	}
	if cfg.AlertLimit != 50 {
		t.Errorf("expected 50, got %d", cfg.AlertLimit)
	}
	if cfg.BlocklistURL != "https://example.com/blocklist" {
		t.Errorf("got %s", cfg.BlocklistURL)
	}
	if len(cfg.Blocklist) != 2 || cfg.Blocklist[0] != "1.2.3.4" {
		t.Errorf("blocklist: %v", cfg.Blocklist)
	}
	if cfg.ListenAddr != "0.0.0.0:9090" {
		t.Errorf("got %s", cfg.ListenAddr)
	}
	if cfg.RunAs != "netmon" {
		t.Errorf("got %s", cfg.RunAs)
	}
	if cfg.SuricataEnabled {
		t.Error("expected suricata disabled")
	}
	if cfg.SuricataConfPath != "/etc/suricata/suricata.yaml" {
		t.Errorf("got %s", cfg.SuricataConfPath)
	}
	if cfg.SuricataEvePath != "/var/log/suricata/eve.json" {
		t.Errorf("got %s", cfg.SuricataEvePath)
	}
}

func TestLoadPartialConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"listen_addr": "0.0.0.0:8484"}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.ListenAddr != "0.0.0.0:8484" {
		t.Errorf("got %s", cfg.ListenAddr)
	}
	if cfg.SuricataEnabled != true {
		t.Error("expected suricata enabled (default)")
	}
	if !cfg.AskOnStart {
		t.Error("AskOnStart should default to true")
	}
}

func TestLoadAskOnStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"ask_on_start": true}`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !cfg.AskOnStart {
		t.Error("AskOnStart should be true when set in config")
	}
}

func TestLoadAskOnStartFalseExplicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"ask_on_start": false}`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.AskOnStart {
		t.Error("AskOnStart should be false when explicitly set false")
	}
}

func TestBlocklistRefreshDefault(t *testing.T) {
	cfg := Default()
	if cfg.BlocklistRefresh != 6*time.Hour {
		t.Errorf("expected 6h default, got %v", cfg.BlocklistRefresh)
	}
}

func TestLoadBlocklistRefresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"blocklist_refresh": "30m", "blocklist_source": "url:myfeed"}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BlocklistRefresh != 30*time.Minute {
		t.Errorf("got %v", cfg.BlocklistRefresh)
	}
	if cfg.BlocklistSource != "url:myfeed" {
		t.Errorf("got %q", cfg.BlocklistSource)
	}
}

func TestLoadBlocklistRefreshInvalidIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"blocklist_refresh": "garbage"}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BlocklistRefresh != 6*time.Hour {
		t.Errorf("invalid value should keep default, got %v", cfg.BlocklistRefresh)
	}
}

func TestAuthDefaults(t *testing.T) {
	cfg := Default()
	if cfg.AuthSessionTTL != 7*24*time.Hour {
		t.Errorf("expected 7d default, got %v", cfg.AuthSessionTTL)
	}
	if cfg.AuthSetupFile != "/var/lib/netmon/setup-token" {
		t.Errorf("got %q", cfg.AuthSetupFile)
	}
}

func TestLoadAuthOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"auth_session_ttl": "24h", "auth_setup_file": "/tmp/setup"}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthSessionTTL != 24*time.Hour {
		t.Errorf("got %v", cfg.AuthSessionTTL)
	}
	if cfg.AuthSetupFile != "/tmp/setup" {
		t.Errorf("got %q", cfg.AuthSetupFile)
	}
}

func TestLoadAPIToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"auth_api_token": "abc123def456"}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthAPIToken != "abc123def456" {
		t.Errorf("got %q, want %q", cfg.AuthAPIToken, "abc123def456")
	}
	if d := Default(); d.AuthAPIToken != "" {
		t.Errorf("default API token should be empty, got %q", d.AuthAPIToken)
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte("{invalid"), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestHomeDirFallback(t *testing.T) {
	// homeDir should handle errors gracefully
	orig := os.Getenv("HOME")
	defer os.Setenv("HOME", orig)
	os.Setenv("HOME", "")

	// We can't easily test os.UserHomeDir failure, but verify the function exists
	if h := homeDir(); h != "" {
		t.Logf("homeDir() = %s", h)
	}
}
