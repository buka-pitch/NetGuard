package config

import (
    "encoding/json"
    "os"
    "time"
)

type Config struct {
    PollInterval time.Duration `json:"poll_interval"`
    DBPath       string        `json:"db_path"`
    BufSize      int           `json:"buffer_size"`
    AlertLimit   int           `json:"alert_limit"`
    BlocklistURL string        `json:"blocklist_url,omitempty"`
    Blocklist    []string      `json:"blocklist,omitempty"`
    ListenAddr   string        `json:"listen_addr"`

    RunAs            string `json:"run_as,omitempty"`

    SuricataEnabled  bool   `json:"suricata_enabled"`
    SuricataConfPath string `json:"suricata_conf_path,omitempty"`
    SuricataEvePath  string `json:"suricata_eve_path,omitempty"`

    ReportEnabled  bool   `json:"report_enabled"`
    ReportTime     string `json:"report_time"`
    ReportInterval int    `json:"report_interval"`
    ReportOutput   string `json:"report_output"`
    ReportWebhook  string `json:"report_webhook,omitempty"`
    ReportFormat   string `json:"report_format"`

    DNSMonitorEnabled bool `json:"dns_monitor_enabled"`

    AskOnStart bool `json:"ask_on_start"`

    BlocklistRefresh time.Duration `json:"blocklist_refresh"`
    BlocklistSource  string        `json:"blocklist_source,omitempty"`

    AuthSessionTTL  time.Duration `json:"auth_session_ttl"`
    AuthSetupFile   string        `json:"auth_setup_file,omitempty"`
    AuthAPIToken    string        `json:"auth_api_token,omitempty"`
}

func Default() *Config {
    return &Config{
        PollInterval:     3 * time.Second,
        DBPath:           "/var/lib/netmon/netmon.db",
        BufSize:          1000,
        AlertLimit:       100,
        ListenAddr:       "127.0.0.1:8484",
        SuricataEnabled:  true,
        ReportEnabled:    true,
        ReportTime:       "08:00",
        ReportInterval:   24,
        ReportOutput:     "file",
        ReportFormat:     "html",
        DNSMonitorEnabled: true,
        AskOnStart:        true,
        BlocklistRefresh:  6 * time.Hour,
        AuthSessionTTL:    7 * 24 * time.Hour,
        AuthSetupFile:     "/var/lib/netmon/setup-token",
    }
}

func Load(path string) (*Config, error) {
    cfg := Default()

    data, err := os.ReadFile(path)
    if err != nil {
        if os.IsNotExist(err) {
            return cfg, nil
        }
        return nil, err
    }

    var raw struct {
        PollInterval     string   `json:"poll_interval"`
        DBPath           string   `json:"db_path"`
        BufSize          int      `json:"buffer_size"`
        AlertLimit       int      `json:"alert_limit"`
        BlocklistURL     string   `json:"blocklist_url"`
        Blocklist        []string `json:"blocklist"`
        ListenAddr       string   `json:"listen_addr"`
        RunAs            string   `json:"run_as"`
        SuricataEnabled  *bool    `json:"suricata_enabled"`
        SuricataConfPath string   `json:"suricata_conf_path"`
        SuricataEvePath  string   `json:"suricata_eve_path"`
        ReportEnabled    *bool    `json:"report_enabled"`
        ReportTime       string   `json:"report_time"`
        ReportInterval   int      `json:"report_interval"`
        ReportOutput     string   `json:"report_output"`
        ReportWebhook    string   `json:"report_webhook"`
        ReportFormat     string   `json:"report_format"`
        DNSMonitorEnabled *bool   `json:"dns_monitor_enabled"`
        AskOnStart        *bool   `json:"ask_on_start"`
        BlocklistRefresh  string  `json:"blocklist_refresh"`
        BlocklistSource   string  `json:"blocklist_source"`
        AuthSessionTTL    string  `json:"auth_session_ttl"`
        AuthSetupFile     string  `json:"auth_setup_file"`
        AuthAPIToken      string  `json:"auth_api_token"`
    }

    if err := json.Unmarshal(data, &raw); err != nil {
        return nil, err
    }

    if raw.PollInterval != "" {
        if d, err := time.ParseDuration(raw.PollInterval); err == nil {
            cfg.PollInterval = d
        }
    }
    if raw.DBPath != "" {
        cfg.DBPath = raw.DBPath
    }
    if raw.BufSize > 0 {
        cfg.BufSize = raw.BufSize
    }
    if raw.AlertLimit > 0 {
        cfg.AlertLimit = raw.AlertLimit
    }
    if raw.BlocklistURL != "" {
        cfg.BlocklistURL = raw.BlocklistURL
    }
    if len(raw.Blocklist) > 0 {
        cfg.Blocklist = raw.Blocklist
    }
    if raw.ListenAddr != "" {
        cfg.ListenAddr = raw.ListenAddr
    }

    if raw.RunAs != "" {
        cfg.RunAs = raw.RunAs
    }

    if raw.SuricataEnabled != nil {
        cfg.SuricataEnabled = *raw.SuricataEnabled
    }
    if raw.SuricataConfPath != "" {
        cfg.SuricataConfPath = raw.SuricataConfPath
    }
    if raw.SuricataEvePath != "" {
        cfg.SuricataEvePath = raw.SuricataEvePath
    }

    if raw.ReportEnabled != nil {
        cfg.ReportEnabled = *raw.ReportEnabled
    }
    if raw.ReportTime != "" {
        cfg.ReportTime = raw.ReportTime
    }
    if raw.ReportInterval > 0 {
        cfg.ReportInterval = raw.ReportInterval
    }
    if raw.ReportOutput != "" {
        cfg.ReportOutput = raw.ReportOutput
    }
    if raw.ReportWebhook != "" {
        cfg.ReportWebhook = raw.ReportWebhook
    }
    if raw.ReportFormat != "" {
        cfg.ReportFormat = raw.ReportFormat
    }

    if raw.DNSMonitorEnabled != nil {
        cfg.DNSMonitorEnabled = *raw.DNSMonitorEnabled
    }

    if raw.AskOnStart != nil {
        cfg.AskOnStart = *raw.AskOnStart
    }

    if raw.BlocklistRefresh != "" {
        if d, err := time.ParseDuration(raw.BlocklistRefresh); err == nil && d > 0 {
            cfg.BlocklistRefresh = d
        }
    }
    if raw.BlocklistSource != "" {
        cfg.BlocklistSource = raw.BlocklistSource
    }

    if raw.AuthSessionTTL != "" {
        if d, err := time.ParseDuration(raw.AuthSessionTTL); err == nil && d > 0 {
            cfg.AuthSessionTTL = d
        }
    }
    if raw.AuthSetupFile != "" {
        cfg.AuthSetupFile = raw.AuthSetupFile
    }

    if raw.AuthAPIToken != "" {
        cfg.AuthAPIToken = raw.AuthAPIToken
    }

    return cfg, nil
}

func homeDir() string {
    home, err := os.UserHomeDir()
    if err != nil {
        return "/tmp"
    }
    return home
}
