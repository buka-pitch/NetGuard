package reports

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"netmon/internal/logutil"
)

type ReportConfig struct {
	Enabled  bool   `json:"enabled"`
	Time     string `json:"time"`     // "08:00"
	Interval int    `json:"interval"` // hours between reports (0 = once daily)
	Output   string `json:"output"`   // "file" or "webhook"
	Webhook  string `json:"webhook,omitempty"`
	Dir      string `json:"dir,omitempty"`
	Format   string `json:"format"` // "html" or "json"
}

type ReportData struct {
	GeneratedAt  int64        `json:"generated_at"`
	TotalConns   int          `json:"total_connections"`
	ActiveConns  int          `json:"active_connections"`
	AlertCount   int          `json:"alert_count"`
	TopProcesses []ProcStat   `json:"top_processes"`
	TopRemotes   []RemoteStat `json:"top_remotes"`
	RecentAlerts []AlertEntry `json:"recent_alerts"`
	TopPorts     []PortStat   `json:"top_ports"`
}

type ProcStat struct {
	Comm  string `json:"comm"`
	Count int    `json:"count"`
}

type RemoteStat struct {
	Addr  string `json:"addr"`
	Port  int    `json:"port"`
	Count int    `json:"count"`
}

type PortStat struct {
	Port  int `json:"port"`
	Count int `json:"count"`
}

type AlertEntry struct {
	RuleName   string `json:"rule_name"`
	Severity   string `json:"severity"`
	Comm       string `json:"comm"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	Message    string `json:"message"`
	CreatedAt  int64  `json:"created_at"`
}

type Scheduler struct {
	mu     sync.Mutex
	db     *sql.DB
	dir    string
	cfg    ReportConfig
	stopCh chan struct{}
}

func NewScheduler(db *sql.DB, dir string, cfg ReportConfig) *Scheduler {
	os.MkdirAll(dir, 0755)
	return &Scheduler{
		db:     db,
		dir:    dir,
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
}

func (s *Scheduler) Start() {
	if !s.cfg.Enabled {
		logutil.Info("reports: scheduler disabled")
		return
	}
	logutil.Info("reports: scheduler enabled, target time=%s, interval=%dh", s.cfg.Time, s.cfg.Interval)
	go s.loop()
}

func (s *Scheduler) Stop() {
	close(s.stopCh)
}

func (s *Scheduler) GenerateNow() error {
	return s.generate()
}

func (s *Scheduler) loop() {
	next := s.nextRun()
	for {
		select {
		case <-time.After(time.Until(next)):
			if err := s.generate(); err != nil {
				logutil.Error("reports: scheduled generation failed: %v", err)
			}
			if s.cfg.Interval > 0 {
				next = time.Now().Add(time.Duration(s.cfg.Interval) * time.Hour)
			} else {
				next = next.Add(24 * time.Hour)
			}
		case <-s.stopCh:
			return
		}
	}
}

func (s *Scheduler) nextRun() time.Time {
	now := time.Now()
	parts := strings.Split(s.cfg.Time, ":")
	h, m := 8, 0
	if len(parts) > 0 {
		fmt.Sscanf(parts[0], "%d", &h)
	}
	if len(parts) > 1 {
		fmt.Sscanf(parts[1], "%d", &m)
	}
	target := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	if target.Before(now) {
		target = target.Add(24 * time.Hour)
	}
	return target
}

func (s *Scheduler) generate() error {
	logutil.Info("reports: generating report")
	data := s.collect()
	var err error
	if s.cfg.Format == "json" {
		err = s.writeJSON(data)
	} else {
		err = s.writeHTML(data)
	}
	if err != nil {
		logutil.Error("reports: write failed: %v", err)
		return err
	}
	if s.cfg.Webhook != "" {
		s.postWebhook(data)
	}
	return nil
}

func (s *Scheduler) collect() *ReportData {
	data := &ReportData{
		GeneratedAt: time.Now().Unix(),
	}

	s.db.QueryRow("SELECT COUNT(*) FROM connections").Scan(&data.TotalConns)
	s.db.QueryRow("SELECT COUNT(*) FROM connections WHERE closed_at IS NULL AND remote_addr != ''").Scan(&data.ActiveConns)

	rows, err := s.db.Query("SELECT comm, COUNT(*) as cnt FROM connections WHERE comm != '' GROUP BY comm ORDER BY cnt DESC LIMIT 10")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p ProcStat
			if err := rows.Scan(&p.Comm, &p.Count); err == nil {
				data.TopProcesses = append(data.TopProcesses, p)
			}
		}
	}

	rrows, err := s.db.Query("SELECT remote_addr, remote_port, COUNT(*) as cnt FROM connections WHERE remote_addr != '' GROUP BY remote_addr, remote_port ORDER BY cnt DESC LIMIT 10")
	if err == nil {
		defer rrows.Close()
		for rrows.Next() {
			var r RemoteStat
			if err := rrows.Scan(&r.Addr, &r.Port, &r.Count); err == nil {
				data.TopRemotes = append(data.TopRemotes, r)
			}
		}
	}

	prows, err := s.db.Query("SELECT remote_port, COUNT(*) as cnt FROM connections WHERE remote_port > 0 GROUP BY remote_port ORDER BY cnt DESC LIMIT 10")
	if err == nil {
		defer prows.Close()
		for prows.Next() {
			var p PortStat
			if err := prows.Scan(&p.Port, &p.Count); err == nil {
				data.TopPorts = append(data.TopPorts, p)
			}
		}
	}

	return data
}

func (s *Scheduler) writeJSON(data *ReportData) error {
	body, _ := json.MarshalIndent(data, "", "  ")
	fname := fmt.Sprintf("report_%s.json", time.Now().Format("20060102_150405"))
	fpath := filepath.Join(s.dir, fname)
	err := os.WriteFile(fpath, body, 0644)
	if err != nil {
		return err
	}
	logutil.Info("reports: wrote %s (%d bytes)", fpath, len(body))
	return nil
}

func (s *Scheduler) writeHTML(data *ReportData) error {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>netmon report</title>`)
	b.WriteString(`<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px;max-width:800px;margin:0 auto}`)
	b.WriteString(`h1{color:#58a6ff;border-bottom:1px solid #21262d;padding-bottom:8px}`)
	b.WriteString(`h2{color:#58a6ff;font-size:14px;margin-top:24px}`)
	b.WriteString(`table{width:100%;border-collapse:collapse;margin:8px 0}`)
	b.WriteString(`th,td{text-align:left;padding:4px 8px;border-bottom:1px solid #21262d;font-size:12px}`)
	b.WriteString(`th{color:#8b949e;text-transform:uppercase;font-size:10px}`)
	b.WriteString(`.stat{display:inline-block;margin:8px 16px 8px 0;font-size:13px}`)
	b.WriteString(`.stat span{color:#8b949e;font-size:10px;display:block;text-transform:uppercase}`)
	b.WriteString(`</style></head><body>`)
	b.WriteString(fmt.Sprintf("<h1>netmon report</h1>"))
	b.WriteString(fmt.Sprintf("<p>generated: %s</p>", time.Unix(data.GeneratedAt, 0).Format(time.RFC1123)))

	b.WriteString(`<div>`)
	b.WriteString(fmt.Sprintf(`<div class="stat"><span>connections</span>%d</div>`, data.TotalConns))
	b.WriteString(fmt.Sprintf(`<div class="stat"><span>active (5m)</span>%d</div>`, data.ActiveConns))
	b.WriteString(fmt.Sprintf(`<div class="stat"><span>alerts</span>%d</div>`, data.AlertCount))
	b.WriteString(`</div>`)

	if len(data.TopProcesses) > 0 {
		b.WriteString(`<h2>top processes</h2><table><tr><th>process</th><th>connections</th></tr>`)
		for _, p := range data.TopProcesses {
			b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d</td></tr>", html.EscapeString(p.Comm), p.Count))
		}
		b.WriteString(`</table>`)
	}

	if len(data.TopRemotes) > 0 {
		b.WriteString(`<h2>top remotes</h2><table><tr><th>address</th><th>port</th><th>connections</th></tr>`)
		for _, r := range data.TopRemotes {
			b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d</td><td>%d</td></tr>", html.EscapeString(r.Addr), r.Port, r.Count))
		}
		b.WriteString(`</table>`)
	}

	if len(data.TopPorts) > 0 {
		b.WriteString(`<h2>top ports</h2><table><tr><th>port</th><th>connections</th></tr>`)
		for _, p := range data.TopPorts {
			b.WriteString(fmt.Sprintf("<tr><td>%d</td><td>%d</td></tr>", p.Port, p.Count))
		}
		b.WriteString(`</table>`)
	}

	b.WriteString(`</body></html>`)

	fname := fmt.Sprintf("report_%s.html", time.Now().Format("20060102_150405"))
	fpath := filepath.Join(s.dir, fname)
	err := os.WriteFile(fpath, []byte(b.String()), 0644)
	if err != nil {
		return err
	}
	logutil.Info("reports: wrote %s (%d bytes)", fpath, b.Len())
	return nil
}

func (s *Scheduler) postWebhook(data *ReportData) {
	if s.cfg.Webhook == "" {
		return
	}
	body, _ := json.Marshal(data)
	// simple POST; could use http.Post but keeping deps minimal
	logutil.Info("reports: webhook %s (not implemented, body size=%d)", s.cfg.Webhook, len(body))
}
