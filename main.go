package main

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"netmon/config"
	"netmon/internal/ai"
	"netmon/internal/auth"
	"netmon/internal/blocklist"
	"netmon/internal/capture"
	"netmon/internal/detect"
	"netmon/internal/dnsmon"
	"netmon/internal/firewall"
	"netmon/internal/logutil"
	"netmon/internal/metrics"
	"netmon/internal/pcap"
	"netmon/internal/privdrop"
	"netmon/internal/reports"
	"netmon/internal/store"
	"netmon/internal/suricata"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

//go:embed static/*
var staticFS embed.FS

var startTime = time.Now()

func main() {
	cfgPath := flag.String("config", "/etc/netmon/config.json", "config file path")
	flag.Parse()

	shutdownCtx, cancelShutdown := context.WithCancel(context.Background())
	defer cancelShutdown()

	if os.Geteuid() != 0 {
		bin, _ := os.Executable()
		logutil.Error("run with: sudo %s", bin)
		os.Exit(1)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		logutil.Error("config: %v", err)
		os.Exit(1)
	}

	st, err := store.New(cfg.DBPath, cfg.BufSize)
	if err != nil {
		logutil.Error("store: %v", err)
		os.Exit(1)
	}
	// Note: st.Close() is invoked explicitly during graceful shutdown so
	// we can flush before other subsystems tear down.

	fw := firewall.New(st.DB())
	fw.InitDB()
	if err := fw.Init(); err != nil {
		logutil.Warn("firewall: init failed (non-fatal, no firewall): %v", err)
	} else {
		logutil.Info("firewall: init ok, restoring allowlist...")
		if err := fw.Restore(); err != nil {
			logutil.Error("firewall: restore error: %v", err)
		}
		logutil.Info("firewall: preseed...")
		fw.PreSeed()
		fw.StartExpiryLoop()
		logutil.Info("firewall: initialized (default-deny)")
	}

	eng := detect.NewEngine()
	eng.AddBlocklist(cfg.Blocklist)

	eventChan := make(chan capture.ConnectionEvent, 10000)
	alertChan := make(chan detect.Alert, 1000)

	var dnsMon *dnsmon.Monitor
	if cfg.DNSMonitorEnabled {
		dnsMon = dnsmon.NewMonitor()
		if err := dnsMon.Start(); err != nil {
			logutil.Warn("dnsmon: failed to start: %v", err)
			dnsMon = nil
		} else {
			logutil.Info("dnsmon: active DNS monitoring enabled")
		}
		if dnsMon != nil && fw != nil {
			dnsMon.SetOnNewDNSServer(func(ip string) {
				if err := fw.AddDNSServer(ip); err != nil {
					logutil.Warn("dnsmon: add nftables dns_server %s: %v", ip, err)
				} else {
					logutil.Info("dnsmon: tracked DNS server %s in nftables", ip)
				}
			})
		}
	}

	poller := capture.NewPoller(cfg.PollInterval, dnsMon, cfg.AskOnStart)
	go poller.Start(shutdownCtx, eventChan)

	go processEvents(shutdownCtx, eventChan, alertChan, st, eng, fw)
	go processAlerts(shutdownCtx, alertChan, st)
	go periodicTrends(shutdownCtx, eng)
	go syncBlocklist(shutdownCtx, eng, fw)

	var suriReader *suricata.Reader
	if cfg.SuricataEnabled {
		suriReader = suricata.NewReader(cfg.AlertLimit, poller.Snapshot, st.DB())
		suriReader.Start()
		logutil.Info("suricata reader started")
	}
	// suriReader.Stop() is invoked during graceful shutdown below.

	ruleStore := detect.NewRuleStore(st.DB())
	eng.AddRule(detect.NewCustomRuleMatcher(ruleStore))

	reportDir := filepath.Dir(cfg.DBPath) + "/reports"
	reportCfg := reports.ReportConfig{
		Enabled:  cfg.ReportEnabled,
		Time:     cfg.ReportTime,
		Interval: cfg.ReportInterval,
		Output:   cfg.ReportOutput,
		Webhook:  cfg.ReportWebhook,
		Dir:      reportDir,
		Format:   cfg.ReportFormat,
	}
	reportSched := reports.NewScheduler(st.DB(), reportDir, reportCfg)
	reportSched.Start()

	// auth: users + sessions + first-user setup token
	authManager := auth.New(st.DB(), cfg.AuthSessionTTL, cfg.AuthSetupFile, false)
	// enable Secure cookie flag if the daemon is bound somewhere other than
	// loopback (the cookie must not be sent over plaintext HTTP in that case,
	// but netmon doesn't do TLS itself — we warn and require the operator to
	// front it with TLS).
	if !isLoopbackListen(cfg.ListenAddr) {
		authManager.SetSecureCookie(true)
		logutil.Warn("auth: listen_addr %s is non-loopback — Secure cookies enabled. Front netmon with TLS or the session cookie will not be sent.", cfg.ListenAddr)
	}
	if setupCreated, err := authManager.Bootstrap(); err != nil {
		logutil.Error("auth: bootstrap failed: %v", err)
	} else if setupCreated {
		logutil.Warn("auth: first-user setup required — see %s", cfg.AuthSetupFile)
	}
	go func() {
		t := time.NewTicker(1 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-shutdownCtx.Done():
				return
			case <-t.C:
				authManager.PurgeExpiredSessions()
			}
		}
	}()

	// remote blocklist fetcher (additive-only — never auto-removes)
	if cfg.BlocklistURL != "" {
		fetcher, err := blocklist.New(cfg.BlocklistURL, cfg.BlocklistSource, cfg.BlocklistRefresh, st)
		if err != nil {
			logutil.Warn("blocklist: init failed: %v", err)
		} else {
			logutil.Info("blocklist: scheduled (url=%s, every=%s, source=%s)", fetcher.URL, fetcher.Every, fetcher.Source)
			go fetcher.Run(shutdownCtx)
		}
	}

	if cfg.RunAs != "" {
		uid, gid, err := privdrop.LookupUser(cfg.RunAs)
		if err == nil {
			if privdrop.MaybeDropUser(uid, gid) {
				logutil.Info("privileges dropped to %s (%d:%d)", cfg.RunAs, uid, gid)
			} else {
				logutil.Warn("failed to drop privileges to %s", cfg.RunAs)
			}
		} else {
			logutil.Warn("user %s not found, running as root", cfg.RunAs)
		}
	}

	mux := http.NewServeMux()

	sub, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(sub))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		fileServer.ServeHTTP(w, r)
	}))

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		uptime := time.Since(startTime).Round(time.Second).String()
		fws := fw.Status()
		m := metrics.Collect()
		resp := map[string]interface{}{
			"status":       "ok",
			"version":      "1.0.0",
			"uptime":       uptime,
			"started_at":   startTime.UTC().Format(time.RFC3339),
			"goroutines":   runtime.NumGoroutine(),
			"memory_mb":    memStats.Alloc / 1024 / 1024,
			"connections":  len(poller.Snapshot()),
			"alerts_total": eng.AlertCount(),
			"firewall": map[string]interface{}{
				"enabled": fws.Enabled,
				"policy":  fws.Policy,
				"panic":   fws.PanicMode,
				"rules":   fws.Rules,
				"pending": fws.Pending,
			},
			"suricata": map[string]interface{}{
				"enabled": suriReader != nil,
			},
			"metrics": m,
		}
		if suriReader != nil {
			ss := suriReader.GetStats()
			resp["suricata"].(map[string]interface{})["alerts_total"] = ss.AlertsTotal
			resp["suricata"].(map[string]interface{})["uptime"] = ss.Uptime
			resp["suricata"].(map[string]interface{})["packets_dropped"] = ss.PacketsDrop
		}
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metrics.Collect())
	})

	mux.HandleFunc("/api/connections", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(poller.Snapshot())
	})

	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(eng.RecentAlerts(cfg.AlertLimit))
	})

	mux.HandleFunc("/api/connections/export", func(w http.ResponseWriter, r *http.Request) {
		conns := poller.Snapshot()
		exportFmt := r.URL.Query().Get("format")
		if exportFmt == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=connections.csv")
			w.Write([]byte("pid,comm,cmdline,exe,ppid,pcomm,local_addr,local_port,remote_addr,remote_port,protocol,state,inode,tx_queue,rx_queue,created_at,domain,tls_sni,http_host,pre_existing,is_vpn,incoming\n"))
			for _, c := range conns {
				fmt.Fprintf(w, "%d,%s,%s,%s,%d,%s,%s,%d,%s,%d,%s,%s,%d,%d,%d,%d,%s,%s,%s,%t,%t,%t\n",
					c.PID, csvEsc(c.Comm), csvEsc(c.Cmdline), csvEsc(c.Exe), c.PPID, csvEsc(c.PComm),
					ipStr(c.LocalAddr), c.LocalPort, ipStr(c.RemoteAddr), c.RemotePort,
					c.Protocol, c.State, c.Inode, c.TxQueue, c.RxQueue, c.CreatedAt,
					csvEsc(c.Domain), csvEsc(c.TLSHost), csvEsc(c.HTTPHost),
					c.PreExisting, c.IsVPN, c.Incoming)
			}
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", "attachment; filename=connections.json")
			json.NewEncoder(w).Encode(conns)
		}
	})

	mux.HandleFunc("/api/alerts/export", func(w http.ResponseWriter, r *http.Request) {
		alerts := eng.RecentAlerts(cfg.AlertLimit)
		exportFmt := r.URL.Query().Get("format")
		if exportFmt == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=alerts.csv")
			w.Write([]byte("rule_name,severity,message,remote_addr,remote_port,comm,created_at\n"))
			for _, a := range alerts {
				fmt.Fprintf(w, "%s,%s,%s,%s,%d,%s,%d\n",
					csvEsc(a.RuleName), csvEsc(string(a.Severity)), csvEsc(a.Message),
					csvEsc(a.RemoteAddr), a.RemotePort, csvEsc(a.Comm), a.CreatedAt)
			}
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", "attachment; filename=alerts.json")
			json.NewEncoder(w).Encode(alerts)
		}
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s := st.Stats()
		s.AlertCount = eng.AlertCount()
		json.NewEncoder(w).Encode(s)
	})

	mux.HandleFunc("/api/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		minutes := 30
		if m := r.URL.Query().Get("minutes"); m != "" {
			if v, err := strconv.Atoi(m); err == nil && v > 0 && v <= 1440 {
				minutes = v
			}
		}
		filterProc := r.URL.Query().Get("process")
		filterRemote := r.URL.Query().Get("remote")
		cutoff := time.Now().Add(-time.Duration(minutes) * time.Minute).UnixMilli()
		db := st.DB()

		type bucket struct {
			Bucket int64 `json:"bucket"`
			Count  int   `json:"count"`
		}
		type sevCount struct {
			Severity int `json:"severity"`
			Count    int `json:"count"`
		}
		type topItem struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		}
		type bwItem struct {
			Name    string `json:"name"`
			Count   int    `json:"count"`
			TxQueue int64  `json:"tx_queue"`
			RxQueue int64  `json:"rx_queue"`
		}
		type flowItem struct {
			Source string `json:"source"`
			Target string `json:"target"`
			Value  int    `json:"value"`
		}
		type protoCount struct {
			Protocol string `json:"protocol"`
			Count    int    `json:"count"`
		}

		resp := struct {
			Summary struct {
				TotalConns  int   `json:"total_conns"`
				ActiveConns int   `json:"active_conns"`
				AlertCount  int   `json:"alert_count"`
				FwEnabled   bool  `json:"fw_enabled"`
				FwPanic     bool  `json:"fw_panic"`
				TotalTx     int64 `json:"total_tx_queue"`
				TotalRx     int64 `json:"total_rx_queue"`
			} `json:"summary"`
			ConnTimeline     []bucket     `json:"conn_timeline"`
			AlertTimeline    []bucket     `json:"alert_timeline"`
			SeverityDist     []sevCount   `json:"severity_dist"`
			TopProcesses     []topItem    `json:"top_processes"`
			TopRemotes       []topItem    `json:"top_remotes"`
			TopPorts         []topItem    `json:"top_ports"`
			ProtocolDist     []protoCount `json:"protocol_dist"`
			BandwidthTop     []bwItem     `json:"bandwidth_top"`
			Flows            []flowItem   `json:"flows"`
			AnomalyThreshold float64      `json:"anomaly_threshold"`
			AnomalyMean      float64      `json:"anomaly_mean"`
		}{
			ConnTimeline:  []bucket{},
			AlertTimeline: []bucket{},
			SeverityDist:  []sevCount{},
			TopProcesses:  []topItem{},
			TopRemotes:    []topItem{},
			TopPorts:      []topItem{},
			ProtocolDist:  []protoCount{},
			BandwidthTop:  []bwItem{},
			Flows:         []flowItem{},
		}

		s := st.Stats()
		fwStatus := fw.Status()
		resp.Summary.TotalConns = s.TotalConns
		resp.Summary.ActiveConns = s.ActiveConns
		resp.Summary.AlertCount = eng.AlertCount()
		resp.Summary.FwEnabled = fwStatus.Enabled
		resp.Summary.FwPanic = fwStatus.PanicMode

		db.QueryRow("SELECT COALESCE(SUM(tx_queue),0), COALESCE(SUM(rx_queue),0) FROM connections").Scan(&resp.Summary.TotalTx, &resp.Summary.TotalRx)

		filterWhere := ""
		args := []interface{}{}
		if filterProc != "" {
			filterWhere += " AND comm LIKE ?"
			args = append(args, "%"+filterProc+"%")
		}
		if filterRemote != "" {
			filterWhere += " AND (remote_addr || ':' || CAST(remote_port AS TEXT)) LIKE ?"
			args = append(args, "%"+filterRemote+"%")
		}

		connArgs := append([]interface{}{cutoff}, args...)
		rows, err := db.Query("SELECT (created_at / 60000) * 60000, COUNT(*) FROM connections WHERE created_at > ?"+filterWhere+" GROUP BY 1 ORDER BY 1", connArgs...)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var b bucket
				rows.Scan(&b.Bucket, &b.Count)
				resp.ConnTimeline = append(resp.ConnTimeline, b)
			}
		}

		alertArgs := append([]interface{}{cutoff}, args...)
		rows2, err := db.Query(`
            SELECT (created_at / 60000) * 60000, COUNT(*) FROM (
                SELECT created_at FROM suricata_alerts WHERE created_at > ?`+filterWhere+`
                UNION ALL
                SELECT created_at FROM alerts WHERE created_at > ?`+filterWhere+`
            ) GROUP BY 1 ORDER BY 1
        `, append(alertArgs, alertArgs...)...)
		if err == nil {
			defer rows2.Close()
			for rows2.Next() {
				var b bucket
				rows2.Scan(&b.Bucket, &b.Count)
				resp.AlertTimeline = append(resp.AlertTimeline, b)
			}
		}

		rows3, err := db.Query(`
            SELECT severity, COUNT(*) FROM (
                SELECT severity FROM suricata_alerts
                UNION ALL
                SELECT severity FROM alerts
            ) GROUP BY severity ORDER BY severity
        `)
		if err == nil {
			defer rows3.Close()
			for rows3.Next() {
				var s sevCount
				rows3.Scan(&s.Severity, &s.Count)
				resp.SeverityDist = append(resp.SeverityDist, s)
			}
		}

		procArgs := args
		rows4, err := db.Query("SELECT comm, COUNT(*) as c FROM connections WHERE pid > 0 AND comm != ''"+filterWhere+" GROUP BY comm ORDER BY c DESC LIMIT 10", procArgs...)
		if err == nil {
			defer rows4.Close()
			for rows4.Next() {
				var t topItem
				rows4.Scan(&t.Name, &t.Count)
				resp.TopProcesses = append(resp.TopProcesses, t)
			}
		}

		remoteArgs := args
		rows5, err := db.Query("SELECT remote_addr || ':' || CAST(remote_port AS TEXT), COUNT(*) as c FROM connections WHERE remote_addr NOT IN ('0.0.0.0','::','')"+filterWhere+" GROUP BY remote_addr, remote_port ORDER BY c DESC LIMIT 10", remoteArgs...)
		if err == nil {
			defer rows5.Close()
			for rows5.Next() {
				var t topItem
				rows5.Scan(&t.Name, &t.Count)
				resp.TopRemotes = append(resp.TopRemotes, t)
			}
		}

		portArgs := args
		rows6, err := db.Query("SELECT CAST(remote_port AS TEXT), COUNT(*) as c FROM connections WHERE remote_port > 0"+filterWhere+" GROUP BY remote_port ORDER BY c DESC LIMIT 10", portArgs...)
		if err == nil {
			defer rows6.Close()
			for rows6.Next() {
				var t topItem
				rows6.Scan(&t.Name, &t.Count)
				resp.TopPorts = append(resp.TopPorts, t)
			}
		}

		rows7, err := db.Query("SELECT protocol, COUNT(*) FROM connections WHERE protocol != ''" + filterWhere + " GROUP BY protocol")
		if err == nil {
			defer rows7.Close()
			for rows7.Next() {
				var p protoCount
				rows7.Scan(&p.Protocol, &p.Count)
				resp.ProtocolDist = append(resp.ProtocolDist, p)
			}
		}

		bwArgs := args
		rows8, err := db.Query("SELECT comm, COUNT(*) as c, COALESCE(SUM(tx_queue),0), COALESCE(SUM(rx_queue),0) FROM connections WHERE pid > 0 AND comm != ''"+filterWhere+" GROUP BY comm ORDER BY c DESC LIMIT 10", bwArgs...)
		if err == nil {
			defer rows8.Close()
			for rows8.Next() {
				var b bwItem
				rows8.Scan(&b.Name, &b.Count, &b.TxQueue, &b.RxQueue)
				resp.BandwidthTop = append(resp.BandwidthTop, b)
			}
		}

		flowArgs := args
		rows9, err := db.Query("SELECT comm, remote_addr || ':' || CAST(remote_port AS TEXT) as target, COUNT(*) as c FROM connections WHERE pid > 0 AND comm != '' AND remote_addr NOT IN ('0.0.0.0','::','')"+filterWhere+" GROUP BY comm, remote_addr, remote_port ORDER BY c DESC LIMIT 30", flowArgs...)
		if err == nil {
			defer rows9.Close()
			for rows9.Next() {
				var f flowItem
				rows9.Scan(&f.Source, &f.Target, &f.Value)
				resp.Flows = append(resp.Flows, f)
			}
		}

		// anomaly detection: mean + 2*stddev on conn timeline
		if len(resp.ConnTimeline) > 1 {
			var sum, sumSq float64
			for _, b := range resp.ConnTimeline {
				sum += float64(b.Count)
				sumSq += float64(b.Count) * float64(b.Count)
			}
			n := float64(len(resp.ConnTimeline))
			resp.AnomalyMean = sum / n
			variance := (sumSq / n) - (resp.AnomalyMean * resp.AnomalyMean)
			if variance < 0 {
				variance = 0
			}
			resp.AnomalyThreshold = resp.AnomalyMean + 2*math.Sqrt(variance)
		}

		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/dashboard/heatmap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		days := 7
		if d := r.URL.Query().Get("days"); d != "" {
			if v, err := strconv.Atoi(d); err == nil && v > 0 && v <= 90 {
				days = v
			}
		}
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).UnixMilli()
		db := st.DB()

		type cell struct {
			DOW   int `json:"dow"`
			Hour  int `json:"hour"`
			Count int `json:"count"`
		}
		cells := []cell{}

		rows, err := db.Query(`SELECT CAST(strftime('%w', created_at / 1000, 'unixepoch') AS INTEGER) AS dow,
            CAST(strftime('%H', created_at / 1000, 'unixepoch') AS INTEGER) AS hour,
            COUNT(*) as cnt
            FROM connections WHERE created_at > ?
            GROUP BY dow, hour ORDER BY dow, hour`, cutoff)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var c cell
				rows.Scan(&c.DOW, &c.Hour, &c.Count)
				cells = append(cells, c)
			}
		}

		json.NewEncoder(w).Encode(cells)
	})

	mux.HandleFunc("/api/suricata/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s, _ := suricata.CheckStatus()
		json.NewEncoder(w).Encode(s)
	})

	mux.HandleFunc("/api/suricata/install", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		flusher, _ := w.(http.Flusher)
		fw := &flushWriter{w: w, f: flusher}
		err := suricata.InstallStream(fw)
		if err != nil {
			msg := strings.TrimSpace(err.Error())
			if strings.Contains(msg, "could not lock database") || strings.Contains(msg, "db.lck") {
				msg = "stale package manager lock detected — run: sudo rm -f /var/lib/pacman/db.lck"
			}
			fmt.Fprintf(fw, "\n--- failed: %s ---\n", msg)
			return
		}
		fmt.Fprintf(fw, "\n--- done ---\n")
	})

	mux.HandleFunc("/api/suricata/install/dry-run", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		plan, err := suricata.Inspect()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(plan)
	})

	mux.HandleFunc("/api/suricata/install/apply", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		flusher, _ := w.(http.Flusher)
		fw := &flushWriter{w: w, f: flusher}
		plan, err := suricata.Inspect()
		if err != nil {
			fmt.Fprintf(fw, "failed: %s\n", err)
			return
		}
		id, err := suricata.Apply(plan)
		if err != nil {
			fmt.Fprintf(fw, "apply failed: %s\n", err)
			fmt.Fprintf(fw, "rollback attempted — check files manually\n")
			return
		}
		fmt.Fprintf(fw, "done\n")
		fmt.Fprintf(fw, "rollback id: %s\n", id)
		fmt.Fprintf(fw, "to undo: POST /api/suricata/install/rollback (id=%s)\n", id)
	})

	mux.HandleFunc("/api/suricata/install/rollback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body) // empty body = rollback newest
		if err := suricata.Rollback(body.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "rolled_back", "id": body.ID})
	})

	mux.HandleFunc("/api/suricata/install/checkpoints", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		ids, err := suricata.ListCheckpoints()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if ids == nil {
			ids = []string{}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"checkpoints": ids})
	})
	mux.HandleFunc("/api/suricata/start", suricataAction(suricata.Start, "started"))
	mux.HandleFunc("/api/suricata/stop", suricataAction(suricata.Stop, "stopped"))
	mux.HandleFunc("/api/suricata/restart", suricataAction(suricata.Restart, "restarted"))

	mux.HandleFunc("/api/suricata/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if suriReader == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"alerts": []suricata.Alert{}, "total": 0})
			return
		}
		limit := cfg.AlertLimit
		if l := r.URL.Query().Get("limit"); l != "" {
			if v, err := parseInt(l); err == nil && v > 0 && v <= 500 {
				limit = v
			}
		}
		offset := 0
		if o := r.URL.Query().Get("offset"); o != "" {
			if v, err := parseInt(o); err == nil && v >= 0 {
				offset = v
			}
		}
		f := &suricata.AlertFilter{
			Q:        r.URL.Query().Get("q"),
			Severity: r.URL.Query().Get("severity"),
			IP:       r.URL.Query().Get("ip"),
			Comm:     r.URL.Query().Get("comm"),
			Proto:    r.URL.Query().Get("proto"),
			Action:   r.URL.Query().Get("action"),
			Sig:      r.URL.Query().Get("sig"),
		}
		if f.Q == "" && f.Severity == "" && f.IP == "" && f.Comm == "" && f.Proto == "" && f.Action == "" && f.Sig == "" {
			alerts, total := suriReader.QueryAlerts(limit, offset, nil)
			json.NewEncoder(w).Encode(map[string]interface{}{"alerts": alerts, "total": total})
			return
		}
		alerts, total := suriReader.QueryAlerts(limit, offset, f)
		json.NewEncoder(w).Encode(map[string]interface{}{"alerts": alerts, "total": total})
	})

	mux.HandleFunc("/api/suricata/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			cfg, err := suricata.ReadConfig()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(cfg)
		case http.MethodPost:
			var form suricata.ConfigForm
			if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := suricata.WriteConfig(&form); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			suricata.Restart()
			json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
		}
	})

	mux.HandleFunc("/api/suricata/rules", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		rules, err := suricata.ListRules()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(rules)
	})

	mux.HandleFunc("/api/suricata/rules/toggle", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			Name   string `json:"name"`
			Enable bool   `json:"enable"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := suricata.ToggleRule(req.Name, req.Enable); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "toggled"})
	})

	mux.HandleFunc("/api/suricata/rules/upload", func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(10 << 20)
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()
		content, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := suricata.UploadRule(header.Filename, content); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "uploaded"})
	})

	mux.HandleFunc("/api/suricata/alerts/export", func(w http.ResponseWriter, r *http.Request) {
		if suriReader == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"alerts": []suricata.Alert{}, "total": 0})
			return
		}
		alerts, _ := suriReader.QueryAlerts(5000, 0, nil)
		exportFmt := r.URL.Query().Get("format")
		if exportFmt == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=suricata_alerts.csv")
			w.Write([]byte("timestamp,src_ip,src_port,dst_ip,dst_port,protocol,action,signature,category,severity,comm,cmdline\n"))
			for _, a := range alerts {
				fmt.Fprintf(w, "%s,%s,%d,%s,%d,%s,%s,%s,%s,%d,%s,%s\n",
					csvEsc(a.Timestamp), csvEsc(a.SrcIP), a.SrcPort, csvEsc(a.DstIP), a.DstPort,
					csvEsc(a.Proto), csvEsc(a.Action), csvEsc(a.Signature), csvEsc(a.Category),
					a.Severity, csvEsc(a.Comm), csvEsc(a.Cmdline))
			}
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", "attachment; filename=suricata_alerts.json")
			json.NewEncoder(w).Encode(map[string]interface{}{"alerts": alerts, "total": len(alerts)})
		}
	})

	mux.HandleFunc("/api/suricata/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if suriReader == nil {
			json.NewEncoder(w).Encode(&suricata.Stats{})
			return
		}
		json.NewEncoder(w).Encode(suriReader.GetStats())
	})

	mux.HandleFunc("/api/firewall/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(fw.Status())
	})

	mux.HandleFunc("/api/firewall/pending", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		list, err := fw.GetPending()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if list == nil {
			list = []firewall.Pending{}
		}
		json.NewEncoder(w).Encode(list)
	})

	mux.HandleFunc("/api/firewall/approve", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID   int64  `json:"id"`
			Mode string `json:"mode"` // "once" or "always"
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Mode == "" {
			req.Mode = "once"
		}
		if err := fw.Approve(req.ID, req.Mode); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
	})

	mux.HandleFunc("/api/firewall/deny", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID int64 `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := fw.Deny(req.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "denied"})
	})

	mux.HandleFunc("/api/firewall/approve-all", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Mode string `json:"mode"` // "once" or "always"
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Mode == "" {
			req.Mode = "once"
		}
		pendings, err := fw.GetPending()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		approved := 0
		for _, p := range pendings {
			if err := fw.Approve(p.ID, req.Mode); err != nil {
				logutil.Error("firewall: approve-all %d: %v", p.ID, err)
				continue
			}
			approved++
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "approved": approved})
	})

	mux.HandleFunc("/api/firewall/deny-all", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		pendings, err := fw.GetPending()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		denied := 0
		for _, p := range pendings {
			if err := fw.Deny(p.ID); err != nil {
				logutil.Error("firewall: deny-all %d: %v", p.ID, err)
				continue
			}
			denied++
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "denied": denied})
	})

	mux.HandleFunc("/api/firewall/deny-app", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID int64 `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := fw.DenyApp(req.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "denied_app"})
	})

	mux.HandleFunc("/api/firewall/app-denylist", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "DELETE" {
			idStr := r.URL.Query().Get("id")
			if idStr == "" {
				http.Error(w, "missing id", http.StatusBadRequest)
				return
			}
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil {
				http.Error(w, "invalid id", http.StatusBadRequest)
				return
			}
			if err := fw.RemoveAppDeny(id); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
		entries, err := fw.LoadAppDenylist()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if entries == nil {
			entries = []firewall.AppDenylistEntry{}
		}
		json.NewEncoder(w).Encode(entries)
	})

	mux.HandleFunc("/api/firewall/panic", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		st := fw.Status()
		if st.PanicMode {
			fw.ClearPanic()
			json.NewEncoder(w).Encode(map[string]string{"status": "panic_off"})
		} else {
			fw.PanicMode(5 * time.Minute)
			json.NewEncoder(w).Encode(map[string]string{"status": "panic_5min"})
		}
	})

	mux.HandleFunc("/api/firewall/allow-app", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ExePath string `json:"exe_path"`
			Process string `json:"process"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.ExePath == "" && req.Process == "" {
			http.Error(w, "exe_path or process required", http.StatusBadRequest)
			return
		}
		if err := fw.AllowApp(req.ExePath, req.Process); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// auto-approve all current pending items from this app
		pendings, _ := fw.GetPending()
		approved := 0
		for _, p := range pendings {
			if (req.ExePath != "" && p.ExePath == req.ExePath) || (req.Process != "" && p.Process == req.Process) {
				if err := fw.Approve(p.ID, "always"); err != nil {
					logutil.Error("firewall: allow-app auto-approve %d: %v", p.ID, err)
					continue
				}
				approved++
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "approved": approved})
	})

	mux.HandleFunc("/api/firewall/app-allowlist", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "DELETE" {
			idStr := r.URL.Query().Get("id")
			if idStr == "" {
				http.Error(w, "missing id", http.StatusBadRequest)
				return
			}
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil {
				http.Error(w, "invalid id", http.StatusBadRequest)
				return
			}
			if err := fw.RemoveApp(id); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
		apps, err := fw.ListAllowedApps()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if apps == nil {
			apps = []firewall.AppAllowlistEntry{}
		}
		json.NewEncoder(w).Encode(apps)
	})

	mux.HandleFunc("/api/firewall/allowlist", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "DELETE" {
			idStr := r.URL.Query().Get("id")
			if idStr == "" {
				http.Error(w, "missing id", http.StatusBadRequest)
				return
			}
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil {
				http.Error(w, "invalid id", http.StatusBadRequest)
				return
			}
			if err := fw.DeleteRule(id); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		if page < 1 {
			page = 1
		}
		if perPage < 1 || perPage > 100 {
			perPage = 25
		}
		rules, total, err := fw.LoadAllowlistPaged(page, perPage)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if rules == nil {
			rules = []firewall.Rule{}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data":     rules,
			"total":    total,
			"page":     page,
			"per_page": perPage,
		})
	})

	mux.HandleFunc("/api/firewall/blocklist", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			var req struct {
				IP     string `json:"ip"`
				Source string `json:"source"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			if req.IP == "" {
				json.NewEncoder(w).Encode(map[string]string{"error": "ip is required"})
				return
			}
			src := req.Source
			if src == "" {
				src = "api"
			}
			if err := st.BlocklistIP(req.IP, src); err != nil {
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "blocked", "ip": req.IP})
			return
		}
		if r.Method == "DELETE" {
			ip := r.URL.Query().Get("ip")
			if ip == "" {
				http.Error(w, "missing ip", http.StatusBadRequest)
				return
			}
			if err := fw.RemoveBlocklist(ip); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		if page < 1 {
			page = 1
		}
		if perPage < 1 || perPage > 100 {
			perPage = 25
		}
		entries, total, err := fw.LoadBlocklistPaged(page, perPage)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if entries == nil {
			entries = []firewall.BlocklistEntry{}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data":     entries,
			"total":    total,
			"page":     page,
			"per_page": perPage,
		})
	})

	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(ruleStore.List())
		case http.MethodPost:
			var req struct {
				Name       string                `json:"name"`
				Severity   detect.Severity       `json:"severity"`
				Conditions detect.RuleConditions `json:"conditions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if req.Name == "" {
				http.Error(w, "name required", http.StatusBadRequest)
				return
			}
			if req.Severity == "" {
				req.Severity = detect.SevMedium
			}
			if err := detect.ValidateRuleConditions(req.Conditions); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			id, err := ruleStore.Add(req.Name, req.Severity, req.Conditions)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "id": id})
		case http.MethodPut:
			var req struct {
				ID         int64                 `json:"id"`
				Name       string                `json:"name"`
				Enabled    bool                  `json:"enabled"`
				Severity   detect.Severity       `json:"severity"`
				Conditions detect.RuleConditions `json:"conditions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if req.Severity == "" {
				req.Severity = detect.SevMedium
			}
			if err := detect.ValidateRuleConditions(req.Conditions); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := ruleStore.Update(req.ID, req.Name, req.Enabled, req.Severity, req.Conditions); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
		case http.MethodDelete:
			idStr := r.URL.Query().Get("id")
			if idStr == "" {
				http.Error(w, "missing id", http.StatusBadRequest)
				return
			}
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil {
				http.Error(w, "invalid id", http.StatusBadRequest)
				return
			}
			if err := ruleStore.Delete(id); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/rules/toggle", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID      int64 `json:"id"`
			Enabled bool  `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := ruleStore.Toggle(req.ID, req.Enabled); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "toggled"})
	})

	mux.HandleFunc("/api/rules/preview", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Name       string                `json:"name"`
			Severity   detect.Severity       `json:"severity"`
			Conditions detect.RuleConditions `json:"conditions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Severity == "" {
			req.Severity = detect.SevMedium
		}
		if err := detect.ValidateRuleConditions(req.Conditions); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Name == "" {
			req.Name = "(draft)"
		}

		snapshot := poller.Snapshot()
		resp := previewRule(detect.CustomRule{
			Name:       req.Name,
			Severity:   req.Severity,
			Conditions: req.Conditions,
			Enabled:    true,
		}, snapshot, st)
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/rules/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}

		usages, err := st.RuleUsage()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		type summary struct {
			TotalRules   int    `json:"total_rules"`
			EnabledRules int    `json:"enabled_rules"`
			TotalHits    int    `json:"total_hits"`
			HotRule      string `json:"hot_rule,omitempty"`
			HotHits      int    `json:"hot_hits,omitempty"`
			LastAlertAt  int64  `json:"last_alert_at,omitempty"`
		}

		resp := struct {
			Summary summary           `json:"summary"`
			Rules   []store.RuleUsage `json:"rules"`
		}{
			Rules: usages,
		}

		for _, u := range usages {
			resp.Summary.TotalRules++
			if u.Enabled {
				resp.Summary.EnabledRules++
			}
			resp.Summary.TotalHits += u.HitCount
			if u.HitCount > resp.Summary.HotHits {
				resp.Summary.HotHits = u.HitCount
				resp.Summary.HotRule = u.Name
			}
			if u.LastAlertAt > resp.Summary.LastAlertAt {
				resp.Summary.LastAlertAt = u.LastAlertAt
			}
		}

		json.NewEncoder(w).Encode(resp)
	})

	pcapDir := filepath.Dir(cfg.DBPath) + "/captures"
	capturer := pcap.NewCapturer(pcapDir, defaultIface())

	mux.HandleFunc("/api/pcap/capture", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req pcap.CaptureRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.PID > 0 {
			var targets []pcap.HostPort
			for _, c := range poller.Snapshot() {
				if c.PID != req.PID {
					continue
				}
				if c.RemoteAddr != nil && !c.RemoteAddr.IsUnspecified() {
					targets = append(targets, pcap.HostPort{Host: c.RemoteAddr.String(), Port: c.RemotePort})
				}
			}
			req.Filter = pcap.BuildFilter(targets)
			if req.Filter == "ip" {
				http.Error(w, "no remote connections found for this process", http.StatusBadRequest)
				return
			}
		}
		result, err := capturer.Capture(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(result)
	})

	mux.HandleFunc("/api/pcap/download/", func(w http.ResponseWriter, r *http.Request) {
		fname := strings.TrimPrefix(r.URL.Path, "/api/pcap/download/")
		if fname == "" || strings.Contains(fname, "..") {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}
		fpath := filepath.Join(pcapDir, filepath.Base(fname))
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
		w.Header().Set("Content-Disposition", "attachment; filename="+fname)
		http.ServeFile(w, r, fpath)
	})

	mux.HandleFunc("/api/pcap/read/", func(w http.ResponseWriter, r *http.Request) {
		fname := strings.TrimPrefix(r.URL.Path, "/api/pcap/read/")
		if fname == "" || strings.Contains(fname, "..") {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}
		fname = filepath.Base(fname)
		text, err := capturer.Read(fname)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(text))
	})

	aiClient := ai.NewOllamaClient("", "")
	models, listErr := aiClient.ListModels()
	if len(models) > 0 {
		aiClient.SelectModel(models[0].Name)
		logutil.Info("ai: using model %s", models[0].Name)
	} else {
		logutil.Info("ai: using default model qwen3:8b (no models detected)")
		if listErr != nil {
			logutil.Warn("ai: cannot list models — is Ollama running? %v", listErr)
		}
	}
	aiHandler := ai.NewChatHandlerWithPcap(aiClient, st, &pcapAdapter{capturer})

	mux.HandleFunc("/api/ai/chat", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Messages []ai.Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		reply, err := aiHandler.Handle(req.Messages)
		if err != nil {
			logutil.Error("ai: %v", err)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"reply": reply})
	})

	mux.HandleFunc("/api/ai/chat/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Messages []ai.Message `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		err := aiHandler.HandleStream(req.Messages, func(token string) {
			fmt.Fprintf(w, "data: %s\n\n", token)
			flusher.Flush()
		})
		if err != nil {
			fmt.Fprintf(w, "data: [ERROR] %s\n\n", err.Error())
			flusher.Flush()
		}
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	})

	mux.HandleFunc("/api/ai/models", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			var req struct {
				Model string `json:"model"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := aiHandler.SelectModel(req.Model); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "model": aiHandler.CurrentModel()})
			return
		}
		models, err := aiHandler.ListModels()
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"models":  []ai.ModelInfo{},
				"current": aiHandler.CurrentModel(),
				"error":   err.Error(),
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"models":  models,
			"current": aiHandler.CurrentModel(),
		})
	})

	mux.HandleFunc("/api/processes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		type procEntry struct {
			PID     int              `json:"pid"`
			Comm    string           `json:"comm"`
			Exe     string           `json:"exe"`
			Cmdline string           `json:"cmdline"`
			Count   int              `json:"conn_count"`
			Conns   []map[string]any `json:"connections"`
		}
		conns := poller.Snapshot()
		procMap := make(map[int]*procEntry)
		for _, c := range conns {
			if c.PID == 0 {
				continue
			}
			e, ok := procMap[c.PID]
			if !ok {
				e = &procEntry{
					PID:     c.PID,
					Comm:    c.Comm,
					Exe:     c.Exe,
					Cmdline: c.Cmdline,
				}
				procMap[c.PID] = e
			}
			e.Count++
			addr := ""
			if c.RemoteAddr != nil {
				addr = c.RemoteAddr.String()
			}
			e.Conns = append(e.Conns, map[string]any{
				"remote_addr": addr,
				"remote_port": c.RemotePort,
				"local_addr":  ipStr(c.LocalAddr),
				"local_port":  c.LocalPort,
				"protocol":    c.Protocol,
				"state":       c.State,
				"domain":      c.Domain,
			})
		}
		list := make([]*procEntry, 0, len(procMap))
		for _, e := range procMap {
			list = append(list, e)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].Count > list[j].Count
		})
		json.NewEncoder(w).Encode(list)
	})

	mux.HandleFunc("/api/ai/analyze-pcap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Filename string `json:"filename"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		text, err := capturer.Read(req.Filename)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		truncated := false
		if len(text) > 12000 {
			text = text[:6000] + "\n... [CAPTURE TRUNCATED — showing first 6000 and last 6000 characters] ...\n" + text[len(text)-6000:]
			truncated = true
		}
		prompt := "Analyze this packet capture dump. Identify the protocols, endpoints, any suspicious activity, and provide a concise security assessment.\n\n" + text
		if truncated {
			prompt += "\n\nNote: the capture was longer than shown — you are seeing only the first 6000 and last 6000 characters, so your assessment may be incomplete."
		}
		reply, err := aiClient.Chat([]ai.Message{
			{Role: "system", Content: "You are a network packet analysis expert. Analyze pcap dumps and provide clear security assessments. Do not ask for tools — the data is already in the message."},
			{Role: "user", Content: prompt},
		}, nil)
		if err != nil {
			logutil.Error("ai analyze-pcap: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var analysis string
		if reply != nil {
			analysis = reply.Content
		}
		if analysis == "" {
			analysis = "no analysis returned"
		}
		json.NewEncoder(w).Encode(map[string]string{"analysis": analysis})
	})

	mux.HandleFunc("/api/reports/generate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if err := reportSched.GenerateNow(); err != nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "generated"})
	})

	mux.HandleFunc("/api/reports/files", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		entries, _ := os.ReadDir(reportDir)
		type fileInfo struct {
			Name    string `json:"name"`
			Size    int64  `json:"size"`
			ModTime string `json:"mod_time"`
		}
		var files []fileInfo
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, _ := e.Info()
			files = append(files, fileInfo{
				Name:    e.Name(),
				Size:    info.Size(),
				ModTime: info.ModTime().Format("Jan 02 15:04"),
			})
		}
		json.NewEncoder(w).Encode(files)
	})

	mux.HandleFunc("/api/reports/download/", func(w http.ResponseWriter, r *http.Request) {
		fname := strings.TrimPrefix(r.URL.Path, "/api/reports/download/")
		if fname == "" || strings.Contains(fname, "..") {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}
		fpath := filepath.Join(reportDir, filepath.Base(fname))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+fname)
		http.ServeFile(w, r, fpath)
	})

	var upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	wsClients := make(map[*websocket.Conn]bool)
	var wsMu sync.Mutex

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			logutil.Error("ws: upgrade: %v", err)
			return
		}

		wsMu.Lock()
		wsClients[c] = true
		wsMu.Unlock()

		c.SetReadLimit(512)
		for {
			_, _, err := c.ReadMessage()
			if err != nil {
				break
			}
		}

		wsMu.Lock()
		delete(wsClients, c)
		wsMu.Unlock()
		c.Close()
	})

	go func() {
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-shutdownCtx.Done():
				return
			case <-t.C:
			}

			wsMu.Lock()
			clientCount := len(wsClients)
			wsMu.Unlock()

			if clientCount == 0 {
				continue
			}

			payload := collectPayload(poller, eng, st, fw, suriReader, cfg)
			data, err := json.Marshal(payload)
			if err != nil {
				continue
			}

			wsMu.Lock()
			clients := make([]*websocket.Conn, 0, len(wsClients))
			for c := range wsClients {
				clients = append(clients, c)
			}
			wsMu.Unlock()

			for _, c := range clients {
				c := c
				go func() {
					c.SetWriteDeadline(time.Now().Add(1 * time.Second))
					if err := c.WriteMessage(websocket.TextMessage, data); err != nil {
						c.Close()
						wsMu.Lock()
						delete(wsClients, c)
						wsMu.Unlock()
					}
				}()
			}
		}
	}()

	// periodic enrich cache cleanup
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-shutdownCtx.Done():
				return
			case <-t.C:
				now := time.Now().Unix()
				enrichMu.Lock()
				for k, v := range enrichCache {
					if v.expiresAt <= now {
						delete(enrichCache, k)
					}
				}
				enrichMu.Unlock()
			}
		}
	}()

	// fallback scanner: every 5s scan /proc/net/tcp for SYN_SENT connections
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-shutdownCtx.Done():
				return
			case <-t.C:
			}
			if fw == nil {
				continue
			}
			entries := capture.ScanSynSent()
			for _, e := range entries {
				if fw.IsAppDenied(e.Exe, e.Comm) {
					continue
				}
				if !fw.IsBlocked(e.PID, e.Exe, e.Comm, e.IP, "tcp", e.Port) {
					continue
				}
				if fw.AlreadyPending(e.Exe, e.IP, "tcp", e.Port) {
					continue
				}
				p := firewall.Pending{
					ExePath: e.Exe,
					Process: e.Comm,
					IP:      e.IP,
					Port:    e.Port,
					Proto:   "tcp",
					Pid:     e.PID,
				}
				id, err := fw.QueuePending(p)
				if err == nil {
					logutil.Info("firewall: fallback-pending %d: %s → %s:%d", id, e.Comm, e.IP, e.Port)
				} else {
					logutil.Error("firewall: fallback ERROR %v", err)
				}
			}
		}
	}()

	mux.HandleFunc("/api/lookup/rdns", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, `{"error":"missing ip param"}`, http.StatusBadRequest)
			return
		}
		names, err := net.LookupAddr(ip)
		if err != nil || len(names) == 0 {
			json.NewEncoder(w).Encode(map[string]string{"ip": ip, "ptr": ""})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"ip": ip, "ptr": names[0]})
	})

	mux.HandleFunc("/api/lookup/geoip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, `{"error":"missing ip param"}`, http.StatusBadRequest)
			return
		}
		resp, err := http.Get("http://ip-api.com/json/" + ip + "?fields=country,regionName,city,lat,lon,isp,org,as,query")
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		w.Write(body)
	})

	mux.HandleFunc("/api/lookup/geoip/batch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ipsParam := r.URL.Query().Get("ips")
		if ipsParam == "" {
			json.NewEncoder(w).Encode(map[string]interface{}{"results": []interface{}{}})
			return
		}
		ips := strings.Split(ipsParam, ",")
		type result struct {
			IP      string  `json:"query"`
			Country string  `json:"country"`
			Region  string  `json:"regionName"`
			City    string  `json:"city"`
			Lat     float64 `json:"lat"`
			Lon     float64 `json:"lon"`
			ISP     string  `json:"isp"`
			Org     string  `json:"org"`
			AS      string  `json:"as"`
		}
		results := []result{}
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			var r result
			resp, err := http.Get("http://ip-api.com/json/" + ip + "?fields=query,country,regionName,city,lat,lon,isp,org,as")
			if err != nil {
				results = append(results, result{IP: ip})
				continue
			}
			json.NewDecoder(resp.Body).Decode(&r)
			resp.Body.Close()
			results = append(results, r)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
	})

	mux.HandleFunc("/api/lookup/whois", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, "missing ip param", http.StatusBadRequest)
			return
		}
		cmd := exec.Command("whois", ip)
		out, err := cmd.Output()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(out)
	})

	mux.HandleFunc("/api/lookup/threat", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, `{"error":"missing ip param"}`, http.StatusBadRequest)
			return
		}
		// check DNSBL (dnsbl.dronebl.org)
		names, _ := net.LookupAddr(ip)
		result := map[string]interface{}{
			"ip":      ip,
			"ptr":     "",
			"blocked": false,
			"sources": []string{},
		}
		if len(names) > 0 {
			result["ptr"] = names[0]
		}
		// check our blocklist
		for _, bl := range cfg.Blocklist {
			if bl == ip {
				result["blocked"] = true
				result["sources"] = append(result["sources"].([]string), "local blocklist")
			}
		}
		json.NewEncoder(w).Encode(result)
	})

	// --- auth endpoints (unauthenticated by design) ---

	mux.HandleFunc("/api/auth/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		setup := authManager.SetupRequired()
		var authed bool
		var uid int64
		var username string
		var passwordResetRequired bool
		if tok := sessionTokenFromRequest(r); tok != "" {
			if id, err := authManager.ValidateSession(tok); err == nil {
				authed = true
				uid = id
				username, _ = authManager.ValidateSessionAndGetUsername(uid)
				ok, _ := authManager.PasswordMeetsPolicy(uid)
				passwordResetRequired = !ok
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated":              authed,
			"setup_required":             setup,
			"user_id":                    uid,
			"username":                   username,
			"password_reset_required":    passwordResetRequired,
			"min_password_length":        auth.MinPasswordLength,
		})
	})

	setupHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if !authManager.SetupRequired() {
			http.Error(w, `{"error":"setup already complete"}`, http.StatusConflict)
			return
		}
		var req struct {
			SetupToken string `json:"setup_token"`
			Username   string `json:"username"`
			Password   string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if err := authManager.ConsumeSetupToken(req.SetupToken); err != nil {
			status := http.StatusForbidden
			if errors.Is(err, auth.ErrNoSetupToken) {
				// No token in the DB. Two possibilities:
				//   1. Users already exist (setup is done) — this is
				//      normally caught by SetupRequired() above, but
				//      race with another in-flight setup can land here.
				//   2. Token file was deleted but no user was created
				//      (botched setup). Operator needs to restart the
				//      daemon to regenerate.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"no_setup_pending","hint":"setup token not found — if this is a fresh install, restart the daemon to regenerate one; otherwise sign in at /login"}`))
				return
			}
			http.Error(w, `{"error":"`+err.Error()+`"}`, status)
			return
		}
		uid, err := authManager.CreateUser(req.Username, req.Password)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		tok, err := authManager.LoginAndCreateSession(uid)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		setSessionCookie(w, authManager, tok)
		issueXSRF(w, authManager)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "user_id": uid})
	}

	loginHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		uid, locked, err := authManager.Authenticate(req.Username, req.Password)
		if err != nil {
			status := http.StatusUnauthorized
			if locked {
				status = http.StatusTooManyRequests
			}
			http.Error(w, `{"error":"`+err.Error()+`"}`, status)
			return
		}
		tok, err := authManager.LoginAndCreateSession(uid)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		setSessionCookie(w, authManager, tok)
		issueXSRF(w, authManager)
		// surface the password-reset nag so the UI can show a banner
		ok, _ := authManager.PasswordMeetsPolicy(uid)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":                  "ok",
			"user_id":                 uid,
			"password_reset_required": !ok,
		})
	}

	mux.HandleFunc("/api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if tok := sessionTokenFromRequest(r); tok != "" {
			_ = authManager.DeleteSession(tok)
		}
		clearSessionCookie(w, authManager)
		clearXSRF(w, authManager)
		json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
	})

	// --- password change (requires current session + password) ---
	mux.HandleFunc("/api/auth/password", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		uid := auth.UserIDFromContext(r.Context())
		if uid == 0 {
			http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}
		var req struct {
			Current string `json:"current"`
			New     string `json:"new"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if err := authManager.ChangePassword(uid, req.Current, req.New, true); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		// Issue a new session for the user since all of theirs were deleted.
		tok, err := authManager.CreateSession(uid)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		setSessionCookie(w, authManager, tok)
		json.NewEncoder(w).Encode(map[string]string{"status": "password_changed"})
	})

	// --- password reset (no current session required, uses out-of-band token) ---
	passwordResetHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			ResetToken string `json:"reset_token"`
			New        string `json:"new"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		username, err := authManager.ConsumePasswordResetToken(req.ResetToken)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusForbidden)
			return
		}
		uid, err := authManager.ForcePasswordReset(username, req.New)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		tok, err := authManager.LoginAndCreateSession(uid)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		setSessionCookie(w, authManager, tok)
		issueXSRF(w, authManager)
		json.NewEncoder(w).Encode(map[string]string{"status": "password_reset"})
	}

	// --- admin-only: issue a reset token for a user (writes to disk) ---
	mux.HandleFunc("/api/auth/password-reset/issue", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if auth.UserIDFromContext(r.Context()) == 0 {
			http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if err := authManager.IssuePasswordResetToken(req.Username); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "reset_token_issued"})
	})

	// --- revoke all other sessions for the current user ---
	mux.HandleFunc("/api/auth/sessions/revoke-all", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		uid := auth.UserIDFromContext(r.Context())
		if uid == 0 {
			http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}
		// delete all but the current token (which we re-issue fresh)
		currentTok := sessionTokenFromRequest(r)
		_ = authManager.DeleteAllSessionsForUser(uid)
		tok, err := authManager.CreateSession(uid)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		_ = currentTok
		setSessionCookie(w, authManager, tok)
		issueXSRF(w, authManager)
		json.NewEncoder(w).Encode(map[string]string{"status": "revoked_all"})
	})

	// --- audit log (auth events) ---
	mux.HandleFunc("/api/auth/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if auth.UserIDFromContext(r.Context()) == 0 {
			http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}
		events, err := authManager.ListRecentEvents(100)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if events == nil {
			events = []map[string]interface{}{}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"events": events})
	})

	// convenience redirects so users can type /login or /setup without .html
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login.html", http.StatusFound)
	})
	mux.HandleFunc("/setup", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/setup.html", http.StatusFound)
	})
	mux.HandleFunc("/password-reset", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/password-reset.html", http.StatusFound)
	})

	// Register the three auth-mutating endpoints through the IP rate
	// limiter. Everything else (the static file server, the dashboard
	// `/api/*` calls, the WebSocket, the password-change endpoint, etc.) is
	// unthrottled. Per-username lockout still applies inside Authenticate()
	// for /api/auth/login regardless of which middleware path wraps the
	// handler.
	rateLimiter := authManager.RateLimiter()
	mux.Handle("/api/auth/login",          rateLimiter.Middleware()(http.HandlerFunc(loginHandler)))
	mux.Handle("/api/auth/setup",          rateLimiter.Middleware()(http.HandlerFunc(setupHandler)))
	mux.Handle("/api/auth/password-reset", rateLimiter.Middleware()(http.HandlerFunc(passwordResetHandler)))

	csrfHandler := auth.CSRFMiddleware(
		"/api/auth/login", "/api/auth/setup", "/api/auth/password-reset", "/api/auth/logout",
	)

	handler := authManager.Middleware(
		"/login", "/setup", "/password-reset", "/api/health", "/api/auth/",
		// PWA assets — must be reachable without a session so Chrome can
		// resolve the manifest and favicon before the user logs in.
		"/icon-192.png", "/icon-512.png", "/icon-maskable-512.png",
		"/manifest.json", "/sw.js",
	)(csrfHandler(mux))

	srv := &http.Server{Addr: cfg.ListenAddr, Handler: handler}

	go func() {
		logutil.Info("dashboard: http://%s", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			logutil.Error("http: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logutil.Info("shutting down...")

	// 1. Stop accepting new connections; let in-flight requests finish
	//    (with a 10s ceiling). Shutdown() is non-blocking — it returns
	//    once all conns are closed or the context expires.
	shutdownHTTP, cancelHTTP := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelHTTP()
	if err := srv.Shutdown(shutdownHTTP); err != nil {
		logutil.Warn("http: graceful shutdown timed out: %v", err)
		_ = srv.Close()
	}

	// 2. Signal every background goroutine to stop (via shutdownCtx).
	cancelShutdown()

	// 3. Stop subsystems that hold external resources.
	if dnsMon != nil {
		dnsMon.Stop()
	}
	poller.Stop()
	if suriReader != nil {
		suriReader.Stop()
	}
	if reportSched != nil {
		reportSched.Stop()
	}

	// 4. Flush any buffered connection events to SQLite before closing.
	if err := st.Close(); err != nil {
		logutil.Warn("store: close: %v", err)
	}

	logutil.Info("firewall rules preserved (default-deny stays active)")
	logutil.Info("to disable: sudo nft delete table inet netmon")
}

type pcapAdapter struct {
	*pcap.Capturer
}

func (a *pcapAdapter) ListCaptures() ([]ai.CaptureInfo, error) {
	caps, err := a.Capturer.ListCaptures()
	if err != nil {
		return nil, err
	}
	res := make([]ai.CaptureInfo, len(caps))
	for i, c := range caps {
		res[i] = ai.CaptureInfo{Filename: c.Filename, Size: c.Size, CreatedAt: c.CreatedAt}
	}
	return res, nil
}

func (a *pcapAdapter) ReadCapture(filename string, maxLines int, filter string) (string, error) {
	return a.Capturer.ReadCapture(filename, maxLines, filter)
}

// isLoopbackListen reports whether addr (host:port) is a loopback bind.
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch host {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// sessionTokenFromRequest extracts the current session token from the request,
// reading cookie, query string, or Authorization header (in that order).
func sessionTokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(auth.SessionCookieName); err == nil {
		return c.Value
	}
	if v := r.URL.Query().Get("token"); v != "" {
		return v
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// setSessionCookie writes the session cookie on the response. HttpOnly so the
// token can't be read from JS; SameSite=Lax so the cookie rides along on
// dashboard fetches; Path=/ so it's sent to every /api/* call.
func setSessionCookie(w http.ResponseWriter, m *auth.Manager, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.SecureCookie(),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(m.SessionTTL()),
	})
}

func clearSessionCookie(w http.ResponseWriter, m *auth.Manager) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.SecureCookie(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// issueXSRF mints a CSRF token and writes it as a non-HttpOnly cookie. JS
// reads this and echoes it as the X-XSRF-TOKEN header on every mutating
// request.
func issueXSRF(w http.ResponseWriter, m *auth.Manager) {
	tok, err := auth.NewXSRFToken()
	if err != nil {
		logutil.Warn("auth: csrf token mint failed: %v", err)
		return
	}
	auth.SetXSRFCookie(w, tok, m.SecureCookie())
}

func clearXSRF(w http.ResponseWriter, m *auth.Manager) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.XSRFCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   m.SecureCookie(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

func suricataAction(fn func() error, okMsg string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := fn()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": okMsg})
	}
}

func processEvents(ctx context.Context, events <-chan capture.ConnectionEvent, alerts chan<- detect.Alert, st *store.Store, eng *detect.Engine, fw *firewall.Manager) {
	defer func() {
		if r := recover(); r != nil {
			logutil.Error("CRASH: processEvents panicked: %v", r)
			// restart the goroutine so event processing isn't lost forever
			go processEvents(ctx, events, alerts, st, eng, fw)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			handleConnectionEvent(ev, alerts, st, eng, fw)
		}
	}
}

// handleConnectionEvent applies the same logic the original loop body did,
// but split out so processEvents can use a select instead of range.
func handleConnectionEvent(ev capture.ConnectionEvent, alerts chan<- detect.Alert, st *store.Store, eng *detect.Engine, fw *firewall.Manager) {
	st.Insert(ev)
	// queue pending approval for new outbound connections blocked by firewall
	isUDP := strings.HasPrefix(ev.Protocol, "udp")
	isRaw := strings.HasPrefix(ev.Protocol, "raw") || strings.HasPrefix(ev.Protocol, "icmp")
	if ev.Type == capture.EventNew && !ev.RemoteAddr.IsUnspecified() && ev.RemoteAddr.IsGlobalUnicast() && fw != nil && (ev.State == "SYN_SENT" || isUDP) && !isRaw {
		ipStr := ev.RemoteAddr.String()
		proto := ev.Protocol
		if isUDP {
			proto = "udp"
		}
		if fw.IsAppDenied(ev.Exe, ev.Comm) {
			return
		}
		blocked := fw.IsBlocked(ev.PID, ev.Exe, ev.Comm, ipStr, proto, ev.RemotePort)
		dup := fw.AlreadyPending(ev.Exe, ipStr, proto, ev.RemotePort)
		if !blocked && fw.IsAppAllowed(ev.Exe, ev.Comm) {
			if err := fw.Allow(ipStr, proto, ev.RemotePort); err != nil {
				logutil.Error("firewall: auto-allow for app %s %s:%d/%s: %v", ev.Comm, ipStr, ev.RemotePort, proto, err)
			}
			return
		}
		if !blocked || dup {
			return
		}
		source := "new"
		if ev.PreExisting {
			source = "preexisting"
		}
		p := firewall.Pending{
			ExePath:   ev.Exe,
			Process:   ev.Comm,
			IP:        ipStr,
			Port:      ev.RemotePort,
			Proto:     proto,
			Direction: "out",
			Pid:       ev.PID,
			Source:    source,
		}
		id, err := fw.QueuePending(p)
		if err == nil {
			logutil.Info("firewall: pending approval %d: %s → %s:%d (source=%s)", id, ev.Comm, ipStr, ev.RemotePort, source)
			enrichPending(st.DB(), fw, id, ipStr, ev.RemotePort)
		} else {
			logutil.Error("firewall: queue pending ERROR: %v", err)
		}
	}

	// handle incoming connections — remote initiated to our service
	if ev.Type == capture.EventNew && ev.Incoming && ev.RemoteAddr != nil && !ev.RemoteAddr.IsLoopback() && !ev.RemoteAddr.IsUnspecified() && fw != nil {
		ipStr := ev.RemoteAddr.String()
		proto := ev.Protocol
		if strings.HasPrefix(proto, "tcp") {
			proto = "tcp"
		}
		if fw.IsAppDenied(ev.Exe, ev.Comm) {
			return
		}
		blocked := fw.IsBlockedIn(ev.PID, ev.Exe, ev.Comm, ipStr, proto, ev.LocalPort)
		dup := fw.AlreadyPendingIn(ev.Exe, ipStr, proto, ev.LocalPort)
		if !blocked || dup {
			return
		}
		source := "new"
		if ev.PreExisting {
			source = "preexisting"
		}
		p := firewall.Pending{
			ExePath:   ev.Exe,
			Process:   ev.Comm,
			IP:        ipStr,
			Port:      ev.LocalPort,
			Proto:     proto,
			Direction: "in",
			Pid:       ev.PID,
			Source:    source,
		}
		id, err := fw.QueuePending(p)
		if err == nil {
			logutil.Info("firewall: pending incoming %d: %s ← %s:%d (service %d, source=%s)", id, ev.Comm, ipStr, ev.RemotePort, ev.LocalPort, source)
			enrichPending(st.DB(), fw, id, ipStr, ev.RemotePort)
		} else {
			logutil.Error("firewall: queue incoming pending ERROR: %v", err)
		}
	}

	if alert := eng.Eval(ev); alert != nil {
		alerts <- *alert
	}
}

func enrichPending(db *sql.DB, fw *firewall.Manager, pendingID int64, ip string, port int) {
	go func() {
		time.Sleep(3 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		names, _ := net.DefaultResolver.LookupAddr(ctx, ip)
		cutoff := time.Now().Add(-60 * time.Second).Unix()
		var httpData, tlsData, dnsData string
		db.QueryRow(`
            SELECT http_data, tls_data, dns_data FROM suricata_alerts
            WHERE dst_ip=? AND dst_port=? AND timestamp > ?
            ORDER BY id DESC LIMIT 1
        `, ip, port, cutoff).Scan(&httpData, &tlsData, &dnsData)
		var parts []string
		if len(names) > 0 {
			parts = append(parts, names[0])
		}
		if httpData != "" {
			parts = append(parts, "http:"+httpData)
		}
		if tlsData != "" {
			parts = append(parts, "tls:"+tlsData)
		}
		if dnsData != "" {
			parts = append(parts, "dns:"+dnsData)
		}
		if len(parts) > 0 {
			combined := strings.Join(parts, " | ")
			fw.UpdatePendingAppData(pendingID, combined)
			logutil.Info("firewall: enriched pending %d: %s", pendingID, combined)
		}
	}()
}

func processAlerts(ctx context.Context, alerts <-chan detect.Alert, st *store.Store) {
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-alerts:
			logutil.Warn("ALERT [%s] %s: %s", a.Severity, a.RuleName, a.Message)
			st.DB().Exec(
				`INSERT INTO alerts(rule_id, rule_name, severity, pid, comm, remote_addr, remote_port, message, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
				a.RuleID, a.RuleName, string(a.Severity), a.PID, a.Comm, a.RemoteAddr, a.RemotePort, a.Message, a.CreatedAt,
			)
		}
	}
}

func periodicTrends(ctx context.Context, eng *detect.Engine) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, alert := range eng.DetectTrends() {
				logutil.Warn("TREND [%s] %s: %s", alert.Severity, alert.RuleName, alert.Message)
			}
		}
	}
}

func syncBlocklist(ctx context.Context, eng *detect.Engine, fw *firewall.Manager) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if ips, err := fw.LoadBlocklistIPs(); err == nil {
				eng.AddBlocklist(ips)
			}
		}
	}
}

type wsPayload struct {
	Connections []capture.Connection `json:"connections"`
	Alerts      []detect.Alert       `json:"alerts"`
	Stats       interface{}          `json:"stats"`
	FWStatus    *firewall.Status     `json:"fw_status,omitempty"`
	FWPending   []firewall.Pending   `json:"fw_pending,omitempty"`
	SuriStats   *suricata.Stats      `json:"suri_stats,omitempty"`
}

type rulePreviewMatch struct {
	PID          int     `json:"pid"`
	Comm         string  `json:"comm"`
	Exe          string  `json:"exe,omitempty"`
	LocalAddr    string  `json:"local_addr,omitempty"`
	LocalPort    int     `json:"local_port,omitempty"`
	RemoteAddr   string  `json:"remote_addr,omitempty"`
	RemotePort   int     `json:"remote_port,omitempty"`
	Protocol     string  `json:"protocol,omitempty"`
	State        string  `json:"state,omitempty"`
	CreatedAt    int64   `json:"created_at,omitempty"`
	Status       string  `json:"status"`
	SampleCount  int     `json:"sample_count,omitempty"`
	MeanInterval float64 `json:"mean_interval_ms,omitempty"`
}

type rulePreviewResponse struct {
	Rule           detect.CustomRule  `json:"rule"`
	CandidateCount int                `json:"candidate_count"`
	TriggeredCount int                `json:"triggered_count"`
	Matches        []rulePreviewMatch `json:"matches"`
	Notes          []string           `json:"notes,omitempty"`
}

type enrichEntry struct {
	tlsHost   string
	httpHost  string
	expiresAt int64
}

var (
	enrichMu    sync.Mutex
	enrichCache = map[string]enrichEntry{}
)

func enrichConnections(conns []capture.Connection, db *sql.DB) {
	if db == nil || len(conns) == 0 {
		return
	}
	now := time.Now().Unix()
	cutoff := now - 60
	for i, c := range conns {
		if c.RemoteAddr == nil {
			continue
		}
		ip := c.RemoteAddr.String()
		port := c.RemotePort
		key := ip + ":" + strconv.Itoa(port)

		enrichMu.Lock()
		entry, ok := enrichCache[key]
		enrichMu.Unlock()
		if ok && entry.expiresAt > now {
			conns[i].TLSHost = entry.tlsHost
			conns[i].HTTPHost = entry.httpHost
			continue
		}

		var tlsData, httpData string
		db.QueryRow(`
            SELECT tls_data, http_data FROM suricata_alerts
            WHERE dst_ip=? AND dst_port=? AND created_at > ?
            ORDER BY id DESC LIMIT 1
        `, ip, port, cutoff).Scan(&tlsData, &httpData)
		if tlsData != "" {
			var tls struct {
				SNI string `json:"sni"`
			}
			if json.Unmarshal([]byte(tlsData), &tls) == nil && tls.SNI != "" {
				conns[i].TLSHost = tls.SNI
			}
		}
		if httpData != "" {
			var http struct {
				Hostname string `json:"hostname"`
			}
			if json.Unmarshal([]byte(httpData), &http) == nil && http.Hostname != "" {
				conns[i].HTTPHost = http.Hostname
			}
		}
		enrichMu.Lock()
		enrichCache[key] = enrichEntry{
			tlsHost:   conns[i].TLSHost,
			httpHost:  conns[i].HTTPHost,
			expiresAt: now + 60,
		}
		enrichMu.Unlock()
	}
}

func collectPayload(poller *capture.Poller, eng *detect.Engine, st *store.Store, fw *firewall.Manager, suriReader *suricata.Reader, cfg *config.Config) wsPayload {
	conns := poller.Snapshot()
	enrichConnections(conns, st.DB())
	p := wsPayload{
		Connections: conns,
		Alerts:      eng.RecentAlerts(cfg.AlertLimit),
	}
	s := st.Stats()
	s.AlertCount = eng.AlertCount()
	p.Stats = s

	if fw != nil {
		fs := fw.Status()
		p.FWStatus = &fs
		pl, _ := fw.GetPending()
		if pl == nil {
			pl = []firewall.Pending{}
		}
		p.FWPending = pl
	}

	if suriReader != nil {
		ss := suriReader.GetStats()
		p.SuriStats = ss
	}

	return p
}

const maxRulePreviewMatches = 50

func previewRule(rule detect.CustomRule, snapshot []capture.Connection, st *store.Store) rulePreviewResponse {
	resp := rulePreviewResponse{
		Rule: rule,
	}

	beacon := rule.Conditions.MinInterval > 0 || rule.Conditions.MaxInterval > 0 || rule.Conditions.MinSamples > 0
	if beacon {
		resp.Notes = append(resp.Notes, "beacon rules are simulated against recent stored connection history")
	}

	seen := make(map[string]struct{})
	truncated := false
	for _, conn := range snapshot {
		if !detect.RuleMatchesStatic(rule.Conditions, conn) {
			continue
		}

		key := fmt.Sprintf("%d|%s|%d|%s", conn.PID, ipStr(conn.RemoteAddr), conn.RemotePort, conn.Protocol)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		resp.CandidateCount++

		match := rulePreviewMatch{
			PID:        conn.PID,
			Comm:       conn.Comm,
			Exe:        conn.Exe,
			LocalAddr:  ipStr(conn.LocalAddr),
			LocalPort:  conn.LocalPort,
			RemoteAddr: ipStr(conn.RemoteAddr),
			RemotePort: conn.RemotePort,
			Protocol:   conn.Protocol,
			State:      conn.State,
			CreatedAt:  conn.CreatedAt,
			Status:     "trigger",
		}

		if beacon {
			history, err := st.QueryConns(store.ConnFilter{
				Process:    conn.Comm,
				RemoteIP:   ipStr(conn.RemoteAddr),
				RemotePort: conn.RemotePort,
				Protocol:   conn.Protocol,
				Limit:      50,
			})
			if err != nil {
				resp.Notes = append(resp.Notes, fmt.Sprintf("history lookup failed for %s: %v", conn.Comm, err))
				continue
			}
			timestamps := make([]int64, 0, len(history))
			for i := len(history) - 1; i >= 0; i-- {
				timestamps = append(timestamps, history[i].CreatedAt)
			}
			ok, mean, samples := detect.BeaconConditionsMet(rule.Conditions, timestamps)
			match.SampleCount = samples
			match.MeanInterval = mean
			if ok {
				match.Status = "trigger"
				resp.TriggeredCount++
			} else {
				match.Status = "pending"
			}
		} else {
			resp.TriggeredCount++
		}

		if len(resp.Matches) >= maxRulePreviewMatches {
			if !truncated {
				resp.Notes = append(resp.Notes, fmt.Sprintf("showing first %d candidates only", maxRulePreviewMatches))
				truncated = true
			}
			continue
		}

		resp.Matches = append(resp.Matches, match)
	}

	sort.Slice(resp.Matches, func(i, j int) bool {
		wi := 0
		wj := 0
		if resp.Matches[i].Status != "trigger" {
			wi = 1
		}
		if resp.Matches[j].Status != "trigger" {
			wj = 1
		}
		if wi != wj {
			return wi < wj
		}
		if resp.Matches[i].RemoteAddr != resp.Matches[j].RemoteAddr {
			return resp.Matches[i].RemoteAddr < resp.Matches[j].RemoteAddr
		}
		if resp.Matches[i].RemotePort != resp.Matches[j].RemotePort {
			return resp.Matches[i].RemotePort < resp.Matches[j].RemotePort
		}
		return resp.Matches[i].PID < resp.Matches[j].PID
	})

	return resp
}

func parseInt(s string) (int, error) {
	var v int
	_, err := fmt.Sscanf(s, "%d", &v)
	return v, err
}

func csvEsc(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func ipStr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func defaultIface() string {
	cmd := exec.Command("sh", "-c", "ip route show default | awk '{print $5}' | head -1")
	out, err := cmd.Output()
	if err != nil {
		return "eth0"
	}
	iface := strings.TrimSpace(string(out))
	if iface == "" {
		return "eth0"
	}
	return iface
}
