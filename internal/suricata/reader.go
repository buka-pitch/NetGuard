package suricata

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"netmon/internal/capture"
	"netmon/internal/logutil"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Reader struct {
	mu       sync.Mutex
	alerts   []Alert
	stats    *Stats
	cap      func() []capture.Connection
	maxAlert int
	db       *sql.DB
	done     chan struct{}
	// currentFile is the eve.log fd held by tail(). Stop() closes it so the
	// blocking bufio.Scanner unblocks with ErrClosed.
	currentFile *os.File
}

func NewReader(maxAlert int, snapshot func() []capture.Connection, db *sql.DB) *Reader {
	r := &Reader{
		maxAlert: maxAlert,
		cap:      snapshot,
		stats:    &Stats{},
		db:       db,
		done:     make(chan struct{}),
	}
	r.initDB()
	return r
}

// Stop signals the tail goroutine to exit. Safe to call multiple times.
// Closes the currently held eve.log fd so the blocking bufio.Scanner
// unblocks promptly.
func (r *Reader) Stop() {
	select {
	case <-r.done:
		return
	default:
	}
	close(r.done)
	r.mu.Lock()
	if f := r.currentFile; f != nil {
		_ = f.Close()
	}
	r.mu.Unlock()
}

func (r *Reader) initDB() {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS suricata_alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL DEFAULT '',
            src_ip      TEXT NOT NULL DEFAULT '',
            src_port    INTEGER NOT NULL DEFAULT 0,
            dst_ip      TEXT NOT NULL DEFAULT '',
            dst_port    INTEGER NOT NULL DEFAULT 0,
            protocol    TEXT NOT NULL DEFAULT '',
            action      TEXT NOT NULL DEFAULT '',
            signature   TEXT NOT NULL DEFAULT '',
            category    TEXT NOT NULL DEFAULT '',
            severity    INTEGER NOT NULL DEFAULT 0,
            gid         INTEGER NOT NULL DEFAULT 0,
            pid         INTEGER NOT NULL DEFAULT 0,
            comm        TEXT NOT NULL DEFAULT '',
            cmdline     TEXT NOT NULL DEFAULT '',
            exe         TEXT NOT NULL DEFAULT '',
            ppid        INTEGER NOT NULL DEFAULT 0,
            pcomm       TEXT NOT NULL DEFAULT '',
            duration    TEXT NOT NULL DEFAULT '',
            http_data   TEXT NOT NULL DEFAULT '',
            tls_data    TEXT NOT NULL DEFAULT '',
            dns_data    TEXT NOT NULL DEFAULT '',
            created_at  INTEGER NOT NULL
        )`,
		`CREATE INDEX IF NOT EXISTS idx_suri_alerts_ts ON suricata_alerts(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_suri_alerts_sev ON suricata_alerts(severity)`,
		`CREATE TABLE IF NOT EXISTS reader_state (
            key   TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        )`,
	}
	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			logutil.Error("suricata: initDB: %v", err)
		}
	}
	// migrate old table — add columns that may not exist yet
	for _, alter := range []string{
		"ALTER TABLE suricata_alerts ADD COLUMN gid INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE suricata_alerts ADD COLUMN cmdline TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE suricata_alerts ADD COLUMN exe TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE suricata_alerts ADD COLUMN ppid INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE suricata_alerts ADD COLUMN pcomm TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE suricata_alerts ADD COLUMN duration TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE suricata_alerts ADD COLUMN http_data TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE suricata_alerts ADD COLUMN tls_data TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE suricata_alerts ADD COLUMN dns_data TEXT NOT NULL DEFAULT ''",
	} {
		r.db.Exec(alter)
	}
}

func (r *Reader) loadOffset() (offset int64, inode uint64) {
	r.db.QueryRow("SELECT value FROM reader_state WHERE key='eve_offset'").Scan(&offset)
	var raw int64
	r.db.QueryRow("SELECT value FROM reader_state WHERE key='eve_inode'").Scan(&raw)
	inode = uint64(raw)
	return
}

func (r *Reader) saveOffset(offset int64, inode uint64) {
	r.db.Exec("INSERT OR REPLACE INTO reader_state(key,value) VALUES('eve_offset',?)", offset)
	r.db.Exec("INSERT OR REPLACE INTO reader_state(key,value) VALUES('eve_inode',?)", int64(inode))
}

func (r *Reader) Start() {
	go r.tail()
}

func (r *Reader) RecentAlerts(n int) []Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.alerts) <= n {
		out := make([]Alert, len(r.alerts))
		copy(out, r.alerts)
		return out
	}
	return r.alerts[len(r.alerts)-n:]
}

func (r *Reader) QueryAlerts(n, offset int, f *AlertFilter) ([]Alert, int) {
	if r.db != nil {
		return r.queryDB(n, offset, f)
	}
	if f == nil {
		all := r.RecentAlerts(n)
		total := len(all)
		if offset > len(all) {
			return []Alert{}, total
		}
		end := offset + n
		if end > len(all) {
			end = len(all)
		}
		return all[offset:end], total
	}
	r.mu.Lock()
	all := make([]Alert, len(r.alerts))
	copy(all, r.alerts)
	r.mu.Unlock()

	var filtered []Alert
	for _, a := range all {
		if matchAlert(&a, f) {
			filtered = append(filtered, a)
		}
	}
	total := len(filtered)
	if offset > len(filtered) {
		return []Alert{}, total
	}
	end := offset + n
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[offset:end], total
}

func (r *Reader) queryDB(n, offset int, f *AlertFilter) ([]Alert, int) {
	where := []string{}
	args := []interface{}{}

	if f != nil {
		if f.Q != "" {
			q := "%" + f.Q + "%"
			where = append(where, `(timestamp LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR signature LIKE ? OR category LIKE ? OR comm LIKE ? OR cmdline LIKE ? OR proto LIKE ?)`)
			args = append(args, q, q, q, q, q, q, q, q)
		}
		if f.Severity != "" {
			op := "="
			val := f.Severity
			if strings.HasPrefix(val, ">") {
				op = ">"
				val = val[1:]
			} else if strings.HasPrefix(val, "<") {
				op = "<"
				val = val[1:]
			}
			if v, err := strconv.Atoi(val); err == nil {
				where = append(where, fmt.Sprintf("severity %s ?", op))
				args = append(args, v)
			}
		}
		if f.IP != "" {
			ip := "%" + f.IP + "%"
			where = append(where, `(src_ip LIKE ? OR dst_ip LIKE ?)`)
			args = append(args, ip, ip)
		}
		if f.Comm != "" {
			where = append(where, `comm LIKE ?`)
			args = append(args, "%"+f.Comm+"%")
		}
		if f.Proto != "" {
			where = append(where, `protocol = ?`)
			args = append(args, f.Proto)
		}
		if f.Action != "" {
			where = append(where, `action = ?`)
			args = append(args, f.Action)
		}
		if f.Sig != "" {
			where = append(where, `signature LIKE ?`)
			args = append(args, "%"+f.Sig+"%")
		}
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	r.db.QueryRow("SELECT COUNT(*) FROM suricata_alerts"+whereClause, args...).Scan(&total)

	query := "SELECT id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, action, signature, category, severity, gid, pid, comm, cmdline, exe, ppid, pcomm, duration, http_data, tls_data, dns_data FROM suricata_alerts" + whereClause + " ORDER BY id DESC LIMIT ? OFFSET ?"
	args = append(args, n, offset)

	rows, err := r.db.Query(query, args...)
	if err != nil {
		logutil.Error("suricata: queryDB: %v", err)
		return []Alert{}, total
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var a Alert
		var id int64
		var httpData, tlsData, dnsData string
		rows.Scan(&id, &a.Timestamp, &a.SrcIP, &a.SrcPort, &a.DstIP, &a.DstPort,
			&a.Proto, &a.Action, &a.Signature, &a.Category, &a.Severity, &a.GID,
			&a.PID, &a.Comm, &a.Cmdline, &a.Exe, &a.ParentPID, &a.ParentComm, &a.Duration,
			&httpData, &tlsData, &dnsData)
		if httpData != "" {
			json.Unmarshal([]byte(httpData), &a.HTTP)
		}
		if tlsData != "" {
			json.Unmarshal([]byte(tlsData), &a.TLS)
		}
		if dnsData != "" {
			json.Unmarshal([]byte(dnsData), &a.DNS)
		}
		alerts = append(alerts, a)
	}
	return alerts, total
}

func (r *Reader) GetStats() *Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := *r.stats
	return &s
}

type AlertFilter struct {
	Q        string // free-text search across all fields
	Severity string // >N, <N, =N
	IP       string // matches src or dst
	Comm     string
	Proto    string
	Action   string
	Sig      string // substring match on signature
}

func matchAlert(a *Alert, f *AlertFilter) bool {
	if f == nil {
		return true
	}
	if f.Q != "" {
		q := strings.ToLower(f.Q)
		haystack := strings.ToLower(
			a.Timestamp + " " + a.SrcIP + " " + a.DstIP +
				" " + a.Signature + " " + a.Category +
				" " + a.Comm + " " + a.Proto +
				" " + a.Action + " " + a.Cmdline)
		if !strings.Contains(haystack, q) {
			return false
		}
	}
	if f.Severity != "" {
		if !cmpNum(f.Severity, a.Severity) {
			return false
		}
	}
	if f.IP != "" {
		ip := strings.ToLower(f.IP)
		if !strings.Contains(strings.ToLower(a.SrcIP), ip) &&
			!strings.Contains(strings.ToLower(a.DstIP), ip) {
			return false
		}
	}
	if f.Comm != "" {
		if !strings.Contains(strings.ToLower(a.Comm), strings.ToLower(f.Comm)) {
			return false
		}
	}
	if f.Proto != "" {
		if strings.ToLower(a.Proto) != strings.ToLower(f.Proto) {
			return false
		}
	}
	if f.Action != "" {
		if strings.ToLower(a.Action) != strings.ToLower(f.Action) {
			return false
		}
	}
	if f.Sig != "" {
		if !strings.Contains(strings.ToLower(a.Signature), strings.ToLower(f.Sig)) {
			return false
		}
	}
	return true
}

func cmpNum(expr string, val int) bool {
	if len(expr) == 0 {
		return true
	}
	if expr[0] == '>' {
		if len(expr) > 1 && expr[1] == '=' {
			n, _ := strconv.Atoi(expr[2:])
			return val >= n
		}
		n, _ := strconv.Atoi(expr[1:])
		return val > n
	}
	if expr[0] == '<' {
		if len(expr) > 1 && expr[1] == '=' {
			n, _ := strconv.Atoi(expr[2:])
			return val <= n
		}
		n, _ := strconv.Atoi(expr[1:])
		return val < n
	}
	if expr[0] == '!' {
		n, _ := strconv.Atoi(expr[1:])
		return val != n
	}
	n, _ := strconv.Atoi(expr)
	if expr[0] == '=' {
		n, _ = strconv.Atoi(expr[1:])
	}
	return val == n
}

func (r *Reader) tail() {
	path := defaultEveLogPath()
	var lineCount int

	// openInProgress is closed when Stop is called, which forces us out of
	// the inner scanner loop (because we close the underlying file) and
	// out of the outer rotation loop (via the done select).
	for {
		select {
		case <-r.done:
			return
		default:
		}

		f, err := os.Open(path)
		if err != nil {
			logutil.Warn("suricata: cannot open %s: %v (retry in 5s)", path, err)
			select {
			case <-r.done:
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		// expose f to Stop() so it can interrupt the blocking scanner
		r.mu.Lock()
		r.currentFile = f
		r.mu.Unlock()

		fi, _ := f.Stat()
		var lastPos int64
		savedOff, savedInode := r.loadOffset()
		curInode := fi.Sys().(*syscall.Stat_t).Ino

		if savedInode == curInode && savedOff > 0 && savedOff <= fi.Size() {
			lastPos = savedOff
		} else if fi.Size() > 1024*1024 {
			lastPos = fi.Size() - 1024*1024
			logutil.Info("suricata: new file, tailing last 1MB")
		}

		f.Seek(lastPos, 0)
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 256*1024), 256*1024)

		for sc.Scan() {
			line := sc.Text()
			if len(line) == 0 {
				continue
			}
			lastPos += int64(len(line)) + 1
			lineCount++

			var flow eveFlow
			if err := json.Unmarshal([]byte(line), &flow); err != nil {
				continue
			}

			switch flow.EventType {
			case "alert":
				r.handleAlert(&flow)
			case "stats":
				r.handleStats(&flow)
			}

			if lineCount%100 == 0 {
				r.saveOffset(lastPos, curInode)
			}
		}

		if sc.Err() != nil {
			// ErrClosed means we deliberately closed the file from Stop()
			if !errors.Is(sc.Err(), os.ErrClosed) {
				logutil.Warn("suricata: scan error: %v", sc.Err())
			}
		}

		r.saveOffset(lastPos, curInode)
		f.Close()

		select {
		case <-r.done:
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (r *Reader) handleAlert(flow *eveFlow) {
	alert := Alert{
		Timestamp: flow.Timestamp,
		SrcIP:     flow.SrcIP,
		SrcPort:   flow.SrcPort,
		DstIP:     flow.DestIP,
		DstPort:   flow.DestPort,
		Proto:     flow.Proto,
	}

	if flow.Alert != nil {
		alert.Action = flow.Alert.Action
		alert.GID = flow.Alert.GID
		alert.Signature = flow.Alert.Signature
		alert.Category = flow.Alert.Category
		alert.Severity = flow.Alert.Severity
	}

	if flow.HTTP != nil {
		alert.HTTP = &HTTP{
			Hostname:  flow.HTTP.Hostname,
			URL:       flow.HTTP.URL,
			UserAgent: flow.HTTP.UserAgent,
			Method:    flow.HTTP.Method,
			Status:    flow.HTTP.Status,
			Mime:      flow.HTTP.Mime,
			Length:    flow.HTTP.Length,
		}
	}

	if flow.TLS != nil {
		alert.TLS = &TLS{
			Subject:     flow.TLS.Subject,
			IssuerDN:    flow.TLS.IssuerDN,
			Fingerprint: flow.TLS.Fingerprint,
			SNI:         flow.TLS.SNI,
			Version:     flow.TLS.Version,
		}
	}

	if flow.DNS != nil {
		dns := &DNS{
			Type:  flow.DNS.Type,
			Query: flow.DNS.Query,
			RCode: flow.DNS.RCode,
		}
		if flow.DNS.Answers != nil {
			for _, a := range flow.DNS.Answers {
				dns.Answers = append(dns.Answers, DNSAnswer{
					Name: a.Name,
					Type: a.Type,
					Data: a.Data,
				})
			}
		}
		alert.DNS = dns
	}

	r.enrich(&alert)

	r.mu.Lock()
	r.alerts = append(r.alerts, alert)
	if len(r.alerts) > r.maxAlert {
		r.alerts = r.alerts[len(r.alerts)-r.maxAlert:]
	}
	r.mu.Unlock()

	r.persistAlert(&alert)

	logutil.Warn("SURICATA [%d] %s: %s → %s:%d (%s)",
		alert.Severity, alert.Signature,
		alert.SrcIP, alert.DstIP, alert.DstPort, alert.Comm)
}

func (r *Reader) persistAlert(a *Alert) {
	if r.db == nil {
		return
	}
	var httpJSON, tlsJSON, dnsJSON string
	if a.HTTP != nil {
		b, _ := json.Marshal(a.HTTP)
		httpJSON = string(b)
	}
	if a.TLS != nil {
		b, _ := json.Marshal(a.TLS)
		tlsJSON = string(b)
	}
	if a.DNS != nil {
		b, _ := json.Marshal(a.DNS)
		dnsJSON = string(b)
	}
	r.db.Exec(`INSERT INTO suricata_alerts
        (timestamp, src_ip, src_port, dst_ip, dst_port, protocol, action, signature, category, severity, gid, pid, comm, cmdline, exe, ppid, pcomm, duration, http_data, tls_data, dns_data, created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.Timestamp, a.SrcIP, a.SrcPort, a.DstIP, a.DstPort, a.Proto, a.Action, a.Signature, a.Category, a.Severity, a.GID,
		a.PID, a.Comm, a.Cmdline, a.Exe, a.ParentPID, a.ParentComm, a.Duration,
		httpJSON, tlsJSON, dnsJSON, time.Now().Unix())
}

func (r *Reader) handleStats(flow *eveFlow) {
	if flow.Stats == nil {
		return
	}
	r.mu.Lock()
	if flow.Stats.Capture != nil {
		r.stats.PacketsTotal = flow.Stats.Capture.KernelPackets
		r.stats.PacketsDrop = flow.Stats.Capture.KernelDrops
	}
	if flow.Stats.Detect != nil {
		r.stats.AlertsTotal = flow.Stats.Detect.Alert
	}
	var mem int64
	if flow.Stats.Flow != nil {
		mem += flow.Stats.Flow.Memuse
	}
	if flow.Stats.Tcp != nil {
		mem += flow.Stats.Tcp.Memuse
	}
	r.stats.MemUsage = mem
	uptime := flow.Stats.Uptime
	if uptime > 0 {
		r.stats.AlertsPerSec = float64(r.stats.AlertsTotal) / float64(uptime)
	}
	r.stats.Uptime = fmt.Sprintf("%ds", uptime)
	r.mu.Unlock()
}

func (r *Reader) enrich(alert *Alert) {
	if r.cap == nil {
		return
	}
	snap := r.cap()
	var best *capture.Connection
	bestScore := 0
	for i := range snap {
		c := &snap[i]
		score := matchAlertConnection(c, alert)
		if score > bestScore {
			bestScore = score
			best = c
			if score == 2 {
				break
			}
		}
	}
	if best == nil {
		return
	}

	alert.PID = best.PID
	alert.Comm = best.Comm
	alert.Cmdline = best.Cmdline
	alert.Exe = best.Exe
	alert.ParentPID = best.PPID
	alert.ParentComm = best.PComm
	if best.CreatedAt > 0 {
		secs := time.Now().UnixMilli()/1000 - best.CreatedAt/1000
		if secs < 60 {
			alert.Duration = fmt.Sprintf("%ds", secs)
		} else if secs < 3600 {
			alert.Duration = fmt.Sprintf("%dm%ds", secs/60, secs%60)
		} else {
			alert.Duration = fmt.Sprintf("%dh%dm", secs/3600, (secs%3600)/60)
		}
	}
}

func matchAlertConnection(c *capture.Connection, alert *Alert) int {
	if c == nil || alert == nil || c.LocalAddr == nil || c.RemoteAddr == nil {
		return 0
	}

	local := c.LocalAddr.String()
	remote := c.RemoteAddr.String()

	// Highest confidence: exact tuple in the observed direction.
	if alert.SrcIP != "" && alert.DstIP != "" && alert.SrcPort > 0 && alert.DstPort > 0 &&
		local == alert.SrcIP && c.LocalPort == alert.SrcPort &&
		remote == alert.DstIP && c.RemotePort == alert.DstPort {
		return 2
	}

	// Reverse tuple still maps the same flow, but is slightly weaker.
	if alert.SrcIP != "" && alert.DstIP != "" && alert.SrcPort > 0 && alert.DstPort > 0 &&
		local == alert.DstIP && c.LocalPort == alert.DstPort &&
		remote == alert.SrcIP && c.RemotePort == alert.SrcPort {
		return 1
	}

	// Fallbacks for sparse Suricata events that only populate one side of the flow.
	if alert.DstIP != "" && alert.DstPort > 0 && remote == alert.DstIP && c.RemotePort == alert.DstPort {
		return 1
	}
	if alert.SrcIP != "" && alert.SrcPort > 0 && local == alert.SrcIP && c.LocalPort == alert.SrcPort {
		return 1
	}

	return 0
}
