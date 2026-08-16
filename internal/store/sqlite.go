package store

import (
	"database/sql"
	"fmt"
	_ "modernc.org/sqlite"
	"netmon/internal/capture"
	"netmon/internal/logutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Store struct {
	db      *sql.DB
	buffer  []capture.ConnectionEvent
	bufSize int
	mu      sync.Mutex
}

func New(path string, bufSize int) (*Store, error) {
	// Skip in-memory databases (used by tests) and special paths.
	isFileDB := path != ":memory:" && !strings.HasPrefix(path, "file::memory:")
	if isFileDB {
		os.MkdirAll(filepath.Dir(path), 0755)
		// If the DB doesn't exist yet, create it 0600 explicitly so the
		// world can't read it. The auth package stores bcrypt password
		// hashes here — they shouldn't be world-readable.
		if _, err := os.Stat(path); os.IsNotExist(err) {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return nil, fmt.Errorf("create db: %w", err)
			}
			_ = f.Close()
		} else if err == nil {
			// existing file — tighten perms if they were loose
			if err := os.Chmod(path, 0600); err != nil {
				logutil.Warn("store: could not chmod %s to 0600: %v", path, err)
			}
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &Store{
		db:      db,
		buffer:  make([]capture.ConnectionEvent, 0, bufSize),
		bufSize: bufSize,
	}, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error {
	s.flush()
	return s.db.Close()
}

func migrate(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS connections (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            pid         INTEGER NOT NULL DEFAULT 0,
            uid         INTEGER NOT NULL DEFAULT 0,
            comm        TEXT NOT NULL DEFAULT '',
            cmdline     TEXT NOT NULL DEFAULT '',
            exe         TEXT NOT NULL DEFAULT '',
            ppid        INTEGER NOT NULL DEFAULT 0,
            pcomm       TEXT NOT NULL DEFAULT '',
            local_addr  TEXT NOT NULL DEFAULT '',
            local_port  INTEGER NOT NULL DEFAULT 0,
            remote_addr TEXT NOT NULL DEFAULT '',
            remote_port INTEGER NOT NULL DEFAULT 0,
            protocol    TEXT NOT NULL DEFAULT 'tcp',
            state       TEXT NOT NULL DEFAULT '',
            tx_queue    INTEGER NOT NULL DEFAULT 0,
            rx_queue    INTEGER NOT NULL DEFAULT 0,
            inode       INTEGER NOT NULL DEFAULT 0,
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER NOT NULL,
            closed_at   INTEGER
        )`,
		`CREATE INDEX IF NOT EXISTS idx_connections_created ON connections(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_remote ON connections(remote_addr, remote_port)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_local ON connections(local_addr, local_port)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_pid ON connections(pid)`,

		`CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id     INTEGER NOT NULL DEFAULT 0,
            rule_name   TEXT NOT NULL,
            severity    TEXT NOT NULL,
            pid         INTEGER NOT NULL DEFAULT 0,
            comm        TEXT NOT NULL DEFAULT '',
            remote_addr TEXT NOT NULL DEFAULT '',
            remote_port INTEGER NOT NULL DEFAULT 0,
            message     TEXT NOT NULL DEFAULT '',
            created_at  INTEGER NOT NULL
        )`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at)`,

		`CREATE TABLE IF NOT EXISTS blocklist (
            ip          TEXT PRIMARY KEY,
            source      TEXT NOT NULL DEFAULT '',
            added_at    INTEGER NOT NULL
        )`,

		`CREATE TABLE IF NOT EXISTS process_cache (
            pid         INTEGER PRIMARY KEY,
            comm        TEXT NOT NULL DEFAULT '',
            first_seen  INTEGER NOT NULL,
            last_seen   INTEGER NOT NULL
        )`,

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
            pid         INTEGER NOT NULL DEFAULT 0,
            comm        TEXT NOT NULL DEFAULT '',
            payload     TEXT NOT NULL DEFAULT '',
            created_at  INTEGER NOT NULL
        )`,
		`CREATE INDEX IF NOT EXISTS idx_suricata_alerts_ts ON suricata_alerts(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_suricata_alerts_sig ON suricata_alerts(signature)`,
		`CREATE INDEX IF NOT EXISTS idx_suricata_alerts_sev ON suricata_alerts(severity)`,
	}

	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("exec %q: %w", q[:40], err)
		}
	}
	// migrate existing schemas — add columns that may not exist yet
	for _, alter := range []string{
		"ALTER TABLE connections ADD COLUMN cmdline TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE connections ADD COLUMN exe TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE connections ADD COLUMN ppid INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE connections ADD COLUMN pcomm TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE alerts ADD COLUMN rule_id INTEGER NOT NULL DEFAULT 0",
	} {
		db.Exec(alter)
	}

	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id)`); err != nil {
		return fmt.Errorf("create alerts rule_id index: %w", err)
	}
	return nil
}

func (s *Store) Insert(event capture.ConnectionEvent) {
	s.mu.Lock()
	s.buffer = append(s.buffer, event)
	if len(s.buffer) >= s.bufSize {
		s.flushLocked()
	}
	s.mu.Unlock()
}

func (s *Store) flush() {
	s.mu.Lock()
	s.flushLocked()
	s.mu.Unlock()
}

func (s *Store) flushLocked() {
	if len(s.buffer) == 0 {
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		logutil.Error("db begin: %v", err)
		return
	}
	defer tx.Rollback()

	now := time.Now().UnixMilli()

	for _, ev := range s.buffer {
		switch ev.Type {
		case capture.EventNew:
			_, err := tx.Exec(
				`INSERT INTO connections
                 (pid, uid, comm, cmdline, exe, ppid, pcomm,
                  local_addr, local_port, remote_addr, remote_port,
                  protocol, state, tx_queue, rx_queue, inode, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				ev.PID, ev.UID, ev.Comm, ev.Cmdline, ev.Exe, ev.PPID, ev.PComm,
				ev.LocalAddr.String(), ev.LocalPort,
				ev.RemoteAddr.String(), ev.RemotePort,
				ev.Protocol, ev.State,
				ev.TxQueue, ev.RxQueue,
				ev.Inode, ev.CreatedAt, now,
			)
			if err != nil {
				logutil.Error("insert conn: %v", err)
			}

		case capture.EventClose:
			_, err := tx.Exec(
				`UPDATE connections SET closed_at = ?, updated_at = ?,
                 tx_queue = ?, rx_queue = ?
                 WHERE local_addr = ? AND local_port = ?
                   AND remote_addr = ? AND remote_port = ? AND closed_at IS NULL`,
				now, now, ev.TxQueue, ev.RxQueue,
				ev.LocalAddr.String(), ev.LocalPort,
				ev.RemoteAddr.String(), ev.RemotePort,
			)
			if err != nil {
				logutil.Error("update conn: %v", err)
			}
		case capture.EventUpdate:
			_, err := tx.Exec(
				`UPDATE connections SET state = ?, tx_queue = ?, rx_queue = ?,
                 updated_at = ?
                 WHERE local_addr = ? AND local_port = ?
                   AND remote_addr = ? AND remote_port = ? AND closed_at IS NULL`,
				ev.State, ev.TxQueue, ev.RxQueue, now,
				ev.LocalAddr.String(), ev.LocalPort,
				ev.RemoteAddr.String(), ev.RemotePort,
			)
			if err != nil {
				logutil.Error("update conn: %v", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		logutil.Error("db commit: %v", err)
	}

	s.buffer = s.buffer[:0]
}

type Stats struct {
	TotalConns   int         `json:"total_conns"`
	ActiveConns  int         `json:"active_conns"`
	AlertCount   int         `json:"alert_count"`
	TopProcesses []ProcCount `json:"top_processes"`
	TopIPs       []IPCount   `json:"top_ips"`
}

type ProcCount struct {
	Comm  string `json:"comm"`
	Count int    `json:"count"`
}

type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

func (s *Store) Stats() Stats {
	s.flush()
	var st Stats
	s.db.QueryRow("SELECT COUNT(*) FROM connections WHERE remote_addr NOT IN ('0.0.0.0','::')").Scan(&st.TotalConns)
	s.db.QueryRow("SELECT COUNT(*) FROM connections WHERE closed_at IS NULL AND remote_addr NOT IN ('0.0.0.0','::')").Scan(&st.ActiveConns)
	s.db.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&st.AlertCount)

	rows, _ := s.db.Query("SELECT comm, COUNT(*) as c FROM connections WHERE pid > 0 AND comm != '' GROUP BY comm ORDER BY c DESC LIMIT 10")
	if rows != nil {
		for rows.Next() {
			var p ProcCount
			rows.Scan(&p.Comm, &p.Count)
			st.TopProcesses = append(st.TopProcesses, p)
		}
		rows.Close()
	}

	rows, _ = s.db.Query("SELECT remote_addr, COUNT(*) as c FROM connections WHERE remote_addr NOT IN ('0.0.0.0','::','') GROUP BY remote_addr ORDER BY c DESC LIMIT 10")
	if rows != nil {
		for rows.Next() {
			var i IPCount
			rows.Scan(&i.IP, &i.Count)
			st.TopIPs = append(st.TopIPs, i)
		}
		rows.Close()
	}

	return st
}

type ConnFilter struct {
	Process    string
	RemoteIP   string
	RemotePort int
	LocalPort  int
	Protocol   string
	State      string
	Since      int64
	Limit      int
}

type ConnResult struct {
	PID        int
	UID        int
	Comm       string
	Cmdline    string
	Exe        string
	PPID       int
	PComm      string
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
	Protocol   string
	State      string
	CreatedAt  int64
	ClosedAt   *int64
}

func (s *Store) QueryConns(f ConnFilter) ([]ConnResult, error) {
	s.flush()
	q := "SELECT pid, uid, comm, cmdline, exe, ppid, pcomm, local_addr, local_port, remote_addr, remote_port, protocol, state, created_at, closed_at FROM connections WHERE 1=1"
	var args []interface{}
	if f.Process != "" {
		q += " AND comm = ?"
		args = append(args, f.Process)
	}
	if f.RemoteIP != "" {
		q += " AND remote_addr = ?"
		args = append(args, f.RemoteIP)
	}
	if f.RemotePort > 0 {
		q += " AND remote_port = ?"
		args = append(args, f.RemotePort)
	}
	if f.LocalPort > 0 {
		q += " AND local_port = ?"
		args = append(args, f.LocalPort)
	}
	if f.Protocol != "" {
		q += " AND protocol = ?"
		args = append(args, f.Protocol)
	}
	if f.State != "" {
		q += " AND state = ?"
		args = append(args, f.State)
	}
	if f.Since > 0 {
		q += " AND created_at >= ?"
		args = append(args, f.Since)
	}
	q += " ORDER BY created_at DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []ConnResult
	for rows.Next() {
		var r ConnResult
		if err := rows.Scan(&r.PID, &r.UID, &r.Comm, &r.Cmdline, &r.Exe, &r.PPID, &r.PComm,
			&r.LocalAddr, &r.LocalPort, &r.RemoteAddr, &r.RemotePort,
			&r.Protocol, &r.State, &r.CreatedAt, &r.ClosedAt); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

type AlertFilter struct {
	Severity string
	Limit    int
}

type AlertResult struct {
	ID         int64
	RuleName   string
	Severity   string
	PID        int
	Comm       string
	RemoteAddr string
	RemotePort int
	Message    string
	CreatedAt  int64
}

type RuleUsage struct {
	RuleID         int64  `json:"rule_id"`
	Name           string `json:"name"`
	Enabled        bool   `json:"enabled"`
	Severity       string `json:"severity"`
	HitCount       int    `json:"hit_count"`
	LastAlertAt    int64  `json:"last_alert_at,omitempty"`
	LastMessage    string `json:"last_message,omitempty"`
	LastRemote     string `json:"last_remote,omitempty"`
	LastRemotePort int    `json:"last_remote_port,omitempty"`
	LastComm       string `json:"last_comm,omitempty"`
}

func (s *Store) QueryAlerts(f AlertFilter) ([]AlertResult, error) {
	s.flush()
	q := "SELECT id, rule_name, severity, pid, comm, remote_addr, remote_port, message, created_at FROM alerts WHERE 1=1"
	var args []interface{}
	if f.Severity != "" {
		q += " AND severity = ?"
		args = append(args, f.Severity)
	}
	q += " ORDER BY created_at DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []AlertResult
	for rows.Next() {
		var r AlertResult
		if err := rows.Scan(&r.ID, &r.RuleName, &r.Severity, &r.PID, &r.Comm, &r.RemoteAddr, &r.RemotePort, &r.Message, &r.CreatedAt); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

func (s *Store) GetAlert(id int64) (*AlertResult, error) {
	s.flush()
	var r AlertResult
	err := s.db.QueryRow(
		`SELECT id, rule_name, severity, pid, comm, remote_addr, remote_port, message, created_at FROM alerts WHERE id = ?`,
		id,
	).Scan(&r.ID, &r.RuleName, &r.Severity, &r.PID, &r.Comm, &r.RemoteAddr, &r.RemotePort, &r.Message, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) RuleUsage() ([]RuleUsage, error) {
	s.flush()
	rows, err := s.db.Query(`
		SELECT
			r.id,
			r.name,
			r.enabled,
			r.severity,
			COALESCE(SUM(
				CASE
					WHEN a.rule_id = r.id OR (a.rule_id = 0 AND a.rule_name = r.name) THEN 1
					ELSE 0
				END
			), 0) AS hit_count
		FROM rules r
		LEFT JOIN alerts a ON a.rule_id = r.id OR (a.rule_id = 0 AND a.rule_name = r.name)
		GROUP BY r.id, r.name, r.enabled, r.severity
		ORDER BY hit_count DESC, r.id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usages []RuleUsage
	for rows.Next() {
		var u RuleUsage
		if err := rows.Scan(&u.RuleID, &u.Name, &u.Enabled, &u.Severity, &u.HitCount); err != nil {
			return nil, err
		}
		usages = append(usages, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(usages) == 0 {
		return usages, nil
	}

	for i := range usages {
		var (
			lastMessage    string
			lastRemote     string
			lastRemotePort int
			lastComm       string
		)
		err := s.db.QueryRow(`
			SELECT comm, remote_addr, remote_port, message, created_at
			FROM alerts
			WHERE rule_id = ? OR (rule_id = 0 AND rule_name = ?)
			ORDER BY created_at DESC
			LIMIT 1
		`, usages[i].RuleID, usages[i].Name).Scan(&lastComm, &lastRemote, &lastRemotePort, &lastMessage, &usages[i].LastAlertAt)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, err
		}
		usages[i].LastMessage = lastMessage
		usages[i].LastRemote = lastRemote
		usages[i].LastRemotePort = lastRemotePort
	}

	return usages, nil
}

type AnalysisContext struct {
	CurrentConns []ConnResult
	HistoryConns []ConnResult
	Alerts       []AlertResult
	TotalHistory int
}

func (s *Store) GetAnalysisContext(remoteIP string, remotePort int) (*AnalysisContext, error) {
	s.flush()
	ctx := &AnalysisContext{}

	current, err := s.QueryConns(ConnFilter{
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
		State:      "ESTABLISHED",
		Limit:      50,
	})
	if err != nil {
		return nil, err
	}
	ctx.CurrentConns = current

	history, err := s.QueryConns(ConnFilter{
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
		Limit:      100,
	})
	if err != nil {
		return nil, err
	}
	ctx.HistoryConns = history
	ctx.TotalHistory = len(history)

	alerts, err := s.QueryAlerts(AlertFilter{
		Limit: 50,
	})
	if err != nil {
		return nil, err
	}
	var filtered []AlertResult
	for _, a := range alerts {
		if a.RemoteAddr == remoteIP {
			filtered = append(filtered, a)
		}
	}
	ctx.Alerts = filtered

	return ctx, nil
}

func (s *Store) GetConnHistory(remoteIP string, limit int) ([]ConnResult, error) {
	return s.QueryConns(ConnFilter{RemoteIP: remoteIP, Limit: limit})
}

func (s *Store) insertAlert(rule, severity string, pid int, comm, remoteAddr string, remotePort int, message string, ruleID ...int64) {
	var rid int64
	if len(ruleID) > 0 {
		rid = ruleID[0]
	}
	s.db.Exec(
		`INSERT INTO alerts(rule_id, rule_name, severity, pid, comm, remote_addr, remote_port, message, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		rid, rule, severity, pid, comm, remoteAddr, remotePort, message, time.Now().UnixMilli(),
	)
}

func (s *Store) BlocklistIP(ip string, source string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO blocklist(ip, source, added_at) VALUES(?,?,?)`,
		ip, source, time.Now().Unix(),
	)
	return err
}
