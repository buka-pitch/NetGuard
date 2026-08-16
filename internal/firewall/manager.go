package firewall

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"netmon/internal/logutil"
	"sync"
	"time"
)

type Manager struct {
	mu       sync.Mutex
	db       *sql.DB
	panicEnd int64
}

func New(db *sql.DB) *Manager {
	return &Manager{db: db}
}

func (m *Manager) InitDB() {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS allowlist (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			exe_path   TEXT NOT NULL DEFAULT '',
			process    TEXT NOT NULL DEFAULT '',
			ip         TEXT NOT NULL DEFAULT '',
			port       INTEGER NOT NULL DEFAULT 0,
			proto      TEXT NOT NULL DEFAULT 'tcp',
			mode       TEXT NOT NULL DEFAULT 'once',
			ttl_secs   INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS pending_approvals (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			exe_path    TEXT NOT NULL DEFAULT '',
			process     TEXT NOT NULL DEFAULT '',
			parent_chain TEXT NOT NULL DEFAULT '',
			ip          TEXT NOT NULL DEFAULT '',
			port        INTEGER NOT NULL DEFAULT 0,
			proto       TEXT NOT NULL DEFAULT 'tcp',
			pid         INTEGER NOT NULL DEFAULT 0,
			created_at  INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_approvals(created_at)`,
		`ALTER TABLE pending_approvals ADD COLUMN domain TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE pending_approvals ADD COLUMN app_data TEXT NOT NULL DEFAULT ''`,
		`CREATE TABLE IF NOT EXISTS app_allowlist (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			exe_path   TEXT NOT NULL DEFAULT '',
			process    TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL
		)`,
		// remove old broad preseed entries that opened all traffic
		`DELETE FROM allowlist WHERE port=0 AND (process='NetworkManager' OR process='sshd' OR process='netmon')`,
		`ALTER TABLE allowlist ADD COLUMN direction TEXT NOT NULL DEFAULT 'out'`,
		`ALTER TABLE pending_approvals ADD COLUMN direction TEXT NOT NULL DEFAULT 'out'`,
		`CREATE TABLE IF NOT EXISTS blocklist (
			ip          TEXT PRIMARY KEY,
			source      TEXT NOT NULL DEFAULT '',
			added_at    INTEGER NOT NULL
		)`,
		`ALTER TABLE blocklist ADD COLUMN process TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE blocklist ADD COLUMN port INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE blocklist ADD COLUMN proto TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE blocklist ADD COLUMN direction TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE blocklist ADD COLUMN domain TEXT NOT NULL DEFAULT ''`,
		`CREATE TABLE IF NOT EXISTS app_denylist (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			exe_path    TEXT NOT NULL DEFAULT '',
			process     TEXT NOT NULL DEFAULT '',
			created_at  INTEGER NOT NULL
		)`,
		`ALTER TABLE pending_approvals ADD COLUMN source TEXT NOT NULL DEFAULT 'new'`,
	}
	for _, q := range queries {
		if _, err := m.db.Exec(q); err != nil {
			logutil.Error("firewall: initDB: %v", err)
		}
	}
}

func (m *Manager) LoadAllowlist() ([]Rule, error) {
	rows, err := m.db.Query("SELECT id, exe_path, process, ip, port, proto, mode, direction, ttl_secs, created_at FROM allowlist WHERE mode='always'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []Rule
	for rows.Next() {
		var r Rule
		rows.Scan(&r.ID, &r.ExePath, &r.Process, &r.IP, &r.Port, &r.Proto, &r.Mode, &r.Direction, &r.TTLSecs, &r.CreatedAt)
		rules = append(rules, r)
	}
	return rules, nil
}

func (m *Manager) LoadAllowlistPaged(page, perPage int) ([]Rule, int, error) {
	var total int
	m.db.QueryRow("SELECT COUNT(*) FROM allowlist WHERE mode='always'").Scan(&total)
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * perPage
	rows, err := m.db.Query("SELECT id, exe_path, process, ip, port, proto, mode, direction, ttl_secs, created_at FROM allowlist WHERE mode='always' ORDER BY created_at DESC LIMIT ? OFFSET ?", perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var rules []Rule
	for rows.Next() {
		var r Rule
		rows.Scan(&r.ID, &r.ExePath, &r.Process, &r.IP, &r.Port, &r.Proto, &r.Mode, &r.Direction, &r.TTLSecs, &r.CreatedAt)
		rules = append(rules, r)
	}
	return rules, total, nil
}

func (m *Manager) AddRule(r Rule) (int64, error) {
	r.CreatedAt = time.Now().Unix()
	if r.Direction == "" {
		r.Direction = "out"
	}
	res, err := m.db.Exec("INSERT INTO allowlist(exe_path, process, ip, port, proto, mode, direction, ttl_secs, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
		r.ExePath, r.Process, r.IP, r.Port, r.Proto, r.Mode, r.Direction, r.TTLSecs, r.CreatedAt)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	r.ID = id
	logutil.Info("firewall: added rule %d: %s → %s:%d/%s (%s dir=%s)", id, r.Process, r.IP, r.Port, r.Proto, r.Mode, r.Direction)
	return id, nil
}

func (m *Manager) RemoveRule(id int64) error {
	_, err := m.db.Exec("DELETE FROM allowlist WHERE id=?", id)
	return err
}

func (m *Manager) DeleteRule(id int64) error {
	var ip, proto, direction string
	var port int
	row := m.db.QueryRow("SELECT ip, port, proto, direction FROM allowlist WHERE id=?", id)
	if err := row.Scan(&ip, &port, &proto, &direction); err != nil {
		return err
	}
	if ip != "" && port > 0 {
		if direction == "in" {
			if err := m.RevokeIn(ip, proto, port); err != nil {
				logutil.Error("firewall: DeleteRule revoke-in %s %s/%d: %v", ip, proto, port, err)
			}
		} else {
			if err := m.Revoke(ip, proto, port); err != nil {
				logutil.Error("firewall: DeleteRule revoke %s %s/%d: %v", ip, proto, port, err)
			}
		}
	}
	_, err := m.db.Exec("DELETE FROM allowlist WHERE id=?", id)
	return err
}

func (m *Manager) QueuePending(p Pending) (int64, error) {
	p.CreatedAt = time.Now().Unix()
	if p.Direction == "" {
		p.Direction = "out"
	}
	if p.Source == "" {
		p.Source = "new"
	}
	res, err := m.db.Exec("INSERT INTO pending_approvals(exe_path, process, parent_chain, ip, port, proto, direction, pid, domain, app_data, source, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
		p.ExePath, p.Process, p.ParentChain, p.IP, p.Port, p.Proto, p.Direction, p.Pid, p.Domain, p.AppData, p.Source, p.CreatedAt)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	p.ID = id
	return id, nil
}

func (m *Manager) GetPending() ([]Pending, error) {
	cutoff := time.Now().Add(-5 * time.Minute).Unix()
	m.db.Exec("DELETE FROM pending_approvals WHERE created_at < ?", cutoff)

	rows, err := m.db.Query("SELECT id, exe_path, process, parent_chain, ip, port, proto, direction, pid, domain, app_data, source, created_at FROM pending_approvals ORDER BY created_at DESC LIMIT 50")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Pending
	for rows.Next() {
		var p Pending
		rows.Scan(&p.ID, &p.ExePath, &p.Process, &p.ParentChain, &p.IP, &p.Port, &p.Proto, &p.Direction, &p.Pid, &p.Domain, &p.AppData, &p.Source, &p.CreatedAt)
		list = append(list, p)
	}
	return list, nil
}

func (m *Manager) UpdatePendingAppData(id int64, appData string) error {
	_, err := m.db.Exec("UPDATE pending_approvals SET app_data=? WHERE id=?", appData, id)
	return err
}

func (m *Manager) RemovePending(id int64) error {
	_, err := m.db.Exec("DELETE FROM pending_approvals WHERE id=?", id)
	return err
}

func (m *Manager) ClearPending() error {
	_, err := m.db.Exec("DELETE FROM pending_approvals")
	return err
}

func (m *Manager) Approve(id int64, mode string) error {
	pending, err := m.getPending(id)
	if err != nil {
		return err
	}

	r := Rule{
		ExePath:   pending.ExePath,
		Process:   pending.Process,
		IP:        pending.IP,
		Port:      pending.Port,
		Proto:     pending.Proto,
		Direction: pending.Direction,
		Mode:      mode,
	}
	if mode == "once" {
		r.TTLSecs = 300
	}

	if _, err := m.AddRule(r); err != nil {
		return err
	}

	// nftables rule — log failure but don't leave stale pending
	if r.Direction == "in" {
		if err := m.AllowIn(pending.IP, pending.Proto, pending.Port); err != nil {
			logutil.Error("firewall: Approve AllowIn(%s,%s,%d): %v", pending.IP, pending.Proto, pending.Port, err)
		}
	} else {
		if err := m.Allow(pending.IP, pending.Proto, pending.Port); err != nil {
			logutil.Error("firewall: Approve Allow(%s,%s,%d): %v", pending.IP, pending.Proto, pending.Port, err)
		}
	}
	return m.RemovePending(pending.ID)
}

func (m *Manager) CleanExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().Unix()
	rows, err := m.db.Query("SELECT id, ip, port, proto, direction, created_at, ttl_secs FROM allowlist WHERE mode='once' AND ((ttl_secs > 0 AND created_at + ttl_secs < ?) OR (ttl_secs = 0 AND created_at + 300 < ?))", now, now)
	if err != nil {
		logutil.Error("firewall: CleanExpired query: %v", err)
		return
	}
	defer rows.Close()

	type expiredEntry struct {
		ID        int64
		IP        string
		Port      int
		Proto     string
		Direction string
	}
	var expired []expiredEntry
	for rows.Next() {
		var e struct {
			ID        int64
			IP        string
			Port      int
			Proto     string
			Direction string
			CreatedAt int64
			TTLSecs   int
		}
		if err := rows.Scan(&e.ID, &e.IP, &e.Port, &e.Proto, &e.Direction, &e.CreatedAt, &e.TTLSecs); err != nil {
			logutil.Error("firewall: CleanExpired scan: %v", err)
			continue
		}
		expired = append(expired, expiredEntry{e.ID, e.IP, e.Port, e.Proto, e.Direction})
	}
	for _, e := range expired {
		if e.Direction == "in" {
			if err := m.RevokeIn(e.IP, e.Proto, e.Port); err != nil {
				logutil.Error("firewall: CleanExpired revoke-in %s %s/%d: %v", e.IP, e.Proto, e.Port, err)
			}
		} else {
			if err := m.Revoke(e.IP, e.Proto, e.Port); err != nil {
				logutil.Error("firewall: CleanExpired revoke %s %s/%d: %v", e.IP, e.Proto, e.Port, err)
			}
		}
		m.db.Exec("DELETE FROM allowlist WHERE id=?", e.ID)
		logutil.Info("firewall: expired rule %d: %s:%d/%s", e.ID, e.IP, e.Port, e.Proto)
	}
}

func (m *Manager) StartExpiryLoop() {
	go func() {
		for {
			time.Sleep(30 * time.Second)
			m.CleanExpired()
		}
	}()
	logutil.Info("firewall: TTL expiry loop started (30s interval)")
}

func (m *Manager) getPending(id int64) (*Pending, error) {
	row := m.db.QueryRow("SELECT id, exe_path, process, parent_chain, ip, port, proto, direction, pid, domain, app_data, created_at FROM pending_approvals WHERE id=?", id)
	var p Pending
	err := row.Scan(&p.ID, &p.ExePath, &p.Process, &p.ParentChain, &p.IP, &p.Port, &p.Proto, &p.Direction, &p.Pid, &p.Domain, &p.AppData, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (m *Manager) Deny(id int64) error {
	p, err := m.getPending(id)
	if err != nil {
		return err
	}
	if p.IP != "" && p.Port > 0 {
		if p.Direction == "in" {
			m.RevokeIn(p.IP, p.Proto, p.Port)
		} else {
			m.Revoke(p.IP, p.Proto, p.Port)
		}
	}
	m.db.Exec("INSERT OR IGNORE INTO blocklist(ip, source, added_at, process, port, proto, direction, domain) VALUES(?,?,?,?,?,?,?,?)",
		p.IP, "firewall-deny", time.Now().Unix(), p.Process, p.Port, p.Proto, p.Direction, p.Domain)
	return m.RemovePending(id)
}

type BlocklistEntry struct {
	IP        string `json:"ip"`
	Source    string `json:"source"`
	AddedAt   int64  `json:"added_at"`
	Process   string `json:"process"`
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Direction string `json:"direction"`
	Domain    string `json:"domain"`
}

func (m *Manager) LoadBlocklist() ([]BlocklistEntry, error) {
	rows, err := m.db.Query("SELECT ip, source, added_at, process, port, proto, direction, domain FROM blocklist ORDER BY added_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlocklistEntry
	for rows.Next() {
		var e BlocklistEntry
		if err := rows.Scan(&e.IP, &e.Source, &e.AddedAt, &e.Process, &e.Port, &e.Proto, &e.Direction, &e.Domain); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (m *Manager) LoadBlocklistPaged(page, perPage int) ([]BlocklistEntry, int, error) {
	var total int
	m.db.QueryRow("SELECT COUNT(*) FROM blocklist").Scan(&total)
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * perPage
	rows, err := m.db.Query("SELECT ip, source, added_at, process, port, proto, direction, domain FROM blocklist ORDER BY added_at DESC LIMIT ? OFFSET ?", perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []BlocklistEntry
	for rows.Next() {
		var e BlocklistEntry
		if err := rows.Scan(&e.IP, &e.Source, &e.AddedAt, &e.Process, &e.Port, &e.Proto, &e.Direction, &e.Domain); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out, total, nil
}

func (m *Manager) LoadBlocklistIPs() ([]string, error) {
	rows, err := m.db.Query("SELECT ip FROM blocklist")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			continue
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func (m *Manager) RemoveBlocklist(ip string) error {
	_, err := m.db.Exec("DELETE FROM blocklist WHERE ip=?", ip)
	return err
}

func (m *Manager) Block(ip string, port int) error {
	return m.Revoke(ip, "tcp", port)
}

func (m *Manager) PanicMode(duration time.Duration) {
	m.mu.Lock()
	m.panicEnd = time.Now().Add(duration).Unix()
	m.mu.Unlock()
	m.SetPolicy("accept")
	logutil.Warn("firewall: panic mode for %s", duration)
	go func() {
		time.Sleep(duration)
		m.mu.Lock()
		m.panicEnd = 0
		m.mu.Unlock()
		m.SetPolicy("drop")
		logutil.Warn("firewall: panic mode ended")
	}()
}

func (m *Manager) ClearPanic() {
	m.mu.Lock()
	m.panicEnd = 0
	m.mu.Unlock()
	m.SetPolicy("drop")
	logutil.Info("firewall: panic mode cleared")
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	panicEnd := m.panicEnd
	m.mu.Unlock()

	policy, _ := m.GetPolicy()
	pendings, _ := m.GetPending()

	return Status{
		Enabled:    m.IsEnabled(),
		Policy:     policy,
		Rules:      m.RuleCount(),
		Pending:    len(pendings),
		PanicMode:  panicEnd > time.Now().Unix(),
		PanicUntil: panicEnd,
	}
}

func (m *Manager) AllowApp(exePath, process string) error {
	var exists int
	m.db.QueryRow("SELECT COUNT(*) FROM app_allowlist WHERE exe_path=? OR process=?", exePath, process).Scan(&exists)
	if exists > 0 {
		return nil // already allowed, idempotent
	}
	_, err := m.db.Exec("INSERT INTO app_allowlist(exe_path, process, created_at) VALUES(?,?,?)", exePath, process, time.Now().Unix())
	if err == nil {
		logutil.Info("firewall: app allowed: %s (%s)", process, exePath)
	}
	return err
}

func (m *Manager) RemoveApp(id int64) error {
	r, err := m.db.Exec("DELETE FROM app_allowlist WHERE id=?", id)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return fmt.Errorf("app allowlist entry %d not found", id)
	}
	return nil
}

func (m *Manager) ListAllowedApps() ([]AppAllowlistEntry, error) {
	rows, err := m.db.Query("SELECT id, exe_path, process, created_at FROM app_allowlist ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []AppAllowlistEntry
	for rows.Next() {
		var e AppAllowlistEntry
		if err := rows.Scan(&e.ID, &e.ExePath, &e.Process, &e.CreatedAt); err != nil {
			logutil.Error("firewall: ListAllowedApps scan: %v", err)
			continue
		}
		list = append(list, e)
	}
	return list, nil
}

func (m *Manager) IsAppAllowed(exePath, process string) bool {
	row := m.db.QueryRow("SELECT COUNT(*) FROM app_allowlist WHERE exe_path=? OR process=?", exePath, process)
	var count int
	row.Scan(&count)
	return count > 0
}

func (m *Manager) IsAppDenied(exePath, process string) bool {
	row := m.db.QueryRow("SELECT COUNT(*) FROM app_denylist WHERE exe_path=? OR process=?", exePath, process)
	var count int
	row.Scan(&count)
	return count > 0
}

func (m *Manager) isBlocklisted(ip string) bool {
	if ip == "" {
		return false
	}
	row := m.db.QueryRow("SELECT COUNT(*) FROM blocklist WHERE ip=?", ip)
	var count int
	if err := row.Scan(&count); err != nil {
		return false
	}
	return count > 0
}

func (m *Manager) AddAppDeny(exePath, process string) error {
	_, err := m.db.Exec("INSERT OR IGNORE INTO app_denylist(exe_path, process, created_at) VALUES(?,?,?)", exePath, process, time.Now().Unix())
	return err
}

func (m *Manager) RemoveAppDeny(id int64) error {
	_, err := m.db.Exec("DELETE FROM app_denylist WHERE id=?", id)
	return err
}

func (m *Manager) LoadAppDenylist() ([]AppDenylistEntry, error) {
	rows, err := m.db.Query("SELECT id, exe_path, process, created_at FROM app_denylist ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []AppDenylistEntry
	for rows.Next() {
		var e AppDenylistEntry
		if err := rows.Scan(&e.ID, &e.ExePath, &e.Process, &e.CreatedAt); err != nil {
			logutil.Error("firewall: LoadAppDenylist scan: %v", err)
			continue
		}
		list = append(list, e)
	}
	return list, nil
}

func (m *Manager) DenyApp(id int64) error {
	p, err := m.getPending(id)
	if err != nil {
		return err
	}
	if err := m.AddAppDeny(p.ExePath, p.Process); err != nil {
		return err
	}
	return m.Deny(id)
}

func (m *Manager) IsBlocked(pid int, exePath, process, ip, proto string, port int) bool {
	// app-level denylist — always blocked (silent drop)
	if m.IsAppDenied(exePath, process) {
		return true
	}
	// IP blocklist must win even for allowlisted apps.
	if m.isBlocklisted(ip) {
		return true
	}
	// app-level allowlist bypasses per-connection checks when not blocklisted
	if m.IsAppAllowed(exePath, process) {
		return false
	}
	// allowlist can have wildcard IP="0.0.0.0/0" (any) and port=0 (any)
	// matches by exe_path OR process name (so renames/relocated binaries still get approved)
	// only matches outgoing rules (direction='out')
	row := m.db.QueryRow(`
		SELECT COUNT(*) FROM allowlist
		WHERE proto=? AND direction='out'
		  AND (port=? OR port=0)
		  AND (ip=? OR ip='0.0.0.0/0')
		  AND (exe_path=? OR process=?)
	`, proto, port, ip, exePath, process)
	var count int
	row.Scan(&count)
	return count == 0
}

func (m *Manager) AlreadyPending(exePath, ip, proto string, port int) bool {
	cutoff := time.Now().Add(-30 * time.Second).Unix()
	m.db.Exec("DELETE FROM pending_approvals WHERE exe_path=? AND ip=? AND proto=? AND port=? AND created_at < ? AND direction='out'", exePath, ip, proto, port, cutoff)

	row := m.db.QueryRow("SELECT COUNT(*) FROM pending_approvals WHERE exe_path=? AND ip=? AND proto=? AND port=? AND created_at >= ? AND direction='out'", exePath, ip, proto, port, cutoff)
	var count int
	row.Scan(&count)
	return count > 0
}

func (m *Manager) IsBlockedIn(pid int, exePath, process, ip, proto string, port int) bool {
	if m.IsAppDenied(exePath, process) {
		return true
	}
	if m.isBlocklisted(ip) {
		return true
	}
	if m.IsAppAllowed(exePath, process) {
		return false
	}
	// incoming rules match by saddr (source IP of the remote)
	row := m.db.QueryRow(`
		SELECT COUNT(*) FROM allowlist
		WHERE proto=? AND direction='in'
		  AND (port=? OR port=0)
		  AND (ip=? OR ip='0.0.0.0/0')
	`, proto, port, ip)
	var count int
	row.Scan(&count)
	return count == 0
}

func (m *Manager) AlreadyPendingIn(exePath, ip, proto string, port int) bool {
	cutoff := time.Now().Add(-30 * time.Second).Unix()
	m.db.Exec("DELETE FROM pending_approvals WHERE exe_path=? AND ip=? AND proto=? AND port=? AND created_at < ? AND direction='in'", exePath, ip, proto, port, cutoff)

	row := m.db.QueryRow("SELECT COUNT(*) FROM pending_approvals WHERE exe_path=? AND ip=? AND proto=? AND port=? AND created_at >= ? AND direction='in'", exePath, ip, proto, port, cutoff)
	var count int
	row.Scan(&count)
	return count > 0
}

func (m *Manager) PreSeed() {
	preseed := []Rule{
		// DNS — needed by systemd-resolved (and any process via it)
		{Process: "systemd-resolved", ExePath: "/usr/lib/systemd/systemd-resolved", IP: "0.0.0.0/0", Port: 53, Proto: "udp", Mode: "always"},
		{Process: "systemd-resolved", ExePath: "/usr/lib/systemd/systemd-resolved", IP: "0.0.0.0/0", Port: 53, Proto: "tcp", Mode: "always"},
		// NTP — chronyd
		{Process: "chronyd", ExePath: "/usr/bin/chronyd", IP: "0.0.0.0/0", Port: 123, Proto: "udp", Mode: "always"},
		// DHCP — dhcpcd
		{Process: "dhcpcd", ExePath: "/usr/bin/dhcpcd", IP: "0.0.0.0/0", Port: 67, Proto: "udp", Mode: "always"},
		{Process: "dhcpcd", ExePath: "/usr/bin/dhcpcd", IP: "0.0.0.0/0", Port: 68, Proto: "udp", Mode: "always"},
		{Process: "dhcpcd", ExePath: "/usr/bin/dhcpcd", IP: "0.0.0.0/0", Port: 546, Proto: "udp", Mode: "always"},
	}
	for _, r := range preseed {
		var exists int
		m.db.QueryRow("SELECT COUNT(*) FROM allowlist WHERE exe_path=? AND ip=? AND port=? AND proto=?", r.ExePath, r.IP, r.Port, r.Proto).Scan(&exists)
		if exists == 0 {
			m.AddRule(r)
			if err := m.Allow(r.IP, r.Proto, r.Port); err != nil {
				logutil.Error("firewall: preseed Allow %s %s/%d: %v", r.Process, r.Proto, r.Port, err)
			}
		}
	}
	logutil.Info("firewall: preseeded %d system rules", len(preseed))
}

func HTTPClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second}
}

func TrayPollStatus(serverURL string) (*Status, error) {
	resp, err := HTTPClient().Get(serverURL + "/api/firewall/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var s Status
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}
