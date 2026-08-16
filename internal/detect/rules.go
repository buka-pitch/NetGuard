package detect

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netmon/internal/capture"
	"netmon/internal/logutil"
)

type CustomRule struct {
	ID         int64          `json:"id"`
	Name       string         `json:"name"`
	Enabled    bool           `json:"enabled"`
	Severity   Severity       `json:"severity"`
	Conditions RuleConditions `json:"conditions"`
	CreatedAt  int64          `json:"created_at"`
}

type RuleConditions struct {
	ProcessName string  `json:"process_name,omitempty"`
	IPRange     string  `json:"ip_range,omitempty"`
	PortRange   string  `json:"port_range,omitempty"`
	MinInterval int64   `json:"min_interval,omitempty"`
	MaxInterval int64   `json:"max_interval,omitempty"`
	MinSamples  int     `json:"min_samples,omitempty"`
	EntropyMax  float64 `json:"entropy_max,omitempty"`
}

func ValidateRuleConditions(c RuleConditions) error {
	if c.MinInterval < 0 {
		return fmt.Errorf("min_interval must be >= 0")
	}
	if c.MaxInterval < 0 {
		return fmt.Errorf("max_interval must be >= 0")
	}
	if c.MinSamples < 0 {
		return fmt.Errorf("min_samples must be >= 0")
	}
	if c.EntropyMax < 0 {
		return fmt.Errorf("entropy_max must be >= 0")
	}
	if c.MinInterval > 0 && c.MaxInterval > 0 && c.MinInterval > c.MaxInterval {
		return fmt.Errorf("min_interval cannot be greater than max_interval")
	}
	if c.IPRange != "" {
		if err := validateIPRange(c.IPRange); err != nil {
			return err
		}
	}
	if c.PortRange != "" {
		if err := validatePortRange(c.PortRange); err != nil {
			return err
		}
	}
	return nil
}

func validateIPRange(ipRange string) error {
	if _, err := netip.ParsePrefix(ipRange); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(ipRange); err == nil {
		return nil
	}
	return fmt.Errorf("invalid ip_range %q", ipRange)
}

func validatePortRange(portRange string) error {
	for _, part := range strings.Split(portRange, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return fmt.Errorf("invalid port_range %q: empty segment", portRange)
		}
		if strings.Contains(part, "-") {
			parts := strings.SplitN(part, "-", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return fmt.Errorf("invalid port_range segment %q", part)
			}
			lo, hi, err := parsePortBounds(parts[0], parts[1])
			if err != nil {
				return fmt.Errorf("invalid port_range segment %q: %w", part, err)
			}
			if lo > hi {
				return fmt.Errorf("invalid port_range segment %q: low greater than high", part)
			}
		} else {
			if _, err := parsePortValue(part); err != nil {
				return fmt.Errorf("invalid port_range value %q: %w", part, err)
			}
		}
	}
	return nil
}

func parsePortBounds(loStr, hiStr string) (int, int, error) {
	lo, err := parsePortValue(loStr)
	if err != nil {
		return 0, 0, err
	}
	hi, err := parsePortValue(hiStr)
	if err != nil {
		return 0, 0, err
	}
	return lo, hi, nil
}

func parsePortValue(v string) (int, error) {
	out, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, err
	}
	if out < 0 || out > 65535 {
		return 0, fmt.Errorf("port out of range")
	}
	return out, nil
}

type RuleStore struct {
	mu    sync.Mutex
	db    *sql.DB
	rules []CustomRule
}

func NewRuleStore(db *sql.DB) *RuleStore {
	rs := &RuleStore{db: db}
	rs.migrate()
	rs.load()
	return rs
}

func (rs *RuleStore) migrate() {
	rs.db.Exec(`CREATE TABLE IF NOT EXISTS rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		severity TEXT NOT NULL DEFAULT 'medium',
		conditions TEXT NOT NULL DEFAULT '{}',
		created_at INTEGER NOT NULL
	)`)
}

func (rs *RuleStore) load() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = nil
	rows, err := rs.db.Query("SELECT id, name, enabled, severity, conditions, created_at FROM rules ORDER BY id")
	if err != nil {
		logutil.Error("rules: load: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var r CustomRule
		var condJSON string
		if err := rows.Scan(&r.ID, &r.Name, &r.Enabled, &r.Severity, &condJSON, &r.CreatedAt); err != nil {
			logutil.Error("rules: scan: %v", err)
			continue
		}
		json.Unmarshal([]byte(condJSON), &r.Conditions)
		rs.rules = append(rs.rules, r)
	}
}

func (rs *RuleStore) List() []CustomRule {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make([]CustomRule, len(rs.rules))
	copy(out, rs.rules)
	return out
}

func (rs *RuleStore) Add(name string, severity Severity, conditions RuleConditions) (int64, error) {
	if err := ValidateRuleConditions(conditions); err != nil {
		return 0, err
	}
	condJSON, _ := json.Marshal(conditions)
	now := time.Now().Unix()
	res, err := rs.db.Exec("INSERT INTO rules(name, enabled, severity, conditions, created_at) VALUES(?,1,?,?,?)",
		name, severity, string(condJSON), now)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	rs.load()
	logutil.Info("rules: added %q (id=%d)", name, id)
	return id, nil
}

func (rs *RuleStore) Update(id int64, name string, enabled bool, severity Severity, conditions RuleConditions) error {
	if err := ValidateRuleConditions(conditions); err != nil {
		return err
	}
	condJSON, _ := json.Marshal(conditions)
	_, err := rs.db.Exec("UPDATE rules SET name=?, enabled=?, severity=?, conditions=? WHERE id=?",
		name, enabled, severity, string(condJSON), id)
	if err == nil {
		rs.load()
	}
	return err
}

func (rs *RuleStore) Toggle(id int64, enabled bool) error {
	_, err := rs.db.Exec("UPDATE rules SET enabled=? WHERE id=?", enabled, id)
	if err == nil {
		rs.load()
	}
	return err
}

func (rs *RuleStore) Delete(id int64) error {
	_, err := rs.db.Exec("DELETE FROM rules WHERE id=?", id)
	if err == nil {
		rs.load()
	}
	return err
}

func (rs *RuleStore) GetEnabled() []CustomRule {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	var out []CustomRule
	for _, r := range rs.rules {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out
}

type crBeaconKey struct {
	RuleID int64
	PID    int
	Addr   string
	Port   int
}

type CustomRuleMatcher struct {
	store      *RuleStore
	mu         sync.Mutex
	beaconTrak map[crBeaconKey][]int64
}

func NewCustomRuleMatcher(store *RuleStore) *CustomRuleMatcher {
	return &CustomRuleMatcher{
		store:      store,
		beaconTrak: make(map[crBeaconKey][]int64),
	}
}

func (m *CustomRuleMatcher) Name() string { return "custom_rules" }

func (m *CustomRuleMatcher) Eval(event capture.ConnectionEvent, eng *Engine) *Alert {
	if event.Type != capture.EventNew {
		return nil
	}

	rules := m.store.GetEnabled()

	for _, rule := range rules {
		c := rule.Conditions

		if !RuleMatchesStatic(c, event.Connection) {
			continue
		}
		if hasBeaconConditions(c) {
			if alert := m.evalBeacon(rule, event); alert != nil {
				return alert
			}
			continue
		}

		return &Alert{
			RuleID:     rule.ID,
			RuleName:   rule.Name,
			Severity:   rule.Severity,
			PID:        event.PID,
			Comm:       event.Comm,
			RemoteAddr: remoteIPString(event.RemoteAddr),
			RemotePort: event.RemotePort,
			Message:    fmt.Sprintf("Custom rule %q matched: %s → %s:%d", rule.Name, event.Comm, remoteIPString(event.RemoteAddr), event.RemotePort),
			CreatedAt:  time.Now().UnixMilli(),
		}
	}
	return nil
}

func (m *CustomRuleMatcher) evalBeacon(rule CustomRule, event capture.ConnectionEvent) *Alert {
	c := rule.Conditions
	if event.RemoteAddr == nil || event.RemoteAddr.IsLoopback() {
		return nil
	}

	key := crBeaconKey{
		RuleID: rule.ID,
		PID:    event.PID,
		Addr:   event.RemoteAddr.String(),
		Port:   event.RemotePort,
	}

	m.mu.Lock()
	m.beaconTrak[key] = append(m.beaconTrak[key], event.CreatedAt)
	ts := m.beaconTrak[key]
	if len(ts) > 50 {
		ts = ts[len(ts)-50:]
		m.beaconTrak[key] = ts
	}
	n := len(ts)
	// copy timestamps under lock to avoid race on slice
	samples := make([]int64, n)
	copy(samples, ts)
	m.mu.Unlock()

	matched, mean, sampleCount := BeaconConditionsMet(c, samples)
	if !matched {
		return nil
	}

	return &Alert{
		RuleID:     rule.ID,
		RuleName:   rule.Name,
		Severity:   rule.Severity,
		PID:        event.PID,
		Comm:       event.Comm,
		RemoteAddr: event.RemoteAddr.String(),
		RemotePort: event.RemotePort,
		Message:    fmt.Sprintf("Beacon rule %q: ~%.0fms intervals across %d samples to %s:%d (%s)", rule.Name, mean, sampleCount, event.RemoteAddr.String(), event.RemotePort, event.Comm),
		CreatedAt:  time.Now().UnixMilli(),
	}
}

func RuleMatchesStatic(c RuleConditions, conn capture.Connection) bool {
	if conn.RemoteAddr == nil {
		return false
	}
	if c.ProcessName != "" && !matchProcess(conn.Comm, c.ProcessName) {
		return false
	}
	ip := conn.RemoteAddr.String()
	if c.IPRange != "" && !matchIPRange(ip, c.IPRange) {
		return false
	}
	if c.PortRange != "" && !matchPortRange(conn.RemotePort, c.PortRange) {
		return false
	}
	if c.EntropyMax > 0 && !matchEntropy(ip, c.EntropyMax) {
		return false
	}
	return true
}

func hasBeaconConditions(c RuleConditions) bool {
	return c.MinInterval > 0 || c.MaxInterval > 0 || c.MinSamples > 0
}

func BeaconConditionsMet(c RuleConditions, timestamps []int64) (bool, float64, int) {
	if len(timestamps) == 0 {
		return false, 0, 0
	}

	samples := make([]int64, len(timestamps))
	copy(samples, timestamps)
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })

	minSamples := c.MinSamples
	if minSamples < 5 {
		minSamples = 5
	}
	if len(samples) < minSamples {
		return false, 0, len(samples)
	}

	intervals := make([]float64, len(samples)-1)
	for i := 1; i < len(samples); i++ {
		intervals[i-1] = float64(samples[i] - samples[i-1])
	}
	if len(intervals) == 0 {
		return false, 0, len(samples)
	}

	mean := 0.0
	for _, v := range intervals {
		mean += v
	}
	mean /= float64(len(intervals))

	if c.MinInterval > 0 && mean < float64(c.MinInterval) {
		return false, mean, len(samples)
	}
	if c.MaxInterval > 0 && mean > float64(c.MaxInterval) {
		return false, mean, len(samples)
	}
	return true, mean, len(samples)
}

func remoteIPString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func matchProcess(comm, pattern string) bool {
	return strings.Contains(strings.ToLower(comm), strings.ToLower(pattern))
}

func matchIPRange(ip, cidr string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	return prefix.Contains(addr)
}

func matchPortRange(port int, portRange string) bool {
	for _, part := range strings.Split(portRange, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return false
		}
		if strings.Contains(part, "-") {
			parts := strings.SplitN(part, "-", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				continue
			}
			lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil || lo < 0 || lo > 65535 {
				continue
			}
			hi, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil || hi < 0 || hi > 65535 {
				continue
			}
			if port >= lo && port <= hi {
				return true
			}
		} else {
			target, err := strconv.Atoi(part)
			if err == nil && target >= 0 && target <= 65535 && port == target {
				return true
			}
		}
	}
	return false
}

func matchEntropy(ip string, maxEntropy float64) bool {
	if !strings.Contains(ip, ".") {
		return false
	}
	host := strings.Split(ip, ":")[0]
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return false
	}
	name := strings.Join(parts[:len(parts)-1], ".")
	if len(name) < 3 {
		return false
	}
	e := shannonEntropy(name)
	return e > maxEntropy
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	var e float64
	for _, c := range freq {
		p := c / float64(len(s))
		e -= p * math.Log2(p)
	}
	return e
}
