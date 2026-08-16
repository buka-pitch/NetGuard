package detect

import (
	"fmt"
	"math"
	"netmon/internal/capture"
	"sort"
	"sync"
	"time"
)

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

type Alert struct {
	RuleID     int64    `json:"rule_id,omitempty"`
	RuleName   string   `json:"rule_name"`
	Severity   Severity `json:"severity"`
	PID        int      `json:"pid"`
	Comm       string   `json:"comm"`
	RemoteAddr string   `json:"remote_addr"`
	RemotePort int      `json:"remote_port"`
	Message    string   `json:"message"`
	CreatedAt  int64    `json:"created_at"`
}

type Rule interface {
	Name() string
	Eval(capture.ConnectionEvent, *Engine) *Alert
}

type Engine struct {
	mu          sync.Mutex
	rules       []Rule
	blocklist   map[string]bool
	beaconTrack map[beaconKey][]int64
	alerts      []Alert
}

type beaconKey struct {
	PID        int
	RemoteAddr string
	RemotePort int
}

func NewEngine() *Engine {
	e := &Engine{
		blocklist:   make(map[string]bool),
		beaconTrack: make(map[beaconKey][]int64),
	}
	e.rules = []Rule{
		&BeaconRule{},
		&BlocklistRule{},
		&AnomalyPortRule{},
	}
	return e
}

func (e *Engine) AddRule(r Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
}

func (e *Engine) AddBlocklist(ips []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ip := range ips {
		e.blocklist[ip] = true
	}
}

func (e *Engine) IsBlocked(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.blocklist[ip]
}

func (e *Engine) Eval(event capture.ConnectionEvent) *Alert {
	for _, rule := range e.rules {
		if alert := rule.Eval(event, e); alert != nil {
			e.alerts = append(e.alerts, *alert)
			return alert
		}
	}
	return nil
}

func (e *Engine) AlertCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.alerts)
}

func (e *Engine) RecentAlerts(n int) []Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.alerts) <= n {
		result := make([]Alert, len(e.alerts))
		copy(result, e.alerts)
		return result
	}
	return e.alerts[len(e.alerts)-n:]
}

type BeaconRule struct{}

func (r *BeaconRule) Name() string { return "beacon_detection" }

func (r *BeaconRule) Eval(event capture.ConnectionEvent, eng *Engine) *Alert {
	if event.Type != capture.EventNew {
		return nil
	}
	if event.RemoteAddr == nil || event.RemoteAddr.IsLoopback() {
		return nil
	}

	key := beaconKey{
		PID:        event.PID,
		RemoteAddr: event.RemoteAddr.String(),
		RemotePort: event.RemotePort,
	}

	eng.mu.Lock()
	eng.beaconTrack[key] = append(eng.beaconTrack[key], event.CreatedAt)
	timestamps := eng.beaconTrack[key]
	if len(timestamps) > 20 {
		timestamps = timestamps[len(timestamps)-20:]
	}
	eng.beaconTrack[key] = timestamps
	eng.mu.Unlock()

	if len(timestamps) < 5 {
		return nil
	}

	intervals := make([]float64, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		intervals[i-1] = float64(timestamps[i] - timestamps[i-1])
	}

	mean, variance := meanVariance(intervals)
	if variance < 0.15*mean && mean > 500 && mean < 300000 {
		return &Alert{
			RuleName:   r.Name(),
			Severity:   SevHigh,
			PID:        event.PID,
			Comm:       event.Comm,
			RemoteAddr: event.RemoteAddr.String(),
			RemotePort: event.RemotePort,
			Message: fmt.Sprintf("Beaconing detected: %.0fms intervals to %s:%d (PID %d, %s)",
				mean, event.RemoteAddr.String(), event.RemotePort, event.PID, event.Comm),
			CreatedAt: time.Now().UnixMilli(),
		}
	}

	return nil
}

type BlocklistRule struct{}

func (r *BlocklistRule) Name() string { return "blocklist_match" }

func (r *BlocklistRule) Eval(event capture.ConnectionEvent, eng *Engine) *Alert {
	if event.Type != capture.EventNew {
		return nil
	}
	if event.RemoteAddr == nil {
		return nil
	}

	ip := event.RemoteAddr.String()
	eng.mu.Lock()
	blocked := eng.blocklist[ip]
	eng.mu.Unlock()

	if blocked {
		return &Alert{
			RuleName:   r.Name(),
			Severity:   SevCritical,
			PID:        event.PID,
			Comm:       event.Comm,
			RemoteAddr: ip,
			RemotePort: event.RemotePort,
			Message: fmt.Sprintf("Connection to blocklisted IP: %s:%d (%s, PID %d)",
				ip, event.RemotePort, event.Comm, event.PID),
			CreatedAt: time.Now().UnixMilli(),
		}
	}
	return nil
}

type AnomalyPortRule struct{}

var suspiciousPorts = map[int]string{
	4444:  "metasploit default",
	1337:  "leet shell",
	31337: "back orifice",
	6666:  "irc/unknown",
	6667:  "irc",
	6668:  "irc",
	8443:  "alternative https",
	5555:  "android adb",
	8080:  "alternative http",
	22:    "ssh",
	23:    "telnet",
	445:   "smb",
	135:   "rpc",
	3389:  "rdp",
}

func (r *AnomalyPortRule) Name() string { return "anomalous_port" }

func (r *AnomalyPortRule) Eval(event capture.ConnectionEvent, eng *Engine) *Alert {
	if event.Type != capture.EventNew {
		return nil
	}
	if event.RemoteAddr == nil || event.RemoteAddr.IsLoopback() {
		return nil
	}

	if desc, ok := suspiciousPorts[event.RemotePort]; ok {
		sev := SevMedium
		if event.RemotePort == 4444 || event.RemotePort == 1337 || event.RemotePort == 31337 {
			sev = SevHigh
		}
		return &Alert{
			RuleName:   r.Name(),
			Severity:   sev,
			PID:        event.PID,
			Comm:       event.Comm,
			RemoteAddr: event.RemoteAddr.String(),
			RemotePort: event.RemotePort,
			Message: fmt.Sprintf("%s -> %s:%d (%s, PID %d)",
				desc, event.RemoteAddr.String(), event.RemotePort, event.Comm, event.PID),
			CreatedAt: time.Now().UnixMilli(),
		}
	}
	return nil
}

func meanVariance(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	var sumSq float64
	for _, v := range values {
		d := v - mean
		sumSq += d * d
	}
	variance := math.Sqrt(sumSq / float64(len(values)))
	return mean, variance
}

func LinearModel(points []float64) (slope, intercept float64) {
	if len(points) < 2 {
		return 0, 0
	}
	n := len(points)
	x := make([]float64, n)
	for i := range x {
		x[i] = float64(i)
	}
	var sumX, sumY, sumXY, sumX2 float64
	for i := range points {
		sumX += x[i]
		sumY += points[i]
		sumXY += x[i] * points[i]
		sumX2 += x[i] * x[i]
	}
	slope = (float64(n)*sumXY - sumX*sumY) / (float64(n)*sumX2 - sumX*sumX)
	intercept = (sumY - slope*sumX) / float64(n)
	return
}

func (e *Engine) DetectTrends() []Alert {
	e.mu.Lock()
	defer e.mu.Unlock()

	var alerts []Alert

	for key, timestamps := range e.beaconTrack {
		if len(timestamps) < 10 {
			continue
		}

		intervals := make([]float64, len(timestamps)-1)
		for i := 1; i < len(timestamps); i++ {
			intervals[i-1] = float64(timestamps[i] - timestamps[i-1])
		}

		sort.Float64s(intervals)

		q1 := intervals[len(intervals)/4]
		q3 := intervals[len(intervals)*3/4]
		iqr := q3 - q1

		if iqr < 50 && len(timestamps) >= 10 {
			mean := 0.0
			for _, v := range intervals {
				mean += v
			}
			mean /= float64(len(intervals))

			if mean > 1000 && mean < 3600000 {
				alerts = append(alerts, Alert{
					RuleName:   "jitter_analysis",
					Severity:   SevHigh,
					PID:        key.PID,
					RemoteAddr: key.RemoteAddr,
					RemotePort: key.RemotePort,
					Message: fmt.Sprintf("Low-jitter beacon: IQR=%.0fms, mean=%.0fms to %s:%d (PID %d)",
						iqr, mean, key.RemoteAddr, key.RemotePort, key.PID),
					CreatedAt: time.Now().UnixMilli(),
				})
			}
		}
	}

	return alerts
}
