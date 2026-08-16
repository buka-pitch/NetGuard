package metrics

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Metrics struct {
	// Process info
	Uptime       string `json:"uptime"`
	GoVersion    string `json:"go_version"`
	NumCPU       int    `json:"num_cpu"`
	NumGoroutine int    `json:"num_goroutine"`
	NumCgoCall   int64  `json:"num_cgo_call"`
	StartedAt    string `json:"started_at"`

	// Memory (from runtime.MemStats)
	MemoryAllocMB uint64 `json:"memory_alloc_mb"`
	MemoryTotalMB uint64 `json:"memory_total_mb"`
	MemoryHeapMB  uint64 `json:"memory_heap_mb"`
	MemorySysMB   uint64 `json:"memory_sys_mb"`
	MemoryStackMB uint64 `json:"memory_stack_mb"`

	// Memory (from /proc/self/statm)
	MemoryRSSMB uint64 `json:"memory_rss_mb"`

	// CPU (from /proc/self/stat and runtime)
	CPUUserSeconds   float64 `json:"cpu_user_seconds"`
	CPUSystemSeconds float64 `json:"cpu_system_seconds"`
	CPUTotalSeconds  float64 `json:"cpu_total_seconds"`
	CPUPercent       float64 `json:"cpu_percent"`

	// GC
	GCNum           uint32  `json:"gc_num"`
	GCTotalPauseMs  float64 `json:"gc_total_pause_ms"`
	GCLastPauseMs   float64 `json:"gc_last_pause_ms"`

	// File descriptors
	OpenFDs int `json:"open_fds"`
}

var (
	startTime    = time.Now()
	lastUtime    int64
	lastStime    int64
	lastCPUTime  = time.Now()
	firstCPUCall = true
)

const clockTicks = 100 // sysconf(_SC_CLK_TCK) on Linux

func Collect() *Metrics {
	m := &Metrics{}

	// Process info
	m.Uptime = time.Since(startTime).Round(time.Second).String()
	m.GoVersion = runtime.Version()
	m.NumCPU = runtime.NumCPU()
	m.NumGoroutine = runtime.NumGoroutine()
	m.NumCgoCall = runtime.NumCgoCall()
	m.StartedAt = startTime.UTC().Format(time.RFC3339)

	// Memory from runtime
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.MemoryAllocMB = memStats.Alloc / 1024 / 1024
	m.MemoryTotalMB = memStats.TotalAlloc / 1024 / 1024
	m.MemoryHeapMB = memStats.HeapAlloc / 1024 / 1024
	m.MemorySysMB = memStats.Sys / 1024 / 1024
	m.MemoryStackMB = memStats.StackInuse / 1024 / 1024

	// RSS from /proc/self/statm
	if rss, err := readRSS(); err == nil {
		m.MemoryRSSMB = rss
	} else {
		m.MemoryRSSMB = (memStats.HeapInuse + memStats.StackInuse) / 1024 / 1024
	}

	// CPU from /proc/self/stat — delta-based instantaneous usage
	if utime, stime, err := readCPUTimes(); err == nil {
		total := float64(utime+stime) / clockTicks
		user := float64(utime) / clockTicks
		sys := float64(stime) / clockTicks
		m.CPUUserSeconds = user
		m.CPUSystemSeconds = sys
		m.CPUTotalSeconds = total

		if firstCPUCall {
			firstCPUCall = false
			m.CPUPercent = 0
		} else {
			dt := time.Since(lastCPUTime).Seconds()
			dCPU := float64((utime-lastUtime)+(stime-lastStime)) / clockTicks
			if dt > 0 && dCPU >= 0 {
				m.CPUPercent = (dCPU / dt) * 100
			} else {
				m.CPUPercent = 0
			}
		}

		lastUtime = utime
		lastStime = stime
		lastCPUTime = time.Now()
	} else {
		_ = memStats
	}

	// GC stats
	m.GCNum = memStats.NumGC
	totalPause := time.Duration(memStats.PauseTotalNs)
	m.GCTotalPauseMs = float64(totalPause.Milliseconds())
	if m.GCNum > 0 {
		m.GCLastPauseMs = float64(time.Duration(memStats.PauseNs[(memStats.NumGC+255)%256]).Microseconds()) / 1000.0
	}

	// Open file descriptors
	if fds, err := countOpenFDs(); err == nil {
		m.OpenFDs = fds
	} else {
		m.OpenFDs = 0
	}

	return m
}

func (m *Metrics) MarshalJSON() ([]byte, error) {
	// Alias to avoid infinite recursion with json.Marshal
	type MetricsAlias Metrics
	return json.Marshal((*MetricsAlias)(m))
}

// readRSS reads resident set size from /proc/self/statm
func readRSS() (uint64, error) {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, fmt.Errorf("unexpected statm format")
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, err
	}
	// page size is typically 4096
	return pages * 4096 / 1024 / 1024, nil
}

// readCPUTimes reads utime and stime from /proc/self/stat
func readCPUTimes() (utime, stime int64, err error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, 0, err
	}
	// find the last ')' to handle comm with parens
	idx := strings.LastIndex(string(data), ")")
	if idx < 0 {
		return 0, 0, fmt.Errorf("cannot parse /proc/self/stat: no closing paren")
	}
	rest := strings.Fields(string(data)[idx+2:]) // skip ") "
	if len(rest) < 13 {
		return 0, 0, fmt.Errorf("unexpected stat format: only %d fields after comm", len(rest))
	}
	utime, err = strconv.ParseInt(rest[11], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse utime: %w", err)
	}
	stime, err = strconv.ParseInt(rest[12], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse stime: %w", err)
	}
	return utime, stime, nil
}

// countOpenFDs counts entries in /proc/self/fd
func countOpenFDs() (int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}
