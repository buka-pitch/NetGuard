package metrics

import (
	"runtime"
	"testing"
)

func TestCollect_ReturnsNonNil(t *testing.T) {
	m := Collect()
	if m == nil {
		t.Fatal("Collect() returned nil")
	}
}

func TestCollect_HasAllFields(t *testing.T) {
	m := Collect()

	// Process info
	if m.Uptime == "" {
		t.Error("Uptime is empty")
	}
	if m.GoVersion == "" {
		t.Error("GoVersion is empty")
	}
	if m.NumCPU <= 0 {
		t.Errorf("NumCPU = %d, want > 0", m.NumCPU)
	}
	if m.NumGoroutine <= 0 {
		t.Errorf("NumGoroutine = %d, want > 0", m.NumGoroutine)
	}
	if m.StartedAt == "" {
		t.Error("StartedAt is empty")
	}

	// Memory
	if m.MemoryRSSMB <= 0 {
		t.Errorf("MemoryRSSMB = %d, want > 0", m.MemoryRSSMB)
	}
	if m.MemoryAllocMB < 0 {
		t.Errorf("MemoryAllocMB = %d, want >= 0", m.MemoryAllocMB)
	}
	if m.MemorySysMB <= 0 {
		t.Errorf("MemorySysMB = %d, want > 0", m.MemorySysMB)
	}
	if m.MemoryHeapMB < 0 {
		t.Errorf("MemoryHeapMB = %d, want >= 0", m.MemoryHeapMB)
	}
	if m.MemoryStackMB < 0 {
		t.Errorf("MemoryStackMB = %d, want >= 0", m.MemoryStackMB)
	}

	// Memory hierarchy sanity (only if values are non-zero)
	if m.MemoryHeapMB > 0 && m.MemoryAllocMB > 0 && m.MemoryHeapMB > m.MemoryAllocMB {
		t.Errorf("MemoryHeapMB (%d) > MemoryAllocMB (%d)", m.MemoryHeapMB, m.MemoryAllocMB)
	}

	// CPU
	if m.CPUUserSeconds < 0 {
		t.Errorf("CPUUserSeconds = %f, want >= 0", m.CPUUserSeconds)
	}
	if m.CPUSystemSeconds < 0 {
		t.Errorf("CPUSystemSeconds = %f, want >= 0", m.CPUSystemSeconds)
	}
	if m.CPUTotalSeconds < 0 {
		t.Errorf("CPUTotalSeconds = %f, want >= 0", m.CPUTotalSeconds)
	}
	if m.CPUPercent < 0 {
		t.Errorf("CPUPercent = %f, want >= 0", m.CPUPercent)
	}
	if m.CPUPercent > float64(runtime.NumCPU()*100) {
		t.Errorf("CPUPercent = %f, exceeds numCPU*100 (%d)", m.CPUPercent, runtime.NumCPU()*100)
	}

	// GC
	if m.GCNum == 0 && m.GCTotalPauseMs > 0 {
		t.Errorf("GCNum = 0 but GCTotalPauseMs = %f", m.GCTotalPauseMs)
	}
	if m.GCLastPauseMs < 0 {
		t.Errorf("GCLastPauseMs = %f, want >= 0", m.GCLastPauseMs)
	}

	// File descriptors
	if m.OpenFDs <= 0 {
		t.Errorf("OpenFDs = %d, want > 0", m.OpenFDs)
	}
}

func TestCollect_CPUFieldsHaveSaneProportions(t *testing.T) {
	m := Collect()
	// User + System should roughly equal Total
	diff := m.CPUTotalSeconds - (m.CPUUserSeconds + m.CPUSystemSeconds)
	if diff < -0.001 || diff > 0.001 {
		t.Errorf("CPUTotalSeconds (%f) != CPUUserSeconds (%f) + CPUSystemSeconds (%f), diff=%f",
			m.CPUTotalSeconds, m.CPUUserSeconds, m.CPUSystemSeconds, diff)
	}
}

func TestCollect_MemoryFieldsValid(t *testing.T) {
	m := Collect()

	// RSS should be <= total system memory (checking absurd values)
	if m.MemoryRSSMB > 1024*1024 {
		t.Errorf("MemoryRSSMB = %d MB, seems impossibly high", m.MemoryRSSMB)
	}

	// Alloc should be <= Sys
	if m.MemoryAllocMB > m.MemorySysMB {
		t.Errorf("MemoryAllocMB (%d) > MemorySysMB (%d)", m.MemoryAllocMB, m.MemorySysMB)
	}
}

func TestCollect_SuccessiveCallsStable(t *testing.T) {
	m1 := Collect()
	m2 := Collect()
	// These should be close (within a few seconds)
	diff := m2.CPUTotalSeconds - m1.CPUTotalSeconds
	if diff < 0 {
		t.Errorf("CPUTotalSeconds decreased: %f -> %f", m1.CPUTotalSeconds, m2.CPUTotalSeconds)
	}
	// Memory shouldn't change drastically
	if m2.MemoryRSSMB > m1.MemoryRSSMB+100 {
		t.Errorf("MemoryRSSMB jumped by more than 100 MB: %d -> %d", m1.MemoryRSSMB, m2.MemoryRSSMB)
	}
}

func TestCollect_JSONSerializable(t *testing.T) {
	m := Collect()
	data, err := m.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("MarshalJSON returned empty")
	}
	// Verify it starts with { and ends with }
	if data[0] != '{' || data[len(data)-1] != '}' {
		t.Errorf("JSON doesn't look like an object: %s", string(data))
	}
}

func TestCollect_OpenFDsReasonable(t *testing.T) {
	m := Collect()
	if m.OpenFDs > 10000 {
		t.Errorf("OpenFDs = %d, seems unreasonably high for this process", m.OpenFDs)
	}
}
