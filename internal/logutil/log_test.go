package logutil

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
)

func captureStderr(fn func()) string {
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()

	fn()
	w.Close()

	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

func TestInit(t *testing.T) {
	Init("debug")
	if minLevel != "debug" {
		t.Errorf("expected debug level, got %s", minLevel)
	}
	Init("invalid")
	if minLevel != "debug" {
		t.Errorf("level should not change for invalid: %s", minLevel)
	}
	Init("error")
	if minLevel != "error" {
		t.Errorf("expected error, got %s", minLevel)
	}
	Init("info")
}

func TestShouldLog(t *testing.T) {
	orig := minLevel
	defer func() { minLevel = orig }()

	minLevel = "info"
	if !shouldLog("info") {
		t.Error("info should log at info level")
	}
	if !shouldLog("error") {
		t.Error("error should log at info level")
	}
	if shouldLog("debug") {
		t.Error("debug should not log at info level")
	}

	minLevel = "debug"
	if !shouldLog("debug") {
		t.Error("debug should log at debug level")
	}
}

func TestLevelOutput(t *testing.T) {
	orig := minLevel
	minLevel = "debug"
	defer func() { minLevel = orig }()

	out := captureStderr(func() {
		Info("hello %s", "world")
		Warn("warning %d", 42)
		Error("error msg")
		Debug("debug msg")
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected at least 4 log lines, got %d", len(lines))
	}

	checkLevel := func(line, expectedLevel string) {
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad JSON: %v (line: %s)", err, line)
		}
		if e.Level != expectedLevel {
			t.Errorf("expected level %s, got %s: %s", expectedLevel, e.Level, line)
		}
		if e.Time == "" {
			t.Error("missing time")
		}
	}

	checkLevel(lines[0], "info")
	checkLevel(lines[1], "warn")
	checkLevel(lines[2], "error")
	checkLevel(lines[3], "debug")
}

func TestLevelFiltering(t *testing.T) {
	orig := minLevel
	minLevel = "error"
	defer func() { minLevel = orig }()

	out := captureStderr(func() {
		Info("should not appear")
		Error("should appear")
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d: %q", len(lines), out)
	}
	if !strings.Contains(lines[0], "should appear") {
		t.Errorf("unexpected content: %s", lines[0])
	}
}

func TestConcurrentLogging(t *testing.T) {
	orig := minLevel
	minLevel = "info"
	defer func() { minLevel = orig }()

	out := captureStderr(func() {
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				Info("goroutine %d", n)
			}(i)
		}
		wg.Wait()
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 20 {
		t.Errorf("expected 20 lines, got %d", len(lines))
	}
}

func TestJSONWriter(t *testing.T) {
	out := captureStderr(func() {
		w := &jsonWriter{}
		n, err := w.Write([]byte("test message\n"))
		if err != nil {
			t.Fatalf("Write error: %v", err)
		}
		if n <= 0 {
			t.Error("expected bytes written")
		}
	})

	var e Entry
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &e); err != nil {
		t.Fatalf("bad JSON: %v (output: %s)", err, out)
	}
	if e.Message != "test message" {
		t.Errorf("got message %q", e.Message)
	}
	if e.Level != "info" {
		t.Errorf("got level %q", e.Level)
	}
}
