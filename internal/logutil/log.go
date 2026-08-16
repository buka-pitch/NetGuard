package logutil

import (
	"encoding/json"
	"fmt"
	stdlog "log"
	"os"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"msg"`
}

var (
	mu          sync.Mutex
	minLevel    = "info"
	levelValues = map[string]int{"debug": 0, "info": 1, "warn": 2, "error": 3}
)

func Init(lvl string) {
	mu.Lock()
	defer mu.Unlock()
	lvl = strings.ToLower(lvl)
	if _, ok := levelValues[lvl]; ok {
		minLevel = lvl
	}
	stdlog.SetFlags(0)
	stdlog.SetOutput(&jsonWriter{})
}

type jsonWriter struct{}

func (j *jsonWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	e := Entry{
		Time:    time.Now().UTC().Format(time.RFC3339),
		Level:   "info",
		Message: msg,
	}
	b, _ := json.Marshal(e)
	fmt.Fprintln(os.Stderr, string(b))
	return len(p), nil
}

func shouldLog(lvl string) bool {
	return levelValues[lvl] >= levelValues[minLevel]
}

func logf(lvl, format string, args ...interface{}) {
	if !shouldLog(lvl) {
		return
	}
	msg := fmt.Sprintf(format, args...)
	e := Entry{Time: time.Now().UTC().Format(time.RFC3339), Level: lvl, Message: msg}
	b, _ := json.Marshal(e)
	mu.Lock()
	fmt.Fprintln(os.Stderr, string(b))
	mu.Unlock()
}

func Debug(format string, args ...interface{}) { logf("debug", format, args...) }
func Info(format string, args ...interface{})  { logf("info", format, args...) }
func Warn(format string, args ...interface{})  { logf("warn", format, args...) }
func Error(format string, args ...interface{}) { logf("error", format, args...) }


