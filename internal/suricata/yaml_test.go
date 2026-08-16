package suricata

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadConfigAtMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suricata.yaml")
	if err := os.WriteFile(path, []byte("vars:\n  address-groups: [unterminated"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadConfigAt(path); err == nil {
		t.Fatal("expected malformed YAML to return an error")
	} else if !strings.Contains(err.Error(), "parse") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestWriteConfigAtMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suricata.yaml")
	if err := os.WriteFile(path, []byte("vars:\n  address-groups: [unterminated"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := WriteConfigAt(path, defaultConfig()); err == nil {
		t.Fatal("expected malformed YAML to return an error on write")
	}
}
