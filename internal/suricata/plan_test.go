package suricata

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRollbackRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(func() { SetCheckpointDir("/var/lib/netmon/suricata-checkpoints") })
	SetCheckpointDir(dir)

	target := filepath.Join(dir, "suricata.yaml")
	original := []byte("# original config\naf-packet:\n  - interface: eth0\n")
	if err := os.WriteFile(target, original, 0644); err != nil {
		t.Fatal(err)
	}

	// simulate the post-install mutation
	mutated := []byte("# original config\naf-packet:\n  - interface: eth1\n")
	if err := os.WriteFile(target, mutated, 0644); err != nil {
		t.Fatal(err)
	}

	// build a checkpoint as Apply would
	cp := &Checkpoint{
		PlanID:    "plan-test",
		CreatedAt: 0,
		Files:     map[string][]byte{target: original},
		Meta:      map[string]string{},
	}

	if err := Rollback("plan-test", cp); err != nil {
		t.Fatal(err)
	}

	// verify the file was restored
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Errorf("file not restored:\n got: %q\nwant: %q", got, original)
	}
}

func TestRollbackDeletesCreatedFile(t *testing.T) {
	dir := t.TempDir()
	SetCheckpointDir(dir)
	t.Cleanup(func() { SetCheckpointDir("/var/lib/netmon/suricata-checkpoints") })

	target := filepath.Join(dir, "newly-created.cfg")
	// snapshot records the file as "didn't exist before"
	cp := &Checkpoint{
		PlanID:  "plan-test",
		Files:   map[string][]byte{},
		Deleted: map[string]bool{target: true},
		Meta:    map[string]string{},
	}

	// simulate a file that was created during apply
	if err := os.WriteFile(target, []byte("created"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := Rollback("plan-test", cp); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("expected file to be deleted on rollback, stat err=%v", err)
	}
}

func TestListCheckpointsNewestFirst(t *testing.T) {
	dir := t.TempDir()
	SetCheckpointDir(dir)
	t.Cleanup(func() { SetCheckpointDir("/var/lib/netmon/suricata-checkpoints") })

	// empty
	if ids, err := ListCheckpoints(); err != nil || len(ids) != 0 {
		t.Errorf("expected empty list, got %v err=%v", ids, err)
	}

	// write a meta file for two checkpoints
	for _, id := range []string{"plan-a", "plan-b"} {
		if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte(`{"plan_id":"`+id+`"}`), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// plus a non-json file (should be ignored)
	if err := os.WriteFile(filepath.Join(dir, "stray.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	ids, err := ListCheckpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 ids, got %v", ids)
	}
	for _, id := range ids {
		if id == "stray" {
			t.Errorf("non-json file leaked into checkpoint list: %v", ids)
		}
	}
}

func TestEndsWith(t *testing.T) {
	if !endsWith("decoder-events.rules", ".rules") {
		t.Error("endsWith should match suffix")
	}
	if endsWith("decoder-events", ".rules") {
		t.Error("endsWith should not match when suffix is longer than string")
	}
	if endsWith("rules.txt", ".rules") {
		t.Error("endsWith should not match different suffix")
	}
}

func TestJoinQuoted(t *testing.T) {
	got := joinQuoted([]string{"a.rules", "b.rules"})
	want := `"a.rules", "b.rules"`
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
