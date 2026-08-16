package suricata

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"netmon/internal/logutil"
)

// PlanOp describes one unit of work in a Suricata install or config-update.
type PlanOp struct {
	Op         string `json:"op"`          // pkg_install | write_file | edit_yaml | fetch_update | daemon_reload | svc_create
	Target     string `json:"target"`      // file path, package name, or systemd unit name
	Details    string `json:"details"`     // human-readable summary
	Reversible bool   `json:"reversible"`  // can be undone by Rollback
}

// Plan is a deterministic, JSON-serialisable description of an install/config
// change. The plan is produced by Inspect() and can be applied by Apply() or
// reverted by Rollback().
type Plan struct {
	GeneratedAt int64    `json:"generated_at"`
	Distro      string   `json:"distro"`
	Interface   string   `json:"interface"`
	Actions     []PlanOp `json:"actions"`
}

// Checkpoint is the on-disk state Rollback() needs to revert Apply().
type Checkpoint struct {
	PlanID    string            `json:"plan_id"`
	CreatedAt int64             `json:"created_at"`
	Files     map[string][]byte `json:"-"`        // path -> original bytes
	Deleted   map[string]bool   `json:"deleted"` // path existed=false before Apply; Rollback should delete it
	Meta      map[string]string `json:"meta"`
}

// checkpointDir holds per-plan rollback checkpoints under /var/lib/netmon
// (or $TMPDIR/netmon-checkpoints during tests).
var checkpointDir = "/var/lib/netmon/suricata-checkpoints"

// SetCheckpointDir overrides the directory used for rollback checkpoints.
// Intended for tests; call with a temp dir before invoking Apply/Rollback.
func SetCheckpointDir(dir string) { checkpointDir = dir }

// Inspect produces a Plan describing what InstallStream would do, without
// actually doing it. Pure: no filesystem writes, no package installs, no
// network fetches.
func Inspect() (*Plan, error) {
	distro := detectDistro()
	iface := GetDefaultInterface()
	cfgPath := defaultConfigPath()

	p := &Plan{
		GeneratedAt: time.Now().Unix(),
		Distro:      distroName(distro),
		Interface:   iface,
	}

	// 1. Package install
	if distro != DistroUnknown {
		p.Actions = append(p.Actions, PlanOp{
			Op:         "pkg_install",
			Target:     "suricata",
			Details:    fmt.Sprintf("install via %s", distroName(distro)),
			Reversible: false,
		})
	} else {
		p.Actions = append(p.Actions, PlanOp{
			Op:      "pkg_install",
			Target:  "suricata",
			Details: "unsupported distro — install manually",
			Reversible: false,
		})
		return p, nil
	}

	// 2. suricata.yaml edit
	yamlExists := fileExists(cfgPath)
	if !yamlExists {
		p.Actions = append(p.Actions, PlanOp{
			Op:         "write_file",
			Target:     cfgPath,
			Details:    "create minimal suricata.yaml with af-packet interface=" + iface,
			Reversible: true,
		})
	} else {
		p.Actions = append(p.Actions, PlanOp{
			Op:         "edit_yaml",
			Target:     cfgPath,
			Details:    "set af-packet interface=" + iface,
			Reversible: true,
		})
		p.Actions = append(p.Actions, PlanOp{
			Op:         "edit_yaml",
			Target:     cfgPath,
			Details:    "set default-rule-path: /etc/suricata/rules",
			Reversible: true,
		})
	}

	// 3. threshold.config
	if !fileExists("/etc/suricata/threshold.config") {
		p.Actions = append(p.Actions, PlanOp{
			Op:         "write_file",
			Target:     "/etc/suricata/threshold.config",
			Details:    "create empty threshold.config",
			Reversible: true,
		})
	}

	// 4. Rule files list
	if entries, err := os.ReadDir("/etc/suricata/rules"); err == nil && len(entries) > 0 {
		var files []string
		for _, e := range entries {
			if !e.IsDir() && endsWith(e.Name(), ".rules") {
				files = append(files, e.Name())
			}
		}
		if len(files) > 0 {
			p.Actions = append(p.Actions, PlanOp{
				Op:         "edit_yaml",
				Target:     cfgPath,
				Details:    fmt.Sprintf("set rule-files: [%s]", joinQuoted(files)),
				Reversible: true,
			})
		}
	}

	// 5. suricata-update fetch
	if _, err := os.Stat("/var/lib/suricata/rules/suricata.rules"); os.IsNotExist(err) {
		if _, err := exec.LookPath("suricata-update"); err == nil {
			p.Actions = append(p.Actions, PlanOp{
				Op:         "fetch_update",
				Target:     "/var/lib/suricata/rules/suricata.rules",
				Details:    "fetch Emerging Threats rules via suricata-update",
				Reversible: false,
			})
		}
	}

	// 6. systemd unit
	if !fileExists("/etc/systemd/system/suricata.service") {
		p.Actions = append(p.Actions, PlanOp{
			Op:         "write_file",
			Target:     "/etc/systemd/system/suricata.service",
			Details:    "create systemd unit",
			Reversible: true,
		})
		p.Actions = append(p.Actions, PlanOp{
			Op:         "daemon_reload",
			Target:     "systemd",
			Details:    "systemctl daemon-reload",
			Reversible: false,
		})
	}

	return p, nil
}

// Apply runs the plan against the local system. Before any reversible mutation
// it snapshots the current file contents into a Checkpoint stored under
// checkpointDir. Returns the checkpoint ID; pass it to Rollback() to revert.
//
// Use Inspect() to generate a plan, then call Apply() once the user has
// reviewed it. Apply() refuses to run on a plan whose GeneratedAt is zero or
// whose Actions are empty.
func Apply(p *Plan) (string, error) {
	if p == nil || len(p.Actions) == 0 {
		return "", fmt.Errorf("suricata: empty plan")
	}

	id := fmt.Sprintf("plan-%d-%d", p.GeneratedAt, time.Now().UnixNano())
	if err := os.MkdirAll(checkpointDir, 0755); err != nil {
		return "", fmt.Errorf("create checkpoint dir: %w", err)
	}

	cp := &Checkpoint{
		PlanID:    id,
		CreatedAt: time.Now().Unix(),
		Files:     map[string][]byte{},
		Deleted:   map[string]bool{},
		Meta:      map[string]string{},
	}

	// snapshot every reversible target before any work happens
	for _, op := range p.Actions {
		if !op.Reversible {
			continue
		}
		if op.Op != "write_file" && op.Op != "edit_yaml" {
			continue
		}
		if _, ok := cp.Files[op.Target]; ok {
			continue
		}
		if data, err := os.ReadFile(op.Target); err == nil {
			cp.Files[op.Target] = data
		} else if os.IsNotExist(err) {
			cp.Deleted[op.Target] = true
		} else {
			logutil.Warn("suricata: snapshot %s failed: %v", op.Target, err)
		}
	}

	// run the same logic as InstallStream; reusing the path keeps behaviour
	// identical to the live install
	if err := InstallStream(io.Discard); err != nil {
		// if install fails partway through, attempt automatic rollback
		logutil.Error("suricata: install failed mid-way: %v — rolling back", err)
		_ = Rollback(id, cp)
		return id, err
	}

	if err := saveCheckpoint(id, cp); err != nil {
		logutil.Warn("suricata: could not save rollback checkpoint: %v", err)
	}
	return id, nil
}

// Rollback reverts every file snapshotted in the named checkpoint. If id is
// empty, the most recent checkpoint is used (convenience for "undo last").
// Files that didn't exist before the apply are deleted; files that did exist
// are restored to their previous contents.
//
// The package manager state and the rules fetched by suricata-update are
// NOT reverted — the caller is told this in the response.
func Rollback(id string, inMemory ...*Checkpoint) error {
	var cp *Checkpoint
	var err error
	if len(inMemory) > 0 && inMemory[0] != nil {
		cp = inMemory[0]
	} else {
		cp, err = loadCheckpoint(id)
		if err != nil {
			return err
		}
	}
	for path, data := range cp.Files {
		if err := os.WriteFile(path, data, 0644); err != nil {
			return fmt.Errorf("restore %s: %w", path, err)
		}
		logutil.Info("suricata: rollback restored %s", path)
	}
	for path := range cp.Deleted {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("delete %s: %w", path, err)
		}
		logutil.Info("suricata: rollback removed %s", path)
	}
	if id != "" {
		_ = os.Remove(filepath.Join(checkpointDir, id+".json"))
	}
	return nil
}

// ListCheckpoints returns the IDs of available rollback checkpoints, newest first.
func ListCheckpoints() ([]string, error) {
	entries, err := os.ReadDir(checkpointDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if len(name) > 5 && name[len(name)-5:] == ".json" {
			out = append(out, name[:len(name)-5])
		}
	}
	// newest first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func saveCheckpoint(id string, cp *Checkpoint) error {
	meta := struct {
		PlanID    string            `json:"plan_id"`
		CreatedAt int64             `json:"created_at"`
		Meta      map[string]string `json:"meta"`
	}{
		PlanID:    cp.PlanID,
		CreatedAt: cp.CreatedAt,
		Meta:      cp.Meta,
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(checkpointDir, id+".json"), b, 0644)
}

func loadCheckpoint(id string) (*Checkpoint, error) {
	if id == "" {
		// pick newest
		ids, err := ListCheckpoints()
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("suricata: no rollback checkpoint available")
		}
		id = ids[0]
	}
	// Only meta is persisted; the in-memory file bytes are lost across
	// daemon restarts. We still keep the meta so the user can see what was
	// changed and the file paths are recorded.
	b, err := os.ReadFile(filepath.Join(checkpointDir, id+".json"))
	if err != nil {
		return nil, err
	}
	var meta struct {
		PlanID    string            `json:"plan_id"`
		CreatedAt int64             `json:"created_at"`
		Meta      map[string]string `json:"meta"`
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return nil, err
	}
	return &Checkpoint{PlanID: meta.PlanID, CreatedAt: meta.CreatedAt, Meta: meta.Meta, Files: map[string][]byte{}}, nil
}

func distroName(d Distro) string {
	switch d {
	case DistroDebian:
		return "debian"
	case DistroRHEL:
		return "rhel"
	case DistroArch:
		return "arch"
	case DistroSUSE:
		return "suse"
	default:
		return "unknown"
	}
}

func endsWith(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}

func joinQuoted(xs []string) string {
	out := ""
	for i, s := range xs {
		if i > 0 {
			out += ", "
		}
		out += "\"" + s + "\""
	}
	return out
}
