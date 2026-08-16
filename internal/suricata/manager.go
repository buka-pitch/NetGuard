package suricata

import (
    "bytes"
    "fmt"
    "io"
    "os"
    "os/exec"
    "runtime"
    "strings"
)

type Distro int

const (
    DistroDebian Distro = iota
    DistroRHEL
    DistroArch
    DistroSUSE
    DistroUnknown
)

func detectDistro() Distro {
    if _, err := exec.LookPath("apt"); err == nil {
        return DistroDebian
    }
    if _, err := exec.LookPath("dnf"); err == nil {
        return DistroRHEL
    }
    if _, err := exec.LookPath("yum"); err == nil {
        return DistroRHEL
    }
    if _, err := exec.LookPath("pacman"); err == nil {
        return DistroArch
    }
    if _, err := exec.LookPath("zypper"); err == nil {
        return DistroSUSE
    }
    return DistroUnknown
}

func isRoot() bool {
    return os.Geteuid() == 0
}

func sudo(args ...string) *exec.Cmd {
    if isRoot() {
        return exec.Command(args[0], args[1:]...)
    }
    sudoPath, err := exec.LookPath("sudo")
    if err != nil {
        return exec.Command(args[0], args[1:]...)
    }
    return exec.Command(sudoPath, append([]string{"-n"}, args...)...)
}

func Install() error {
    switch detectDistro() {
    case DistroDebian:
        return run(sudo("apt", "update", "-y"), sudo("apt", "install", "-y", "suricata"))
    case DistroRHEL:
        return run(sudo("dnf", "install", "-y", "suricata"))
    case DistroArch:
        return run(sudo("pacman", "-S", "--noconfirm", "suricata"))
    case DistroSUSE:
        return run(sudo("zypper", "install", "-y", "suricata"))
    }
    return fmt.Errorf("unsupported distro: %s", runtime.GOOS)
}

func serviceUnit() string {
    return `[Unit]
Description=Suricata Intrusion Detection System
After=network.target

[Service]
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
Type=simple

[Install]
WantedBy=multi-user.target
`}

func InstallStream(w io.Writer) error {
    switch detectDistro() {
    case DistroDebian:
        if err := runStream(w, sudo("apt", "update", "-y"), sudo("apt", "install", "-y", "suricata")); err != nil {
            return err
        }
    case DistroRHEL:
        if err := runStream(w, sudo("dnf", "install", "-y", "suricata")); err != nil {
            return err
        }
    case DistroArch:
        if err := runStream(w, sudo("pacman", "-S", "--noconfirm", "suricata")); err != nil {
            return err
        }
    case DistroSUSE:
        if err := runStream(w, sudo("zypper", "install", "-y", "suricata")); err != nil {
            return err
        }
    default:
        return fmt.Errorf("unsupported distro: %s", runtime.GOOS)
    }
    fmt.Fprintf(w, "\n--- configuring suricata ---\n")
    if err := postInstallConfig(w); err != nil {
        return fmt.Errorf("post-install config: %w", err)
    }
    fmt.Fprintf(w, "done\n")
    return nil
}

func postInstallConfig(w io.Writer) error {
    iface := GetDefaultInterface()
    cfgPath := defaultConfigPath()

    // update suricata.yaml with correct interface
    if err := fixInterface(cfgPath, iface); err != nil {
        return fmt.Errorf("set interface %s: %w", iface, err)
    }
    fmt.Fprintf(w, "  interface: %s\n", iface)

    // create threshold.config if missing
    tcPath := "/etc/suricata/threshold.config"
    if _, err := os.Stat(tcPath); os.IsNotExist(err) {
        os.WriteFile(tcPath, []byte("# threshold.config\n"), 0644)
        fmt.Fprintf(w, "  created threshold.config\n")
    }

    // configure rules — use the package's event rules and run suricata-update
    rulesDir := "/etc/suricata/rules"
    if entries, err := os.ReadDir(rulesDir); err == nil && len(entries) > 0 {
        // point default-rule-path to the package's rules dir
        setYamlField(cfgPath, "default-rule-path", rulesDir)
        ruleFiles := make([]string, 0, len(entries))
        for _, e := range entries {
            if !e.IsDir() && strings.HasSuffix(e.Name(), ".rules") {
                ruleFiles = append(ruleFiles, e.Name())
            }
        }
        if len(ruleFiles) > 0 {
            setYamlRuleFiles(cfgPath, ruleFiles)
        }
        fmt.Fprintf(w, "  rules: %d files\n", len(ruleFiles))
    }

    // run suricata-update to fetch threat rules
    if _, err := exec.LookPath("suricata-update"); err == nil {
        fmt.Fprintf(w, "  running suricata-update...\n")
        fmt.Fprintf(w, "    (fetching Emerging Threats rules)\n")
        cmd := sudo("suricata-update")
        cmd.Stdout = w
        cmd.Stderr = w
        cmd.Run()
        // after update, add suricata.rules if it was created
        updatedPath := "/var/lib/suricata/rules/suricata.rules"
        if _, err := os.Stat(updatedPath); err == nil {
            addYamlRuleFile(cfgPath, "suricata.rules")
            fmt.Fprintf(w, "  added suricata.rules from update\n")
        }
    } else {
        fmt.Fprintf(w, "  suricata-update not found, install with: sudo pacman -S suricata-update\n")
    }

    // ensure service unit exists (some packages don't ship one)
    svcPath := "/etc/systemd/system/suricata.service"
    if _, err := os.Stat(svcPath); os.IsNotExist(err) {
        fmt.Fprintf(w, "  creating suricata.service\n")
        unit := serviceUnit()
        if err := os.WriteFile(svcPath, []byte(unit), 0644); err != nil {
            return fmt.Errorf("write service unit: %w", err)
        }
        if err := sudo("systemctl", "daemon-reload").Run(); err != nil {
            return fmt.Errorf("daemon-reload: %w", err)
        }
    }

    return nil
}

func setYamlField(path, key, value string) {
    data, err := os.ReadFile(path)
    if err != nil {
        return
    }
    lines := strings.Split(string(data), "\n")
    for i, line := range lines {
        trimmed := strings.TrimSpace(line)
        if strings.HasPrefix(trimmed, key+":") {
            lines[i] = strings.Repeat(" ", leadingSpaces(line)) + key + ": " + value
            break
        }
    }
    os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

func setYamlRuleFiles(path string, files []string) {
    data, err := os.ReadFile(path)
    if err != nil {
        return
    }
    lines := strings.Split(string(data), "\n")
    inRuleFiles := false
    start, end := -1, -1
    for i, line := range lines {
        trimmed := strings.TrimSpace(line)
        if trimmed == "rule-files:" {
            inRuleFiles = true
            start = i
            continue
        }
        if inRuleFiles {
            if trimmed == "" || (len(line) > 0 && line[0] != ' ' && line[0] != '\t') {
                end = i
                break
            }
            // keep going to find the end
        }
    }
    if end < 0 {
        end = len(lines)
    }
    // build new rule-files block
    newLines := []string{lines[start]}
    for _, f := range files {
        newLines = append(newLines, "  - "+f)
    }
    result := append(lines[:start], newLines...)
    result = append(result, lines[end:]...)
    os.WriteFile(path, []byte(strings.Join(result, "\n")), 0644)
}

func addYamlRuleFile(path, rule string) {
    data, err := os.ReadFile(path)
    if err != nil {
        return
    }
    lines := strings.Split(string(data), "\n")
    inRuleFiles := false
    for i := len(lines) - 1; i >= 0; i-- {
        trimmed := strings.TrimSpace(lines[i])
        if inRuleFiles {
            if strings.HasPrefix(trimmed, "- ") {
                // check if already present
                val := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
                if val == rule {
                    return
                }
                // insert after last rule file entry
                lines = append(lines[:i+1], append([]string{"  - " + rule}, lines[i+1:]...)...)
                os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
                return
            }
        }
        if trimmed == "rule-files:" {
            inRuleFiles = true
        }
    }
}

func leadingSpaces(s string) int {
    count := 0
    for _, ch := range s {
        if ch == ' ' {
            count++
        } else if ch == '\t' {
            count += 4
        } else {
            break
        }
    }
    return count
}

func fixInterface(path, iface string) error {
    data, err := os.ReadFile(path)
    if err != nil {
        // if yaml doesn't exist, create minimal one
        cfg := defaultConfig()
        cfg.Interface = iface
        return WriteConfig(cfg)
    }
    // surgically replace the af-packet interface line
    lines := strings.Split(string(data), "\n")
    inAfpkt := false
    changed := false
    for i, line := range lines {
        trimmed := strings.TrimSpace(line)
        if trimmed == "af-packet:" {
            inAfpkt = true
            continue
        }
        if inAfpkt {
            if strings.HasPrefix(trimmed, "- interface:") {
                old := strings.TrimSpace(trimmed)
                lines[i] = strings.Replace(line, old, "- interface: "+iface, 1)
                changed = true
                break
            }
            // stop if we hit another top-level key (no indent)
            if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && trimmed != "" {
                break
            }
        }
    }
    if changed {
        return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
    }
    // fallback: write full config via WriteConfig
    cfg := defaultConfig()
    cfg.Interface = iface
    return WriteConfig(cfg)
}

func runStream(w io.Writer, cmds ...*exec.Cmd) error {
    for _, cmd := range cmds {
        cmd.Stdout = w
        cmd.Stderr = w
        if err := cmd.Run(); err != nil {
            return err
        }
    }
    return nil
}

func run(cmds ...*exec.Cmd) error {
    for _, cmd := range cmds {
        out, err := cmd.CombinedOutput()
        if err != nil {
            return cleanErr(string(out), err)
        }
    }
    return nil
}

func Start() error {
    autoFixConfig()
    return svcAction("start")
}

func autoFixConfig() {
    iface := GetDefaultInterface()
    cfgPath := defaultConfigPath()
    data, err := os.ReadFile(cfgPath)
    if err != nil {
        return
    }
    // fix interface if yaml still references a non-existent one
    if !strings.Contains(string(data), "interface: "+iface) {
        fixInterface(cfgPath, iface)
    }
    // run suricata-update once if rules don't exist
    updatedPath := "/var/lib/suricata/rules/suricata.rules"
    if _, err := os.Stat(updatedPath); os.IsNotExist(err) {
        if _, err := exec.LookPath("suricata-update"); err == nil {
            sudo("suricata-update").Run()
        }
    }
    if _, err := os.Stat(updatedPath); err == nil {
        if !strings.Contains(string(data), "- suricata.rules") {
            addYamlRuleFile(cfgPath, "suricata.rules")
        }
    }
    // set default-rule-path if it's missing or wrong
    if !strings.Contains(string(data), "default-rule-path: /etc/suricata/rules") {
        setYamlField(cfgPath, "default-rule-path", "/etc/suricata/rules")
    }
    // add event rules if not present and /etc/suricata/rules has files
    if entries, err := os.ReadDir("/etc/suricata/rules"); err == nil && len(entries) > 0 {
        if !strings.Contains(string(data), "- decoder-events.rules") {
            ruleFiles := make([]string, 0, len(entries))
            for _, e := range entries {
                if !e.IsDir() && strings.HasSuffix(e.Name(), ".rules") {
                    ruleFiles = append(ruleFiles, e.Name())
                }
            }
            if len(ruleFiles) > 0 {
                setYamlRuleFiles(cfgPath, ruleFiles)
            }
        }
    }
}

func Stop() error {
    return svcAction("stop")
}

func Restart() error {
    autoFixConfig()
    return svcAction("restart")
}

func svcAction(action string) error {
    if _, err := exec.LookPath("systemctl"); err == nil {
        out, err := sudo("systemctl", action, "suricata").CombinedOutput()
        if err != nil {
            return cleanErr(string(out), err)
        }
        return nil
    }
    if _, err := exec.LookPath("service"); err == nil {
        out, err := sudo("service", "suricata", action).CombinedOutput()
        if err != nil {
            return cleanErr(string(out), err)
        }
        return nil
    }
    return fmt.Errorf("no service manager found (install systemctl or service)")
}

func cleanErr(out string, err error) error {
    msg := strings.TrimSpace(out)
    if strings.Contains(msg, "password is required") {
        return fmt.Errorf("root access needed: run netmon with 'sudo' or configure passwordless sudo for netmon")
    }
    if strings.Contains(msg, "could not lock database") || strings.Contains(msg, "db.lck") {
        return fmt.Errorf("another package manager is running, or a stale lock exists — run: sudo rm -f /var/lib/pacman/db.lck")
    }
    if strings.Contains(msg, "Unit.*not found") || strings.Contains(msg, "service not found") {
        return fmt.Errorf("suricata service unit missing — install or reinstall suricata first")
    }
    if len(msg) > 0 {
        return fmt.Errorf("%s", msg)
    }
    return err
}

func CheckStatus() (*Status, error) {
    s := &Status{}

    if _, err := exec.LookPath("suricata"); err == nil {
        s.Installed = true
        out, _ := exec.Command("suricata", "--version").Output()
        if len(out) > 0 {
            s.Version = strings.TrimSpace(string(out))
        }
    }

    if _, err := exec.LookPath("systemctl"); err == nil {
        out, _ := exec.Command("systemctl", "is-active", "suricata").Output()
        s.Running = strings.TrimSpace(string(out)) == "active"
        if s.Running {
            o, _ := exec.Command("systemctl", "show", "suricata", "--property=ActiveEnterTimestamp").Output()
            if len(o) > 0 {
                s.Uptime = strings.TrimSpace(strings.TrimPrefix(string(o), "ActiveEnterTimestamp="))
            }
        }
        // check if the service unit file exists
        if o, err := exec.Command("systemctl", "cat", "suricata.service").Output(); err == nil && len(o) > 0 {
            s.ServiceOk = true
        }
    } else if _, err := exec.LookPath("service"); err == nil {
        out, _ := exec.Command("service", "suricata", "status").Output()
        s.Running = bytes.Contains(out, []byte("running")) || bytes.Contains(out, []byte("start/running"))
        s.ServiceOk = s.Running // can't easily check without running
    }

    return s, nil
}

func defaultConfigPath() string {
    paths := []string{
        "/etc/suricata/suricata.yaml",
        "/usr/local/etc/suricata/suricata.yaml",
        "/opt/suricata/etc/suricata/suricata.yaml",
    }
    for _, p := range paths {
        if fileExists(p) {
            return p
        }
    }
    return "/etc/suricata/suricata.yaml"
}

func defaultEveLogPath() string {
    paths := []string{
        "/var/log/suricata/eve.json",
        "/usr/local/var/log/suricata/eve.json",
        "/opt/suricata/var/log/suricata/eve.json",
    }
    for _, p := range paths {
        if fileExists(p) {
            return p
        }
    }
    return "/var/log/suricata/eve.json"
}

func defaultRulePath() string {
    paths := []string{
        "/etc/suricata/rules",
        "/usr/local/etc/suricata/rules",
        "/var/lib/suricata/rules",
    }
    for _, p := range paths {
        if dirExists(p) {
            return p
        }
    }
    return "/etc/suricata/rules"
}

func fileExists(path string) bool {
    err := exec.Command("test", "-f", path).Run()
    return err == nil
}

func dirExists(path string) bool {
    err := exec.Command("test", "-d", path).Run()
    return err == nil
}

func EnsureDirs() {
    for _, d := range []string{defaultRulePath(), "/var/log/suricata"} {
        sudo("mkdir", "-p", d).Run()
    }
}

func GetDefaultInterface() string {
    out, err := exec.Command("sh", "-c", "ip route get 1 | grep -oP 'dev \\K\\S+'").Output()
    if err == nil && len(out) > 0 {
        return strings.TrimSpace(string(out))
    }
    out, err = exec.Command("sh", "-c", "route -n | grep '^0.0.0.0' | awk '{print $NF}'").Output()
    if err == nil && len(out) > 0 {
        return strings.TrimSpace(string(out))
    }
    return "eth0"
}

var DetectDistro = detectDistro
var SvcAction = svcAction
