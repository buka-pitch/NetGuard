package pcap

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"netmon/internal/logutil"
)

type CaptureRequest struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	PID      int    `json:"pid,omitempty"`
	Duration int    `json:"duration,omitempty"`
	Iface    string `json:"iface,omitempty"`
	Filter   string `json:"-"`
}

type CaptureResult struct {
	Path     string `json:"path"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	Command  string `json:"command"`
}

type Capturer struct {
	dir      string
	iface    string
	tcpdump  string
}

func NewCapturer(dir, iface string) *Capturer {
	os.MkdirAll(dir, 0755)
	tcpdumpPath := findTcpdump()
	if tcpdumpPath == "" {
		logutil.Warn("pcap: tcpdump not found in PATH or common locations — captures disabled")
	}
	return &Capturer{dir: dir, iface: iface, tcpdump: tcpdumpPath}
}

func findTcpdump() string {
	if p, err := exec.LookPath("tcpdump"); err == nil {
		return p
	}
	for _, p := range []string{
		"/usr/sbin/tcpdump",
		"/usr/bin/tcpdump",
		"/sbin/tcpdump",
		"/bin/tcpdump",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (c *Capturer) Capture(req CaptureRequest) (*CaptureResult, error) {
	if c.tcpdump == "" {
		return nil, fmt.Errorf("tcpdump not found on system")
	}
	if req.Duration <= 0 {
		req.Duration = 30
	}
	if req.Duration > 300 {
		req.Duration = 300
	}

	filter := req.Filter
	if filter == "" {
		if req.Host != "" {
			filter = fmt.Sprintf("host %s", req.Host)
			if req.Port > 0 {
				filter = fmt.Sprintf("host %s and port %d", req.Host, req.Port)
			}
		} else {
			filter = "ip"
		}
	}

	iface := req.Iface
	if iface == "" {
		if req.Host != "" {
			iface = routeIface(req.Host)
		}
		if iface == "" {
			iface = c.iface
		}
	}
	fname := fmt.Sprintf("capture_pid%d_%d.pcap", req.PID, timeNow())
	if req.Host != "" {
		fname = fmt.Sprintf("capture_%s_%d_%d.pcap", req.Host, req.Port, timeNow())
	}
	fpath := filepath.Join(c.dir, fname)

	var stderr bytes.Buffer
	cmd := exec.Command(c.tcpdump,
		"-i", iface,
		"-w", fpath,
		filter,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stderr = &stderr
	logutil.Info("pcap: starting: %s", cmd.String())

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tcpdump start: %w", err)
	}

	timer := time.AfterFunc(time.Duration(req.Duration)*time.Second, func() {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	})
	defer timer.Stop()

	err := cmd.Wait()
	timer.Stop()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logutil.Info("pcap: tcpdump exited (code %d): %s", exitErr.ExitCode(), stderr.String())
		} else {
			return nil, fmt.Errorf("tcpdump wait: %w", err)
		}
	}

	info, err := os.Stat(fpath)
	if err != nil {
		return nil, fmt.Errorf("pcap stat: %w", err)
	}

	return &CaptureResult{
		Path:     fpath,
		Filename: fname,
		Size:     info.Size(),
		Command:  fmt.Sprintf("tcpdump -i %s -w %s %s", iface, fname, filter),
	}, nil
}

func (c *Capturer) Read(filename string) (string, error) {
	if c.tcpdump == "" {
		return "", fmt.Errorf("tcpdump not found on system")
	}
	fpath := filepath.Join(c.dir, filepath.Base(filename))
	var out bytes.Buffer
	cmd := exec.Command(c.tcpdump, "-n", "-r", fpath)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("tcpdump read: %w", err)
	}
	return out.String(), nil
}

type CaptureInfo struct {
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	CreatedAt int64  `json:"created_at"`
}

func (c *Capturer) ListCaptures() ([]CaptureInfo, error) {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return nil, fmt.Errorf("read captures dir: %w", err)
	}
	var caps []CaptureInfo
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pcap") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		caps = append(caps, CaptureInfo{
			Filename:  e.Name(),
			Size:      info.Size(),
			CreatedAt: info.ModTime().Unix(),
		})
	}
	return caps, nil
}

func (c *Capturer) ReadCapture(filename string, maxLines int, filter string) (string, error) {
	if c.tcpdump == "" {
		return "", fmt.Errorf("tcpdump not found on system")
	}
	fpath := filepath.Join(c.dir, filepath.Base(filename))
	args := []string{"-n", "-r", fpath}
	if filter != "" {
		args = append(args, filter)
	}
	cmd := exec.Command(c.tcpdump, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("tcpdump read: %w", err)
	}
	if maxLines <= 0 {
		return string(out), nil
	}
	lines := strings.SplitN(string(out), "\n", maxLines+1)
	if len(lines) > maxLines {
		lines = lines[:maxLines]
		lines[len(lines)-1] = "... (output truncated, showing " + fmt.Sprint(maxLines) + " lines)"
	}
	return strings.Join(lines, "\n"), nil
}

func timeNow() int64 {
	return time.Now().Unix()
}

type HostPort struct {
	Host string
	Port int
}

// BuildFilter creates a combined tcpdump BPF filter for multiple host:port pairs.
// Falls back to host-only when there are too many distinct hosts.
func isIPv6(host string) bool {
	return strings.Contains(host, ":")
}

// quoteHost wraps IPv6 addresses in brackets for tcpdump port expressions.
func quoteHost(host string) string {
	if isIPv6(host) {
		return "[" + host + "]"
	}
	return host
}

// hostFilter returns "host <addr>" — works for IPv4 and IPv6.
func hostFilter(host string) string {
	return "host " + host
}

// hostPortFilter returns "host <addr> and port N" — brackets IPv6 for tcpdump.
func hostPortFilter(host string, port int) string {
	return fmt.Sprintf("host %s and port %d", quoteHost(host), port)
}

// BuildFilter creates a combined tcpdump BPF filter for multiple host:port pairs.
// Falls back to host-only when there are too many distinct hosts.
func BuildFilter(targets []HostPort) string {
	if len(targets) == 0 {
		return "ip"
	}
	if len(targets) == 1 {
		if targets[0].Port > 0 {
			return hostPortFilter(targets[0].Host, targets[0].Port)
		}
		return hostFilter(targets[0].Host)
	}

	// group by host
	type hostEntry struct {
		ports []int
	}
	hosts := make(map[string]*hostEntry)
	for _, t := range targets {
		if _, ok := hosts[t.Host]; !ok {
			hosts[t.Host] = &hostEntry{}
		}
		if t.Port > 0 {
			hosts[t.Host].ports = append(hosts[t.Host].ports, t.Port)
		}
	}

	// if many distinct hosts, use a simpler host-only filter
	if len(hosts) > 10 {
		var parts []string
		for h := range hosts {
			parts = append(parts, hostFilter(h))
		}
		return "(" + strings.Join(parts, " or ") + ")"
	}

	var parts []string
	for h, e := range hosts {
		if len(e.ports) > 0 {
			var portStrs []string
			for _, p := range e.ports {
				portStrs = append(portStrs, fmt.Sprintf("%d", p))
			}
			parts = append(parts, fmt.Sprintf("(host %s and (port %s))", quoteHost(h), strings.Join(portStrs, " or port ")))
		} else {
			parts = append(parts, hostFilter(h))
		}
	}
	return strings.Join(parts, " or ")
}

func routeIface(host string) string {
	if host == "" {
		return ""
	}
	cmd := exec.Command("ip", "route", "get", host)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}
