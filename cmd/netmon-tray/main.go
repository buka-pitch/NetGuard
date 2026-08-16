// netmon-tray — system tray application for netmon firewall.
// Provides status icon, pending approval management, and quick actions.
package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"net/http"
	"netmon/internal/logutil"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/getlantern/systray"
)

// Logo-derived tray icons, generated from static/logo.svg by install.sh.
// Regenerate with: convert -background none -resize 64x64 \
//   [-fill <tint> -tint 50] static/logo.svg cmd/netmon-tray/assets/tray-<state>.png
//
//go:embed assets/tray-active.png
var iconActive []byte

//go:embed assets/tray-pending.png
var iconPending []byte

//go:embed assets/tray-panic.png
var iconPanic []byte

var serverURL string

// apiToken is the optional machine credential presented to the daemon via
// Authorization: Bearer. Populated from -token or -token-file.
var apiToken string

const defaultTokenFile = "/etc/netmon/tray-token"

type pendingItem struct {
	ID      int64  `json:"id"`
	ExePath string `json:"exe_path"`
	Process string `json:"process"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Source  string `json:"source,omitempty"`
}

type fwStatus struct {
	Enabled   bool `json:"enabled"`
	Policy    string `json:"policy"`
	Pending   int   `json:"pending"`
	PanicMode bool  `json:"panic_mode"`
}

const maxPendingSlots = 10

type pendingSlot struct {
	parent        *systray.MenuItem
	approveOnce   *systray.MenuItem
	approveAlways *systray.MenuItem
	deny          *systray.MenuItem
	currentID     atomic.Int64
}

func main() {
	addr := flag.String("addr", "http://127.0.0.1:8484", "netmon daemon URL")
	token := flag.String("token", "", "netmon API token (auth_api_token from daemon config)")
	tokenFile := flag.String("token-file", defaultTokenFile, "path to a file containing the API token (first line, trailing whitespace trimmed)")
	flag.Parse()
	serverURL = *addr
	apiToken = resolveAPIToken(*token, *tokenFile)
	if apiToken == "" {
		logutil.Warn("tray: no API token configured — the daemon will reject unauthenticated requests. Set -token or -token-file (daemon config: auth_api_token).")
	}
	systray.Run(onReady, onExit)
}

// resolveAPIToken returns the explicit -token if set, otherwise reads the
// first non-empty line of the token file. Empty string when neither exists.
func resolveAPIToken(explicit, file string) string {
	if explicit != "" {
		return strings.TrimSpace(explicit)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

func onReady() {
	systray.SetIcon(iconActive)
	systray.SetTooltip("netmon firewall")

	statusItem := systray.AddMenuItem("Starting...", "Firewall status")
	statusItem.Disable()

	systray.AddSeparator()

	dashItem := systray.AddMenuItem("Open Dashboard", "Open netmon web dashboard")
	// quick-link submenu for common pages — saves a click
	openAllowlist := dashItem.AddSubMenuItem("Allowlist", "Open /allowlist.html")
	openEvents := dashItem.AddSubMenuItem("Events", "Open /events.html (auth audit log)")
	openRules := dashItem.AddSubMenuItem("Rules", "Open /rules.html (custom alert rules)")
	openSuricata := dashItem.AddSubMenuItem("IDS", "Open /suricata.html (Suricata dashboard)")
	openReports := dashItem.AddSubMenuItem("Reports", "Open /reports.html")

	systray.AddSeparator()

	approveAllOnce := systray.AddMenuItem("Approve All (once)", "Approve all pending as once")
	approveAllAlways := systray.AddMenuItem("Approve All (always)", "Approve all pending as always")
	denyAll := systray.AddMenuItem("Deny All", "Deny all pending")

	systray.AddSeparator()

	panicItem := systray.AddMenuItem("Panic Mode (5 min)", "Disable firewall for 5 minutes")
	stopItem := systray.AddMenuItem("Stop daemon", "Stop the netmon daemon (systemctl stop netmon)")

	systray.AddSeparator()

	moreItem := systray.AddMenuItem("", "")
	moreItem.Hide()

	var slots [maxPendingSlots]pendingSlot
	for i := range slots {
		s := &slots[i]
		s.parent = systray.AddMenuItem("", "")
		s.approveOnce = s.parent.AddSubMenuItem("Approve (once)", "")
		s.approveAlways = s.parent.AddSubMenuItem("Approve (always)", "")
		s.deny = s.parent.AddSubMenuItem("Deny", "")
		s.parent.Hide()
		go handlePendingClicks(s)
	}

	quitItem := systray.AddMenuItem("Quit", "Exit netmon tray")

	notified := make(map[int64]bool)

	go pollLoop(statusItem, moreItem, &slots, notified)

	for {
		select {
		case <-dashItem.ClickedCh:
			openURL("http://127.0.0.1:8484")
		case <-openAllowlist.ClickedCh:
			openURL("http://127.0.0.1:8484/allowlist.html")
		case <-openEvents.ClickedCh:
			openURL("http://127.0.0.1:8484/events.html")
		case <-openRules.ClickedCh:
			openURL("http://127.0.0.1:8484/rules.html")
		case <-openSuricata.ClickedCh:
			openURL("http://127.0.0.1:8484/suricata.html")
		case <-openReports.ClickedCh:
			openURL("http://127.0.0.1:8484/reports.html")
		case <-approveAllOnce.ClickedCh:
			doBulk("approve", "once")
		case <-approveAllAlways.ClickedCh:
			doBulk("approve", "always")
		case <-denyAll.ClickedCh:
			doBulk("deny", "")
		case <-panicItem.ClickedCh:
			postAPI("/api/firewall/panic", nil)
		case <-stopItem.ClickedCh:
			stopDaemon()
		case <-quitItem.ClickedCh:
			systray.Quit()
			return
		}
	}
}

// stopDaemon asks systemd to stop the netmon daemon. It uses pkexec for a
// graphical sudo prompt so the user doesn't need a terminal handy.
func stopDaemon() {
	if _, err := exec.LookPath("pkexec"); err != nil {
		notifyStopResult(false, "pkexec not installed")
		return
	}
	cmd := exec.Command("pkexec", "systemctl", "stop", "netmon.service")
	if err := cmd.Run(); err != nil {
		notifyStopResult(false, err.Error())
		return
	}
	notifyStopResult(true, "")
}

func notifyStopResult(ok bool, detail string) {
	var summary, body string
	if ok {
		summary = "netmon daemon stopped"
		body = "systemctl stop netmon.service succeeded"
	} else {
		summary = "netmon daemon: stop failed"
		body = detail
	}
	exec.Command("notify-send", "-a", "netmon", "-i",
		map[bool]string{true: "dialog-information", false: "dialog-error"}[ok],
		summary, body).Run()
	logutil.Info("tray: %s (%s)", summary, body)
}

func onExit() {
	logutil.Info("netmon-tray: exiting")
}

func handlePendingClicks(s *pendingSlot) {
	for {
		select {
		case <-s.approveOnce.ClickedCh:
			if id := s.currentID.Load(); id > 0 {
				postAPI("/api/firewall/approve", map[string]interface{}{"id": id, "mode": "once"})
			}
		case <-s.approveAlways.ClickedCh:
			if id := s.currentID.Load(); id > 0 {
				postAPI("/api/firewall/approve", map[string]interface{}{"id": id, "mode": "always"})
			}
		case <-s.deny.ClickedCh:
			if id := s.currentID.Load(); id > 0 {
				postAPI("/api/firewall/deny", map[string]interface{}{"id": id})
			}
		}
	}
}

func pollLoop(statusItem *systray.MenuItem, moreItem *systray.MenuItem, slots *[maxPendingSlots]pendingSlot, notified map[int64]bool) {
	for {
		poll(statusItem, moreItem, slots, notified)
		time.Sleep(2 * time.Second)
	}
}

func poll(statusItem *systray.MenuItem, moreItem *systray.MenuItem, slots *[maxPendingSlots]pendingSlot, notified map[int64]bool) {
	s, err := fetchStatus()
	if err != nil {
		statusItem.SetTitle("netmon: unreachable")
		statusItem.SetTooltip("Cannot reach netmon daemon")
		systray.SetIcon(genIcon(color.RGBA{120, 120, 120, 255}))
		systray.SetTooltip("netmon: unreachable")
		return
	}

	now := time.Now().Format("15:04:05")
	if s.PanicMode {
		systray.SetIcon(iconPanic)
		systray.SetTooltip(fmt.Sprintf("netmon: PANIC MODE · last update %s", now))
	} else if s.Pending > 0 {
		systray.SetIcon(iconPending)
		systray.SetTooltip(fmt.Sprintf("netmon: %d pending · last update %s", s.Pending, now))
	} else {
		systray.SetIcon(iconActive)
		systray.SetTooltip(fmt.Sprintf("netmon: active · last update %s", now))
	}

	if !s.Enabled {
		statusItem.SetTitle("netmon: disabled")
	} else if s.PanicMode {
		statusItem.SetTitle(fmt.Sprintf("netmon: PANIC MODE (%d pending)", s.Pending))
	} else {
		statusItem.SetTitle(fmt.Sprintf("netmon: enabled, %d pending", s.Pending))
	}

	pendings, err := fetchPending()
	if err != nil {
		return
	}

	for _, p := range pendings {
		if !notified[p.ID] {
			notified[p.ID] = true
			sendNotify(&p)
		}
	}
	for id := range notified {
		found := false
		for _, p := range pendings {
			if p.ID == id {
				found = true
				break
			}
		}
		if !found {
			delete(notified, id)
		}
	}

	for i := range pendings {
		if i >= maxPendingSlots {
			moreItem.SetTitle(fmt.Sprintf("(%d more pending...)", len(pendings)-maxPendingSlots))
			moreItem.Show()
			break
		}
		moreItem.Hide()
		p := &pendings[i]
		s := &slots[i]
		s.currentID.Store(p.ID)
		tag := ""
		if p.Source == "preexisting" {
			tag = " [pre-existing]"
		}
		s.parent.SetTitle(fmt.Sprintf("%s%s → %s:%d", p.Process, tag, p.IP, p.Port))
		s.parent.SetTooltip(fmt.Sprintf("%s → %s:%d/%s (source=%s)", p.Process, p.IP, p.Port, p.Proto, p.Source))
		s.parent.Show()
	}
	for i := len(pendings); i < maxPendingSlots; i++ {
		slots[i].currentID.Store(0)
		slots[i].parent.Hide()
	}
}

func fetchStatus() (*fwStatus, error) {
	resp, err := doGet(serverURL + "/api/firewall/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var s fwStatus
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

func fetchPending() ([]pendingItem, error) {
	resp, err := doGet(serverURL + "/api/firewall/pending")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var list []pendingItem
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	return list, nil
}

// doGet performs an authenticated GET. When an API token is configured it is
// sent as Authorization: Bearer, which the daemon accepts as a machine
// credential (auth_api_token config).
func doGet(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	attachToken(req)
	return http.DefaultClient.Do(req)
}

func sendNotify(p *pendingItem) {
	tag := ""
	if p.Source == "preexisting" {
		tag = " [pre-existing]"
	}
	summary := fmt.Sprintf("Blocked:%s %s → %s:%d", tag, p.Process, p.IP, p.Port)
	body := fmt.Sprintf("exe: %s\nproto: %s", p.ExePath, p.Proto)
	exec.Command("notify-send", "-a", "netmon", "-i", "dialog-warning", summary, body).Run()
	logutil.Info("notify: %s", summary)
}

func doBulk(action, mode string) {
	ep := "/api/firewall/" + action
	if mode != "" {
		ep += "-" + mode
	}
	postAPI(ep, nil)
}

func postAPI(path string, body interface{}) {
	var reqBody string
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = string(b)
	}
	req, err := http.NewRequest(http.MethodPost, serverURL+path, strings.NewReader(reqBody))
	if err != nil {
		logutil.Error("api error %s: %v", path, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	attachToken(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logutil.Error("api error %s: %v", path, err)
		return
	}
	resp.Body.Close()
}

// attachToken adds the machine API token to the request when one is loaded.
func attachToken(req *http.Request) {
	if apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+apiToken)
	}
}

func openURL(url string) {
	cmd := exec.Command("xdg-open", url)
	cmd.Start()
}

func genIcon(c color.RGBA) []byte {
	img := image.NewRGBA(image.Rect(0, 0, 22, 22))
	draw.Draw(img, img.Bounds(), image.Transparent, image.Point{}, draw.Src)
	for y := 0; y < 22; y++ {
		for x := 0; x < 22; x++ {
			dx, dy := x-11, y-11
			d := dx*dx + dy*dy
			if d < 80 {
				img.Set(x, y, c)
			}
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}
