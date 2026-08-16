<div align="center">

# NetGuard

**Per-process network monitoring + zero-trust firewall for Linux**

A network security monitor that attributes every live connection to a process,
enforces a default-deny nftables firewall, and ships a command-center dashboard
with real-time alerts, behavioral detection, and an AI assistant.

</div>

---

## Highlights

- **Per-process attribution** — every TCP/UDP/ICMP flow is resolved to a PID,
  executable, full command line, and parent process chain via inode lookup.
- **Zero-trust firewall** — nftables output/input chains with **default-deny**
  policy. New connections queue for approval; approve once or permanently, or
  deny the app outright.
- **Behavioral detection** — beaconing detection, low-variance interval
  analysis, and jitter/trend scoring over historical flow data.
- **Suricata IDS integration** — one-click install with dry-run + rollback,
  live `eve.json` tailing, every alert enriched with the responsible process,
  and full rule management from the web UI.
- **Reactive defense** — one-click **PANIC** mode blasts the page red and
  reverts the policy; rDNS/GeoIP/whois/DNSBL threat lookups per connection.
- **On-demand PCAP** — capture traffic for any host:port from the UI, download
  the `.pcap`, or ask the built-in AI to analyze it.
- **AI assistant** — Ollama-backed chat that reads live connections, pending
  approvals, and captured traffic with native tool calling.
- **Auth + audit** — setup-token first-run provisioning, CSRF protection,
  rate limiting per route, password policy, forced password reset, and a full
  authentication audit log.
- **PWA dashboard** — installable, offline-cacheable, responsive. JS + CSS
  embedded in a single static binary (zero runtime deps, `CGO_ENABLED=0`).

## Screenshots

(TODO: add dashboard / alerts / geo map / insights screenshots)

## Quick start

```sh
# build (static, no CGO)
make build            # -> bin/netmon

# install daemon + systemd service + tray app (run as root)
sudo ./install.sh
```

On first boot the daemon creates an admin account; see
[docs/INSTALLATION.md](docs/INSTALLATION.md#first-time-setup).

Dashboard: <http://127.0.0.1:8484>

## Documentation

| Doc | Contents |
|-----|----------|
| [Installation](docs/INSTALLATION.md) | Build, systemd service, tray app, first-run setup, upgrade |
| [Configuration](docs/CONFIGURATION.md) | `config.json` reference, defaults, hardening flags |
| [API reference](docs/API.md) | Every REST + WebSocket endpoint |
| [Architecture](docs/ARCHITECTURE.md) | Data flow, detection engine, firewall model |
| [Security](docs/SECURITY.md) | Auth model, CSRF, rate limiting, audit logging |
| [Suricata integration](docs/SURICATA.md) | IDS install flow, eve.json enrichment, rules |

## Dashboard pages

- **live** (`/`) — command center: KPI strip, live connection table, alerts,
  pending approvals, top processes/destinations.
- **ids** (`/suricata.html`) — Suricata status, alerts, rules, install/rollback.
- **rules** (`/rules.html`) — custom behavioral detection rules.
- **insights** (`/insights.html`) — time-series charts + activity heatmap.
- **inspect** (`/inspect.html`) — per-process traffic inspector + PCAP capture.
- **geo** (`/geo.html`) — live GeoIP map.
- **reports** (`/reports.html`) — generated daily reports, export.
- **events** (`/events.html`) — authentication audit log.
- **allowlist** (`/allowlist.html`) — approved connections and apps.

## Requirements

- Linux with `nftables` (firewall) and `/proc/net` access
- `tcpdump` + `iproute2` (runtime deps, installed by `install.sh`)
- Go 1.21+ to build
- Optional: Suricata (managed in-app), Ollama (AI assistant),
  `libappindicator`/GTK3 (tray app)

## Project layout

```
main.go                 # daemon: CLI, HTTP, WS, integration wiring
cmd/netmon-tray/        # systray app (CGO)
internal/
  auth/                 # users, sessions, CSRF, rate limit, audit
  capture/              # /proc/net polling, inode→PID, enrichment
  detect/               # behavioral detection engine + custom rules
  firewall/             # nftables enforcement, pending approvals
  suricata/             # eve.json reader, config mgmt, installer
  store/                # SQLite (pure Go driver), batching
  reports/ metrics/     # scheduled reports, self-monitoring
  ai/                   # Ollama client + tools
  pcap/ dnsmon/ lookup/ blocklist/ privdrop/ logutil/
static/                 # embedded PWA dashboard
```

## Repository stats

- ~17k lines of Go across the daemon, 14 packages with unit tests.
- Two binaries: `netmon` (root daemon, static) + `netmon-tray` (user systray).

## License & credits

NetGuard is an open-source personal/network security tool. Use it on networks
you own or are authorized to monitor. Firewall enforcement is applied via
`nftables` and is non-destructive by design (panic + auto-revert).

---

Built for the security-minded homelab. Feedback and pull requests welcome.