# Netmon — Plan

## Overview

A Linux network security monitor that tracks every connection by process with zero-trust firewall enforcement. Two binaries: `netmon` (root daemon, static CGO_ENABLED=0) and `netmon-tray` (user process, CGO_ENABLED=1 for systray).

## Architecture

```
netmon (root daemon :8484)
├── Capture — polls /proc/net/{tcp,udp,raw,icmp}{,6} every 1s
│   ├── inode→PID resolution via /proc/<pid>/fd
│   └── Enrichment: cmdline, exe, parent chain, rDNS, domain
├── Detection engine
│   ├── BeaconRule — variance <15% of mean interval, 5+ samples
│   ├── BlocklistRule — IP match against blocklist table
│   └── DetectTrends — IQR <50ms jitter analysis (10+ samples)
├── Firewall (nftables via exec.Command)
│   ├── Output chain (default-deny) + allowed set
│   ├── Input chain (default-deny) + allowed_in set
│   ├── Pre-seeded system rules (systemd-resolved, chronyd, dhcpcd)
│   ├── App allowlist (full process bypass)
│   └── Panic mode (policy accept with auto-revert)
├── Suricata integration
│   ├── eve.json tail-reader with offset tracking
│   ├── Process enrichment (match flow by IP:port → PID/comm)
│   ├── Config management (read/write suricata.yaml)
│   ├── systemctl start/stop/restart
│   └── Rule file toggling + upload
├── SQLite storage (modernc.org/sqlite, pure Go)
│   ├── connections, alerts, blocklist, pending_approvals
│   ├── allowlist, app_allowlist, suricata_alerts
│   └── Flush batching (100 events / 1s)
├── HTTP server
│   ├── REST API (/api/*) + WebSocket (/ws) every 200ms
│   ├── Static file server for dashboard
│   └── rDNS/GeoIP/threat lookup endpoints
└── Firewall manager
    ├── initDB with direction column migrations
    ├── PreSeed system rules (dedup by exe+ip+port+proto)
    ├── Pending queue with 30s dedup window
    ├── Approve/Deny with direction-aware nftables ops
    └── CleanExpired every 30s (revokes one-shot rules)

netmon-tray (user process)
└── systray icon + polling daemon status
```

## Current State

All core features built and tested (47 unit tests across 4 packages):

- [x] /proc/net polling (TCP, UDP, ICMP, raw — v4 + v6)
- [x] Process-to-connection attribution (inode→PID resolver)
- [x] Connection enrichment (cmdline, exe, ppid, pcomm, gpid, gcomm, domain)
- [x] TLS SNI + HTTP host from suricata alerts on live connections
- [x] nftables output chain (default-deny, app + per-conn allowlist)
- [x] nftables input chain (default-deny, allowed_in set)
- [x] Incoming connection detection via SYN_SENT tracking
- [x] Pre-existing connection suppression on first poll
- [x] VPN port heuristic badge
- [x] Firewall pending approval system (30s dedup, direction-aware)
- [x] Detection engine (beacon, blocklist, jitter/trends)
- [x] Suricata eve.json reader + process enrichment
- [x] Suricata config management + service control
- [x] Suricata rule upload + toggling
- [x] SQLite storage layer (batch writes, all event types)
- [x] WebSocket live push (200ms interval)
- [x] REST API (connections, alerts, stats, firewall CRUD)
- [x] Web dashboard with sortable/filterable connection table
- [x] Connection detail expansion (cmdline, exe, parent, queues)
- [x] Sortable columns with arrow indicators
- [x] Toast notifications + confirmation dialogs
- [x] Responsive CSS grid layout (3-col → 2-col → 1-col)
- [x] Allowlist page with add-rule form + delete
- [x] Panic mode toggle with pulse animation
- [x] rDNS/GeoIP/threat lookup buttons
- [x] Professional dark theme (CSS custom properties)
- [x] Firewall direction isolation (out vs in rules)
- [x] nftables errors non-fatal (graceful without root)
- [x] Tray binary skeleton (poll daemon status + systray)

## Remaining

- [x] Clean up suricata "resuming from offset" log spam
- [x] Add TLS SNI and HTTP host to live connection display
- [x] Process ancestry chain in connection details (gpid/gcomm)
- [x] CSV/JSON export endpoints (/api/connections/export, /api/alerts/export, /api/suricata/alerts/export)
- [x] Whois lookup endpoint (/api/lookup/whois)
- [x] Geolocation map (Leaflet.js, /geo.html)
- [x] Structured JSON logging (internal/logutil package)
- [x] Self-monitoring / health endpoint (/api/health)
- [x] Capability dropping after init (internal/privdrop + config run_as)
- [x] Tray notifications for blocked connections (notify-send via sendNotify)
- [x] Tray auto-start systemd user service (scripts/netmon-tray.service)
- [ ] Custom Alert Rules UI — store rules in DB, CRUD from web UI, eval engine reads from DB
- [ ] PCAP Extraction — on-demand tcpdump capture from UI, download .pcap
- [ ] Scheduled Reports — daily summary of top connections, alerts, trends (HTML/JSON)
- [ ] eBPF Phase 2 (blocked: kernel lacks CONFIG_DEBUG_INFO_BTF)
