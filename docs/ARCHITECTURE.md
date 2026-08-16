# Architecture

NetGuard is a root daemon (`netmon`) that ties `/proc` process visibility,
a default-deny nftables firewall, and behavioral + signature detection into
one web dashboard — plus an optional user-level systray app (`netmon-tray`).

```
┌──────────────────────── netmon (root daemon :8484) ────────────────────────┐
│                                                                            │
│  capture.Poller ──► /proc/net/{tcp,udp,raw,icmp}{,6} every poll_interval   │
│     │   inode ──► /proc/<pid>/fd            » process attribution           │
│     │   enrichment: cmdline, exe, ppid/pcomm, parent chain, domain         │
│     ▼                                                                      │
│  detect.Engine                                                             │
│     ├── blocklist matching (static + remote feeds)                         │
│     ├── beacon detection (interval variance, sample count)                 │
│     └── trend/jitter analysis                                             │
│     ▼                                                                      │
│  store ──(SQLite, pure-Go modernc driver, batched 100/1s)────────┐         │
│   connections · alerts · pending_approvals · allowlists · rules  │         │
│     ▲                                                            │         │
│  firewall.Manager ── nftables ───────────────────────────────────┘         │
│   output chain (default-deny)  input chain (default-deny)                  │
│   allowed[:in] sets · app_allowlist bypass · panic mode (auto-revert)      │
│                                                                            │
│  suricata.Reader ── tail /var/log/suricata/eve.json                        │
│   alerts enriched with PID + comm by IP:port match                         │
│  suricata.Manager ── systemctl + yaml read/write + rule toggle/upload     │
│  reports.Scheduler ── daily HTML/JSON or webhook                           │
│  dnsmon ── watches DNS server changes                                     │
│  ai ── Ollama client + tool-calling (chat, analyze-pcap)                   │
│                                                                            │
│  HTTP server: REST /api/* + WebSocket /ws (push every 1s)                  │
│  embedded static PWA (single binary, no runtime deps)                      │
│  auth: setup token · sessions · CSRF · rate-limit · audit log              │
└────────────────────────────────────────────────────────────────────────────┘

netmon-tray (user process, CGO systray)
  polls daemon state → icon states (active / pending / panic) + notifications
  quick links: dashboard · events · panic
```

## Data flow (per poll)

```
1. Snapshot /proc/net tables  →  connections with local/remote addr:port,
   state, inode
2. Resolve each inode → PID via /proc/<pid>/fd symlinks
3. Enrich with proc info (exe, cmdline, parent chain) + domain/TLS/HTTP hints
4. Diff against previous snapshot → new/updated/closed events
5. Push events to store, engine, firewall queue
6. Firewall: new outbound/inbound connections to unknown targets queue for
   approval; approved ones get rules in the nftables set
7. Detection engine emits alerts for blocklist hits / beacons / trends
8. WebSocket fans out the combined payload to all dashboard clients
```

## Firewall model

Zero-trust default-deny. nftables chains are populated (not replaced):

- **output chain** — packets permitted only if they match the allowed set
  (or a seeded system rule for resolvers/NTP), otherwise the SYN is the
  trigger for a pending approval.
- **input chain** — inbound only for allowed services; anything else raises an
  incoming-connection prompt.
- **app allowlist** — a process that is fully approved skips per-connection
  prompts via its rule.
- **panic mode** — transitional policy to accept, auto-reverts after a short
  window; visible as a full-page red state in the UI.

Prompts are deduplicated per target on a 30 s window; pending approvals can
be handled individually (`once` / `always` / `deny` / `deny app`) or in bulk.

## Detection engine

- **Blocklist** — static config IPs plus remote feeds (refresh interval
  configurable) are flagged on connection.
- **Beaconing** — samples the connection interval; low variance over >= 5
  samples triggers a high-severity alert.
- **Trend/jitter** — 10+ sample analysis of timing variance (IQR) flags hosts
  with suspiciously consistent timing.

Custom rules are persisted to SQLite and evaluated live from the **rules**
page; `preview` dry-runs a rule against stored history.

## Suricata integration

One-click install with an **install planner**:

1. `dry-run` — checks system, plans YAML changes + service steps, saves a
   restore checkpoint (no side effects).
2. `apply` — executes the plan (config write → service start).
3. `rollback` — restores from the checkpoint.

The reader tails `eve.json` with offset tracking and enriches each alert by
matching flow IP:port against the current process snapshot, so every
signature alert shows the responsible process. Rules can be toggled/uploaded
from the UI.

## Storage

SQLite via `modernc.org/sqlite` (pure Go). Writes are batched
(100 events / 1 s) to keep disk IO low. Schema covers: connections, alerts,
suricata alerts, pending approvals, allowlists, denylists, custom rules,
report metadata, and the auth audit log.

## Why `/proc` polling and not eBPF

The original design targeted eBPF CO-RE, but the target kernel lacks
`CONFIG_DEBUG_INFO_BTF`, so the live path uses `/proc/net` polling — which is
portable, dependency-free, and (being inode-based) still gives precise
process attribution. See `IMPLEMENTATION_PLAN.md` for history.

## Source layout

```
main.go                 # CLI, HTTP, WS, subsystem wiring, graceful shutdown
cmd/netmon-tray/        # systray client (CGO)
config/                 # typed config + defaults
internal/
  auth/                 # users, sessions, CSRF, rate limit, audit
  capture/              # poller, /proc enrichment, (ebpf stubs)
  detect/               # engine + rules + trends
  firewall/             # nftables manager + approval queue
  suricata/             # reader, manager, plan/install, yaml
  store/                # sqlite schema + batch writer
  reports/              # scheduler, html/json/webhook
  ai/                   # ollama client + tools
  pcap/ dnsmon/ lookup/ blocklist/ privdrop/ metrics/ logutil/
static/                 # embedded PWA
```