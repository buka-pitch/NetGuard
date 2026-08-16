# Suricata + netmon Integration Plan

## Data Flow

```
Suricata ──► /var/log/suricata/eve.json (JSON lines)
                  │
                  ▼
          netmon suricata reader
          (tail -f + parse + enrich)
                  │
                  ▼
          ┌─────────────────────┐
          │  Match flow against  │
          │  poller's process    │
          │  snapshot by IP:port │
          └──────────┬──────────┘
                     ▼
          ┌─────────────────────┐
          │  Enriched alert:    │
          │  Suricata meta +    │
          │  PID + comm + path  │
          └──────────┬──────────┘
                     ▼
          ┌─────────────────────┐
          │  SQLite + API + UI  │
          └─────────────────────┘

          netmon manages Suricata:
          ┌─────────────────────┐
          │  Read/write YAML    │
          │  Start/stop service │
          │  Toggle rule files  │
          └─────────────────────┘
```

## New Files (5 backend + 2 frontend)

```
internal/suricata/
├── types.go      # SuricataAlert, SuricataStatus, SuricataConfig
├── reader.go     # Tail eve.json, parse JSON, enrich with process info
├── config.go     # Read/write suricata.yaml via gopkg.in/yaml.v3
└── manager.go    # systemctl start/stop/restart + status

static/
├── suricata.html # Suricata dashboard (alerts, rules, settings)
└── suricata.js   # Fetch API, render tables, config editing
```

## API Endpoints

```
GET  /api/suricata/status        — running? uptime? packets/drops?
GET  /api/suricata/alerts        — enriched alerts from eve.json
POST /api/suricata/restart       — systemctl restart suricata
GET  /api/suricata/config        — suricata.yaml as JSON
POST /api/suricata/config        — update and restart
GET  /api/suricata/rules         — list rule files with enable status
POST /api/suricata/rules/toggle  — enable/disable a rule file
```

## UI Layout

Current dashboard gets a nav bar: [Live] [Suricata]

### Suricata page tabs:

| Tab | Shows |
|-----|-------|
| **Alerts** | Timestamp, Src→Dst:port, Signature, Category, Severity, PID/Comm |
| **Rules** | Rule files with toggles, rule counts |
| **Settings** | suricata.yaml key fields as form inputs (HOME_NET, interface, etc.) |
| **Stats** | Packets processed, dropped, alerts/second from unix socket |

## Enrichment Strategy

Suricata alerts have IP:port pairs but no PID. netmon matches them:

```go
func (r *Reader) enrich(alert SuricataFlow, snapshot []capture.Connection) *SuricataAlert {
    for _, conn := range snapshot {
        if (conn.RemoteAddr.String() == alert.DstIP && conn.RemotePort == alert.DstPort) ||
           (conn.LocalAddr.String() == alert.SrcIP && conn.LocalPort == alert.SrcPort) {
            alert.PID = conn.PID
            alert.Comm = conn.Comm
            break
        }
    }
}
```

## Key Integration Points

| netmon capability | Suricata gap | Benefit |
|---|---|---|
| Process map | Knows nothing about processes | Every alert gets PID + process name |
| Connection history | Only real-time | Cross-reference past flows |
| Beacon detection | Only signature-based | Behavioral + signature combined |
| Dashboard | Raw eve.log | Filtered, enriched, process-aware |
| Config management | Manual YAML editing | Web UI for YAML + rules |
