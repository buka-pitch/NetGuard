# API reference

Base: the dashboard root (`http://127.0.0.1:8484` by default). All `/api/*`
routes (except the marked public auth endpoints) require a valid session.

## Authentication & sessions

Public (reachable without a session):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/auth/status` | Session + setup status (used by the frontend bootstrap) |
| POST | `/api/auth/login` | Log in (JSON: `{username, password}`) |
| POST | `/api/auth/setup` | First-run admin creation (JSON: `{token, username, password}`) |
| POST | `/api/auth/password-reset` | Reset via out-of-band token (JSON: `{reset_token, new}`) |

Authenticated:

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/auth/logout` | End the current session |
| POST | `/api/auth/password` | Change password (JSON: `{current, new}`) |
| POST | `/api/auth/password-reset/issue` | Admin: issue reset token for a user |
| POST | `/api/auth/sessions/revoke-all` | Kill every session except the current one |
| GET | `/api/auth/events` | Last 100 auth audit events |

Session tokens are carried in a `HttpOnly` cookie (`netmon_session`), or via
`?token=` / `Authorization: Bearer`. Mutating requests must include the
`X-XSRF-TOKEN` header (cookie `netmon_xsrf`). See [SECURITY.md](SECURITY.md).

## Connections & stats

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/connections` | Live connections (optionally `?state=`) |
| GET | `/api/connections/export` | CSV/JSON export (`?format=csv` or `json`) |
| GET | `/api/processes` | Processes with active traffic |
| GET | `/api/stats` | Totals: connection counts, alerts, top processes/IPs |
| GET | `/api/alerts` | Detection alerts |
| GET | `/api/alerts/export` | CSV/JSON export |
| GET | `/api/dashboard` | Time-series data (`?minutes=`, `&process=`, `&remote=`) |
| GET | `/api/dashboard/heatmap` | Activity heatmap buckets |
| GET | `/api/metrics` | Self-monitoring: CPU, RSS, goroutines, fds, uptime |
| GET | `/api/health` | Liveness + firewall state |

## Firewall

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/firewall/status` | State: enabled, policy, panic mode, pending count |
| GET | `/api/firewall/pending` | Queued connections awaiting approval |
| POST | `/api/firewall/approve` | `{id, mode}` mode `once` or `always` |
| POST | `/api/firewall/approve-all` | `{mode}` approve everything pending |
| POST | `/api/firewall/deny` | `{id}` deny a connection |
| POST | `/api/firewall/deny-all` | Deny all pending |
| POST | `/api/firewall/deny-app` | `{id}` permanently silence an app's prompts |
| POST | `/api/firewall/allow-app` | `{exe?/process?}` full bypass for an app |
| GET/POST | `/api/firewall/allowlist` | Per-connection allowlist rules |
| GET | `/api/firewall/app-allowlist` | Approved apps |
| GET | `/api/firewall/app-denylist` | Denied apps |
| GET/POST | `/api/firewall/blocklist` | Blocklist IPs |
| POST | `/api/firewall/panic` | Toggle panic mode (blast-firewall-off, auto-revert) |

## Suricata IDS

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/suricata/status` | Running state, uptime, stats |
| POST | `/api/suricata/start` `/stop` `/restart` | Service control |
| GET | `/api/suricata/config` | `suricata.yaml` as JSON |
| GET | `/api/suricata/rules` | Rule files + enable status |
| POST | `/api/suricata/rules/toggle` | Enable/disable a rule file |
| POST | `/api/suricata/rules/upload` | Upload a rules file |
| GET | `/api/suricata/alerts` | Enriched alerts from eve.json |
| GET | `/api/suricata/alerts/export` | CSV/JSON export |
| GET | `/api/suricata/stats` | Flow/packet counters |
| POST | `/api/suricata/install` | Install Suricata |
| POST | `/api/suricata/install/dry-run` | Simulate install, report planned changes |
| POST | `/api/suricata/install/apply` | Apply a dry-run plan |
| POST | `/api/suricata/install/rollback` | Undo the last applied plan |
| GET | `/api/suricata/install/checkpoints` | Saved restore points |

## Lookups

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/lookup/rdns` | `?ip=` reverse DNS |
| GET | `/api/lookup/geoip` | `?ip=` GeoIP (city, coords, ISP) |
| GET | `/api/lookup/geoip/batch` | `?ips=a,b,c` batch GeoIP |
| GET | `/api/lookup/whois` | `?ip=` whois text |
| GET | `/api/lookup/threat` | `?ip=` DNSBL / threat intel check |

## PCAP

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/pcap/capture` | Start a capture; returns a filename |
| GET | `/api/pcap/download/<file>` | Download the `.pcap` |
| GET | `/api/pcap/read/<file>` | Read summary text of a capture |

## Custom rules & reports

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/rules` | Custom behavioral rules |
| POST | `/api/rules/toggle` | Enable/disable a rule |
| GET | `/api/rules/preview` | Dry-run a rule against history |
| GET | `/api/rules/stats` | Rule hit counts |
| POST | `/api/reports/generate` | Generate a report now |
| GET | `/api/reports/files` | List generated reports |
| GET | `/api/reports/download/<file>` | Download a report |

## AI assistant

Uses a local Ollama instance (default `http://localhost:11434`, model
`qwen3:8b`). Requires Ollama running on the same host.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/ai/models` | Available model tags |
| POST | `/api/ai/chat` | One-shot chat completion |
| POST | `/api/ai/chat/stream` | Streaming chat (SSE) |
| POST | `/api/ai/analyze-pcap` | Ask the assistant to analyze a capture |

## WebSocket

`GET /ws` — pushes a combined payload every **1 s** while any client is
connected. Payload shape:

```json
{
  "connections": [...],
  "alerts": [...],
  "stats": {...},
  "fw_status": {"enabled": true, "policy": "block", "panic_mode": false, "pending": 2},
  "fw_pending": [...]
}
```

## Auth on API calls from scripts

```sh
# grab a session cookie, then call anything
curl -c jar -X POST http://127.0.0.1:8484/api/auth/login \
  -d '{"username":"admin","password":"Sup3rSecret!"}'
curl -b jar http://127.0.0.1:8484/api/auth/events
```

For server-to-server access you can also pass the token without cookies:

```sh
curl "http://127.0.0.1:8484/api/stats?token=<session-token>"
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8484/api/stats
```