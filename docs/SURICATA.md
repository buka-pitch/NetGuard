# Suricata integration

NetGuard bundles management of a Suricata IDS: install, config, rule
control, and live alert enrichment — all from the dashboard (**ids** page).

## Data flow

```
Suricata ──► /var/log/suricata/eve.json (JSON lines)
                  │
                  ▼
          suricata reader (tail -f, offset-tracked)
                  │
                  ▼
          Match flow against capture.Poller's snapshot by IP:port
                  ▼
          Enriched alert: PID + comm + parent chain + Suricata meta
                  ▼
          SQLite + API + UI
```

The value-add: signature alerts from Suricata only contain IP:port pairs.
NetGuard owns the process map, so every alert is decorated with the actual
program responsible.

## Install flow (plan → apply → rollback)

| Step | Endpoint | Effect |
|------|----------|--------|
| Dry run | `POST /api/suricata/install/dry-run` | Inspect system, compute JSON plan (config edits + service steps), save restore checkpoint. **No side effects.** |
| Apply | `POST /api/suricata/install/apply` | Execute the approved plan (write YAML → start service). |
| Rollback | `POST /api/suricata/install/rollback` | Restore from the last checkpoint. |
| Checkpoints | `GET /api/suricata/install/checkpoints` | List saved restore points. |

Plans are also available as full **JSON** documents, so a reviewer can pick
a plan that best matches the environment.

## Config management

`suricata.yaml` is read/written through `internal/suricata` (via
`gopkg.in/yaml.v3`) and exposed as JSON by the API — the UI edits key fields
(HOME_NET, interface, etc.) as form inputs instead of raw YAML.

## Rule management

- List rule files with enable status and counts.
- Toggle individual rule files on/off.
- Upload custom rule files from the UI.

## Alert enrichment

```text
suricata_alerts
  ├── from eve.json: signature, category, severity, action, flow
  └── joined with poller snapshot by (src|dst) IP:port:
        pid, comm, exe, cmdline, parent chain
```

## Service control

`/api/suricata/start` · `/stop` · `/restart` proxy to `systemctl`, and
`/api/suricata/stats` surfaces flow/packet counters. Status is surfaced on
the dashboard's monitoring strip.

## Related files

```
internal/suricata/
├── types.go    # SuricataAlert, SuricataStatus, SuricataConfig
├── reader.go   # tail eve.json, parse, enrich with process info
├── manager.go  # systemctl control + status
├── rules.go    # rule file listing / toggling / upload
├── yaml.go     # YAML read/write helpers
└── plan.go     # install planner: dry-run / apply / rollback checkpoints
```