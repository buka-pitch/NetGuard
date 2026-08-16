# Configuration

The daemon reads a JSON configuration file. Default location:
`/etc/netmon/config.json` (override with `-config /path`).

If the file does not exist, built-in defaults are used — the daemon is fully
functional out of the box.

## Full example

```json
{
  "poll_interval": "3s",
  "db_path": "/var/lib/netmon/netmon.db",
  "buffer_size": 1000,
  "alert_limit": 100,
  "listen_addr": "127.0.0.1:8484",

  "blocklist_url": "",
  "blocklist": [
    "185.130.5.253",
    "5.188.62.18"
  ],
  "blocklist_refresh": "6h",
  "blocklist_source": "local",

  "run_as": "netmon",
  "ask_on_start": true,

  "suricata_enabled": true,
  "suricata_conf_path": "/etc/suricata/suricata.yaml",
  "suricata_eve_path": "/var/log/suricata/eve.json",

  "report_enabled": true,
  "report_time": "08:00",
  "report_interval": 24,
  "report_output": "file",
  "report_webhook": "https://hooks.example.com/...",
  "report_format": "html",

  "dns_monitor_enabled": true,

  "auth_session_ttl": "168h",
  "auth_setup_file": "/var/lib/netmon/setup-token"
}
```

## Fields

### Capture & storage

| Field | Default | Description |
|-------|---------|-------------|
| `poll_interval` | `3s` | How often `/proc/net/*` is polled |
| `db_path` | `/var/lib/netmon/netmon.db` | SQLite database path |
| `buffer_size` | `1000` | Event queue buffer size |
| `alert_limit` | `100` | Alerts kept per page in the UI |
| `listen_addr` | `127.0.0.1:8484` | HTTP/WebSocket bind address |

Press `[0-9]+h`/`m`/`s` duration strings are accepted for all duration fields.

### Blocklist

| Field | Default | Description |
|-------|---------|-------------|
| `blocklist_url` | `""` | Remote blocklist feed to fetch |
| `blocklist` | `[]` | Static list of IPs to treat as malicious |
| `blocklist_refresh` | `6h` | How often to re-fetch a remote feed |
| `blocklist_source` | `local` | Label for the blocklist source |

Connections to blocklisted IPs are flagged by the detection engine.

### Privilege / behavior

| Field | Default | Description |
|-------|---------|-------------|
| `run_as` | `""` | Drop privileges to this Unix user after startup (see Security) |
| `ask_on_start` | `true` | Prompt for approval of connections already open at daemon start |

### Suricata IDS

| Field | Default | Description |
|-------|---------|-------------|
| `suricata_enabled` | `true` | Enable eve.json tailing + integration |
| `suricata_conf_path` | `/etc/suricata/suricata.yaml` | YAML config managed by the app |
| `suricata_eve_path` | `/var/log/suricata/eve.json` | Log file tailed for alerts |

### Scheduled reports

| Field | Default | Description |
|-------|---------|-------------|
| `report_enabled` | `true` | Generate daily reports |
| `report_time` | `08:00` | Local time to generate |
| `report_interval` | `24` | Hours between reports |
| `report_output` | `file` | `file` or `webhook` |
| `report_webhook` | `""` | Endpoint to POST reports to (when `webhook`) |
| `report_format` | `html` | `html` or `json` |

### DNS monitoring

| Field | Default | Description |
|-------|---------|-------------|
| `dns_monitor_enabled` | `true` | Watch for new/changed DNS server configs |

### Auth

| Field | Default | Description |
|-------|---------|-------------|
| `auth_session_ttl` | `168h` (`7d`) | Session cookie lifetime |
| `auth_setup_file` | `/var/lib/netmon/setup-token` | Where the one-time setup token lives |

## Example minimal config

```json
{
  "listen_addr": "0.0.0.0:8484",
  "poll_interval": "1s",
  "ask_on_start": false
}
```

> **Security note:** binding to `0.0.0.0` exposes the dashboard on the network.
> Auth is required, but prefer a reverse proxy with TLS for remote access. See
> [SECURITY.md](SECURITY.md).