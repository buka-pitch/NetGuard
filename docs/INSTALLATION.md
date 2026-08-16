# Installation

NetGuard ships as two binaries:

| Binary | Runs as | Purpose | Build |
|--------|---------|---------|-------|
| `netmon` | root | daemon: capture, firewall, IDS, HTTP | static, `CGO_ENABLED=0` |
| `netmon-tray` | user | systray icon + notifications | `CGO_ENABLED=1` (GTK/AppIndicator) |

## Prerequisites

- Linux (tested on Debian-family; apt/dnf/yum/pacman/zypper/apk supported)
- `nftables` in the kernel/userspace for firewall enforcement
- Go 1.21+ to build from source
- Optional: `suricata` (managed via the app), `ollama` (AI assistant),
  GTK3 + AppIndicator dev packages (tray)

## Build

```sh
# daemon (static binary, no runtime C dependencies)
make build                       # or: CGO_ENABLED=0 go build -o bin/netmon .

# tray app (needs CGO + GTK headers)
CGO_ENABLED=1 go build -o bin/netmon-tray ./cmd/netmon-tray

# run tests
make test                        # or: go test ./...
```

## Install (recommended)

```sh
sudo ./install.sh
```

The installer will:

1. Regenerate PWA + tray icons from `static/logo.svg` if ImageMagick is present.
2. Detect your package manager and install deps (`tcpdump`,
   `iproute2`, plus tray build deps).
3. Copy `bin/netmon` to `/usr/local/bin/netmon`.
4. Install and start the systemd unit `netmon.service`.
5. Build the tray app and (when run via sudo) install
   `netmon-tray.service` as a **user** unit under the invoking user, enabling
   `linger` so it survives logout.

Verify:

```sh
systemctl status netmon
http://127.0.0.1:8484
```

## Manual install / systemd

If you prefer to run it yourself:

```sh
sudo install -m 755 bin/netmon /usr/local/bin/netmon
sudo install -m 644 scripts/netmon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netmon
```

`netmon.service` (from the repo):

```ini
[Unit]
Description=NetMon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/netmon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

The daemon reads configuration from `/etc/netmon/config.json` by default
(see [CONFIGURATION.md](CONFIGURATION.md)); pass `-config <path>` to override.

To run it directly (for testing, no systemd):

```sh
sudo ./bin/netmon -config /path/to/config.json
```

## First-time setup

On a fresh install (no users exist yet):

1. Retrieve the one-time setup token (also printed in the logs):

   ```sh
   sudo cat /var/lib/netmon/setup-token
   ```

2. Open `http://127.0.0.1:8484/setup` and paste the token to create the
   admin user.

The token expires after **24 h**; restarting the daemon generates a fresh one.

Password policy: at least **12 characters**, must include lower, upper,
digit, and symbol characters (e.g. `Sup3rSecret!`).

## Upgrading from a pre-auth version

Existing users are flagged for a forced password reset. A per-user reset
token is written to `/var/lib/netmon/password-reset-token.<username>`
(expires in **1 h**). Deliver it out-of-band; the user pastes it at
`http://127.0.0.1:8484/password-reset.html` and sets a new password.

## Tray app

Installed automatically by `install.sh` when run via sudo. Otherwise, enable
manually for $USER:

```sh
sudo cp scripts/netmon-tray.service /home/$USER/.config/systemd/user/
systemctl --user enable --now netmon-tray
loginctl enable-linger $USER   # survives logout
```

The tray icon shows daemon state (active / pending approvals / panic) and can
jump straight to the dashboard, the events page, or panic on demand.

The tray authenticates to the daemon with a machine API token. `install.sh`
generates one, writes it to `auth_api_token` in `/etc/netmon/config.json`, and
stores a copy at `/etc/netmon/tray-token` which the tray reads by default
(`-token-file`). If you configure manually, ensure both sides match:

```sh
# daemon config /etc/netmon/config.json
{ "auth_api_token": "<long random hex>" }
# tray: either a -token-file or -token pointing at the same value
netmon-tray -token-file=/etc/netmon/tray-token
```

## Uninstalling

```sh
sudo systemctl disable --now netmon
sudo systemctl --user disable --now netmon-tray
sudo rm /usr/local/bin/netmon /usr/local/bin/netmon-tray
sudo rm /etc/systemd/system/netmon.service
sudo rm -rf /var/lib/netmon /etc/netmon
```

## Common operations

```sh
journalctl -u netmon -f              # daemon logs
systemctl restart netmon             # restart daemon
sudo cat /var/lib/netmon/netmon.db   # SQLite data
```

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Firewall shows "off" | nftables missing or not writable; check logs |
| Panel loads but no firewall rules | Permission denied — daemon must be root |
| PCAP capture fails | `tcpdump` missing; re-run `install.sh` or install it |
| Events page redirects to login | Session cookie cleared; re-login |
| Setup page not offered | A user already exists; log in instead |
| AI assistant unavailable | Ollama not running at `http://localhost:11434` |

For kernel/eBPF details (and why the project uses `/proc/net` polling instead),
see [PLAN.md](../PLAN.md).