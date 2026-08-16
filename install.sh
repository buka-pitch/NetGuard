#!/bin/sh
set -e

if [ "$(id -u)" != 0 ]; then
  echo "this installer must be run as root (sudo)"
  exit 1
fi

echo "=== netmon installer ==="

# gen_token prints a strong random hex token for the machine API credential.
gen_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

# regenerate PWA icons from logo.svg if ImageMagick is available.
# this lets a single SVG change propagate to the embedded PNGs.
SCRIPT_DIR="$(dirname "$0")"
if [ -f "$SCRIPT_DIR/static/logo.svg" ] && command -v convert >/dev/null 2>&1; then
  echo "regenerating PWA icons from logo.svg..."
  convert -background none -resize 192x192 "$SCRIPT_DIR/static/logo.svg" \
      "$SCRIPT_DIR/static/icon-192.png" 2>/dev/null || true
  convert -background none -resize 512x512 "$SCRIPT_DIR/static/logo.svg" \
      "$SCRIPT_DIR/static/icon-512.png" 2>/dev/null || true
  convert -background none -resize 368x368 -gravity center -extent 512x512 \
      -background '#0a84ff' "$SCRIPT_DIR/static/logo.svg" \
      "$SCRIPT_DIR/static/icon-maskable-512.png" 2>/dev/null || true

  # tray-state icons (64x64 PNGs, color-tinted variants of logo.svg) used
  # by netmon-tray for the active/pending/panic states. Disconnected state
  # uses a procedural grey circle in the binary.
  echo "regenerating tray icons from logo.svg..."
  mkdir -p "$SCRIPT_DIR/cmd/netmon-tray/assets"
  convert -background none -resize 64x64 "$SCRIPT_DIR/static/logo.svg" \
      "$SCRIPT_DIR/cmd/netmon-tray/assets/tray-active.png" 2>/dev/null || true
  convert -background none -resize 64x64 -fill '#c8b400' -tint 50 \
      "$SCRIPT_DIR/static/logo.svg" \
      "$SCRIPT_DIR/cmd/netmon-tray/assets/tray-pending.png" 2>/dev/null || true
  convert -background none -resize 64x64 -fill '#c80000' -tint 50 \
      "$SCRIPT_DIR/static/logo.svg" \
      "$SCRIPT_DIR/cmd/netmon-tray/assets/tray-panic.png" 2>/dev/null || true
elif [ -f "$SCRIPT_DIR/static/logo.svg" ]; then
  echo "warning: ImageMagick 'convert' not found — PWA + tray icons will use"
  echo "         whatever is already committed. install imagemagick to regenerate."
fi

# detect package manager
PM=""
PM_INSTALL=""
if command -v apt >/dev/null 2>&1; then
  PM="apt"
  PM_INSTALL="apt install -y"
elif command -v dnf >/dev/null 2>&1; then
  PM="dnf"
  PM_INSTALL="dnf install -y"
elif command -v yum >/dev/null 2>&1; then
  PM="yum"
  PM_INSTALL="yum install -y"
elif command -v pacman >/dev/null 2>&1; then
  PM="pacman"
  PM_INSTALL="pacman -S --noconfirm"
elif command -v zypper >/dev/null 2>&1; then
  PM="zypper"
  PM_INSTALL="zypper install -y"
elif command -v apk >/dev/null 2>&1; then
  PM="apk"
  PM_INSTALL="apk add"
else
  echo "warning: no supported package manager found — install tcpdump manually"
fi

# install dependencies
DEPS="tcpdump iproute2"
DEPS_TRAY=""
if [ -n "$PM" ]; then
  case "$PM" in
    apt)    DEPS_TRAY="libgtk-3-dev libayatana-appindicator3-dev" ;;
    dnf|yum) DEPS_TRAY="gtk3-devel libappindicator-gtk3-devel" ;;
    pacman) DEPS_TRAY="gtk3 libappindicator-gtk3" ;;
    zypper) DEPS_TRAY="gtk3-devel libappindicator3-devel" ;;
    apk)    DEPS_TRAY="gtk+3.0-dev libappindicator-dev" ;;
  esac
  echo "installing dependencies: $DEPS"
  $PM_INSTALL $DEPS
  if [ -n "$DEPS_TRAY" ]; then
    echo "installing tray build deps: $DEPS_TRAY"
    $PM_INSTALL $DEPS_TRAY || echo "warning: tray build deps failed — tray build will likely fail"
  fi
fi

# find binary
SCRIPT_DIR="$(dirname "$0")"
BIN=""
for p in "$SCRIPT_DIR/bin/netmon" "$SCRIPT_DIR/netmon"; do
  if [ -f "$p" ] && [ -x "$p" ]; then
    BIN="$p"
    break
  fi
done

if [ -z "$BIN" ]; then
  echo "error: netmon binary not found — build it first: go build -o bin/netmon ."
  exit 1
fi

echo "installing binary: /usr/local/bin/netmon"
cp "$BIN" /usr/local/bin/netmon
chmod 755 /usr/local/bin/netmon

# --- configure machine API token for local helpers (netmon-tray) ---
# The tray runs as a desktop user and must authenticate to the daemon. A
# dedicated machine token (auth_api_token) is generated once and handed to
# the tray via /etc/netmon/tray-token. It only grants firewall access — NOT
# the user-scoped /api/auth/* admin actions (password change, password
# reset, session revocation, audit log) which still require a real session.
mkdir -p /etc/netmon
TOKEN_FILE=/etc/netmon/tray-token
if [ ! -f /etc/netmon/config.json ]; then
  # no config yet — emit one carrying only auth_api_token so every other
  # setting falls back to the daemon's built-in defaults
  echo "creating /etc/netmon/config.json with generated API token"
  echo "{ \"auth_api_token\": \"$(gen_token)\" }" > /etc/netmon/config.json
elif ! grep -q '"auth_api_token"' /etc/netmon/config.json; then
  if command -v jq >/dev/null 2>&1; then
    echo "adding auth_api_token to /etc/netmon/config.json"
    TMP="$TOKEN_FILE.tmp.$$"
    jq --arg t "$(gen_token)" '.auth_api_token = $t' /etc/netmon/config.json > "$TMP" \
      && mv "$TMP" /etc/netmon/config.json
  else
    echo "warning: jq not found — /etc/netmon/config.json has no auth_api_token."
    echo "         add it manually (see docs/CONFIGURATION.md) or the tray will stay unauthenticated."
  fi
fi
if [ -f /etc/netmon/tray-token ]; then
  echo "reusing existing tray token at $TOKEN_FILE"
else
  echo "writing tray token to $TOKEN_FILE"
  grep '"auth_api_token"' /etc/netmon/config.json | head -1 | sed -E 's/.*: *"([^"]+)".*/\1/' > "$TOKEN_FILE"
  chmod 644 "$TOKEN_FILE"
fi

# install systemd service
if command -v systemctl >/dev/null 2>&1; then
  echo "installing systemd service"
  cat > /etc/systemd/system/netmon.service << 'SERVICE'
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
SERVICE
  systemctl daemon-reload
  systemctl enable netmon
  echo "starting netmon"
  systemctl start netmon
  systemctl --no-pager status netmon
else
  echo "systemd not found — service file not installed"
  echo "run manually: /usr/local/bin/netmon &"
fi

# --- netmon-tray (user-mode tray icon) ---

# build netmon-tray (requires CGO + libappindicator headers)
echo "building netmon-tray (CGO_ENABLED=1)"
if ! command -v go >/dev/null 2>&1; then
  echo "warning: 'go' toolchain not found on PATH — skipping tray build"
else
  if ! command -v gcc >/dev/null 2>&1; then
    echo "warning: 'gcc' not found — cannot build netmon-tray (CGO required)"
  else
    mkdir -p "$SCRIPT_DIR/bin"
    if CGO_ENABLED=1 go build -o "$SCRIPT_DIR/bin/netmon-tray" ./cmd/netmon-tray; then
      echo "installing binary: /usr/local/bin/netmon-tray"
      cp "$SCRIPT_DIR/bin/netmon-tray" /usr/local/bin/netmon-tray
      chmod 755 /usr/local/bin/netmon-tray
    else
      echo "warning: netmon-tray build failed — install manually: CGO_ENABLED=1 go build -o bin/netmon-tray ./cmd/netmon-tray"
    fi
  fi
fi

# install as a user systemd service (must run under a real user, not root)
if [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = "root" ]; then
  echo
  echo "netmon-tray binary is at /usr/local/bin/netmon-tray"
  echo "to autostart it for your user:"
  echo "  systemctl --user enable --now netmon-tray"
  echo "  loginctl enable-linger \$USER  # so it survives logout"
else
  TRAY_USER="$SUDO_USER"
  TRAY_UID="$(id -u "$TRAY_USER")"
  USER_UNIT_DIR="/home/$TRAY_USER/.config/systemd/user"
  USER_UNIT="$USER_UNIT_DIR/netmon-tray.service"
  SVC_SRC="$SCRIPT_DIR/scripts/netmon-tray.service"

  if [ ! -f "$SVC_SRC" ]; then
    echo "warning: $SVC_SRC not found — skipping tray service install"
  elif ! command -v systemctl >/dev/null 2>&1; then
    echo "warning: systemctl not found — skipping tray service install"
  else
    # run the rest as the invoking user (need write access to their home + per-user systemd bus)
    run_as_user() {
      su - "$TRAY_USER" -c "XDG_RUNTIME_DIR=/run/user/$TRAY_UID $*"
    }

    mkdir -p "$USER_UNIT_DIR"
    chown "$TRAY_USER:$TRAY_USER" "$USER_UNIT_DIR"
    cp "$SVC_SRC" "$USER_UNIT"
    chown "$TRAY_USER:$TRAY_USER" "$USER_UNIT"

    # enable linger so the service survives logout
    if command -v loginctl >/dev/null 2>&1; then
      loginctl enable-linger "$TRAY_USER" 2>/dev/null || true
    fi

    echo "installing user systemd service for $TRAY_USER: netmon-tray"
    if run_as_user "systemctl --user daemon-reload" \
       && run_as_user "systemctl --user enable netmon-tray" \
       && run_as_user "systemctl --user start netmon-tray"; then
      run_as_user "systemctl --user --no-pager status netmon-tray" || true
    else
      echo "warning: failed to enable netmon-tray user service — start it manually:"
      echo "  sudo -u $TRAY_USER systemctl --user start netmon-tray"
    fi
  fi
fi

echo
echo "=== install complete ==="
echo "dashboard: http://127.0.0.1:8484"
echo "logs:      journalctl -u netmon -f"
echo "tray:      systemctl --user status netmon-tray"
echo
echo "first-time setup:"
echo "  on a fresh install (no users yet), the daemon writes a one-time"
echo "  setup token to /var/lib/netmon/setup-token (mode 0600) and logs"
echo "  the file path. retrieve it with:"
echo "    sudo cat /var/lib/netmon/setup-token"
echo "  then open http://127.0.0.1:8484/setup and paste it to create the"
echo "  admin user. the token expires after 24h; restart the daemon to"
echo "  generate a fresh one."
echo
echo "  password rules: 12+ characters, must include lower, upper, digit,"
echo "  and symbol characters (e.g. 'Sup3rSecret!')."
echo
echo "  on upgrade from a pre-auth version, any existing user is flagged"
echo "  for password reset. a per-user reset token is auto-generated at"
echo "  /var/lib/netmon/password-reset-token.<username> (expires in 1h)."
echo "  deliver the token out-of-band; the user pastes it at"
echo "  http://127.0.0.1:8484/password-reset.html and sets a new password."
echo
echo "  auth events are visible in the dashboard under 'events' or via"
echo "    curl -b 'netmon_session=<token>' http://127.0.0.1:8484/api/auth/events"
