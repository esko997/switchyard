#!/bin/sh
# Install Switchyard's desk, monitor, read-only LAN view and authenticated HTTPS LAN desk as systemd user
# services on the control host. Idempotent: rewrites the units and restarts nothing it did not install. An
# already-running foreground instance must be stopped first (the desk port and the monitor's leader lock are
# exclusive). Usage:
#   tools/install-services.sh --lan-address ADDR [--lan-port 8711] [--no-lan]
#                             [--secure-port 8712] [--no-secure-lan]
# --lan-address is required unless both LAN listeners are off (--no-lan --no-secure-lan).
# The units use your fleet's configuration (README: "Your fleet's configuration"): catalogs/home-lab.json,
# home-lab.collectors.json and home-lab.operations.json in this checkout. They are not tracked; copy the
# examples and edit them first.
# The HTTPS desk (docs/auth.md) needs a certificate authority, created here if missing, and an operator
# password, which only the operator can set: `switchyard auth set-password` at a terminal.
set -eu
PROJECT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
CATALOG="$PROJECT/catalogs/home-lab.json"
COLLECTORS="$PROJECT/catalogs/home-lab.collectors.json"
OPERATIONS="$PROJECT/catalogs/home-lab.operations.json"
LAN_ADDRESS=
LAN_PORT=8711
LAN=yes
SECURE_PORT=8712
SECURE=yes
ALLOWED_CLIENTS=
while [ $# -gt 0 ]; do
  case "$1" in
    --lan-address) LAN_ADDRESS=${2:?}; shift 2 ;;
    --lan-port) LAN_PORT=${2:?}; shift 2 ;;
    --no-lan) LAN=no; shift ;;
    --secure-port) SECURE_PORT=${2:?}; shift 2 ;;
    --no-secure-lan) SECURE=no; shift ;;
    --allowed-clients) ALLOWED_CLIENTS=${2:?}; shift 2 ;;
    *) echo "Usage: $0 --lan-address ADDR [--lan-port PORT] [--no-lan] [--secure-port PORT] [--no-secure-lan] [--allowed-clients CIDR]" >&2; exit 2 ;;
  esac
done
if [ -z "$LAN_ADDRESS" ] && { [ "$LAN" = yes ] || [ "$SECURE" = yes ]; }; then
  echo "install-services: --lan-address ADDR is required for the LAN listeners (or pass --no-lan --no-secure-lan)" >&2
  exit 2
fi
# shellcheck source=tools/fleet-config.sh
. "$PROJECT/tools/fleet-config.sh"
require_fleet_config install-services "$CATALOG" "$COLLECTORS" "$OPERATIONS"
refuse_linked_worktree install-services "$PROJECT"
UV=$(command -v uv) || { echo "uv not found on PATH" >&2; exit 1; }
UV=$(readlink -f "$UV")
UNITS="$HOME/.config/systemd/user"
mkdir -p "$UNITS"
RUN="$UV run --project $PROJECT --locked switchyard --catalog $CATALOG --collectors $COLLECTORS"
if [ -n "$ALLOWED_CLIENTS" ]; then
  # A CIDR is one literal command argument, never a shell/systemd fragment.
  case "$ALLOWED_CLIENTS" in
    *[!0-9a-fA-F:./]* | */*/*) echo "install-services: invalid --allowed-clients CIDR" >&2; exit 2 ;;
  esac
  CLIENT_ARGS="--allowed-clients $ALLOWED_CLIENTS"
else
  CLIENT_ARGS=
fi

unit() { # name, description, command
  temporary=$(mktemp "$UNITS/.$1.XXXXXX")
  cat > "$temporary" <<EOF
# Installed by $PROJECT/tools/install-services.sh; edit there, not here.
[Unit]
Description=$2
After=network-online.target

[Service]
WorkingDirectory=$PROJECT
ExecStart=$3
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
EOF
  chmod 0644 "$temporary"
  mv -f "$temporary" "$UNITS/$1"
}

unit switchyard-desk.service "Switchyard desk (full control, loopback 127.0.0.1:8710)" "$RUN --operations $OPERATIONS web"
unit switchyard-monitor.service "Switchyard read-only fleet monitor" "$RUN monitor"
SERVICES="switchyard-desk.service switchyard-monitor.service"
if [ "$LAN" = yes ]; then
  unit switchyard-lan-view.service "Switchyard read-only LAN view ($LAN_ADDRESS:$LAN_PORT)" "$RUN --operations $OPERATIONS web --lan-read-only --host $LAN_ADDRESS --port $LAN_PORT${CLIENT_ARGS:+ $CLIENT_ARGS}"
  SERVICES="$SERVICES switchyard-lan-view.service"
fi
if [ "$SECURE" = yes ]; then
  # `tls show` exits 0 either way; it reports whether a CA exists. `tls init` never replaces an existing CA.
  # shellcheck disable=SC2086
  $RUN tls show 2>/dev/null | grep -q '"initialized": true' || $RUN tls init --name "$LAN_ADDRESS" >/dev/null
  unit switchyard-lan.service "Switchyard desk over HTTPS with sign-in ($LAN_ADDRESS:$SECURE_PORT)" "$RUN --operations $OPERATIONS web --lan --host $LAN_ADDRESS --port $SECURE_PORT${CLIENT_ARGS:+ $CLIENT_ARGS}"
  SERVICES="$SERVICES switchyard-lan.service"
fi
if [ -f "$PROJECT/catalogs/home-lab.lan-routes.json" ]; then
  temporary=$(mktemp "$UNITS/.switchyard-lan-dns-sync.XXXXXX")
  cat > "$temporary" <<EOF
# Installed by $PROJECT/tools/install-services.sh; edit there, not here.
[Unit]
Description=Switchyard verified LAN hostname records
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$PROJECT
ExecStart=$RUN --operations $OPERATIONS lan-dns-sync
TimeoutStartSec=7min
EOF
  chmod 0644 "$temporary"
  mv -f "$temporary" "$UNITS/switchyard-lan-dns-sync.service"
  temporary=$(mktemp "$UNITS/.switchyard-lan-dns-sync.XXXXXX")
  cat > "$temporary" <<EOF
# Installed by $PROJECT/tools/install-services.sh; edit there, not here.
[Unit]
Description=Reconcile Switchyard LAN hostname records

[Timer]
OnActiveSec=30s
OnUnitInactiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
  chmod 0644 "$temporary"
  mv -f "$temporary" "$UNITS/switchyard-lan-dns-sync.timer"
  SERVICES="$SERVICES switchyard-lan-dns-sync.timer"
fi
systemctl --user daemon-reload
# shellcheck disable=SC2086
systemctl --user enable --now $SERVICES
# shellcheck disable=SC2086
systemctl --user --no-pager --lines=0 status $SERVICES | grep -E '^●|Active:' || true
[ "$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null)" = yes ] || \
  echo "Note: lingering is off, so these start at login, not at boot (loginctl enable-linger $(id -un) changes that for every user unit)."
