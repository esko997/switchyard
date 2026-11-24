#!/usr/bin/env bash
# Rootless packaging only. Integrated mode deliberately shares host authority.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  run-container.sh demo [--image IMAGE] [--port PORT] [--name NAME]
  run-container.sh integrated --image IMAGE --config-dir DIR --catalog FILE
      --state-dir DIR --ledger-dir DIR --host-holder FILE [--home DIR]
      [--collectors FILE] [--operations FILE] [--sdk DIR]
      [--ssh-dir DIR | --known-hosts FILE] [--ssh-agent SOCKET]
      [--playbook-repo DIR ...] [--name NAME] -- COMMAND [ARGS...]

All integrated paths are existing canonical host paths, mounted at the same path.
Relative catalog/collector/operation filenames are relative to --config-dir.
COMMAND is normally web, monitor or lan-dns-sync. No shell evaluation occurs.
Demo is a disposable, GET-only fictional desk on http://127.0.0.1:8710.
See docs/container.md for the host helper, credentials and systemd setup.
EOF
}
die() { printf 'run-container: %s\n' "$*" >&2; exit 2; }
[[ $# -gt 0 ]] || { usage >&2; exit 2; }
mode=$1
shift
[[ $mode == demo || $mode == integrated ]] || { usage >&2; exit 2; }
image=localhost/switchyard:local
port=8710
name=
config_dir=
catalog=
collectors=
operations=
state_dir=
ledger_dir=
host_holder=
home_dir=${HOME:?HOME is required}
sdk=
ssh_dir=
known_hosts=
ssh_agent=
repos=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h) usage; exit 0 ;;
        --) shift; break ;;
        --image|--port|--name|--config-dir|--catalog|--collectors|--operations|--state-dir|--ledger-dir|--host-holder|--home|--sdk|--ssh-dir|--known-hosts|--ssh-agent|--playbook-repo)
            [[ $# -ge 2 && -n $2 ]] || die "$1 needs a value"
            option=$1
            value=$2
            shift 2
            case $option in
                --image) image=$value ;;
                --port) port=$value ;;
                --name) name=$value ;;
                --config-dir) config_dir=$value ;;
                --catalog) catalog=$value ;;
                --collectors) collectors=$value ;;
                --operations) operations=$value ;;
                --state-dir) state_dir=$value ;;
                --ledger-dir) ledger_dir=$value ;;
                --host-holder) host_holder=$value ;;
                --home) home_dir=$value ;;
                --sdk) sdk=$value ;;
                --ssh-dir) ssh_dir=$value ;;
                --known-hosts) known_hosts=$value ;;
                --ssh-agent) ssh_agent=$value ;;
                --playbook-repo) repos+=("$value") ;;
            esac ;;
        *) die "unknown option $1 (put Switchyard arguments after --)" ;;
    esac
done
[[ $(id -u) != 0 ]] || die 'run as the unprivileged control-host user, not root'
command -v podman >/dev/null || die 'podman is required'
uid=$(id -u)
gid=$(id -g)

# Podman's --mount/--tmpfs syntax cannot safely represent these path delimiters.
canonical() {
    local path
    path=$(realpath -e -- "$1") || die "path does not exist: $1"
    case $path in
        *','*|*':'*|*$'\n'*|*$'\r'*) die "unsupported delimiter in path: $path" ;;
    esac
    printf '%s\n' "$path"
}
directory() { [[ -d $1 ]] || die "not a directory: $1"; canonical "$1"; }
file() { [[ -f $1 ]] || die "not a regular file: $1"; canonical "$1"; }
bind() {
    local mount="type=bind,src=$1,dst=$1"
    [[ ${2:-rw} == ro ]] && mount+=",readonly"
    run+=(--mount "$mount")
}
config_file() {
    local path=$1
    [[ $path == /* ]] || path="$config_dir/$path"
    path=$(file "$path")
    [[ $path == "$config_dir/"* ]] || die "configuration must be below $config_dir: $path"
    printf '%s\n' "$path"
}
run=(podman --remote=false run --rm --pull=never --stop-timeout=50 --userns=keep-id --user "$uid:$gid"
    --read-only --cap-drop=all --security-opt=no-new-privileges
    --tmpfs /tmp:rw,nosuid,nodev,mode=1777)
[[ -z $name ]] || run+=(--name "$name")

if [[ $mode == demo ]]; then
    [[ $# == 0 ]] || die 'demo takes no Switchyard command arguments'
    [[ -z $config_dir && -z $catalog && -z $collectors && -z $operations && -z $state_dir && -z $ledger_dir && -z $host_holder && -z $sdk && -z $ssh_dir && -z $known_hosts && -z $ssh_agent && ${#repos[@]} == 0 ]] || die 'host mounts are integrated-only'
    [[ $port =~ ^[0-9]{1,5}$ ]] && (( 10#$port >= 1024 && 10#$port <= 65535 )) || die 'demo port must be 1024..65535'
    home_dir=/run/switchyard-demo
    # slirp4netns gives the guest 10.0.2.100; only the host loopback is published.
    run+=(--network=slirp4netns:cidr=10.0.2.0/24 --publish "127.0.0.1:$port:$port")
    args=(--catalog /opt/switchyard/catalogs/example.json --state-dir /tmp/switchyard-state
        web --lan-read-only --host 10.0.2.100 --port "$port" --allowed-clients 10.0.2.0/24)
else
    [[ $# -gt 0 ]] || die 'integrated needs a Switchyard command after --'
    [[ -n $config_dir && -n $catalog && -n $state_dir && -n $ledger_dir && -n $host_holder ]] || die 'integrated needs --config-dir, --catalog, --state-dir, --ledger-dir and --host-holder'
    [[ $port == 8710 ]] || die '--port is demo-only; pass web --port after --'
    config_dir=$(directory "$config_dir")
    state_dir=$(directory "$state_dir")
    ledger_dir=$(directory "$ledger_dir")
    home_dir=$(directory "$home_dir")
    host_holder=$(file "$host_holder")
    [[ -x $host_holder ]] || die "host helper is not executable: $host_holder"
    catalog=$(config_file "$catalog")
    runtime_dir="/run/user/$uid"
    [[ -S $runtime_dir/bus ]] || die "systemd user bus missing: $runtime_dir/bus"
    [[ -S $runtime_dir/systemd/private ]] || die "systemd user manager socket missing: $runtime_dir/systemd/private"
    # These are intentional host integration, not a sandbox or a private ledger.
    run+=(--pid=host --network=host --security-opt=label=disable
        --tmpfs "$runtime_dir:rw,nosuid,nodev,mode=1777"
        --env SWITCHYARD_CONTAINER_HOST=1 --env "SWITCHYARD_HOST_HOLDER=$host_holder"
        --env "SWITCHYARD_LEDGER_DIR=$ledger_dir" --env "XDG_RUNTIME_DIR=$runtime_dir"
        --env "DBUS_SESSION_BUS_ADDRESS=unix:path=$runtime_dir/bus")
    [[ ! -v SWITCHYARD_EXTERNAL_LEASE_HOSTS ]] || run+=(--env SWITCHYARD_EXTERNAL_LEASE_HOSTS)
    args=(--catalog "$catalog" --state-dir "$state_dir")
    if [[ -n $collectors ]]; then
        collectors=$(config_file "$collectors")
        args+=(--collectors "$collectors")
    fi
    if [[ -n $operations ]]; then
        operations=$(config_file "$operations")
        args+=(--operations "$operations")
    fi
    args+=("$@")
fi

# Match both $HOME and passwd: OpenSSH consults passwd for default SSH paths.
# The image has no ordinary UID account. The guard below fails on a UID conflict.
run+=(--passwd-entry "switchyard:x:$uid:$gid:Switchyard:$home_dir:/bin/sh"
    --env "HOME=$home_dir" --workdir "$home_dir"
    --tmpfs "$home_dir:rw,nosuid,nodev,mode=1777")
if [[ $mode == integrated ]]; then
    bind "$config_dir" ro
    bind "$state_dir"
    bind "$ledger_dir"
    bind "$runtime_dir/bus" ro
    bind "$runtime_dir/systemd/private" ro
    if [[ -n $sdk ]]; then
        sdk=$(directory "$sdk")
        [[ -x $sdk/platform-tools/adb ]] || die 'SDK must contain executable platform-tools/adb'
        bind "$sdk" ro
        run+=(--env "ANDROID_HOME=$sdk" --env "ANDROID_SDK_ROOT=$sdk")
    fi
    [[ -z $ssh_dir || -z $known_hosts ]] || die 'choose --ssh-dir or --known-hosts, not both'
    if [[ -n $ssh_dir ]]; then
        ssh_dir=$(directory "$ssh_dir")
        [[ $ssh_dir == "$home_dir/.ssh" ]] || die '--ssh-dir must resolve to the canonical HOME/.ssh; use an SSH config there for other identities'
        bind "$ssh_dir" ro
    fi
    if [[ -n $known_hosts ]]; then
        known_hosts=$(file "$known_hosts")
        [[ $known_hosts == "$home_dir/.ssh/known_hosts" ]] || die '--known-hosts must be the canonical HOME/.ssh/known_hosts'
        [[ -n $ssh_agent ]] || die '--known-hosts requires an explicit --ssh-agent socket'
        bind "$known_hosts" ro
    fi
    if [[ -n $ssh_agent ]]; then
        ssh_agent=$(canonical "$ssh_agent")
        [[ -S $ssh_agent ]] || die "not an SSH agent socket: $ssh_agent"
        bind "$ssh_agent" ro
        run+=(--env "SSH_AUTH_SOCK=$ssh_agent")
    fi
    for repo in "${repos[@]}"; do
        repo=$(directory "$repo")
        bind "$repo" ro
    done
fi
# No shell, daemon, TTY, runtime socket or additional supervisor in the image.
exec "${run[@]}" --entrypoint /opt/switchyard/.venv/bin/python "$image" -c '
import os, pwd, sys
if pwd.getpwuid(os.getuid()).pw_dir != os.environ["HOME"]:
    raise SystemExit("container passwd home differs from canonical HOME; refusing SSH identity ambiguity")
os.execv("/opt/switchyard/.venv/bin/switchyard", sys.argv[1:])
' switchyard "${args[@]}"
