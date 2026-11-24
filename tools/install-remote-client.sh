#!/bin/sh
# Install the Switchyard remote client and agent guidance on another registry host. Run on the control host.
#
#   tools/install-remote-client.sh <host-id>            install under `switchyard lease run <host-id>`
#   tools/install-remote-client.sh --render <host-id>   print the Python program that would run there
#
# On the host it writes only: ~/.local/bin/switchyard (the client, 0755, temp file + rename),
# ~/.config/switchyard/remote.json (0600), and, idempotently with timestamped backups of any file it
# changes: the omp skill ~/.omp/agent/managed-skills/switchyard-device-lease/SKILL.md, a marked section in
# ~/.omp/agent/RULES.md, a marked section in ~/.claude/CLAUDE.md (if ~/.claude exists) and a `switchyard`
# stdio entry in ~/.omp/agent/mcp.json (if this host's omp uses the mcpServers format). It never adds SSH
# keys or known_hosts entries; it checks `ssh <control> true` from the host and reports what is missing.
# No services are touched. Exit 3 when the host cannot reach the control host over BatchMode ssh.
# The same client also enrolls for an API key over HTTPS (`switchyard enroll`), for hosts without SSH trust
# to the control host; this installer does not enroll anything.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
# The control host's SSH identity: SWITCHYARD_CONTROL_TARGET, else the single `local_targets` entry of your
# operations policy (catalogs/home-lab.operations.json), which is exactly how operations reach the control host.
CONTROL=${SWITCHYARD_CONTROL_TARGET:-}
if [ -z "$CONTROL" ]; then
    CONTROL=$(python3 -c 'import json, sys
targets = json.load(open(sys.argv[1])).get("local_targets", {})
print(next(iter(targets.values()))["target"] if len(targets) == 1 else "")' "$HERE/../catalogs/home-lab.operations.json" 2>/dev/null || true)
fi
if [ -z "$CONTROL" ]; then
    echo "install-remote-client: set SWITCHYARD_CONTROL_TARGET=user@control-host (no single local_targets entry in catalogs/home-lab.operations.json)" >&2
    exit 2
fi
SWITCHYARD=${SWITCHYARD_BIN:-$HOME/.local/bin/switchyard}
REMOTE_SWITCHYARD="$HOME/.local/bin/switchyard"
REMOTE_MCP="$HOME/.local/bin/switchyard-mcp-remote"

render=no
if [ "${1:-}" = "--render" ]; then
    render=yes
    shift
fi
if [ $# -ne 1 ]; then
    echo "usage: $0 [--render] <host-id>" >&2
    exit 2
fi
HOST=$1
case $HOST in
    *[!a-z0-9-]* | "" | -*) echo "install-remote-client: invalid host ID: $HOST" >&2; exit 2 ;;
esac

program=$(mktemp "${TMPDIR:-/tmp}/switchyard-remote-install.XXXXXX")
trap 'rm -f "$program"' EXIT HUP INT TERM

python3 - "$HERE/switchyard-remote" "$HOST" "$CONTROL" "$REMOTE_SWITCHYARD" "$REMOTE_MCP" > "$program" <<'PY'
import base64, json, os, sys

client_path, host, control, switchyard, mcp = sys.argv[1:]
with open(client_path, encoding="utf-8") as stream:
    client = stream.read()
try:
    with open(os.path.expanduser("~/.omp/agent/mcp.json"), encoding="utf-8") as stream:
        local_mcp = json.load(stream)
    # Only mirror an entry format this fleet's omp demonstrably uses.
    mcp_entry = isinstance(local_mcp.get("mcpServers"), dict) and any(
        isinstance(entry, dict) and entry.get("type") == "stdio" and "command" in entry
        for entry in local_mcp["mcpServers"].values())
except (OSError, ValueError, AttributeError):
    mcp_entry = False

skill = f'''---
name: switchyard-device-lease
description: "Use before adb/ssh/network access from {host} to another registry host: take, hold and release device locks through the Switchyard remote client."
---

# Switchyard device leases from {host}

The fleet's device reservations live in Switchyard's SQLite authority on the control host (`{control}`). This host's `~/.local/bin/switchyard` client takes every lease there over SSH. There is no file-lock fallback.

## When

Before **any** access (even read-only `adb`, `ssh`, network API or file transfer) to **another** Switchyard registry host (`switchyard hosts`, including hosts added later). Work on {host} itself needs no lease unless coordinating with other agents accessing it: then lease `{host}` too.

## One command (preferred)

```sh
switchyard lease run host-a --scope "what and why" -- sh -c 'ssh -o BatchMode=yes "$SWITCHYARD_SSH_TARGET" journalctl --user -n 50'
```

The command runs here with `SWITCHYARD_LEASE_ID`, `SWITCHYARD_DEVICE` and the configured `SWITCHYARD_SSH_TARGET`/`SWITCHYARD_SSH_PORT` or `ANDROID_SERIAL`. USB devices attached to the control host are usually unreachable here. The client sends heartbeats and confirms completion after a known command exit.

- **75 = busy.** Nothing ran; the message names the holder and scope. Wait boundedly (`--wait 300`, maximum 600) or defer; never bypass.
- **76 = lease lost or completion unconfirmed.** The client stops its local process group and does not automatically release. Inspect the target; local cleanup cannot prove the remote command stopped.
- **255 = SSH transport failure.** Do not touch the device; report it.

## Suspect leases (fail-closed)

If the authority loses contact, misses the deadline, or cannot verify completion, it keeps the reservation **suspect**. A lost attached command requires operator attestation that work stopped.

## Several separate tool calls

```sh
switchyard lease hold host-a --scope "inspect configured service"   # JSON with lease_id
switchyard lease release LEASE_ID                                  # immediately when done
```

Remote holds are detached: default deadline 60 minutes, maximum 120; renew with `switchyard lease renew LEASE_ID --ttl 30m`. A missed deadline keeps an unconfirmed reservation. Release promptly after confirming completion; prefer `lease run`. Never hold a device lease while building.

## Status and other commands

- `switchyard lease status <device>`: exit 0 free, 1 held, 2 unknown; shows the handoff baseline. `switchyard lease list` shows holders.
- Read-only state: `switchyard hosts`, `switchyard fleet`, `switchyard definitions`, `switchyard operations`.
- `switchyard mcp` serves cache reads and `lease_hold`, `lease_release`, `lease_renew`; holds are detached and attributed to this host and your Paseo agent.
- No remote `shell`, operations, registry/definition edits or `--pass-lock-fd`; ask the operator or an agent on the control host.
- If Switchyard itself fails (not busy), stop and report. There is no local fallback lock.
'''

section = f'''## Hardware & Networked Device Locks (Mandatory Across All Repos & Worktrees)

Before **any** interaction (including read-only adb, SSH, network API or file transfer) from {host} with another Switchyard registry host, take its lease **through Switchyard** (MUST). The locks live on the control host (`{control}`); this host's `~/.local/bin/switchyard` is a remote client. Work on {host} needs no lease unless coordinating with other agents accessing it.

- One command: `switchyard lease run <device> --scope "<what and why>" -- <command...>`; configured connection variables are exported, and the command runs under the lease.
- Several steps: `switchyard lease hold <device> --scope "..."`, then `switchyard lease release LEASE_ID` after confirming completion. A missed deadline makes the hold suspect, not available to another caller. Never hold a device lease while building.
- Exit 75 means busy; wait boundedly (`--wait` at most 600 seconds) or defer, never bypass. Exit 76 means lease lost and command terminated; inspect before acting again. Exit 255 means control host unreachable; do not touch the device.
- A suspect lease means command state unknown. Inspect the target; a lost attached command requires operator attestation before the reservation clears.
- `switchyard lease status <device>` / `switchyard lease list` show holders; `switchyard hosts` lists the registry.
- No remote shell, operations or `--pass-lock-fd`.
- If Switchyard fails, stop and report. Never hand-roll local locks or ledger lines; never create, edit or replace local ledger copies.
'''

payload = {"client": client, "host_id": host, "control": control, "switchyard": switchyard, "mcp": mcp,
           "skill": skill, "section": section, "mcp_entry": mcp_entry}
encoded = base64.b64encode(json.dumps(payload).encode()).decode()

print(f'PAYLOAD = "{encoded}"')
print(r'''
"""Switchyard remote client installer (generated by tools/install-remote-client.sh on the control host)."""
import base64, json, os, shlex, shutil, subprocess, sys, tempfile, time

PAYLOAD = json.loads(base64.b64decode(PAYLOAD))
HOME = os.path.expanduser("~")
STAMP = time.strftime("%Y%m%d%H%M%S")
BEGIN = "<!-- BEGIN switchyard-remote-device-locks (managed by Switchyard tools/install-remote-client.sh) -->"
END = "<!-- END switchyard-remote-device-locks -->"
CLIENT_MARK = "Switchyard remote client"
report = {"host_id": PAYLOAD["host_id"], "control": PAYLOAD["control"], "files": {}, "problems": []}


def read(path):
    try:
        with open(path, encoding="utf-8") as stream:
            return stream.read()
    except FileNotFoundError:
        return None


def write_atomic(path, text, mode):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install(path, text, mode, *, backup=True):
    old = read(path)
    if old == text:
        report["files"][path] = "unchanged"
        return
    if old is not None:
        mode = os.stat(path).st_mode & 0o777 if mode is None else mode
        if backup:
            shutil.copy2(path, f"{path}.bak-{STAMP}")
            report["files"][path + ".bak-" + STAMP] = "backup"
    write_atomic(path, text, 0o644 if mode is None else mode)
    report["files"][path] = "updated" if old is not None else "created"


def marked(path, section):
    old = read(path) or ""
    block = f"{BEGIN}\n{section.rstrip()}\n{END}\n"
    start, end = old.find(BEGIN), old.find(END)
    if start != -1 and end > start:
        # Replace only the managed block; text before and after it stays byte-identical.
        new = old[:start] + block[:-1] + old[end + len(END):]
    else:
        new = old + ("\n" if old and not old.endswith("\n") else "") + ("\n" if old else "") + block
    install(path, new, None)


# 1. The client itself (back up only a foreign file at that path, not our own older versions).
client = os.path.join(HOME, ".local/bin/switchyard")
existing = read(client)
install(client, PAYLOAD["client"], 0o755, backup=existing is not None and CLIENT_MARK not in existing)
os.makedirs(os.path.join(HOME, ".config/switchyard"), mode=0o700, exist_ok=True)
install(os.path.join(HOME, ".config/switchyard/remote.json"),
        json.dumps({key: PAYLOAD[key] for key in ("control", "switchyard", "mcp", "host_id")}, indent=2) + "\n", 0o600)

# 2. Reachability of the control host from here (keys and known_hosts are the operator's job).
check = f"test -x {shlex.quote(PAYLOAD['switchyard'])} && test -x {shlex.quote(PAYLOAD['mcp'])}"
try:
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", PAYLOAD["control"], check],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    code, stderr = result.returncode, result.stderr
except (OSError, subprocess.TimeoutExpired) as error:
    code, stderr = 255, str(error)
if code == 0:
    report["control_ssh"] = "ok"
elif code == 255 and "Host key verification failed" in stderr:
    report["control_ssh"] = "missing known_hosts entry"
    report["problems"].append(f"{PAYLOAD['control']} is not in this host's known_hosts; the operator must verify and add its host key")
elif code == 255 and "Permission denied" in stderr:
    report["control_ssh"] = "key not authorized"
    report["problems"].append(f"this host's SSH key is not authorized on {PAYLOAD['control']}; the operator must add the fleet key")
elif code == 255:
    report["control_ssh"] = "unreachable"
    report["problems"].append(f"ssh to {PAYLOAD['control']} failed: {stderr.strip()[-300:]}")
else:
    report["control_ssh"] = "connected, but Switchyard wrappers missing"
    report["problems"].append(f"{PAYLOAD['switchyard']} or {PAYLOAD['mcp']} is not executable on the control host; run tools/install-agent-cli.sh there")
login = subprocess.run(["sh", "-lc", "command -v switchyard"], stdin=subprocess.DEVNULL, capture_output=True, text=True)
report["login_shell_path"] = login.stdout.strip() or "switchyard not on a login shell PATH; agents must call ~/.local/bin/switchyard"

# 3. Agent guidance.
omp = os.path.join(HOME, ".omp/agent")
if os.path.isdir(omp):
    install(os.path.join(omp, "managed-skills/switchyard-device-lease/SKILL.md"), PAYLOAD["skill"], 0o644)
    marked(os.path.join(omp, "RULES.md"), PAYLOAD["section"])
    if PAYLOAD["mcp_entry"]:
        path = os.path.join(omp, "mcp.json")
        text = read(path)
        try:
            config = json.loads(text) if text is not None else {}
            if not isinstance(config, dict) or not isinstance(config.setdefault("mcpServers", {}), dict):
                raise ValueError("unexpected structure")
        except ValueError as error:
            report["problems"].append(f"{path} left untouched: {error}")
        else:
            config["mcpServers"]["switchyard"] = {"type": "stdio", "command": client, "args": ["mcp"]}
            install(path, json.dumps(config, indent=2) + "\n", 0o600 if text is None else None)
else:
    report["omp"] = "not installed; skipped"
claude = os.path.join(HOME, ".claude")
if os.path.isdir(claude):
    marked(os.path.join(claude, "CLAUDE.md"), PAYLOAD["section"])
else:
    report["claude"] = "not installed; skipped"

print(json.dumps(report, indent=2))
sys.exit(3 if report["problems"] else 0)
''')
PY

if [ "$render" = yes ]; then
    cat "$program"
    exit 0
fi

for wrapper in "$REMOTE_SWITCHYARD" "$REMOTE_MCP"; do
    if [ ! -x "$wrapper" ]; then
        echo "install-remote-client: $wrapper is missing; run tools/install-agent-cli.sh first" >&2
        exit 1
    fi
done
if ! "$SWITCHYARD" hosts | python3 -c 'import json,sys; sys.exit(0 if any(h.get("id") == sys.argv[1] for h in json.load(sys.stdin)["hosts"]) else 1)' "$HOST"; then
    echo "install-remote-client: $HOST is not a Switchyard registry host" >&2
    exit 2
fi
status=0
"$SWITCHYARD" lease run "$HOST" --scope "install Switchyard remote client and agent guidance (files only; no services)" --wait 60 -- \
    sh -c 'test -n "${SWITCHYARD_SSH_TARGET:-}" || { echo "install-remote-client: host has no SSH target" >&2; exit 2; }
           exec ssh -o BatchMode=yes -p "$SWITCHYARD_SSH_PORT" "$SWITCHYARD_SSH_TARGET" python3 -' < "$program" || status=$?
cat >&2 <<EOF
install-remote-client: SSH leases from $HOST use this client as installed (switchyard lease run|hold ...).
  For HTTPS access with an API key instead (no SSH trust needed), run on $HOST:
    switchyard enroll --server https://<control host>:8712 --scope read|lease [--hosts ...]
  then approve the printed address from any browser and compare the code (docs/remote-agents.md).
EOF
exit "$status"
