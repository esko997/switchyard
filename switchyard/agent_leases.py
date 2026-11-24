"""Attributed device leases backed exclusively by the durable lease database.

Ledger paths are compatibility metadata, not authorization or lock files.
"""
from datetime import datetime, timezone
import getpass
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import threading
import time
import uuid

from . import locks
from .leases import LeaseBusy
from .lease_db import LeaseStore, resource_label
from . import host_context

def host_label(host_id):
    """Ledger label for a registry host without a configured ledger: `host-a` -> HOSTA."""
    return re.sub(r"[^A-Z0-9]", "", host_id.upper())

LEASE_ID = re.compile(r"[0-9a-f]{32}\Z")
AGENT_NAMES = ("omp", "claude", "codex", "antigravity", "gemini")
# An agent session process itself (never signalled by `lease break`; its descendants may hold leases).
AGENT_SESSION = re.compile(r"(omp|claude|codex|antigravity|gemini|paseo)([\s._-]|\Z)")
BREAK_REFUSED = "lease break is for the operator at a terminal; agents must defer and tell the user"
# Short-lived launcher plumbing between the caller and this CLI; never a lease owner.
LAUNCHER_COMMS = {"uv", "python", "python3", "switchyard", "sh", "dash", "env", "timeout", "flock"}
# `lease attach` binds a remote caller's lease to its SSH connection; this caps a forgotten one.
ATTACH_CAP_SECONDS = 7200
PASEO_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
USER_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}\Z")


class _Cancelled(RuntimeError):
    pass


def state_root():
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "switchyard"


def _text(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Lease metadata must be bounded nonempty text (at most 512 characters)")
    return value


def ttl_seconds(value):
    """CLI duration: seconds, or a number suffixed with s, m or h."""
    match = re.fullmatch(r"([0-9]+)([smh]?)", str(value))
    if not match:
        raise ValueError("TTL must be a duration such as 30m")
    seconds = int(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2]]
    return validate_ttl(seconds)


def validate_ttl(seconds):
    if type(seconds) is not int or not 60 <= seconds <= 7200:
        raise ValueError("TTL must be between 1 minute and 2 hours")
    return seconds


def _iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def _epoch(value):
    return datetime.fromisoformat(value).timestamp()


def _read_input(fd, timeout):
    """Wait up to `timeout` for the caller. Returns (eof, data): eof once `fd` is closed or unusable,
    data with whatever bytes arrived (heartbeat newlines, the final `done` line)."""
    data = b""
    try:
        for _ in range(64):
            if not select.select([fd], [], [], timeout)[0]:
                return False, data
            chunk = os.read(fd, 4096)
            if not chunk:
                return True, data
            data, timeout = data + chunk, 0
    except (OSError, ValueError):
        return True, data
    return False, data


def _scan_done(buffer):
    """Split complete input lines; returns (unfinished tail, whether a `done` line arrived)."""
    lines = buffer.split(b"\n")
    return lines[-1][-64:], any(line.strip() == b"done" for line in lines[:-1])


def _age(seconds):
    seconds = max(0, int(seconds))
    return f"{seconds}s" if seconds < 120 else f"{seconds // 60} min"


def process_alive(pid, started):
    path = locks.PROC_ROOT / str(pid)
    if not locks._own_process(path):
        return False
    _, actual = locks._process_stat(path)
    try:
        zombie = locks._read(path / "stat", 4096).rsplit(b")", 1)[1].split()[0] == b"Z"
    except (OSError, IndexError):
        return False
    return actual is not None and actual == started and not zombie


def _ancestry(pid):
    """Own-user process chain from `pid` upwards: pid, start ticks, comm, argv basenames, Paseo agent ID."""
    chain, seen = [], set()
    for _ in range(64):
        if not pid or pid in seen:
            break
        seen.add(pid)
        path = locks.PROC_ROOT / str(pid)
        if not locks._own_process(path):
            break
        parent, started = locks._process_stat(path)
        try:
            comm = locks._clean(locks._read(path / "comm", 1024).decode("utf-8", errors="replace"), 128) or "process"
        except OSError:
            comm = "process"
        try:
            argv = [os.path.basename(item.decode("utf-8", errors="replace"))
                    for item in locks._read(path / "cmdline", 4096).split(b"\0")[:2] if item]
        except OSError:
            argv = []
        agent_id = locks._agent_environment(path).get("PASEO_AGENT_ID")
        chain.append({"pid": pid, "started": started, "comm": comm, "argv": argv, "paseo_id": agent_id, "parent": parent})
        pid = parent
    return chain


def agent_session(item):
    """True for a process that is an agent session itself (omp, claude, codex, ..., the Paseo daemon), by
    its comm or the basename of its program/script, not for the commands such a session runs."""
    names = [item.get("comm") or "", *(item.get("argv") or [])]
    return any(AGENT_SESSION.match(name.lower()) for name in names)


def agent_ancestry(*, environment=None, pid=None):
    """Why the caller counts as an agent (None for an operator at a terminal): a PASEO_AGENT_ID in its
    environment or an ancestor's, or an agent session process among its ancestors."""
    environment = os.environ if environment is None else environment
    if environment.get("PASEO_AGENT_ID"):
        return f"PASEO_AGENT_ID={locks._clean(environment['PASEO_AGENT_ID'], 64)} in the environment"
    for item in _ancestry(os.getppid() if pid is None else pid):
        if item["paseo_id"]:
            return f"ancestor {item['comm']}:{item['pid']} has PASEO_AGENT_ID={item['paseo_id']}"
        if agent_session(item):
            return f"ancestor {item['comm']}:{item['pid']} is an agent session"
    return None


def caller_identity(paseo_agents=None, *, environment=None, pid=None):
    """Find the owning agent, not the short-lived CLI or its intermediate shell."""
    environment = os.environ if environment is None else environment
    names = paseo_agents or {}
    paseo_id = environment.get("PASEO_AGENT_ID")
    chain = _ancestry(os.getppid() if pid is None else pid)
    paseo_id = paseo_id or next((item["paseo_id"] for item in chain if item["paseo_id"]), None)
    agentish = [item for item in chain if any(name in item["comm"].lower() for name in AGENT_NAMES)]
    matching = [item for item in chain if paseo_id and item["paseo_id"] == paseo_id]
    owner_process = next((item for item in agentish if item in matching), None)
    # Without an agent, own the lease by the first long-lived caller (e.g. the operator's
    # interactive shell), not by uv/python/sh plumbing that exits as soon as `hold` returns.
    durable = [item for item in chain if item["comm"] not in LAUNCHER_COMMS]
    owner_process = owner_process or (agentish[0] if agentish else
                                      next((item for item in matching if item in durable), None) or
                                      (durable[0] if durable else chain[0] if chain else None))
    if paseo_id:
        name = (names.get(paseo_id) or {}).get("name")
        owner = f"{name} (paseo:{paseo_id[:8]})" if name else f"paseo:{paseo_id[:8]}"
    elif agentish:
        owner = f"{agentish[0]['comm']}:{agentish[0]['pid']}"
    else:
        owner = getpass.getuser()
    return {"owner": _text(owner), "owner_pid": owner_process["pid"] if owner_process else None,
            "owner_started": owner_process["started"] if owner_process else None,
            "paseo_agent_id": paseo_id}


def blocked_message(label, block):
    if block.get("error"):
        detail = block["error"]
    elif block.get("pending"):
        detail = (f"lease break in progress by {block.get('operator') or 'the operator'} since {block.get('at') or 'unknown time'}"
                  f" ({block.get('reason') or 'no reason'})")
    else:
        owners = ", ".join(item.get("owner") or "?" for item in block.get("revoked") or [] if isinstance(item, dict))
        detail = (f"lease broken by {block.get('operator') or 'the operator'} at {block.get('at') or 'unknown time'}"
                  f" ({block.get('reason') or 'no reason'})" + (f", revoking {owners}" if owners else ""))
    return (f"{label} blocked: {detail}; the old operation is not attested stopped. The operator clears it with "
            f"`switchyard lease clear {label.lower()} --attest-stopped \"how you know it stopped\"`")


def _show(output, label, row, leases):
    """What `lease break` is about to act on, before the operator confirms."""
    print(f"{label}: {row.get('state', 'unknown')}" + (f" (anomaly: {row['anomaly']})" if row.get("anomaly") else ""), file=output)
    # Process discovery is not authority; show only the persisted generation.
    for lease in leases:
        suspect = (f" SUSPECT since {lease.get('suspect_since')} ({lease.get('suspect_cause')})"
                   if lease.get("suspect") else "")
        print(f"  Switchyard lease {lease['lease_id']} mode {lease.get('mode')} owner {lease.get('owner')}"
              f" scope {lease.get('scope')!r} pid {lease.get('pid')}{suspect}", file=output)
    if row.get("blocked"):
        print(f"  already {blocked_message(label, row['blocked'])}", file=output)
    for entry in row.get("last_entries", []):
        print(f"  event {entry.get('at')} {entry.get('event')} {entry.get('owner')}: {entry.get('scope')}", file=output)


def busy_message(row):
    holders = row.get("holders", [])
    # A Switchyard lease whose holder process matches carries the real owner, including remote callers.
    attribution = ((row.get("switchyard_lease") or {}).get("owner") or
                   ", ".join(holder.get("paseo_agent_name") or f"{holder.get('comm') or 'process'}:{holder.get('pid')}" for holder in holders) or "unknown holder")
    claim = next((entry for entry in reversed(row.get("last_entries", [])) if entry.get("event") == "CLAIM"), {})
    scope = claim.get("scope") or "scope unavailable"
    try:
        age = max(0, int(time.time() - _epoch(claim["at"])))
        suffix = f"; {age}s ago"
    except (KeyError, TypeError, ValueError, OverflowError):
        suffix = ""
    lease = row.get("switchyard_lease") or {}
    if lease.get("suspect"):
        try:
            lost = f"connection lost {_age(time.time() - _epoch(lease['suspect_since']))} ago"
        except (KeyError, TypeError, ValueError, OverflowError):
            lost = "connection lost"
        suffix += f"; {lost} ({lease.get('suspect_cause') or 'unknown cause'}), command state unknown; " \
                  "the operator must inspect and attest stopped before clearing this reservation"
    message = f"{row.get('device', 'Device')} busy: {attribution}; {scope}{suffix}"
    if row.get("blocked"):
        message += "; also " + blocked_message(row.get("device", "Device"), row["blocked"])
    return message


def _boot_id():
    try:
        return (locks.PROC_ROOT / "sys/kernel/random/boot_id").read_text().strip() or None
    except OSError:
        return None


def _signal_group(pgid, signum):
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        pass


def _group_alive(pgid):
    """A reaped leader is not proof that its descendants stopped."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        for path in locks.PROC_ROOT.iterdir():
            if not path.name.isdigit():
                continue
            try:
                fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
                if int(fields[2]) == pgid and fields[0] != "Z":
                    return True
            except FileNotFoundError:
                continue
            except (OSError, ValueError, IndexError):
                return True
        return False
    except OSError:
        return True


def systemd_argv(state, holder_command):
    argv = ["systemd-run", "--user", f"--unit={state['holder_unit']}", "--collect",
            f"--property=RuntimeMaxSec={math.ceil(state['ttl_seconds'] + state.get('wait_seconds', 0) + 60)}"]
    if state.get("paseo_agent_id"):
        argv.append(f"--setenv=PASEO_AGENT_ID={state['paseo_agent_id']}")
    return [*argv, "--", *holder_command]


class AgentLeases:
    def __init__(self, *, collectors=None, hosts=(), state_dir=None, paseo_agents=None,
                 ledger_dir=locks.DEFAULT_LEDGER_DIR, clock=time.time, sleep=time.sleep,
                 owner_alive=process_alive, runner=subprocess.run, monotonic=time.monotonic):
        self.collectors, self.hosts = collectors or {}, tuple(hosts)
        self.root = Path(state_dir) if state_dir is not None else state_root()
        self.ledger_dir = Path(ledger_dir).resolve()
        legacy_paths = [Path(value["ledger"]) for value in self.collectors.values() if value.get("ledger")]
        self.states = LeaseStore(self.root / "leases", clock=clock, legacy_paths=legacy_paths,
                                 legacy_dir={self.ledger_dir, *(path.parent for path in legacy_paths)})
        self.paseo_agents = paseo_agents or {}
        self.clock, self.sleep, self.owner_alive = clock, sleep, owner_alive
        self.monotonic, self.runner = monotonic, runner

    def resolve(self, device):
        if not isinstance(device, str):
            raise ValueError("Unknown lease device")
        mappings = {}
        for name in dict.fromkeys((*self.collectors, *self.hosts)):
            config = next((value for key, value in self.collectors.items() if key.casefold() == name.casefold()), {})
            path = Path(config["ledger"]) if config.get("ledger") else self.ledger_dir / f"DEVICE_ACCESS_{host_label(name)}.md"
            if not path.is_absolute() or path != path.resolve():
                raise ValueError("Ledger metadata must be a canonical absolute path")
            mappings[name] = (resource_label(name, path), path, config)
        direct = next((value for name, value in mappings.items() if name.casefold() == device.casefold()), None)
        matches = [value for value in mappings.values() if value[0].casefold() == device.casefold()]
        if direct is None and not matches:
            raise ValueError(f"Unknown lease device: {device} (not a Switchyard registry host)")
        label, path, config = direct or matches[0]
        same = [value for value in mappings.values() if value[0] == label]
        denied = [value.strip() for value in os.environ.get("SWITCHYARD_EXTERNAL_LEASE_HOSTS", "").split(",") if value.strip()]
        if len(denied) > 256 or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value) for value in denied):
            raise ValueError("Invalid SWITCHYARD_EXTERNAL_LEASE_HOSTS")
        aliases = {device.casefold(), label.casefold(),
                   *(name.casefold() for name, value in mappings.items() if value[0] == label)}
        if aliases & {value.casefold() for value in denied}:
            raise ValueError(f"Host {device} requires its external lease coordinator")
        if direct is None:
            endpoints = {(value[2].get("transport"), value[2].get("serial"), value[2].get("target"),
                          value[2].get("port", 22)) for value in same}
            config = same[0][2] if len(endpoints) == 1 else {}
        return label, path, config

    def _exports(self, state, config):
        result = {"SWITCHYARD_LEASE_ID": state["lease_id"], "SWITCHYARD_DEVICE": state["device"]}
        if config.get("transport") == "adb" and config.get("serial"):
            result["ANDROID_SERIAL"] = str(config["serial"])
        elif config.get("transport") == "ssh" and config.get("target"):
            result["SWITCHYARD_SSH_TARGET"] = str(config["target"])
            result["SWITCHYARD_SSH_PORT"] = str(config.get("port", 22))
        return result

    def _origin(self, owner, agent_id, origin_host, origin_user):
        if origin_host is None:
            if agent_id is not None or origin_user is not None:
                raise ValueError("--agent-id and --origin-user require --origin-host")
            return None
        host = next((value for value in self.hosts if isinstance(origin_host, str) and value.casefold() == origin_host.casefold()), None)
        if host is None:
            raise ValueError(f"Unknown origin host: {origin_host} (not a Switchyard registry host)")
        if agent_id is not None and (not isinstance(agent_id, str) or not PASEO_ID.fullmatch(agent_id)):
            raise ValueError("Invalid Paseo agent ID")
        if origin_user is not None and (not isinstance(origin_user, str) or not USER_NAME.fullmatch(origin_user)):
            raise ValueError("Invalid origin user name")
        if owner is not None:
            base = _text(owner)
        elif agent_id:
            cached = self.paseo_agents.get(agent_id) or {}
            name = locks._clean(cached.get("name"), 256) if cached.get("host_id") == host else None
            base = f"{name} (paseo:{agent_id[:8]})" if name else f"paseo:{agent_id[:8]}"
        else:
            base = origin_user or getpass.getuser()
        return {"owner": _text(f"{base}@{host}"), "owner_pid": None, "owner_started": None,
                "paseo_agent_id": agent_id, "origin_host": host}

    def _new(self, device, scope, owner, worktree, mode, ttl=None, origin=None):
        label, path, config = self.resolve(device)
        identity = origin or caller_identity(self.paseo_agents)
        lease_id = uuid.uuid4().hex
        state = {"lease_id": lease_id, "device": label, "ledger": str(path), "ledger_dir": str(self.ledger_dir),
                 **identity, "owner": identity["owner"] if origin or owner is None else _text(owner),
                 "scope": _text(scope), "worktree": _text(str(worktree if worktree is not None else Path.cwd())),
                 "mode": mode, "status": "starting", "created_at": _iso(self.clock()),
                 "expires_at": _iso(self.clock() + ttl) if ttl else None, "ttl_seconds": ttl,
                 "holder_unit": f"switchyard-lease-{label.lower()}-{lease_id[:8]}" if mode == "hold" else None}
        state["env"] = self._exports(state, config)
        return state

    def list(self):
        labels, hosts = {}, {}
        for device in (*self.hosts, *self.collectors):
            try:
                label, path, _ = self.resolve(device)
            except ValueError as error:
                if "external lease coordinator" in str(error):
                    continue
                raise
            labels[label] = str(path)
            hosts.setdefault(label, set()).add(device)
        result = self.states.rows(labels)
        for row in result["ledgers"]:
            row["host_ids"] = sorted(hosts[row["device"]])
        return result

    def status(self, device):
        label, path, _ = self.resolve(device)
        return self.states.rows({label: str(path)})["ledgers"][0]

    def _wait(self, wait):
        if isinstance(wait, bool) or not isinstance(wait, (int, float)) or not math.isfinite(wait) or not 0 <= wait <= 600:
            raise ValueError("--wait must be between 0 and 600 seconds")
        return wait

    def _claim(self, state, wait=0, cancelled=None):
        deadline = self.monotonic() + self._wait(wait)
        while True:
            if cancelled and (reason := cancelled()):
                raise _Cancelled(reason)
            if state.get("ttl_seconds"):
                state["expires_at"] = _iso(self.clock() + state["ttl_seconds"])
            detached = state.get("mode") == "hold" and state.get("detached")
            pid = None if detached else os.getpid()
            state.update(pid=pid, pid_started=locks._process_stat(locks.PROC_ROOT / str(pid))[1] if pid else None,
                         boot_id=_boot_id())
            try:
                return self.states.claim(state)
            except LeaseBusy:
                block = self.states.block(state["device"])
                if block is not None:
                    raise LeaseBusy(blocked_message(state["device"], block)) from None
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    raise LeaseBusy(busy_message(self.status(state["device"]))) from None
                self.sleep(min(1, remaining))

    def run(self, device, command, *, scope, owner=None, worktree=None, wait=0, pass_lock_fd=False):
        if pass_lock_fd:
            raise ValueError("--pass-lock-fd is unsupported by durable leases; migrate the caller to lease run")
        if not command or any(not isinstance(arg, str) for arg in command):
            raise ValueError("lease run requires a command after --")
        state = self._claim(self._new(device, scope, owner, worktree, "run"), wait)
        lease_id, child, received, previous = state["lease_id"], None, [], {}
        reaped, code = False, None
        def forward(signum, _frame):
            received.append(signum)
            if child is not None:
                _signal_group(child.pid, signum)
        try:
            if threading.current_thread() is threading.main_thread():
                for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                    previous[signum] = signal.signal(signum, forward)
            environment = dict(os.environ)
            for key in ("SWITCHYARD_LEASE_ID", "SWITCHYARD_DEVICE", "ANDROID_SERIAL", "SWITCHYARD_SSH_TARGET",
                        "SWITCHYARD_SSH_PORT", "DEVICE_LOCK_FD"):
                environment.pop(key, None)
            environment.update(state["env"])
            child = subprocess.Popen(command, env=environment, start_new_session=True)
            self.states.update(lease_id, lambda value: value.update(command_pid=child.pid))
            for signum in received:
                _signal_group(child.pid, signum)
            code = child.wait()
            reaped = True
            return code if code >= 0 else 128 - code
        finally:
            if child is not None and not reaped:
                _signal_group(child.pid, signal.SIGTERM)
                try:
                    code = child.wait(timeout=5)
                    reaped = True
                except subprocess.TimeoutExpired:
                    _signal_group(child.pid, signal.SIGKILL)
                    try:
                        code = child.wait(timeout=5)
                        reaped = True
                    except subprocess.TimeoutExpired:
                        pass
            for signum, handler in previous.items():
                signal.signal(signum, handler)
            if child is None:
                self.states.finish(lease_id, reason="not-dispatched", outcome="failed")
            elif reaped and not received and code >= 0 and code != 255 and not _group_alive(child.pid):
                self.states.finish(lease_id, reason="completed", outcome="completed", details={"exit_code": code})
            else:
                self.states.suspect(lease_id, "transport-lost" if code == 255 else "command-completion-unconfirmed")

    def _operator(self, identity):
        identity = identity or {"user": getpass.getuser(), "agent": agent_ancestry()}
        if identity.get("agent"):
            raise ValueError(f"{BREAK_REFUSED} ({identity['agent']})")
        user = identity.get("user") or "operator"
        if not USER_NAME.fullmatch(user):
            raise ValueError("Invalid operator user name")
        return user

    def break_lease(self, device, *, reason, signal_holders=False, kill=False, attest_stopped=None,
                    confirm=None, identity=None, output=None):
        output = sys.stdout if output is None else output
        operator, reason = self._operator(identity), _text(reason)
        attestation = _text(attest_stopped) if attest_stopped is not None else None
        if signal_holders or kill:
            raise ValueError("--signal-holders and --kill are unsupported by durable leases; inspect the operation and attest stopped")
        label, _, _ = self.resolve(device)
        row, current = self.status(label), self.states.current(label)
        _show(output, label, row, [current] if current else [])
        if current is None:
            return {"device": label, "status": "not-applicable", "blocked": self.states.block(label) is not None}
        if confirm is None or not confirm(label):
            raise ValueError(f"Not confirmed: type the device label {label} (or pass --yes-device {label})")
        record = self.states.break_device(label, reason=reason, operator=operator,
                                          attest_stopped=attestation, expected_id=current["lease_id"])
        blocked = self.states.block(label) is not None
        revoked = [{key: current.get(key) for key in ("lease_id", "owner", "scope", "mode", "pid", "suspect", "suspect_cause")}
                   | {"ended": attestation is not None}]
        print(f"{label}: generation fenced; " + ("BLOCKED until stop is attested" if blocked else "stop attested"), file=output)
        return {"device": label, "status": "broken", "revoked": revoked, "signalled": [], "killed": [],
                "refused_holders": [], "blocked": blocked, "attestation": attestation, "break": record}

    def clear_block(self, device, *, attest_stopped, confirm=None, identity=None, output=None):
        output = sys.stdout if output is None else output
        operator, attestation = self._operator(identity), _text(attest_stopped)
        label, _, _ = self.resolve(device)
        block = self.states.block(label)
        current = self.states.current(label) if block is None else None
        if block is None and current is None:
            return {"device": label, "status": "not-applicable"}
        if block is None and not current.get("suspect"):
            raise ValueError("Lease is still active; use lease break to fence an active generation")
        print(blocked_message(label, block) if block is not None else busy_message(self.status(label)), file=output)
        if confirm is None or not confirm(label):
            raise ValueError(f"Not confirmed: type the device label {label} (or pass --yes-device {label})")
        if block is not None:
            record = self.states.clear(label, operator=operator, attest_stopped=attestation, expected_block=block)
        else:
            record = self.states.break_device(label, operator=operator, reason="suspect lease cleared after stop attestation",
                                              attest_stopped=attestation, expected_id=current["lease_id"])
            if record.get("blocked"):
                raise LeaseBusy(f"{label}: a block appeared while confirming; inspect and clear that block explicitly")
        print(f"{label}: stop attested; new leases allowed", file=output)
        return {"device": label, "status": "cleared", "clear": record}

    def attach(self, device, *, scope, owner=None, worktree=None, wait=0, agent_id=None, origin_host=None,
               origin_user=None, heartbeat=None, input_fd=0, output=None, completion_proof=False):
        """Only `done` attests completion. EOF, silence, signals and expiry retain
        a durable suspect reservation, even without heartbeat negotiation."""
        if origin_host is not None and completion_proof is not True:
            raise ValueError("Remote lease attach requires a completion-proof client; update switchyard-remote before dispatch")
        if heartbeat is not None and (isinstance(heartbeat, bool) or not isinstance(heartbeat, (int, float))
                                      or not math.isfinite(heartbeat) or not 1 <= heartbeat <= 600):
            raise ValueError("--heartbeat must be between 1 and 600 seconds")
        output = sys.stdout if output is None else output
        origin = self._origin(owner, agent_id, origin_host, origin_user)
        state = self._new(device, scope, owner, worktree, "attach", ATTACH_CAP_SECONDS, origin)
        state["via"] = "switchyard lease attach" + (f" from {origin['origin_host']}" if origin else "")
        if heartbeat is not None:
            state["heartbeat_seconds"] = heartbeat
        received, previous, claimed, attempts = [], {}, False, []
        def emit(value):
            try:
                output.write(json.dumps(value) + "\n")
                output.flush()
                return True
            except (OSError, ValueError):
                return False
        def cancelled():
            attempts.append(True)
            if len(attempts) == 1:
                return None
            return "signal" if received else "disconnected" if _read_input(input_fd, 0)[0] else None
        try:
            if threading.current_thread() is threading.main_thread():
                for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                    previous[signum] = signal.signal(signum, lambda sig, frame: received.append(sig))
            state = self._claim(state, wait, cancelled)
            claimed = True
            lease_id = state["lease_id"]
            if not emit({"status": "claimed", "lease_id": lease_id, "device": state["device"],
                         "expires_at": state["expires_at"], "env": state["env"]}):
                self.states.suspect(lease_id, "claim-delivery-unconfirmed")
                return 1
            heard, buffer = self.monotonic(), b""
            while True:
                current = self.states.read(lease_id)
                if current.get("status") not in {"claimed", "suspect"}:
                    return 1
                if received or self.clock() >= _epoch(current["expires_at"]):
                    self.states.suspect(lease_id, "signal" if received else "expired")
                    return 1
                if heartbeat is not None and not current.get("suspect") and self.monotonic() - heard >= heartbeat:
                    self.states.suspect(lease_id, "silent")
                eof, data = _read_input(input_fd, 0.25)
                if data:
                    heard = self.monotonic()
                    buffer, done = _scan_done(buffer + data)
                    if done:
                        if not self.states.finish(lease_id, reason="released", outcome="completed",
                                                  details={"completion_attestation": "done"}):
                            return 1
                        emit({"status": "released", "lease_id": lease_id, "device": state["device"], "reason": "released"})
                        return 0
                if eof:
                    self.states.suspect(lease_id, "disconnected")
                    return 1
        except _Cancelled:
            return 1
        except BaseException:
            if claimed:
                self.states.suspect(state["lease_id"], "attach-error")
            raise
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)

    def hold(self, device, *, scope, ttl=3600, owner=None, worktree=None, wait=0, detached=False,
             agent_id=None, origin_host=None, origin_user=None):
        ttl = validate_ttl(ttl)
        self._wait(wait)
        origin = self._origin(owner, agent_id, origin_host, origin_user)
        if origin and not detached:
            raise ValueError("--origin-host requires --detached: the owning process is not on this host")
        state = self._new(device, scope, owner, worktree, "hold", ttl, origin)
        state.update(wait_seconds=wait, detached=detached)
        if detached:
            state["via"] = "switchyard lease hold --detached" + (f" from {origin['origin_host']}" if origin else "")
            # TTL-only holds need no watcher process. Expiry is reconciled by the
            # store to suspect, never permission to dispatch another operation.
            state = self._claim(state, wait)
            return {key: state[key] for key in ("lease_id", "device", "expires_at", "holder_unit", "env")}
        if host_context.enabled():
            executable = os.environ.get("SWITCHYARD_HOST_HOLDER", "")
            path = Path(executable)
            if (not executable or not path.is_absolute() or str(path) != executable or ".." in path.parts
                    or any(ord(character) < 32 or ord(character) == 127 for character in executable)):
                raise ValueError("Integrated containers require an absolute trusted SWITCHYARD_HOST_HOLDER executable")
            command = ["/usr/bin/env", "--", executable]
        else:
            command = [sys.executable, "-m", "switchyard.cli"]
        command += ["--state-dir", str(self.root.resolve()), "lease", "_holder", state["lease_id"]]
        self.states.update(state["lease_id"], lambda value: value.update(state), create=True)
        try:
            try:
                self.runner(systemd_argv(state, command), check=True, capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                self.states.finish(state["lease_id"], reason="not-dispatched", outcome="failed")
                raise
            deadline = self.monotonic() + wait + 10
            while self.monotonic() < deadline:
                current = self.states.read(state["lease_id"])
                if current["status"] == "claimed":
                    return {key: current[key] for key in ("lease_id", "device", "expires_at", "holder_unit", "env")}
                if current["status"] != "starting":
                    if current.get("busy"):
                        raise LeaseBusy(current.get("error") or busy_message(self.status(state["device"])))
                    raise ValueError(current.get("error") or "Lease holder did not confirm a claim")
                self.sleep(0.05)
            raise LeaseBusy("Lease holder startup unconfirmed; reservation retained for inspection")
        except BaseException:
            current = self.states.read(state["lease_id"])
            if current["status"] in {"starting", "claimed", "suspect"}:
                self.states.suspect(state["lease_id"], "holder-startup-unconfirmed")
            raise

    def holder(self, lease_id):
        state = self.states.read(lease_id)
        if state.get("mode") != "hold" or state.get("status") != "starting":
            raise ValueError("Lease is not awaiting a holder")
        label, path, _ = self.resolve(state["device"])
        if str(path) != state["ledger"] or label != state["device"]:
            raise ValueError("Lease ledger changed")
        received, previous, claimed = [], {}, False
        try:
            if threading.current_thread() is threading.main_thread():
                for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                    previous[signum] = signal.signal(signum, lambda sig, frame: received.append(sig))
            state = self._claim(state, state.get("wait_seconds", 0),
                                lambda: "signal" if received else
                                "cancelled" if self.states.read(lease_id).get("status") != "starting" else None)
            claimed = True
            while True:
                current = self.states.read(lease_id)
                if current["status"] not in {"claimed", "suspect"}:
                    return
                if received or self.clock() >= _epoch(current["expires_at"]):
                    self.states.suspect(lease_id, "signal" if received else "expired")
                    return
                if not self.owner_alive(current.get("owner_pid"), current.get("owner_started")):
                    self.states.suspect(lease_id, "owner-exited")
                    return
                self.sleep(0.2)
        except (LeaseBusy, _Cancelled) as error:
            if not claimed and self.states.read(lease_id).get("status") == "starting":
                self.states.finish(lease_id, reason="not-dispatched", outcome="failed",
                                   details={"error": str(error), "busy": isinstance(error, LeaseBusy)})
            raise
        except BaseException:
            self.states.suspect(lease_id, "holder-error")
            raise
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)

    def _held_state(self, reference):
        if not isinstance(reference, str):
            raise ValueError("Invalid lease reference")
        matching_id = bool(LEASE_ID.fullmatch(reference))
        if matching_id:
            try:
                state = self.states.read(reference)
            except FileNotFoundError as error:
                raise ValueError("No Switchyard holder state for this lease") from error
            self.states.current(state["device"])
            state = self.states.read(reference)
        else:
            label, _, _ = self.resolve(reference)
            state = self.states.current(label)
            if state is None:
                raise ValueError("No unique Switchyard holder; " + busy_message(self.status(label)))
        if state.get("status") not in {"claimed", "suspect"}:
            raise ValueError("Switchyard lease generation is no longer active")
        if state.get("mode") != "hold":
            raise ValueError("Only Switchyard hold leases can be released or renewed; attach requires its originating done or operator attestation")
        current = self.states.current(state["device"])
        if current is None or current["lease_id"] != state["lease_id"]:
            raise ValueError("Switchyard lease generation is no longer current")
        if state.get("suspect") and not matching_id:
            raise ValueError("Suspect lease completion requires its matching lease ID, not a device alias")
        return state

    def release(self, reference):
        state = self._held_state(reference)
        if not self.states.finish(state["lease_id"], reason="released", outcome="completed",
                                  details={"completion_attestation": "matching-id" if LEASE_ID.fullmatch(reference) else "owner-release"}):
            raise ValueError("Switchyard lease generation changed; completion was not accepted")
        current = self.states.read(state["lease_id"])
        return {"lease_id": state["lease_id"], "device": state["device"], "status": current["status"],
                "reason": current.get("reason")}

    def renew(self, lease_id, *, ttl):
        validate_ttl(ttl)
        if not isinstance(lease_id, str) or not LEASE_ID.fullmatch(lease_id):
            raise ValueError("Renew requires a Switchyard lease ID")
        state = self._held_state(lease_id)
        if state.get("suspect") or self.clock() >= _epoch(state["expires_at"]):
            raise ValueError("Lease has expired or is suspect; confirm completion instead")
        if not state.get("detached"):
            maximum = math.ceil(self.clock() - _epoch(state["created_at"]) + ttl + 60)
            self.runner(["systemctl", "--user", "set-property", "--runtime", state["holder_unit"],
                         f"RuntimeMaxSec={maximum}"], check=True, capture_output=True, timeout=10)
        def renewed(value):
            if value.get("status") != "claimed" or value.get("suspect") or self.clock() >= _epoch(value["expires_at"]):
                raise ValueError("Lease has expired or is suspect")
            value["expires_at"] = _iso(self.clock() + ttl)
        current = self.states.update(lease_id, renewed)
        return {key: current.get(key) for key in ("lease_id", "device", "expires_at", "holder_unit")}




def holder_main(root, lease_id):
    state = LeaseStore(Path(root) / "leases").read(lease_id)
    directory = Path(state.get("ledger_dir", locks.DEFAULT_LEDGER_DIR))
    path = Path(state.get("ledger", ""))
    label = state.get("device")
    if (not directory.is_absolute() or directory != directory.resolve()
            or not path.is_absolute() or path != path.resolve()
            or not isinstance(label, str) or not re.fullmatch(r"[A-Z0-9]{1,64}", label)
            or resource_label(label, path) != label):
        raise ValueError("Lease ledger changed or invalid canonical holder mapping")
    AgentLeases(state_dir=root, ledger_dir=directory, collectors={label: {"ledger": str(path)}}).holder(lease_id)
