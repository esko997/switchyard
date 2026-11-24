"""Bounded, attributed agent leases on the existing canonical ledger inodes.

State files coordinate local holder processes, not device authorization. Kernel
flock remains authoritative, including for contenders that do not use Switchyard.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import getpass
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from . import locks
from .leases import LedgerBroker, LeaseBusy
from . import host_context

def host_label(host_id):
    """Ledger label for a registry host without a configured ledger: `host-a` -> HOSTA."""
    return re.sub(r"[^A-Z0-9]", "", host_id.upper())


def ensure_ledger(host_id, ledger_dir=locks.DEFAULT_LEDGER_DIR):
    """Give a new registry host its canonical ledger so it is leaseable. Creates only (O_EXCL); an existing
    ledger is never opened for writing, replaced or touched. Returns (path, created)."""
    Path(ledger_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
    path = Path(ledger_dir).resolve(strict=True) / f"DEVICE_ACCESS_{host_label(host_id)}.md"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    except FileExistsError:
        return path, False
    with os.fdopen(fd, "w") as stream:
        stream.write(f"# DEVICE_ACCESS_{host_label(host_id)}.md canonical device ledger\n"
                     f"Created {datetime.now(timezone.utc).isoformat()} by Switchyard host-add for registry host {host_id}. "
                     "Append-only; take leases with `switchyard lease`.\n")
    return path, True

LEASE_ID = re.compile(r"[0-9a-f]{32}\Z")
AGENT_NAMES = ("omp", "claude", "codex", "antigravity", "gemini")
# An agent session process itself (never signalled by `lease break`; its descendants may hold leases).
AGENT_SESSION = re.compile(r"(omp|claude|codex|antigravity|gemini|paseo)([\s._-]|\Z)")
BREAK_REFUSED = "lease break is for the operator at a terminal; agents must defer and tell the user"
BLOCK_PREFIX = "blocked-"
# Short-lived launcher plumbing between the caller and this CLI; never a lease owner.
LAUNCHER_COMMS = {"uv", "python", "python3", "switchyard", "sh", "dash", "env", "timeout", "flock"}
PUBLIC_FIELDS = ("lease_id", "owner", "scope", "expires_at", "holder_unit")
# Present only on attach leases whose caller vanished: the lock is still held, the remote command's state unknown.
SUSPECT_FIELDS = ("suspect", "suspect_since", "suspect_cause")
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


class LeaseStates:
    """Private atomic state, with serialized read/modify/write for renew/release races."""
    def __init__(self, directory):
        self.directory = Path(directory)

    def _path(self, lease_id):
        if not isinstance(lease_id, str) or not LEASE_ID.fullmatch(lease_id):
            raise ValueError("Invalid Switchyard lease ID")
        return self.directory / f"{lease_id}.json"

    def _prepare(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Lease state directory must be private, owned and not a symlink")

    def read(self, lease_id):
        path = self._path(lease_id)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise ValueError("Lease state must be a private regular file")
            data = stream.read(65537)
        if len(data) > 65536:
            raise ValueError("Lease state is too large")
        value = json.loads(data)
        if not isinstance(value, dict) or value.get("lease_id") != lease_id:
            raise ValueError("Invalid lease state")
        return value

    def update(self, lease_id, change, *, create=False):
        self._prepare()
        path = self._path(lease_id)
        fd = os.open(path.with_suffix(".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise ValueError("Unsafe lease state lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            if create:
                if path.exists() or path.is_symlink():
                    raise ValueError("Lease ID already exists")
                value = {"lease_id": lease_id}
            else:
                value = self.read(lease_id)
            change(value)
            temp_fd, temporary = tempfile.mkstemp(prefix=".lease-", dir=self.directory)
            try:
                with os.fdopen(temp_fd, "w") as stream:
                    json.dump(value, stream)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            return value
        finally:
            os.close(fd)

    def records(self):
        try:
            paths = list(self.directory.glob("*.json"))
        except OSError:
            return []
        records = []
        for path in paths:
            try:
                records.append(self.read(path.stem))
            except (OSError, ValueError, RecursionError):
                continue
        return records


def enrich_locks(result, lease_state_dir):
    """Attach state only when its process identity matches a real kernel holder; attach any `lease break`
    block (held or free rows alike) as `blocked`."""
    records = LeaseStates(lease_state_dir).records()
    for row in result.get("ledgers", []):
        block = read_block(lease_state_dir, row.get("device"))
        if block is not None:
            row["blocked"] = {key: block.get(key) for key in BLOCK_PUBLIC_FIELDS}
        if row.get("state") != "held":
            continue
        for state in records:
            if state.get("status") != "claimed" or state.get("ledger") != row.get("path"):
                continue
            pid = state.get("pid")
            if any(holder.get("pid") == pid for holder in row.get("holders", [])) and process_alive(pid, state.get("pid_started")):
                row["switchyard_lease"] = {key: state.get(key) for key in PUBLIC_FIELDS}
                if state.get("suspect"):
                    row["switchyard_lease"].update({key: state.get(key) for key in SUSPECT_FIELDS})
                break
    return result


BLOCK_PUBLIC_FIELDS = ("device", "at", "operator", "reason", "revoked", "pending", "error")


def block_path(lease_state_dir, label):
    if not isinstance(label, str) or not re.fullmatch(r"[A-Z0-9]{1,64}", label):
        raise ValueError("Invalid ledger label")
    return Path(lease_state_dir) / f"{BLOCK_PREFIX}{label}.json"


def read_block(lease_state_dir, label):
    """The `lease break` block for a ledger label, or None. Fail-closed: a block file that exists but cannot
    be read or trusted still blocks (with an `error`)."""
    try:
        path = block_path(lease_state_dir, label)
    except ValueError:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as error:
        return {"device": label, "error": f"unreadable block file: {error}"}
    try:
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                return {"device": label, "error": "block file is not a private regular file"}
            value = json.loads(stream.read(65537))
        if not isinstance(value, dict):
            raise ValueError("not an object")
        return value
    except (OSError, ValueError, RecursionError) as error:
        return {"device": label, "error": f"invalid block file: {error}"}


def block_for_ledger(lease_state_dir, ledger_path):
    """Block record for a canonical ledger path (for brokered operations and collectors), or None."""
    name = Path(ledger_path).name
    if not (name.startswith("DEVICE_ACCESS_") and name.endswith(".md")):
        return None
    return read_block(lease_state_dir, name[len("DEVICE_ACCESS_"):-3])


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


def flock_holders(path, *, exclude=()):
    """Own-user processes holding the flock on this exact ledger: every descriptor for the file whose
    /proc/<pid>/fdinfo shows a FLOCK `lock:` line. That line appears only on descriptors sharing the locked
    open file description, so it finds the locker and everything that inherited it (children after the
    locker exited, the omp bash `flock` builtin's host process) but not mere readers. None if /proc is
    unreadable."""
    info = os.stat(path)
    found = set()
    try:
        with os.scandir(locks.PROC_ROOT) as entries:
            for entry in entries:
                if not entry.name.isdigit() or int(entry.name) in exclude or not locks._own_process(Path(entry.path)):
                    continue
                try:
                    with os.scandir(Path(entry.path) / "fd") as descriptors:
                        for descriptor in descriptors:
                            try:
                                opened = os.stat(descriptor.path)
                                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                                    continue
                                text = locks._read(Path(entry.path) / "fdinfo" / descriptor.name, 65536).decode("ascii", "replace")
                            except OSError:
                                continue
                            if any(line.startswith("lock:") and " FLOCK " in line and "->" not in line
                                   for line in text.splitlines()):
                                found.add(int(entry.name))
                                break
                except OSError:
                    continue
    except OSError:
        return None
    return found


def _pid_running(pid):
    try:
        state = locks._read(locks.PROC_ROOT / str(pid) / "stat", 4096).rsplit(b")", 1)[1].split()[0]
    except (OSError, IndexError):
        return False
    return state != b"Z"


def _signal(kill, pid, signum):
    try:
        kill(pid, signum)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _append_event(fd, record):
    """Append one JSON ledger line on a descriptor that holds the ledger's flock."""
    view = memoryview((json.dumps(record) + "\n").encode())
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("Could not append ledger event")
        view = view[written:]
    os.fsync(fd)


def _show(output, label, row, leases, holders):
    """What `lease break` is about to act on, before the operator confirms."""
    print(f"{label}: {row.get('state', 'unknown')}" + (f" (anomaly: {row['anomaly']})" if row.get("anomaly") else ""), file=output)
    for item in holders:
        flags = [flag for flag, on in (("AGENT SESSION: never signalled", item.get("agent_session")),
                                       ("your own shell/ancestor: never signalled", item.get("own_ancestor")),
                                       ("kernel report only", not item.get("verified"))) if on]
        agent = item.get("paseo_agent_name") or item.get("paseo_agent_id")
        print(f"  holder {item.get('comm') or 'process'}:{item['pid']} started {item.get('started_at') or '?'}"
              f" cwd {item.get('cwd') or '?'}" + (f" agent {agent}" if agent else "")
              + (f" [{'; '.join(flags)}]" if flags else ""), file=output)
        if item.get("cmdline"):
            print(f"    command: {item['cmdline']}", file=output)
    for lease in leases:
        suspect = (f" SUSPECT since {lease.get('suspect_since')} ({lease.get('suspect_cause')})"
                   if lease.get("suspect") else "")
        print(f"  Switchyard lease {lease['lease_id']} mode {lease.get('mode')} owner {lease.get('owner')}"
              f" scope {lease.get('scope')!r} pid {lease.get('pid')}{suspect}", file=output)
    if row.get("blocked"):
        print(f"  already {blocked_message(label, row['blocked'])}", file=output)
    for entry in row.get("last_entries", []):
        print(f"  ledger {entry.get('at')} {entry.get('event')} {entry.get('owner')}: {entry.get('scope')}", file=output)


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
                  f"clear with `switchyard lease release {lease.get('lease_id')}` once the remote command is confirmed stopped"
    message = f"{row.get('device', 'Device')} busy: {attribution}; {scope}{suffix}"
    if row.get("blocked"):
        message += "; also " + blocked_message(row.get("device", "Device"), row["blocked"])
    return message


def systemd_argv(state, holder_command):
    argv = ["systemd-run", "--user", f"--unit={state['holder_unit']}", "--collect",
            f"--property=RuntimeMaxSec={math.ceil(state['ttl_seconds'] + state.get('wait_seconds', 0) + 60)}"]
    if state.get("paseo_agent_id"):
        argv.append(f"--setenv=PASEO_AGENT_ID={state['paseo_agent_id']}")
    return [*argv, "--", *holder_command]


class AgentLeases:
    def __init__(self, *, collectors=None, hosts=(), state_dir=None, paseo_agents=None,
                 ledger_dir=locks.DEFAULT_LEDGER_DIR, clock=time.time, sleep=time.sleep,
                 owner_alive=process_alive, runner=subprocess.run, observer=None,
                 monotonic=time.monotonic, kill=os.kill):
        """Every registry host (`hosts`) is leaseable: by its collector's ledger, else DEVICE_ACCESS_<HOST_LABEL>.md."""
        self.collectors = collectors or {}
        self.hosts = tuple(hosts)
        self.root = Path(state_dir) if state_dir is not None else state_root()
        self.states = LeaseStates(self.root / "leases")
        Path(ledger_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
        self.ledger_dir = Path(ledger_dir).resolve(strict=True)
        self.paseo_agents = paseo_agents or {}
        self.clock, self.sleep, self.owner_alive = clock, sleep, owner_alive
        self.monotonic = monotonic
        self.runner = runner
        self.observer = observer
        self.kill = kill  # Process signalling for `lease break` (injectable for tests).

    def resolve(self, device):
        if not isinstance(device, str):
            raise ValueError("Unknown lease device")
        config = next((config for host, config in self.collectors.items() if host.lower() == device.lower()), None)
        host = next((host for host in self.hosts if host.lower() == device.lower()), None)
        label = host_label(host) if host else device.upper()
        if config and config.get("ledger"):
            configured = Path(config["ledger"])
            if configured.parent != self.ledger_dir:
                raise ValueError("Ledger must be directly in the canonical ledger directory")
            label = configured.name.removeprefix("DEVICE_ACCESS_").removesuffix(".md")
        known = {Path(item["ledger"]).name.removeprefix("DEVICE_ACCESS_").removesuffix(".md")
                 for item in self.collectors.values() if item.get("ledger")}
        known |= {host_label(item) for item in self.hosts}
        if label not in known:
            raise ValueError(f"Unknown lease device: {device} (not a Switchyard registry host)")
        path = self.ledger_dir / f"DEVICE_ACCESS_{label}.md"
        external = os.environ.get("SWITCHYARD_EXTERNAL_LEASE_HOSTS", "")
        denied = [item.strip() for item in external.split(",") if item.strip()]
        if len(denied) > 256 or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", item) for item in denied):
            raise ValueError("Invalid SWITCHYARD_EXTERNAL_LEASE_HOSTS")
        aliases = {device.casefold(), label.casefold(), (host or "").casefold()}
        aliases.update(name.casefold() for name, item in self.collectors.items() if item.get("ledger") == str(path))
        aliases.update(name.casefold() for name in self.hosts if host_label(name) == label)
        if aliases & {item.casefold() for item in denied}:
            raise ValueError(f"Host {device} requires its external lease coordinator")
        try:
            info = path.lstat()
        except FileNotFoundError as error:
            raise ValueError(f"Unknown lease device (no existing ledger): {label}") from error
        if not stat.S_ISREG(info.st_mode) or path != path.resolve(strict=True):
            raise ValueError("Ledger must be an existing regular non-symlink file")
        if config is None or not config.get("ledger"):
            configs = [item for item in self.collectors.values() if item.get("ledger") == str(path)]
            # Do not export an arbitrary connection if a ledger maps to several endpoints.
            endpoints = {(item.get("transport"), item.get("serial"), item.get("target"), item.get("port", 22)) for item in configs}
            config = configs[0] if len(endpoints) == 1 else None
        return label, path, config or {}

    def _exports(self, state, config):
        result = {"SWITCHYARD_LEASE_ID": state["lease_id"], "SWITCHYARD_DEVICE": state["device"]}
        if config.get("transport") == "adb" and config.get("serial"):
            result["ANDROID_SERIAL"] = str(config["serial"])
        elif config.get("transport") == "ssh" and config.get("target"):
            result["SWITCHYARD_SSH_TARGET"] = str(config["target"])
            result["SWITCHYARD_SSH_PORT"] = str(config.get("port", 22))
        return result

    def _origin(self, owner, agent_id, origin_host, origin_user):
        """Owner attribution for a caller whose agent process lives on another registry host:
        `<agent name> (paseo:<id8>)@<host>`, `paseo:<id8>@<host>` for an uncached ID, else `<user>@<host>`."""
        if origin_host is None:
            if agent_id is not None or origin_user is not None:
                raise ValueError("--agent-id and --origin-user require --origin-host")
            return None
        host = next((item for item in self.hosts if isinstance(origin_host, str) and item.lower() == origin_host.lower()), None)
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
            # A cached name counts only when Switchyard saw that agent on the claimed origin host.
            name = locks._clean(cached.get("name"), 256) if cached.get("host_id") == host else None
            base = f"{name} (paseo:{agent_id[:8]})" if name else f"paseo:{agent_id[:8]}"
        else:
            base = origin_user or getpass.getuser()
        return {"owner": _text(f"{base}@{host}"), "owner_pid": None, "owner_started": None,
                "paseo_agent_id": agent_id, "origin_host": host}

    def _new(self, device, scope, owner, worktree, mode, ttl=None, origin=None):
        label, path, config = self.resolve(device)
        self._refuse_if_blocked(label)
        identity = origin or caller_identity(self.paseo_agents)
        lease_id = uuid.uuid4().hex
        state = {"lease_id": lease_id, "device": label, "ledger": str(path), "ledger_dir": str(self.ledger_dir),
                 **identity, "owner": identity["owner"] if origin or owner is None else _text(owner),
                 "scope": _text(scope), "worktree": _text(str(worktree if worktree is not None else Path.cwd())),
                 "mode": mode, "status": "starting", "created_at": _iso(self.clock()),
                 "expires_at": _iso(self.clock() + ttl) if ttl else None,
                 "ttl_seconds": ttl, "holder_unit": f"switchyard-lease-{label.lower()}-{lease_id[:8]}" if mode == "hold" else None}
        state["env"] = self._exports(state, config)
        return state

    def list(self):
        if self.observer:
            return enrich_locks(self.observer(), self.states.directory)
        return locks.device_locks(self.ledger_dir, self.paseo_agents, lease_state_dir=self.states.directory)

    def status(self, device):
        label, _, _ = self.resolve(device)
        return next((row for row in self.list()["ledgers"] if row["device"] == label),
                    {"device": label, "state": "unknown", "holders": [], "last_entries": []})

    def _wait(self, wait):
        if isinstance(wait, bool) or not isinstance(wait, (int, float)) or not math.isfinite(wait) or not 0 <= wait <= 600:
            raise ValueError("--wait must be between 0 and 600 seconds")
        return wait

    @contextmanager
    def _acquire(self, state, wait, cancelled=None):
        deadline = self.monotonic() + self._wait(wait)
        broker = LedgerBroker({state["device"]: Path(state["ledger"])})
        while True:
            reason = cancelled() if cancelled else None
            if reason:
                raise _Cancelled(reason)
            if state.get("ttl_seconds"):
                state["expires_at"] = _iso(self.clock() + state["ttl_seconds"])
            context = broker.hold(state["device"], owner=state["owner"], scope=state["scope"],
                                  worktree=state["worktree"], lease_id=state["lease_id"],
                                  metadata={"pid": os.getpid(), "via": state.get("via") or f"switchyard lease {state['mode']}",
                                            **({"expires_at": state["expires_at"]} if state.get("ttl_seconds") else {})})
            try:
                receipt = context.__enter__()
            except LeaseBusy:
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    raise LeaseBusy(busy_message(self.status(state["device"]))) from None
                self.sleep(min(1, remaining))
                continue
            # A `lease break` may have blocked the device between the first check and this flock.
            block = read_block(self.states.directory, state["device"])
            if block is None:
                break
            receipt["release"]["reason"] = "blocked"
            context.__exit__(None, None, None)
            raise LeaseBusy(blocked_message(state["device"], block))
        try:
            yield receipt
        except BaseException:
            context.__exit__(*sys.exc_info())
            raise
        else:
            context.__exit__(None, None, None)

    def run(self, device, command, *, scope, owner=None, worktree=None, wait=0, pass_lock_fd=False):
        """With pass_lock_fd, the child inherits the locked ledger descriptor as DEVICE_LOCK_FD (for
        scripts that verify an inherited lock). Opt-in only: a child
        that daemonizes with it would keep the lock after this lease's RELEASE."""
        if not command or any(not isinstance(arg, str) for arg in command):
            raise ValueError("lease run requires a command after --")
        state = self._new(device, scope, owner, worktree, "run")
        with self._acquire(state, wait) as receipt:
            receipt["release"].update(reason="error", exit_code=None)
            child, received = None, []
            previous = {}

            def forward(signum, _frame):
                received.append(signum)
                if child is not None:
                    try:
                        os.killpg(child.pid, signum)
                    except ProcessLookupError:
                        pass

            try:
                for signum in (signal.SIGINT, signal.SIGTERM):
                    previous[signum] = signal.signal(signum, forward)
                state.update(status="claimed", pid=os.getpid(), pid_started=locks._process_stat(locks.PROC_ROOT / str(os.getpid()))[1])
                self.states.update(state["lease_id"], lambda value: value.update(state), create=True)
                # Inherit the caller environment, but never leak stale lease connection hints.
                environment = dict(os.environ)
                for key in ("SWITCHYARD_LEASE_ID", "SWITCHYARD_DEVICE", "ANDROID_SERIAL", "SWITCHYARD_SSH_TARGET", "SWITCHYARD_SSH_PORT", "DEVICE_LOCK_FD"):
                    environment.pop(key, None)
                environment.update(state["env"])
                passed = ()
                if pass_lock_fd:
                    environment["DEVICE_LOCK_FD"] = str(receipt["fd"])
                    passed = (receipt["fd"],)
                child = subprocess.Popen(command, env=environment, start_new_session=True, pass_fds=passed)
                for signum in received:
                    try:
                        os.killpg(child.pid, signum)
                    except ProcessLookupError:
                        pass
                code = child.wait()
                exit_code = code if code >= 0 else 128 - code
                requested = self._requested_reason(state["lease_id"])
                receipt["release"].update(reason=requested or ("signal" if received or code < 0 else "completed"), exit_code=exit_code)
                return exit_code
            finally:
                if child is not None and child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGTERM)
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
                    except ProcessLookupError:
                        child.wait()
                for signum, handler in previous.items():
                    signal.signal(signum, handler)
                if self._exists(state["lease_id"]):
                    self.states.update(state["lease_id"], lambda value: value.update(status="released", reason=receipt["release"]["reason"]))

    def _exists(self, lease_id):
        try:
            self.states.read(lease_id)
            return True
        except FileNotFoundError:
            return False

    def _refuse_if_blocked(self, label):
        block = read_block(self.states.directory, label)
        if block is not None:
            raise LeaseBusy(blocked_message(label, block))

    def _requested_reason(self, lease_id):
        """A release reason requested from outside the holder (`broken` from `lease break`), if any."""
        try:
            return self.states.read(lease_id).get("release_reason")
        except (OSError, ValueError):
            return None

    # ---- Operator breakglass -------------------------------------------------------------------------

    def _operator(self, identity):
        """Human-only gate. `identity` exists for tests and supervised live proofs that call this method
        directly; the CLI never passes it, so the agent check always runs there."""
        identity = identity or {"user": getpass.getuser(), "agent": agent_ancestry()}
        if identity.get("agent"):
            raise ValueError(f"{BREAK_REFUSED} ({identity['agent']})")
        user = identity.get("user") or "operator"
        if not USER_NAME.fullmatch(user):
            raise ValueError("Invalid operator user name")
        return user

    def _live_leases(self, label):
        return [value for value in self.states.records() if value.get("device") == label
                and value.get("status") == "claimed" and process_alive(value.get("pid"), value.get("pid_started"))]

    def _describe_holders(self, pids, row=None):
        """Attribution for every descriptor holder, flagged when it is an agent session itself or one of
        this process's own ancestors (the operator's shell); neither is ever signalled."""
        boot = locks._boot_time()
        try:
            ticks = os.sysconf("SC_CLK_TCK")
        except (OSError, ValueError):
            ticks = None
        ancestors = {item["pid"] for item in _ancestry(os.getpid())}
        known = {holder.get("pid") for holder in (row or {}).get("holders", [])}
        result = []
        for pid in sorted(set(pids) | {pid for pid in known if isinstance(pid, int) and pid > 0}):
            item = locks._holder(pid, boot, ticks, self.paseo_agents)
            chain = _ancestry(pid)
            item.update(agent_session=bool(chain) and agent_session(chain[0]), own_ancestor=pid in ancestors,
                        verified=pid in pids)
            result.append(item)
        return result

    def _wait_gone(self, pids, seconds):
        deadline = self.monotonic() + seconds
        remaining = set(pids)
        while remaining:
            remaining = {pid for pid in remaining if _pid_running(pid)}
            if not remaining or self.monotonic() >= deadline:
                break
            self.sleep(0.1)
        return remaining

    def _wait_lease_ended(self, lease_id, seconds):
        deadline = self.monotonic() + seconds
        while True:
            try:
                if self.states.read(lease_id).get("status") in {"released", "error"}:
                    return True
            except (OSError, ValueError):
                return True
            if self.monotonic() >= deadline:
                return False
            self.sleep(0.1)

    def _revoke(self, lease, operator):
        """End a Switchyard lease through its own path so it writes exactly one RELEASE, reason `broken`:
        hold units and attach processes (suspect ones too) poll their state; a `run` process is signalled,
        which forwards SIGTERM to its command."""
        lease_id = lease["lease_id"]
        self.states.update(lease_id, lambda value: value.update(release_requested=True, release_reason="broken",
                                                                broken_by=operator))
        if lease.get("mode") == "run":
            _signal(self.kill, lease["pid"], signal.SIGTERM)
        ended = self._wait_lease_ended(lease_id, 10)
        if not ended:
            if lease.get("mode") == "hold" and lease.get("holder_unit"):
                try:
                    self.runner(["systemctl", "--user", "stop", lease["holder_unit"]], check=False, capture_output=True, timeout=10)
                except (OSError, subprocess.SubprocessError):
                    pass
            else:
                _signal(self.kill, lease["pid"], signal.SIGTERM)
            ended = self._wait_lease_ended(lease_id, 5)
        return {"lease_id": lease_id, "owner": lease.get("owner"), "scope": lease.get("scope"), "mode": lease.get("mode"),
                "pid": lease.get("pid"), "suspect": bool(lease.get("suspect")), "suspect_cause": lease.get("suspect_cause"),
                "ended": ended}

    def _lock_ledger(self, path, seconds):
        """Open the canonical ledger and take its flock, polling up to `seconds`; None while still held."""
        fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened, current = os.fstat(fd), os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("Ledger is not the canonical regular file")
            deadline = self.monotonic() + seconds
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return fd
                except BlockingIOError:
                    if self.monotonic() >= deadline:
                        os.close(fd)
                        return None
                    self.sleep(0.25)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def _write_block(self, label, record):
        self.states._prepare()
        temp_fd, temporary = tempfile.mkstemp(prefix=".block-", dir=self.states.directory)
        try:
            with os.fdopen(temp_fd, "w") as stream:
                json.dump(record, stream)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, block_path(self.states.directory, label))
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def break_lease(self, device, *, reason, signal_holders=False, kill=False, attest_stopped=None,
                    confirm=None, identity=None, output=None, verify_seconds=15, signal_grace=10):
        """Operator breakglass for a stuck or suspect lease. Shows every holder, asks `confirm(label)`,
        revokes Switchyard leases (one RELEASE, reason `broken`), optionally signals foreign descriptor
        holders (never agent sessions or the operator's own shell), proves the kernel lock is gone by taking
        it, appends one BREAK line while holding it and, without `attest_stopped`, blocks the device for new
        Switchyard leases until `clear_block`. Returns `status`: broken, still-held or not-applicable."""
        output = sys.stdout if output is None else output
        operator = self._operator(identity)
        reason = _text(reason)
        attest_stopped = _text(attest_stopped) if attest_stopped is not None else None
        if kill and not signal_holders:
            raise ValueError("--kill requires --signal-holders")
        label, path, _ = self.resolve(device)
        row = self.status(label)
        leases = self._live_leases(label)
        holders = self._describe_holders(flock_holders(path, exclude={os.getpid()}) or set(), row)
        _show(output, label, row, leases, holders)
        existing = read_block(self.states.directory, label)
        if not leases and not holders and row.get("state") == "free":
            hint = f"; it is blocked: use `switchyard lease clear {label.lower()}`" if existing else ""
            print(f"{label}: nothing holds this ledger; nothing to break{hint}", file=output)
            return {"device": label, "status": "not-applicable", "blocked": existing is not None}
        if confirm is None or not confirm(label):
            raise ValueError(f"Not confirmed: type the device label {label} (or pass --yes-device {label})")
        # Gate first: a pending block makes every agent acquisition back out (pre-check in `_new`, post-check
        # right after the flock in `_acquire`), so a contender queued on this ledger cannot slip in between
        # the revoke below and the verifying flock. Fail-closed: an exception mid-break leaves it pending.
        self._write_block(label, {"device": label, "ledger": str(path), "at": _iso(self.clock()), "operator": operator,
                                  "reason": reason, "pending": True, "revoked": []})

        def restore():
            """A clean `still-held` result changes nothing else: put back the block state from before."""
            if existing is not None and not existing.get("error"):
                self._write_block(label, existing)
            elif existing is None:
                block_path(self.states.directory, label).unlink(missing_ok=True)

        revoked = [self._revoke(lease, operator) for lease in leases]
        # Whatever still holds the descriptor now (a revoked lease that did not end is included).
        foreign = self._describe_holders(flock_holders(path, exclude={os.getpid()}) or set())
        signalled, killed = [], []
        if foreign and signal_holders:
            protected = [item for item in foreign if item["agent_session"] or item["own_ancestor"] or not item["comm"]]
            if protected:
                for item in protected:
                    why = (f"held inside agent process {item['comm']}:{item['pid']}; ask that agent to exit the command or restart it"
                           if item["agent_session"] else
                           f"held by your own shell or an ancestor of this command ({item['comm']}:{item['pid']}); release it there"
                           if item["own_ancestor"] else
                           f"held by pid {item['pid']} that this user cannot inspect or signal")
                    print(f"{label}: {why}", file=output)
                print(f"{label}: nothing was signalled", file=output)
                restore()
                return {"device": label, "status": "still-held", "revoked": revoked, "signalled": [], "killed": [],
                        "holders": foreign, "refused_holders": [item["pid"] for item in protected]}
            for item in foreign:
                if _signal(self.kill, item["pid"], signal.SIGTERM):
                    signalled.append(item["pid"])
            survivors = self._wait_gone(signalled, signal_grace)
            if survivors and kill:
                for pid in sorted(survivors):
                    if _signal(self.kill, pid, signal.SIGKILL):
                        killed.append(pid)
                self._wait_gone(killed, 5)
        fd = self._lock_ledger(path, verify_seconds)
        if fd is None:
            remaining = self._describe_holders(flock_holders(path, exclude={os.getpid()}) or set(), self.status(label))
            for item in remaining:
                print(f"{label}: still held by {item.get('comm') or 'process'}:{item['pid']}"
                      + (f" ({item['paseo_agent_name'] or item['paseo_agent_id']})" if item.get("paseo_agent_id") else "")
                      + ("" if item["verified"] else " (kernel report only)"), file=output)
            if not remaining:
                print(f"{label}: still locked by a process this user cannot see", file=output)
            print(f"{label}: lock NOT gone; no BREAK recorded and no block set", file=output)
            restore()
            return {"device": label, "status": "still-held", "revoked": revoked, "signalled": signalled,
                    "killed": killed, "holders": remaining}
        blocked = attest_stopped is None or existing is not None
        record = {"at": _iso(self.clock()), "event": "BREAK", "lease_id": revoked[0]["lease_id"] if revoked else None,
                  "resource": label, "owner": f"operator {operator}", "scope": reason, "operator": operator,
                  "reason": reason, "revoked": revoked,
                  "holders": [{key: item.get(key) for key in ("pid", "comm", "cmdline", "paseo_agent_id", "paseo_agent_name")}
                              for item in holders],
                  "signalled": signalled, "killed": killed, "attested_stopped": attest_stopped is not None,
                  "attestation": attest_stopped, "blocked": blocked, "via": "switchyard lease break"}
        try:
            if attest_stopped is None:
                self._write_block(label, {key: record[key] for key in ("at", "operator", "reason", "revoked", "lease_id")}
                                  | {"device": label, "ledger": str(path)})
            _append_event(fd, record)  # On failure the (pending or final) block stays: fail-closed.
            if attest_stopped is not None:
                restore()
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        state = ("BLOCKED for new leases until `switchyard lease clear` attests the old operation stopped"
                 if blocked else "not blocked (stop attested)")
        print(f"{label}: lock is free; BREAK recorded; {state}", file=output)
        return {"device": label, "status": "broken", "revoked": revoked, "signalled": signalled, "killed": killed,
                "blocked": blocked, "attestation": attest_stopped, "break": record}

    def clear_block(self, device, *, attest_stopped, confirm=None, identity=None, output=None, wait=10):
        """Lift a `lease break` block once the operator attests the old operation stopped: appends one CLEAR
        line while holding the ledger's flock, then removes the block."""
        output = sys.stdout if output is None else output
        operator = self._operator(identity)
        attest_stopped = _text(attest_stopped)
        label, path, _ = self.resolve(device)
        block = read_block(self.states.directory, label)
        if block is None:
            print(f"{label}: not blocked; nothing to clear", file=output)
            return {"device": label, "status": "not-applicable"}
        print(blocked_message(label, block), file=output)
        if confirm is None or not confirm(label):
            raise ValueError(f"Not confirmed: type the device label {label} (or pass --yes-device {label})")
        fd = self._lock_ledger(path, wait)
        if fd is None:
            raise LeaseBusy(f"{label}: the ledger is locked ({busy_message(self.status(label))}); "
                            "`lease clear` needs the lock briefly to record CLEAR")
        try:
            record = {"at": _iso(self.clock()), "event": "CLEAR", "lease_id": block.get("lease_id"), "resource": label,
                      "owner": f"operator {operator}", "scope": attest_stopped, "operator": operator,
                      "attestation": attest_stopped, "break_at": block.get("at"), "break_reason": block.get("reason"),
                      "via": "switchyard lease clear"}
            _append_event(fd, record)
            block_path(self.states.directory, label).unlink(missing_ok=True)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        print(f"{label}: CLEAR recorded; new leases allowed", file=output)
        return {"device": label, "status": "cleared", "clear": record}

    def attach(self, device, *, scope, owner=None, worktree=None, wait=0, agent_id=None, origin_host=None,
               origin_user=None, heartbeat=None, input_fd=0, output=None):
        """Hold the ledger for a caller on the other end of `input_fd` (a remote client's SSH connection).

        Prints one `claimed` JSON line (lease ID, device, expiry, connection hints) after CLAIM and one
        `released` line after RELEASE (best effort). A `done` input line releases (`released`): the caller
        confirms its command finished. `lease release <id>` also releases (`released`), SIGTERM/SIGINT give
        `signal`, the 120-minute cap `expired`. Busy raises LeaseBusy before anything is printed.

        Without `heartbeat` (manual use on this host) EOF also means `released`. With `heartbeat` (seconds;
        the remote client always sends it) the caller sends a byte at least that often, and losing it is
        fail-closed: silence (`silent`) or EOF without `done` (`disconnected`) only marks the lease
        `suspect`, because the remote command may still be running. The lock stays held, no RELEASE is
        written and SIGHUP is ignored (the CLI also leaves the SSH session with setsid), until an explicit release, a
        signal or the cap."""
        if heartbeat is not None and (isinstance(heartbeat, bool) or not isinstance(heartbeat, (int, float))
                                      or not math.isfinite(heartbeat) or not 1 <= heartbeat <= 600):
            raise ValueError("--heartbeat must be between 1 and 600 seconds")
        output = sys.stdout if output is None else output
        self._wait(wait)
        origin = self._origin(owner, agent_id, origin_host, origin_user)
        state = self._new(device, scope, owner, worktree, "attach", ATTACH_CAP_SECONDS, origin)
        state["via"] = "switchyard lease attach" + (f" from {origin['origin_host']}" if origin else "")
        if heartbeat is not None:
            state["heartbeat_seconds"] = heartbeat
        lease_id, received, previous, claimed = state["lease_id"], [], {}, []

        def emit(value):
            try:
                output.write(json.dumps(value) + "\n")
                output.flush()
                return True
            except (OSError, ValueError):
                return False  # The caller is gone.

        def on_signal(signum, _frame):
            # Once a heartbeat lease is held, SSH session teardown must not end it.
            if not (signum == signal.SIGHUP and heartbeat is not None and claimed):
                received.append(signum)

        attempts = []

        def cancelled():
            # Checked between lock attempts only: the first attempt always runs (busy => 75, never "cancelled").
            attempts.append(None)
            if len(attempts) == 1:
                return None
            if received:
                return "signal"
            return "released" if _read_input(input_fd, 0)[0] else None

        try:
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                previous[signum] = signal.signal(signum, on_signal)
            with self._acquire(state, wait, cancelled) as receipt:
                receipt["release"]["reason"] = "error"
                try:
                    state.update(status="claimed", pid=os.getpid(), claimed_at=_iso(self.clock()),
                                 pid_started=locks._process_stat(locks.PROC_ROOT / str(os.getpid()))[1])
                    self.states.update(lease_id, lambda value: value.update(state), create=True)
                    claimed.append(True)
                    deadline = _epoch(state["expires_at"])
                    # A claim the caller never received cannot have started a command: release at once.
                    caller_present = emit({"status": "claimed", "lease_id": lease_id, "device": state["device"],
                                           "expires_at": state["expires_at"], "env": state["env"]})
                    heard, buffer, input_open, suspect = self.monotonic(), b"", True, None

                    def mark_suspect(cause):
                        mark = {"suspect": True, "suspect_since": _iso(self.clock()), "suspect_cause": cause}
                        self.states.update(lease_id, lambda value: value.update(mark))
                        return mark

                    while True:
                        current = self.states.read(lease_id)
                        if received:
                            reason = current.get("release_reason") or "signal"
                        elif not caller_present:
                            reason = "released"
                        elif current.get("release_requested"):
                            reason = current.get("release_reason") or "released"
                            if suspect:
                                receipt["release"]["released_after_loss"] = True
                        elif (remaining := deadline - self.clock()) <= 0:
                            reason = "expired"
                        elif heartbeat is not None and suspect is None and self.monotonic() - heard >= heartbeat:
                            suspect = mark_suspect("silent")
                            continue
                        elif not input_open:
                            select.select([], [], [], min(0.25, remaining))
                            continue
                        else:
                            eof, data = _read_input(input_fd, min(0.25, remaining))
                            if data:
                                heard = self.monotonic()
                                buffer, done = _scan_done(buffer + data)
                                if done:
                                    receipt["release"]["reason"] = "released"
                                    break
                            if not eof:
                                continue
                            input_open = False
                            if heartbeat is None:
                                reason = "signal" if received else "released"
                            else:
                                suspect = suspect or mark_suspect("disconnected")
                                continue
                        receipt["release"]["reason"] = reason
                        break
                    if suspect:
                        receipt["release"].update(suspect_cause=suspect["suspect_cause"], suspect_since=suspect["suspect_since"])
                finally:
                    # The context appends exactly one RELEASE before the final state below.
                    reason = receipt["release"]["reason"]
            self.states.update(lease_id, lambda value: value.update(status="released", reason=reason))
            emit({"status": "released", "lease_id": lease_id, "device": state["device"], "reason": reason})
            return 0
        except _Cancelled as error:
            print(f"switchyard: lease attach cancelled before claim ({error})", file=sys.stderr)
            return 1
        except BaseException as error:
            if self._exists(lease_id):
                self.states.update(lease_id, lambda value: value.update(status="error", error=str(error)))
            raise
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)

    def hold(self, device, *, scope, ttl=3600, owner=None, worktree=None, wait=0, detached=False,
             agent_id=None, origin_host=None, origin_user=None):
        """`detached`: TTL-only hold for a caller whose owning process is not on this host (a remote
        agent); it skips the owner-exit watch, so the caller must release it (or let the TTL end it)."""
        ttl = validate_ttl(ttl)
        self._wait(wait)
        origin = self._origin(owner, agent_id, origin_host, origin_user)
        if origin and not detached:
            raise ValueError("--origin-host requires --detached: the owning process is not on this host")
        state = self._new(device, scope, owner, worktree, "hold", ttl, origin)
        state["wait_seconds"] = wait
        if detached:
            state["detached"] = True
            state["via"] = "switchyard lease hold --detached" + (f" from {origin['origin_host']}" if origin else "")
        if host_context.enabled():
            executable = os.environ.get("SWITCHYARD_HOST_HOLDER", "")
            path = Path(executable)
            if (not executable or not path.is_absolute() or str(path) != executable or ".." in path.parts
                    or any(ord(character) < 32 or ord(character) == 127 for character in executable)):
                raise ValueError("Integrated containers require an absolute trusted SWITCHYARD_HOST_HOLDER executable")
            # systemd-run checks argv[0] in the container before handing it to
            # the host manager. The helper itself exists only on the host.
            command = ["/usr/bin/env", "--", executable]
        else:
            command = [sys.executable, "-m", "switchyard.cli"]
        command += ["--state-dir", str(self.root.resolve()), "lease", "_holder", state["lease_id"]]
        self.states.update(state["lease_id"], lambda value: value.update(state), create=True)
        started = self.monotonic()
        try:
            try:
                self.runner(systemd_argv(state, command), check=True, capture_output=True, text=True, timeout=10)
            except subprocess.TimeoutExpired:
                raise LeaseBusy(busy_message(self.status(state["device"]))) from None
            # The holder owns the bounded acquisition wait; startup adds at most 10s.
            deadline = started + wait + 10
            while self.monotonic() < deadline:
                current = self.states.read(state["lease_id"])
                if current["status"] == "claimed":
                    return {key: current[key] for key in ("lease_id", "device", "expires_at", "holder_unit", "env")}
                if current["status"] in {"error", "released"}:
                    if current.get("busy"):
                        raise LeaseBusy(current["error"])
                    raise ValueError(current.get("error") or "Lease holder exited before confirmation")
                self.sleep(0.05)
            raise LeaseBusy(busy_message(self.status(state["device"])))
        except BaseException:
            # Cancellation is persisted first: a delayed unit must never claim after a failed handshake.
            self.states.update(state["lease_id"], lambda value: value.update(release_requested=True))
            try:
                self.runner(["systemctl", "--user", "stop", state["holder_unit"]], check=False, capture_output=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass
            raise

    def holder(self, lease_id):
        state = self.states.read(lease_id)
        if state.get("mode") != "hold" or state.get("status") != "starting":
            raise ValueError("Lease is not awaiting a holder")
        label, path, _ = self.resolve(state["device"])
        if str(path) != state["ledger"] or label != state["device"]:
            raise ValueError("Lease ledger changed")
        def reserve(value):
            if value.get("status") != "starting":
                raise ValueError("Lease is not awaiting a holder")
            value["status"] = "acquiring"
        self.states.update(lease_id, reserve)
        received, previous = [], {}
        try:
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous[signum] = signal.signal(signum, lambda sig, frame: received.append(sig))
            def cancelled():
                if received:
                    return "signal"
                return "released" if self.states.read(lease_id).get("release_requested") else None
            with self._acquire(state, state.get("wait_seconds", 0), cancelled) as receipt:
                receipt["release"]["reason"] = "error"
                try:
                    claimed_at = self.clock()
                    def claimed(value):
                        value.update(status="claimed", pid=os.getpid(),
                                     pid_started=locks._process_stat(locks.PROC_ROOT / str(os.getpid()))[1],
                                     claimed_at=_iso(claimed_at), expires_at=state["expires_at"])
                    self.states.update(lease_id, claimed)
                    while True:
                        current = self.states.read(lease_id)
                        if received:
                            reason = current.get("release_reason") or "signal"
                        elif current.get("release_requested"):
                            reason = current.get("release_reason") or "released"
                        elif self.clock() >= _epoch(current["expires_at"]):
                            reason = "expired"
                        elif not current.get("detached") and not self.owner_alive(current["owner_pid"], current["owner_started"]):
                            reason = "owner-exited"
                        else:
                            self.sleep(0.2)
                            continue
                        receipt["release"]["reason"] = reason
                        break
                finally:
                    # The context appends exactly one RELEASE before the final state below.
                    reason = receipt["release"]["reason"]
            self.states.update(lease_id, lambda value: value.update(status="released", reason=reason))
        except _Cancelled as error:
            self.states.update(lease_id, lambda value: value.update(status="released", reason=str(error)))
        except BaseException as error:
            self.states.update(lease_id, lambda value: value.update(status="error", error=str(error), busy=isinstance(error, LeaseBusy)))
            raise
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)

    def _held_state(self, reference):
        if LEASE_ID.fullmatch(reference):
            try:
                state = self.states.read(reference)
            except FileNotFoundError as error:
                raise ValueError("No Switchyard holder state for this lease") from error
        else:
            label, _, _ = self.resolve(reference)
            candidates = [value for value in self.states.records() if value.get("device") == label
                          and value.get("mode") in {"hold", "attach"} and value.get("status") == "claimed"
                          and self.owner_alive(value.get("pid"), value.get("pid_started"))]
            if len(candidates) != 1:
                raise ValueError("No unique Switchyard holder; " + busy_message(self.status(label)))
            state = candidates[0]
        if state.get("mode") not in {"hold", "attach"}:
            raise ValueError("Only Switchyard hold or attach leases can be released or renewed")
        if state.get("status") != "claimed" or not self.owner_alive(state.get("pid"), state.get("pid_started")):
            raise ValueError("Switchyard lease holder is no longer active")
        # Never trust state alone to control an unrelated or raw-flock holder.
        row = self.status(state["device"])
        if not any(holder.get("pid") == state.get("pid") for holder in row.get("holders", [])):
            raise ValueError("Switchyard holder does not own this ledger; " + busy_message(row))
        return state

    def release(self, reference):
        state = self._held_state(reference)
        lease_id = state["lease_id"]
        self.states.update(lease_id, lambda value: value.update(release_requested=True))
        deadline = self.monotonic() + 10
        while self.monotonic() < deadline:
            current = self.states.read(lease_id)
            if current["status"] in {"released", "error"}:
                return {"lease_id": lease_id, "device": state["device"], "status": current["status"], "reason": current.get("reason")}
            self.sleep(0.05)
        raise ValueError("Release requested, but holder has not confirmed RELEASE within 10 seconds")

    def renew(self, lease_id, *, ttl):
        validate_ttl(ttl)
        state = self._held_state(lease_id)
        if not LEASE_ID.fullmatch(lease_id):
            raise ValueError("Renew requires a Switchyard lease ID")
        if state.get("mode") != "hold":
            raise ValueError("Attach leases end with their connection (120-minute cap) and cannot be renewed")
        if state.get("release_requested") or self.clock() >= _epoch(state["expires_at"]):
            raise ValueError("Lease has expired or is releasing")
        # RuntimeMaxSec is measured from unit activation, not this renewal.
        maximum = math.ceil(self.clock() - _epoch(state["created_at"]) + ttl + 60)
        self.runner(["systemctl", "--user", "set-property", "--runtime", state["holder_unit"],
                     f"RuntimeMaxSec={maximum}"], check=True, capture_output=True, timeout=10)
        def renewed(value):
            if value.get("status") != "claimed" or value.get("release_requested") or self.clock() >= _epoch(value["expires_at"]):
                raise ValueError("Lease has expired or is releasing")
            value["expires_at"] = _iso(self.clock() + ttl)
        current = self.states.update(lease_id, renewed)
        return {key: current.get(key) for key in ("lease_id", "device", "expires_at", "holder_unit")}


def holder_main(root, lease_id):
    states = LeaseStates(Path(root) / "leases")
    state = states.read(lease_id)
    # Private held state contains the configured canonical directory, not a
    # request-supplied arbitrary pathname. Rebuild the exact label mapping:
    # host_label(device) is not necessarily the configured collector label.
    directory = Path(state.get("ledger_dir", locks.DEFAULT_LEDGER_DIR))
    label = state.get("device")
    if (not directory.is_absolute() or directory != directory.resolve(strict=True)
            or not isinstance(label, str) or not re.fullmatch(r"[A-Z0-9]{1,64}", label)):
        raise ValueError("Invalid canonical holder ledger mapping")
    path = directory / f"DEVICE_ACCESS_{label}.md"
    if state.get("ledger") != str(path):
        raise ValueError("Lease ledger changed")
    AgentLeases(state_dir=root, ledger_dir=directory, collectors={"holder": {"ledger": str(path)}}).holder(lease_id)
