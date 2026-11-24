"""Read-only, bounded device-ledger and Linux flock attribution."""
import datetime
import json
import os
from pathlib import Path
import re
import stat


PROC_ROOT = Path("/proc")
def _default_ledger_dir():
    state = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
    return Path(os.environ.get("SWITCHYARD_LEDGER_DIR") or state / "switchyard/ledgers").expanduser().absolute()


DEFAULT_LEDGER_DIR = _default_ledger_dir()
_LOCK = re.compile(r"^\d+:\s+FLOCK\s+\S+\s+\S+\s+(-?\d+)\s+([0-9a-fA-F]+):([0-9a-fA-F]+):(\d+)\s")
_TEXT_ENTRY = re.compile(r"^\s*(?:-\s+)?(\d{4}-\d\d-\d\dT\S+)\s+(CLAIM|RELEASE)\b(.*)$")
_TEXT_FIELD = re.compile(r"(?:^|\s)([A-Za-z_][A-Za-z_0-9-]*)=")


def _clean(value, limit):
    if not isinstance(value, str):
        return None
    value = "".join(c if ord(c) >= 32 and not 127 <= ord(c) <= 159 else " " for c in value).strip()
    return value[:limit] or None


def _read(path, limit):
    with path.open("rb") as stream:
        return stream.read(limit)


def _lock_holders():
    """None means the kernel lock inventory could not be read completely."""
    try:
        data = _read(PROC_ROOT / "locks", 1048577)
        if len(data) > 1048576:
            return None
        holders = {}
        for line in data.decode("ascii", errors="replace").splitlines():
            match = _LOCK.match(line)
            if match:
                pid, major, minor, inode = match.groups()
                key = (int(major, 16), int(minor, 16), int(inode))
                holders.setdefault(key, set()).add(int(pid))
        return holders
    except OSError:
        return None


def _mounts():
    """(mount point, superblock device) pairs; /proc/locks reports the superblock device,
    which differs from st_dev on btrfs subvolumes."""
    try:
        data = _read(PROC_ROOT / "self" / "mountinfo", 1048577)
    except OSError:
        return []
    mounts = []
    for line in data.decode("utf-8", errors="replace").splitlines()[:4096]:
        fields = line.split()
        try:
            major, minor = (int(part) for part in fields[2].split(":"))
        except (IndexError, ValueError):
            continue
        point = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4])
        mounts.append((point, (major, minor)))
    return mounts


def _mount_device(mounts, path):
    target = str(path)
    best = None
    for point, device in mounts:
        if (target == point or point == "/" or target.startswith(point.rstrip("/") + "/")) and (best is None or len(point) > len(best[0])):
            best = (point, device)
    return best[1] if best else None


def _holds_file(pid, info):
    """True/False when the holder's descriptor table proves or disproves it has this exact file open; None when unreadable.
    Superblock-device matches need this because btrfs inode numbers are unique only per subvolume."""
    try:
        with os.scandir(PROC_ROOT / str(pid) / "fd") as descriptors:
            for count, entry in enumerate(descriptors):
                if count >= 4096:
                    return None
                try:
                    opened = os.stat(entry.path)
                except OSError:
                    continue
                if (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino):
                    return True
    except OSError:
        return None
    return False


def _descriptor_holders(info, limit=4096):
    """Own-user processes with this exact file open; None when /proc cannot be scanned. Used only when the
    kernel's lock PID is gone or unconfirmed: a process still holding an inherited descriptor keeps the lock."""
    found = set()
    try:
        with os.scandir(PROC_ROOT) as entries:
            for count, entry in enumerate(entries):
                if count >= limit:
                    return None
                if not entry.name.isdigit() or not _own_process(Path(entry.path)):
                    continue
                if _holds_file(int(entry.name), info):
                    found.add(int(entry.name))
    except OSError:
        return None
    return found


def _boot_time():
    try:
        for line in _read(PROC_ROOT / "stat", 131072).splitlines():
            if line.startswith(b"btime "):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def _process_stat(path):
    try:
        # comm can itself contain spaces and parentheses; fields after its final ')' are stable.
        fields = _read(path / "stat", 4096).rsplit(b")", 1)[1].split()
        return int(fields[1]), int(fields[19])
    except (OSError, ValueError, IndexError):
        return None, None


def _agent_environment(path):
    try:
        result = {}
        for item in _read(path / "environ", 131072).split(b"\0"):
            key, separator, value = item.partition(b"=")
            if separator and key in (b"PASEO_AGENT_ID", b"PASEO_AGENT_CWD"):
                result[key.decode("ascii")] = _clean(value.decode("utf-8", errors="replace"),
                                                      256 if key == b"PASEO_AGENT_ID" else 1024)
        return result
    except OSError:
        return {}


def _own_process(path):
    try:
        return path.stat().st_uid == os.getuid()
    except OSError:
        return False


def _holder(pid, boot_time, ticks, paseo_agents):
    result = dict.fromkeys(("comm", "cmdline", "cwd", "started_at", "paseo_agent_id", "paseo_agent_name"))
    result["pid"] = pid
    path = PROC_ROOT / str(pid)
    if not _own_process(path):
        return result
    parent, started = _process_stat(path)
    if boot_time is not None and started is not None and ticks:
        try:
            result["started_at"] = datetime.datetime.fromtimestamp(
                boot_time + started / ticks, datetime.timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            pass
    try:
        result["comm"] = _clean(_read(path / "comm", 1024).decode("utf-8", errors="replace"), 256)
    except OSError:
        pass
    try:
        args = _read(path / "cmdline", 4096).split(b"\0")
        if args and args[0]:
            args[0] = args[0].rsplit(b"/", 1)[-1]
            result["cmdline"] = _clean(b" ".join(args).decode("utf-8", errors="replace"), 512)
    except OSError:
        pass
    try:
        result["cwd"] = _clean(os.readlink(path / "cwd"), 1024)
    except OSError:
        pass
    environment = _agent_environment(path)
    seen = {pid}
    for _ in range(6):
        if environment.get("PASEO_AGENT_ID") or parent is None or parent <= 0 or parent in seen:
            break
        seen.add(parent)
        path = PROC_ROOT / str(parent)
        if not _own_process(path):
            break
        environment = _agent_environment(path)
        parent, _ = _process_stat(path)
    agent_id = environment.get("PASEO_AGENT_ID")
    result["paseo_agent_id"] = agent_id
    if agent_id:
        agent = paseo_agents.get(agent_id)
        if isinstance(agent, dict):
            result["paseo_agent_name"] = _clean(agent.get("name"), 256)
    return result


def _entries(stream):
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    start = max(0, size - 16384)
    stream.seek(start)
    data = stream.read(16384)
    if start:
        # Never interpret the truncated first line as a complete event.
        data = data.partition(b"\n")[2]
    entries = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except (ValueError, RecursionError):
            value = None
        if not isinstance(value, dict):
            match = _TEXT_ENTRY.match(line)
            if not match:
                continue
            at, event, fields = match.groups()
            value = {"at": at, "event": event}
            matches = list(_TEXT_FIELD.finditer(fields))
            for index, field in enumerate(matches):
                if field[1] in {"owner", "scope"}:
                    end = matches[index + 1].start() if index + 1 < len(matches) else len(fields)
                    value[field[1]] = fields[field.end():end].strip().strip('"\'')
        # BREAK/CLEAR: an operator's `switchyard lease break` / `lease clear` (both end any prior claim).
        if value.get("event") not in ("CLAIM", "RELEASE", "BREAK", "CLEAR"):
            continue
        at = _clean(value.get("at"), 64)
        if at is not None:
            entries.append({"at": at, "event": value["event"], "owner": _clean(value.get("owner"), 256),
                            "scope": _clean(value.get("scope"), 512)})
    return entries[-5:]


def device_locks(ledger_dir=DEFAULT_LEDGER_DIR, paseo_agents=None, *, paths=None):
    """Observe ledgers without flocking or modifying them; unavailable evidence stays unknown."""
    now = datetime.datetime.now(datetime.timezone.utc)
    result = {"observed_at": now.isoformat(), "ledgers": []}
    paseo_agents = paseo_agents or {}
    holders = _lock_holders()
    boot_time = _boot_time()
    try:
        ticks = os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError):
        ticks = None
    if paths is None:
        try:
            paths = []
            with os.scandir(ledger_dir) as directory:
                for entry in directory:
                    if (entry.name.startswith("DEVICE_ACCESS_") and entry.name.endswith(".md")
                            and entry.is_file(follow_symlinks=False)):
                        paths.append(Path(entry.path))
                        if len(paths) >= 64:
                            break
        except OSError:
            return result
    paths = sorted(paths)
    process_cache = {}
    mounts = _mounts() if holders is not None else []
    for path in paths:
        if len(result["ledgers"]) >= 64:
            break
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                continue
        except OSError:
            continue
        key = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
        exact = set(holders.get(key, set())) if holders is not None else set()
        mount = _mount_device(mounts, Path(os.path.realpath(path.parent)) / path.name)
        superblock = (set(holders.get((*mount, info.st_ino), set())) - exact
                      if holders is not None and mount is not None and (*mount, info.st_ino) != key else set())
        # A flock follows its open file description: after the locking process exits (or closes its
        # descriptor) the kernel still reports that PID while an inheritor holds the lock.
        pids = {pid for pid in exact if pid > 0 and (PROC_ROOT / str(pid)).is_dir()}
        stale_exact = exact - pids
        superblock_unreadable = superblock_other = False
        for pid in superblock:
            held = _holds_file(pid, info) if pid > 0 else None
            if held:
                pids.add(pid)
            elif held is None:
                superblock_unreadable = True
            else:
                superblock_other = True
        inferred = set()
        if stale_exact or superblock_unreadable or superblock_other:
            inferred = (_descriptor_holders(info) or set()) - pids - {os.getpid()}
        if holders is None:
            state = "unknown"
        elif pids or inferred or exact:
            state = "held"     # An exact-device entry proves a lock on this file even if unattributed.
        elif superblock_unreadable:
            state = "unknown"
        else:
            state = "free"     # Superblock match while nobody holds this file: an inode collision.
        if not pids and not inferred:
            pids = {pid for pid in stale_exact if pid > 0}  # Keep the kernel's PID, metadata null.
        entries = []
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if stat.S_ISREG(opened.st_mode) and (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino):
                    entries = _entries(stream)
                else:
                    state = "unknown"
        except OSError:
            pass
        processes = []
        for pid in sorted(pid for pid in pids | inferred if pid > 0):
            if pid not in process_cache:
                process_cache[pid] = _holder(pid, boot_time, ticks, paseo_agents)
            processes.append({**process_cache[pid], "inferred": pid in inferred})
        anomaly = None
        if entries:
            latest = entries[-1]
            if state == "held" and latest["event"] in ("RELEASE", "BREAK", "CLEAR"):
                anomaly = "held-after-release"
            elif state == "free" and latest["event"] == "CLAIM":
                try:
                    at = datetime.datetime.fromisoformat(latest["at"].replace("Z", "+00:00"))
                    if at.tzinfo is not None and (now - at).total_seconds() > 600:
                        anomaly = "claim-without-holder"
                except (ValueError, OverflowError):
                    pass
        result["ledgers"].append({"device": path.name[len("DEVICE_ACCESS_"):-3], "path": str(path),
                                  "state": state, "holders": processes, "last_entries": entries, "anomaly": anomaly})
    return result
