"""Packaged, stdlib-only Linux probe. Executed from stdin, never installed remotely.

Only fixed proc/sys metadata, exact systemd allowlists, local Paseo discovery and
opt-in selected container/Paseo metadata are read. No logs or private content.
"""
import datetime
import errno
import ipaddress
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

if __package__:
    from . import container_probe

READ_LIMIT = 131072
PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "Result",
              "ExecMainCode", "ExecMainStatus", "TriggeredBy", "Triggers")
UNIT = re.compile(r"[A-Za-z0-9_:][A-Za-z0-9_.:@-]{0,180}\.(?:service|timer)\Z")


def validate_mounts(mounts):
    """Exact absolute mount points whose FUSE capacity the operator explicitly allows reading."""
    if not isinstance(mounts, list) or len(mounts) > 32 or len(set(mounts)) != len(mounts):
        raise ValueError("invalid storage mount allowlist")
    for mount in mounts:
        if (not isinstance(mount, str) or not mount.startswith("/") or len(mount) > 1024 or mount != "/" and mount.endswith("/")
                or "//" in mount or any(part in (".", "..") for part in mount.split("/")) or any(ord(c) < 32 or ord(c) == 127 for c in mount)):
            raise ValueError("invalid storage mount allowlist")
    return frozenset(mounts)


def text(path, limit=READ_LIMIT):
    with open(path, "r", encoding="utf-8", errors="strict") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("metadata limit")
    return value.strip()


def optional(path):
    try:
        return text(path, 4096)
    except (OSError, ValueError, UnicodeError):
        return None


def integer(path):
    value = optional(path)
    return int(value) if value and value.isdecimal() else None


def cpu_ticks():
    line = text("/proc/stat").splitlines()[0].split()
    if line[0] != "cpu" or len(line) < 5:
        raise ValueError("CPU counters unavailable")
    ticks = [int(v) for v in line[1:9]]  # guest already included in user/nice
    return sum(ticks), ticks[3] + (ticks[4] if len(ticks) > 4 else 0)


def cpu_model():
    for line in text("/proc/cpuinfo").splitlines():
        key, _, value = line.partition(":")
        if key.strip() in ("model name", "Hardware"):
            return value.strip()[:256]
    return None


def cpu():
    before = cpu_ticks()
    started = time.monotonic()
    time.sleep(0.1)
    after = cpu_ticks()
    duration = time.monotonic() - started
    delta, idle = after[0] - before[0], after[1] - before[1]
    utilization = 100 * (delta - idle) / delta if delta > 0 and 0 <= idle <= delta else None
    # Scheduling delays do not turn a longer interval into the promised short sample.
    if duration > 0.25:
        utilization, duration = None, None
    return {"model": cpu_model(), "logical_count": os.cpu_count(), "utilization_percent": utilization,
            "sample_seconds": duration, "load_1m": os.getloadavg()[0]}


def cpu_fast():
    total, idle = cpu_ticks()
    uptime = float(text("/proc/uptime").split()[0])
    boot_id = text("/proc/sys/kernel/random/boot_id")
    return {"model": cpu_model(), "logical_count": os.cpu_count(), "utilization_percent": None,
            "sample_seconds": None, "load_1m": os.getloadavg()[0],
            "counters": {"total_ticks": total, "idle_ticks": idle,
                         "uptime_seconds": uptime, "boot_id": boot_id}}


def memory():
    values = {}
    for line in text("/proc/meminfo").splitlines():
        key, _, value = line.partition(":")
        parts = value.split()
        if len(parts) == 2 and parts[0].isdecimal() and parts[1] == "kB":
            values[key] = int(parts[0]) * 1024
    return dict(zip(("total_bytes", "available_bytes", "swap_total_bytes", "swap_free_bytes"),
                    (values.get(k) for k in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"))))


def gpus():
    result = []
    devices = sorted(Path("/sys/bus/pci/devices").iterdir())
    if len(devices) > 4096:
        raise ValueError("PCI device limit")
    for device in devices:
        pci_class = optional(device / "class")
        if not pci_class or not pci_class.startswith("0x03"):
            continue
        vendor, product = optional(device / "vendor"), optional(device / "device")
        driver = (device / "driver").resolve().name if (device / "driver").is_symlink() else None
        active = optional(device / "power/runtime_status") == "active"
        busy = integer(device / "gpu_busy_percent") if active else None
        total = integer(device / "mem_info_vram_total") if active else None
        used = integer(device / "mem_info_vram_used") if active else None
        name = "PCI GPU " + (vendor + ":" + product if vendor and product else device.name)
        result.append({"id": "pci:" + device.name, "name": name,
                       "driver": driver, "memory_kind": "unknown",
                       "busy_percent": busy if busy is not None and busy <= 100 else None,
                       "vram_total_bytes": total, "vram_used_bytes": used})
    if len(result) > 64:
        raise ValueError("GPU device limit")
    return result


def unescape_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)


def external_statfs(mount):
    """Read one operator-allowlisted FUSE capacity in a killable child, never in this process."""
    child = subprocess.Popen(["/usr/bin/stat", "-f", "-c", "%b %a %f %S", "--", mount], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
    try:
        output, _ = child.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        child.kill()
        try:
            child.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass
        raise OSError("capacity read timed out")
    fields = output.decode("ascii", "strict").split()
    if child.returncode != 0 or len(fields) != 4 or not all(field.isdecimal() for field in fields):
        raise OSError("capacity read failed")
    blocks, available, free, size = map(int, fields)
    if size <= 0 or available > blocks or free > blocks:
        raise OSError("invalid capacity")
    return blocks * size, available * size, (blocks - free) * size


def storage(capacity_mounts=()):
    blocks = Path("/sys/class/block")
    entries = sorted(blocks.iterdir())
    if len(entries) > 1024:
        raise ValueError("block device limit")
    by_dev = {optional(p / "dev"): p for p in entries}
    devices = []
    physical = {}
    for entry in entries:
        if (entry / "partition").exists() or not (entry / "device").exists():
            continue
        ident = "block:" + entry.name
        physical[entry.name] = ident
        resolved = str(entry.resolve())
        transport = next((x for x in ("usb", "nvme", "virtio") if x in resolved), None)
        sectors = integer(entry / "size")
        rota = integer(entry / "queue/rotational")
        devices.append({"id": ident, "name": entry.name, "model": optional(entry / "device/model"),
                        "transport": transport, "rotational": bool(rota) if rota in (0, 1) else None,
                        "size_bytes": sectors * 512 if sectors is not None else None})

    def backing(dev, seen=None):
        seen = set() if seen is None else seen
        entry = by_dev.get(dev)
        if entry is None or entry.name in seen:
            return []
        seen.add(entry.name)
        if entry.name in physical:
            return [physical[entry.name]]
        if (entry / "partition").exists():
            return backing(optional(entry.resolve().parent / "dev"), seen)
        slaves = list((entry / "slaves").iterdir()) if (entry / "slaves").exists() else []
        return sorted({item for slave in slaves for item in backing(optional(slave / "dev"), seen)})

    pools = {}
    btrfs = Path("/sys/fs/btrfs")
    if btrfs.exists():
        for pool in sorted(btrfs.iterdir())[:256]:
            if not (pool / "devices").is_dir():
                continue
            members = [optional(p / "dev") for p in sorted((pool / "devices").iterdir())[:256]]
            for dev in members:
                if dev:
                    pools[dev] = (pool.name, sorted({d for member in members for d in backing(member)}))
    volatile = {"tmpfs", "devtmpfs", "ramfs"}
    images = {"overlay", "squashfs", "erofs", "iso9660", "composefs"}
    persistent = {"ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "ntfs3", "f2fs", "zfs"}
    ignored = {"proc", "sysfs", "devpts", "cgroup", "cgroup2", "securityfs", "debugfs", "tracefs",
               "pstore", "efivarfs", "mqueue", "hugetlbfs", "configfs", "fusectl", "autofs", "binfmt_misc"}
    filesystems = {}
    partial = False
    lines = text("/proc/self/mountinfo").splitlines()
    if len(lines) > 2048:
        raise ValueError("mount limit")
    for line in lines:
        left, sep, right = line.partition(" - ")
        fields, extra = left.split(), right.split()
        if not sep or len(fields) < 6 or len(extra) < 3:
            raise ValueError("invalid mount metadata")
        fstype, source = extra[0], unescape_mount(extra[1])
        if fstype in ignored:
            continue
        dev, mount = fields[2], unescape_mount(fields[4])
        pool = pools.get(dev)
        if fstype == "btrfs" and not pool and source.startswith("/dev/"):
            try:
                st = os.stat(source)
                pool = pools.get(str(os.major(st.st_rdev)) + ":" + str(os.minor(st.st_rdev)))
            except OSError:
                pass
        identity = pool[0] if pool else source if fstype == "btrfs" else dev
        ident = "fs:" + fstype + ":" + identity
        read_only = "ro" in fields[5].split(",") or "ro" in extra[2].split(",")
        if ident in filesystems:
            filesystems[ident]["mounts"].append(mount)
            filesystems[ident]["read_only"] &= read_only
            continue
        kind = "volatile" if fstype in volatile else "image" if fstype in images else "persistent" if fstype in persistent else "unknown"
        total = available = used = None
        backing_ids = pool[1] if pool else backing(dev)
        # Never stat network, automount or unknown/FUSE mounts implicitly: it may block, wake a
        # drive or contact another host. Operators may allowlist exact block-backed mount points.
        if kind == "unknown" and mount in capacity_mounts and backing_ids:
            try:
                total, available, used = external_statfs(mount)
            except (OSError, ValueError, UnicodeError):
                partial = True
        elif kind != "unknown":
            try:
                stats = os.statvfs(mount)
                total, available = stats.f_blocks * stats.f_frsize, stats.f_bavail * stats.f_frsize
                used = (stats.f_blocks - stats.f_bfree) * stats.f_frsize
            except OSError:
                partial = True
        else:
            partial = True
        if kind == "unknown" and total is not None and backing_ids:
            kind = "persistent"
        filesystems[ident] = {"id": ident, "source": source, "type": fstype, "mounts": [mount],
                              "total_bytes": total, "available_bytes": available, "used_bytes": used,
                              "read_only": read_only, "kind": kind,
                              "backing_device_ids": backing_ids}
        if kind == "persistent" and not filesystems[ident]["backing_device_ids"]:
            partial = True
    missing = set(capacity_mounts) - {mount for fs in filesystems.values() for mount in fs["mounts"]}
    partial = partial or bool(missing)
    if len(devices) > 256 or len(filesystems) > 512 or any(len(f["mounts"]) > 256 for f in filesystems.values()):
        raise ValueError("storage resource limit")
    return {"devices": devices, "filesystems": list(filesystems.values())}, partial


def systemctl(units, user):
    """Read fixed properties, with bounded pipes; never let a child outlive the probe."""
    args = ["systemctl", "--no-pager", "--no-ask-password"]
    if user:
        args.append("--user")
    args += ["show", "--property=" + ",".join(PROPERTIES), "--", *units]
    child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             close_fds=True)
    output = bytearray()
    deadline = time.monotonic() + 3
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise ValueError("systemd deadline")
                for key, _ in selector.select(max(0, min(0.1, deadline - time.monotonic()))):
                    part = os.read(key.fd, 8192)
                    if not part:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(part)
                        if len(output) > 65536:
                            raise ValueError("systemd output limit")
        child.wait(timeout=max(0.01, deadline - time.monotonic()))
        return parse_units(output.decode("utf-8"), units), child.returncode
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()


def parse_units(output, allowed):
    result = {}
    for block in output.strip().split("\n\n"):
        properties = {}
        for line in block.splitlines():
            key, sep, value = line.partition("=")
            if not sep or key not in PROPERTIES or key in properties or len(value) > 1024:
                raise ValueError("invalid systemd properties")
            properties[key] = value
        ident = properties.get("Id")
        if ident not in allowed or ident in result:
            raise ValueError("systemd identity outside allowlist")
        result[ident] = properties
    return result


def lifecycle(properties, unit):
    if properties.get("LoadState") != "loaded":
        return "unknown"
    active, sub = properties.get("ActiveState"), properties.get("SubState")
    if active == "failed":
        return "failed"
    if active in ("activating", "reloading", "refreshing"):
        return "starting"
    if active == "deactivating":
        return "stopping"
    if active == "active":
        if unit.endswith(".timer"):
            return "idle" if sub in ("waiting", "elapsed") else "unknown"
        return "completed" if sub == "exited" else "running" if sub == "running" else "unknown"
    if active == "inactive":
        return "stopped"
    return "unknown"


def workload(host_id, scope, unit, properties, at):
    digest = hashlib.sha256((scope + "\0" + unit).encode()).hexdigest()[:32]
    return {"id": host_id + ":systemd:" + digest, "host_id": host_id,
            "backend": "systemd", "scope": scope, "native_id": unit, "name": unit,
            "kind": "scheduled-job" if unit.endswith(".timer") else "service",
            "lifecycle": lifecycle(properties, unit), "health": "unknown", "management": "discovered",
            "observed_at": at, "extensions": {"systemd.v1": properties}}


def validate_paseo(config):
    if not isinstance(config, dict) or set(config) != {"listen", "cli"}:
        raise ValueError("Invalid Paseo configuration")
    listen, cli = config["listen"], config["cli"]
    if not isinstance(listen, str) or len(listen) > 256 or any(ord(c) < 33 or ord(c) == 127 for c in listen):
        raise ValueError("Invalid Paseo listen address")
    parsed = urlsplit("http://" + listen)
    try:
        valid = (parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback)
    except (ValueError, TypeError):
        valid = False
    if not valid or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or not parsed.port:
        raise ValueError("Paseo listen must be a loopback host:port")
    if cli is not None and (not isinstance(cli, str) or not cli.startswith("/") or len(cli) > 4096
                            or any(ord(c) < 32 or ord(c) == 127 for c in cli)):
        raise ValueError("Invalid Paseo CLI path")
    return {"listen": listen, "cli": cli}


def paseo_text(value, *, required=False, limit=256):
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
        raise ValueError("Invalid Paseo metadata")
    return value


def paseo_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate Paseo field")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid Paseo JSON")))


def paseo_http(listen, endpoint, deadline):
    # Redirects and environment proxies must never turn this into a remote request.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("Paseo deadline")
    with opener.open("http://" + listen + endpoint, timeout=min(3, remaining)) as response:
        data = bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise ValueError("Paseo deadline")
            part = response.read1(8192)
            if not part:
                break
            data.extend(part)
            if len(data) > 65536:
                raise ValueError("Paseo HTTP output limit")
    return paseo_json(data.decode("utf-8"))


def paseo_command(cli, subcommand, deadline):
    if subcommand not in {"status", "ls"}:
        raise ValueError("Invalid Paseo subcommand")
    deadline = min(deadline, time.monotonic() + 4)
    if deadline <= time.monotonic():
        raise ValueError("Paseo deadline")
    env = dict(os.environ, PATH=str(Path(cli).parent) + ":/usr/bin:/bin")
    child = subprocess.Popen([cli, subcommand, "--json"], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env=env, close_fds=True, start_new_session=True)
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("Paseo deadline")
                for key, _ in selector.select(min(0.1, remaining)):
                    part = os.read(key.fd, 8192)
                    if not part:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(part)
                        if len(output) > 262144:
                            raise ValueError("Paseo CLI output limit")
        if child.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise ValueError("Paseo CLI unavailable")
        return paseo_json(output.decode("utf-8"))
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        child.stdout.close()


def paseo_workload(host_id, scope, daemon, at):
    digest = hashlib.sha256((scope + "\0" + daemon["server_id"]).encode()).hexdigest()[:32]
    return {"id": host_id + ":paseo:" + digest, "host_id": host_id, "backend": "paseo",
            "scope": scope, "native_id": daemon["server_id"], "name": "paseo-daemon",
            "kind": "service", "lifecycle": daemon["state"], "health": "unknown", "management": "discovered",
            "observed_at": at, "extensions": {"paseo.v1": {"version": daemon["version"], "listen": daemon["listen"]}}}


def observe_paseo(config, *, deadline=None):
    config = validate_paseo(config)
    budget = time.monotonic() + (8 if config["cli"] else 3)
    deadline = min(deadline, budget) if deadline is not None else budget
    daemon = dict.fromkeys(("version", "server_id", "hostname", "listen", "started_at", "relay_enabled"))
    daemon.update(state="unknown", providers=[])
    result = {"configured": True, "daemon": daemon, "agents": None, "cli_candidates": []}
    coverage = {"scope": "paseo", "status": "unavailable", "message": "Paseo metadata unavailable"}
    try:
        http_deadline = min(deadline, time.monotonic() + 3)
        status = paseo_http(config["listen"], "/api/status", http_deadline)
        if not isinstance(status, dict) or status.get("status") != "server_info":
            raise ValueError("Invalid Paseo status")
        metadata = {key: paseo_text(status.get(source), required=key == "server_id")
                    for key, source in (("version", "version"), ("server_id", "serverId"),
                                        ("hostname", "hostname"), ("listen", "listen"))}
        daemon.update(metadata)
        health = paseo_http(config["listen"], "/api/health", http_deadline)
        if not isinstance(health, dict) or health.get("status") != "ok":
            raise ValueError("Invalid Paseo health")
        daemon["state"] = "running"
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        reason = getattr(error, "reason", error)
        if isinstance(reason, ConnectionRefusedError) or getattr(reason, "errno", None) == errno.ECONNREFUSED:
            daemon["state"] = "stopped"
        if time.monotonic() >= deadline:
            coverage["message"] = "Paseo probe deadline reached"
        return result, coverage
    coverage.update(status="partial", message="Paseo daemon only; CLI metadata unavailable")
    if config["cli"] is None:
        return result, coverage
    complete = True
    try:
        status = paseo_command(config["cli"], "status", deadline)
        if not isinstance(status, dict) or not isinstance(status.get("providers"), list) or len(status["providers"]) > 64:
            raise ValueError("Invalid Paseo providers")
        providers = []
        for provider in status["providers"]:
            if not isinstance(provider, dict) or type(provider.get("available")) is not bool:
                raise ValueError("Invalid Paseo provider")
            providers.append({"provider": paseo_text(provider.get("provider"), required=True), "available": provider["available"]})
        started = paseo_text(status.get("startedAt"))
        relay = status.get("relay")
        enabled = relay.get("enabled") if isinstance(relay, dict) else None
        if enabled is not None and type(enabled) is not bool:
            raise ValueError("Invalid Paseo relay")
        daemon.update(providers=providers, started_at=started, relay_enabled=enabled)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, RecursionError):
        complete = False
    try:
        agents = paseo_command(config["cli"], "ls", deadline)
        if not isinstance(agents, list):
            raise ValueError("Invalid Paseo agents")
        clean = []
        for agent in agents:
            if not isinstance(agent, dict):
                complete = False
                continue
            if agent.get("status") == "archived" or agent.get("archived") is True:
                continue
            if len(clean) >= 128:
                complete = False
                break
            try:
                clean.append({key: paseo_text(agent.get(source), required=key in {"id", "status"},
                                              limit=1024 if key == "cwd" else 256)
                              for key, source in (("id", "id"), ("short_id", "shortId"), ("name", "name"),
                                                  ("provider", "provider"), ("status", "status"),
                                                  ("cwd", "cwd"), ("created_at", "created"))})
                if len(json.dumps(clean, ensure_ascii=True).encode()) > 65536:
                    clean.pop()
                    complete = False
                    break
            except ValueError:
                complete = False
        if len({agent["id"] for agent in clean}) != len(clean):
            raise ValueError("Duplicate Paseo agent")
        result["agents"] = clean
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, RecursionError):
        complete = False
    if complete:
        coverage.update(status="complete", message="Read-only Paseo metadata")
    if time.monotonic() >= deadline:
        coverage.update(status="partial", message="Paseo probe deadline reached")
    return result, coverage


def paseo_cli_candidates(deadline):
    """Existence checks only: discovering a CLI never authorizes running it."""
    if time.monotonic() >= deadline:
        return []
    home = os.environ.get("HOME", "")
    paths = []
    if home.startswith("/"):
        try:
            for index, path in enumerate((Path(home) / ".nvm/versions/node").glob("*/bin/paseo")):
                if index >= 8 or time.monotonic() >= deadline:
                    break
                paths.append(path)
        except OSError:
            pass
        paths.append(Path(home) / ".local/bin/paseo")
    paths.extend((Path("/usr/local/bin/paseo"), Path("/usr/bin/paseo")))
    candidates = []
    for path in paths:
        if time.monotonic() >= deadline:
            break
        try:
            value = paseo_text(str(path), required=True, limit=1024)
            if path.is_file() and os.access(path, os.X_OK) and value not in candidates:
                candidates.append(value)
        except (OSError, ValueError):
            pass
    return candidates


def discover_paseo(*, deadline):
    deadline = min(deadline, time.monotonic() + 2)
    result = {"configured": False, "daemon": None, "agents": None,
              "cli_candidates": paseo_cli_candidates(deadline)}
    coverage = {"scope": "paseo", "status": "complete", "message": "No Paseo daemon on the default port"}
    if time.monotonic() >= deadline:
        coverage.update(status="unavailable", message="Paseo discovery deadline reached")
        return result, coverage
    try:
        status = paseo_http("127.0.0.1:6767", "/api/status", deadline)
        if not isinstance(status, dict) or status.get("status") != "server_info":
            raise ValueError("Invalid Paseo status")
        daemon = {key: paseo_text(status.get(source), required=key == "server_id")
                  for key, source in (("version", "version"), ("server_id", "serverId"),
                                      ("hostname", "hostname"), ("listen", "listen"))}
        daemon.update(state="running", providers=[], started_at=None, relay_enabled=None)
        result["daemon"] = daemon
        coverage.update(status="partial", message="Paseo daemon found; observation not configured")
    except (OSError, ValueError, UnicodeError, RecursionError):
        pass
    return result, coverage


def observe(config):
    probe_deadline = time.monotonic() + (19.5 if config.get("paseo", {}).get("cli") else 11.5)
    mode = config.get("mode", "full")
    if mode not in {"full", "fast", "storage"}:
        raise ValueError("invalid sampling mode")
    container_deadline = time.monotonic() + 10.5
    if platform.system() != "Linux" or os.geteuid() == 0:
        raise ValueError("unprivileged Linux observer required")
    hostname = platform.node()
    if hostname != config["expected_hostname"]:
        raise ValueError("host identity mismatch")
    for key in ("user_units", "system_units"):
        if not isinstance(config[key], list) or len(config[key]) > 32 or any(not isinstance(u, str) or not UNIT.fullmatch(u) for u in config[key]):
            raise ValueError("invalid allowlist")
    container_probe.validate_engines(config.get("container_engines", []))
    at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    distribution = None
    try:
        for line in text("/etc/os-release", 16384).splitlines():
            if line.startswith("PRETTY_NAME="):
                distribution = line.split("=", 1)[1].strip('"')[:256]
    except (OSError, ValueError, UnicodeError):
        pass
    snapshot = {"schema_version": 1, "host_id": config["host_id"], "observed_at": at, "collector": "linux-v1",
                "host": {"hostname": hostname, "os": "Linux", "distribution": distribution, "architecture": platform.machine()},
                "cpu": dict.fromkeys(("model", "logical_count", "utilization_percent", "sample_seconds", "load_1m")),
                "memory": dict.fromkeys(("total_bytes", "available_bytes", "swap_total_bytes", "swap_free_bytes")),
                "gpus": [], "storage": {"devices": [], "filesystems": []}, "workloads": [], "coverage": [], "warnings": []}
    capacity_mounts = validate_mounts(config.get("storage_mounts", []))
    readers = (("cpu", cpu), ("memory", memory), ("gpus", gpus), ("storage", lambda: storage(capacity_mounts)))
    if mode == "fast":
        readers = (("cpu", cpu_fast), ("memory", memory))
    elif mode == "storage":
        readers = (("storage", lambda: storage(capacity_mounts)),)
    for scope, reader in readers:
        try:
            value = reader()
            partial = False
            if scope == "storage":
                value, partial = value
            elif scope == "cpu":
                partial = value["utilization_percent"] is None
            elif scope == "memory":
                partial = any(v is None for v in value.values())
            snapshot[scope] = value
            snapshot["coverage"].append({"scope": scope, "status": "partial" if partial else "complete",
                                         "message": "Some readings or topology unavailable" if partial else "Read-only metadata"})
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            snapshot["coverage"].append({"scope": scope, "status": "unavailable", "message": "Metadata unavailable"})
    if mode == "storage":
        return snapshot
    for user, units in ((True, config["user_units"]), (False, config["system_units"])):
        scope = "user:" + str(os.getuid()) if user else "system"
        if not units:
            snapshot["coverage"].append({"scope": "systemd:" + scope, "status": "complete", "message": "Empty configured unit allowlist"})
            continue
        try:
            properties, status = systemctl(units, user)
            for unit in units:
                if unit in properties:
                    snapshot["workloads"].append(workload(config["host_id"], scope, unit, properties[unit], at))
            complete = status == 0 and len(properties) == len(units)
            snapshot["coverage"].append({"scope": "systemd:" + scope, "status": "complete" if complete else "partial",
                                         "message": "Configured unit allowlist only" if complete else "Some configured units unavailable"})
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            snapshot["coverage"].append({"scope": "systemd:" + scope, "status": "unavailable", "message": "Configured unit allowlist unavailable"})
    if mode == "full":
        works, images, coverage = container_probe.observe_containers(
            config["host_id"], config.get("container_engines", []), at, deadline=container_deadline)
        snapshot["workloads"].extend(works)
        snapshot["artifacts"] = images
        snapshot["coverage"].extend(coverage)
        if "paseo" in config:
            snapshot["paseo"], coverage = observe_paseo(config["paseo"], deadline=probe_deadline)
        else:
            snapshot["paseo"], coverage = discover_paseo(deadline=probe_deadline)
        snapshot["coverage"].append(coverage)
        daemon = snapshot["paseo"]["daemon"]
        if daemon is not None and daemon["server_id"] is not None:
            snapshot["workloads"].append(paseo_workload(config["host_id"], "user:" + str(os.getuid()), daemon, at))
    return snapshot


def main(config):
    # Terminating the probe unwinds each owned metadata child before exiting.
    def interrupted(signum, frame):
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    signal.signal(signal.SIGALRM, interrupted)
    signal.alarm(20 if config.get("mode", "full") == "full" and config.get("paseo", {}).get("cli") else 12)
    try:
        result = observe(config)
        encoded = json.dumps(result, allow_nan=False, separators=(",", ":"))
        if len(encoded.encode()) > 262144:
            raise ValueError("snapshot limit")
        print(encoded)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        raise SystemExit(1)
