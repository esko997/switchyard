"""Operator-configured, bounded read-only local/SSH observation transport."""
from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time

from .leases import LedgerBroker, LeaseBusy
from .models import Snapshot
from . import container_probe, host_keys, probe
from . import host_context

MAX_STDOUT = 262144
MAX_STDERR = 16384
DEADLINE_SECONDS = 18.0  # leaves up to 1.5 seconds for termination/reaping, within 20s
HOST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
HOSTNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z")
USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")


class CollectionError(RuntimeError):
    """Sanitized collector failure; never includes remote output or local secrets."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _json(data):
    return json.loads(data, object_pairs_hook=_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))


def _canonical(path):
    if not isinstance(path, str) or len(path) > 4096:
        raise ValueError("Invalid ledger path")
    candidate = Path(path)
    if not candidate.is_absolute() or candidate != candidate.resolve(strict=True) or not candidate.is_file():
        raise ValueError("Ledger must be an existing canonical regular file")
    return candidate


def _target(value):
    if not isinstance(value, str) or value.count("@") != 1:
        raise ValueError("SSH requires user@hostname")
    user, host = value.split("@")
    if not USER.fullmatch(user) or user == "root":
        raise ValueError("SSH requires an unprivileged user")
    if ":" in host:
        if not re.fullmatch(r"[0-9A-Fa-f:.]+", host):
            raise ValueError("Invalid SSH literal")
        ipaddress.IPv6Address(host)
    elif not HOSTNAME.fullmatch(host) or ".." in host or host.endswith("."):
        raise ValueError("Invalid SSH hostname")
    # Numeric dotted addresses must be genuine literals, not ambiguous aliases.
    if all(c in "0123456789." for c in host):
        ipaddress.IPv4Address(host)
    return value


def _validate_config(host):
    if isinstance(host, dict) and host.get("transport") == "adb" and "monitor" in host:
        raise ValueError("Android monitoring is not supported")
    if isinstance(host, dict) and host.get("transport") == "adb":
        from .android import validate_config
        return validate_config(host)
    required = {"host_id", "transport", "expected_hostname", "user_units", "system_units"}
    if not isinstance(host, dict) or not required <= host.keys() or host.keys() - required - {"target", "ledger", "container_engines", "monitor", "storage_mounts", "port", "known_hosts", "paseo"}:
        raise ValueError("Invalid collector host fields")
    result = dict(host)
    if not isinstance(host["host_id"], str) or not HOST_ID.fullmatch(host["host_id"]):
        raise ValueError("Invalid host ID")
    hostname = host["expected_hostname"]
    if not isinstance(hostname, str) or not HOSTNAME.fullmatch(hostname) or ".." in hostname:
        raise ValueError("Invalid expected hostname")
    for key in ("user_units", "system_units"):
        units = host[key]
        if not isinstance(units, list) or len(units) > 32 or any(not isinstance(u, str) or not probe.UNIT.fullmatch(u) for u in units):
            raise ValueError("Invalid exact unit allowlist")
        if len(set(units)) != len(units):
            raise ValueError("Duplicate allowlisted unit")
        result[key] = list(units)
    if "container_engines" in host:
        result["container_engines"] = container_probe.validate_engines(host["container_engines"])
    if "storage_mounts" in host:
        result["storage_mounts"] = sorted(probe.validate_mounts(host["storage_mounts"]))
    if "paseo" in host:
        result["paseo"] = probe.validate_paseo(host["paseo"])
    if "monitor" in host:
        intervals = host["monitor"]
        minimums = {"fast_seconds": 10, "storage_seconds": 60, "inventory_seconds": 300}
        if not isinstance(intervals, dict) or set(intervals) != set(minimums):
            raise ValueError("Invalid monitoring intervals")
        if any(type(intervals[key]) is not int or not minimum <= intervals[key] <= 86400
               for key, minimum in minimums.items()):
            raise ValueError("Invalid monitoring interval")
        result["monitor"] = dict(intervals)
    if host["transport"] == "local":
        if host.keys() & {"target", "ledger", "port", "known_hosts"}:
            raise ValueError("Local observation cannot configure SSH/lease fields")
    elif host["transport"] == "ssh":
        result["target"] = _target(host.get("target"))
        port = host.get("port", 22)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid SSH port")
        if "port" in host:
            result["port"] = port
        if "known_hosts" in host:
            path = host["known_hosts"]
            if not isinstance(path, str) or not path.startswith("/") or len(path) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in path):
                raise ValueError("Invalid known_hosts path")
        _canonical(host.get("ledger"))
        # The operator explicitly declares the shared ledger; never infer it
        # from an address or an account name, both of which may change.
    else:
        raise ValueError("Unsupported collector transport")
    return result


def load_config(path: str | Path | None) -> dict[str, dict]:
    if path is None:
        return {}
    try:
        with Path(path).open("rb") as source:
            data = source.read(65537)
        if len(data) > 65536:
            raise ValueError("Collector configuration too large")
        document = _json(data)
        if not isinstance(document, dict) or set(document) != {"schema_version", "hosts"} or type(document["schema_version"]) is not int or document["schema_version"] != 1:
            raise ValueError("Invalid collector configuration")
        hosts = document["hosts"]
        if not isinstance(hosts, list) or len(hosts) > 64:
            raise ValueError("Invalid collector host list")
        result = {}
        for record in hosts:
            # Collector files are registry seeds; discard the retired lease setting.
            if isinstance(record, dict):
                record = {key: value for key, value in record.items() if key != "lease_wrapper"}
            record = _validate_config(record)
            if record["host_id"] in result:
                raise ValueError("Duplicate collector host ID")
            result[record["host_id"]] = record
        return result
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise ValueError("Invalid or unreadable collector configuration") from error


def _probe_source(config, *, mode="full"):
    data = {key: config[key] for key in ("host_id", "expected_hostname", "user_units", "system_units")}
    data["container_engines"] = config.get("container_engines", [])
    data["storage_mounts"] = config.get("storage_mounts", [])
    data["mode"] = mode
    if "paseo" in config:
        data["paseo"] = config["paseo"]
    # A stdlib-only module namespace, composed into the same stdin batch; no install.
    module = Path(container_probe.__file__).read_text()
    prefix = "import types\ncontainer_probe = types.ModuleType('container_probe')\nexec(" + repr(module) + ", container_probe.__dict__)\n"
    # Python literal containing JSON data, not shell or Python fragments supplied by callers.
    return (prefix + Path(probe.__file__).read_text() + "\nmain(json.loads(" + repr(json.dumps(data)) + "))\n").encode()


def _ssh_command(config):
    command = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1", "-o", "ClearAllForwardings=yes",
            "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "PermitLocalCommand=no",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ControlMaster=no",
            "-o", "ControlPath=none", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
            "-o", "RemoteCommand=none", "-o", "SessionType=default",
            "-o", "ControlPersist=no", "-o", "ForkAfterAuthentication=no", "-o", "StdinNull=no"]
    if config.get("known_hosts"):
        command += ["-o", "UserKnownHostsFile=" + config["known_hosts"],
                    "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlias=switchyard-" + config["host_id"]]
    if config.get("port", 22) != 22:
        command += ["-p", str(config["port"])]
    return command + ["--", config["target"], "python3 -I -S -"]


def _stop(child):
    # Terminate the owned transport group, not just its immediate process.
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        # Do not release a device lease with an unreaped owned process.
        child.wait()


def _run(command, source, deadline):
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True, close_fds=True)
    output, errors = bytearray(), bytearray()
    sent = 0
    try:
        with selectors.DefaultSelector() as selector:
            for stream, event in ((child.stdin, selectors.EVENT_WRITE), (child.stdout, selectors.EVENT_READ), (child.stderr, selectors.EVENT_READ)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, event)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CollectionError("Observation deadline exceeded")
                for key, event in selector.select(min(0.1, remaining)):
                    if event == selectors.EVENT_WRITE:
                        try:
                            sent += os.write(key.fd, source[sent:sent + 8192])
                        except BrokenPipeError:
                            sent = len(source)
                        if sent == len(source):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        part = os.read(key.fd, 8192)
                        if not part:
                            selector.unregister(key.fileobj)
                        else:
                            buffer = output if key.fileobj is child.stdout else errors
                            buffer.extend(part)
                            if len(buffer) > (MAX_STDOUT if buffer is output else MAX_STDERR):
                                raise CollectionError("Observation output limit exceeded")
            status = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        return status, bytes(output)
    except subprocess.TimeoutExpired as error:
        raise CollectionError("Observation deadline exceeded") from error
    finally:
        # Also reap/terminate on KeyboardInterrupt, cancellation, decoding failures,
        # output limits and early exit with inherited pipes still held by a child.
        _stop(child)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


def _validate_snapshot(data, config, *, mode="full"):
    try:
        if mode not in {"full", "fast", "storage"}:
            raise ValueError("Invalid sampling mode")
        value = _json(data)
        if not isinstance(value, dict) or type(value.get("schema_version")) is not int:
            raise ValueError("Invalid snapshot schema")
        snapshot = Snapshot.model_validate(value, strict=True).model_dump(mode="json")
        paseo_enabled = mode == "full" and ("paseo" in config or snapshot["paseo"] is not None)
        if paseo_enabled:
            if snapshot["paseo"] is None:
                raise ValueError("Missing Paseo evidence")
            if snapshot["paseo"]["configured"] != ("paseo" in config):
                raise ValueError("Paseo configuration mismatch")
        elif snapshot["paseo"] is not None:
            raise ValueError("Paseo outside configured scope")
        if snapshot["collector"] != "linux-v1" or snapshot["host_id"] != config["host_id"] or snapshot["host"]["hostname"] != config["expected_hostname"] or snapshot["host"]["os"] != "Linux":
            raise ValueError("Identity mismatch")
        if mode == "full" and snapshot["cpu"]["sample_seconds"] is not None and snapshot["cpu"]["sample_seconds"] > 0.25:
            raise ValueError("Sample interval exceeded")
        if mode == "fast":
            cpu_coverage = next((c for c in snapshot["coverage"] if c["scope"] == "cpu"), None)
            if cpu_coverage and cpu_coverage["status"] != "unavailable" and snapshot["cpu"]["counters"] is None:
                raise ValueError("Fast CPU observation requires cumulative counters")
            if snapshot["cpu"]["sample_seconds"] is not None or snapshot["cpu"]["utilization_percent"] is not None:
                raise ValueError("Fast CPU interval must be derived locally")
        allowed_scopes = {"storage"} if mode == "storage" else {"cpu", "memory", "systemd:system"}
        if mode == "full":
            allowed_scopes |= {"gpus", "storage"}
        if paseo_enabled:
            allowed_scopes.add("paseo")
        user_scopes = set()
        for coverage in snapshot["coverage"]:
            scope = coverage["scope"]
            if scope.startswith("systemd:user:") and re.fullmatch(r"systemd:user:[1-9][0-9]{0,9}", scope):
                user_scopes.add(scope.removeprefix("systemd:"))
            elif scope not in allowed_scopes and not any(scope.startswith(engine + ":") for engine in config.get("container_engines", [])):
                raise ValueError("Unexpected coverage scope")
        if mode == "storage":
            if user_scopes or snapshot["workloads"] or snapshot["artifacts"]:
                raise ValueError("Unexpected storage evidence")
            if {c["scope"] for c in snapshot["coverage"]} != {"storage"}:
                raise ValueError("Missing storage scope")
            return snapshot
        if len(user_scopes) != 1:
            raise ValueError("Missing current user scope")
        user_scope = next(iter(user_scopes))
        engine_scopes = {engine: user_scope if engine == "podman" else "system"
                         for engine in config.get("container_engines", [])} if mode == "full" else {}
        allowed_scopes |= {backend + ":" + scope for backend, scope in engine_scopes.items()}
        if {c["scope"] for c in snapshot["coverage"]} != allowed_scopes | {"systemd:" + user_scope}:
            raise ValueError("Missing observation scopes")
        for work in snapshot["workloads"]:
            scope, unit = work["scope"], work["native_id"]
            if work["backend"] in engine_scopes:
                if scope != engine_scopes[work["backend"]] or set(work["extensions"]) != {"container.v1"}:
                    raise ValueError("Container outside configured scope")
                expected = container_probe.workload(config["host_id"], work["backend"], scope, unit, work["name"],
                                                    work["extensions"]["container.v1"], snapshot["observed_at"])
            elif work["backend"] == "paseo" and paseo_enabled:
                daemon = snapshot["paseo"]["daemon"]
                if scope != user_scope or daemon is None or daemon["server_id"] is None:
                    raise ValueError("Paseo outside current user scope")
                expected = probe.paseo_workload(config["host_id"], scope, daemon, snapshot["observed_at"])
            elif work["backend"] == "systemd":
                units = config["system_units"] if scope == "system" else config["user_units"] if scope in user_scopes else []
                properties = work["extensions"].get("systemd.v1", {})
                if unit not in units or set(work["extensions"]) != {"systemd.v1"} or any(k not in probe.PROPERTIES or not isinstance(v, str) or len(v) > 1024 for k, v in properties.items()):
                    raise ValueError("Workload outside configured scope")
                if properties.get("Id") != unit:
                    raise ValueError("Invalid unit identity")
                expected = probe.workload(config["host_id"], scope, unit, properties, snapshot["observed_at"])
            else:
                raise ValueError("Unexpected workload backend")
            if work != expected:
                raise ValueError("Invalid native workload evidence")
        for image in snapshot["artifacts"]:
            backend, scope = image["backend"], image["scope"]
            if backend not in engine_scopes or scope != engine_scopes[backend] or set(image["extensions"]) != {"container.v1"}:
                raise ValueError("Image outside configured scope")
            expected = container_probe.artifact(config["host_id"], backend, scope, image["native_id"],
                                                image["extensions"]["container.v1"], snapshot["observed_at"])
            if image != expected:
                raise ValueError("Invalid image evidence")
        for backend, scope in engine_scopes.items():
            works = [w for w in snapshot["workloads"] if w["backend"] == backend]
            images = [a for a in snapshot["artifacts"] if a["backend"] == backend]
            coverage = next(c for c in snapshot["coverage"] if c["scope"] == backend + ":" + scope)
            if len(works) > container_probe.MAX_CONTAINERS or len(images) > container_probe.MAX_IMAGES or len(json.dumps([works, images]).encode()) > container_probe.MAX_ENGINE_BYTES:
                raise ValueError("Container evidence limit exceeded")
            if coverage["status"] == "unavailable" and (works or images):
                raise ValueError("Unavailable engine contains evidence")
        for coverage in snapshot["coverage"]:
            scope = coverage["scope"].removeprefix("systemd:")
            if scope != "system" and scope not in user_scopes:
                continue
            expected_units = set(config["system_units"] if scope == "system" else config["user_units"])
            observed_units = {w["native_id"] for w in snapshot["workloads"] if w["backend"] == "systemd" and w["scope"] == scope}
            if coverage["status"] == "complete" and observed_units != expected_units:
                raise ValueError("Complete scope omitted configured units")
            if coverage["status"] == "unavailable" and observed_units:
                raise ValueError("Unavailable scope contains observations")
        if paseo_enabled:
            daemon = snapshot["paseo"]["daemon"]
            works = [work for work in snapshot["workloads"] if work["backend"] == "paseo"]
            coverage = next(c for c in snapshot["coverage"] if c["scope"] == "paseo")
            if len(works) != (1 if daemon is not None and daemon["server_id"] is not None else 0):
                raise ValueError("Missing Paseo workload")
            if "paseo" in config:
                if daemon is None or snapshot["paseo"]["cli_candidates"]:
                    raise ValueError("Invalid configured Paseo metadata")
                if coverage["status"] == "complete" and (daemon["state"] != "running" or snapshot["paseo"]["agents"] is None):
                    raise ValueError("Incomplete Paseo metadata")
            elif coverage["status"] != ("complete" if daemon is None else "partial"):
                raise ValueError("Invalid Paseo discovery coverage")
            if ("paseo" not in config or config["paseo"]["cli"] is None) and (
                    snapshot["paseo"]["agents"] is not None or daemon is not None and (
                        daemon["providers"] or daemon["started_at"] is not None or daemon["relay_enabled"] is not None)):
                raise ValueError("Unconfigured Paseo CLI metadata")
        return snapshot
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
        raise CollectionError("Invalid observation response") from error


def _receipt(ledger, config, outcome):
    fd = os.open(ledger, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        record = {"at": datetime.now(timezone.utc).isoformat(), "event": "OBSERVATION",
                  "host_id": config["host_id"], "collector": "linux-v1", "outcome": outcome,
                  "scope": "read-only configured resource metadata and systemd allowlists; no changes"}
        encoded = (json.dumps(record) + "\n").encode()
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("receipt append failed")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _apply_cpu_delta(snapshot, previous):
    """Compare only validated counters from the same boot; never sleep."""
    current = snapshot["cpu"].get("counters")
    old = (previous or {}).get("cpu", {}).get("counters")
    snapshot["cpu"]["sample_seconds"] = None
    snapshot["cpu"]["utilization_percent"] = None
    if current and old and current["boot_id"] == old["boot_id"]:
        duration = current["uptime_seconds"] - old["uptime_seconds"]
        total = current["total_ticks"] - old["total_ticks"]
        idle = current["idle_ticks"] - old["idle_ticks"]
        if duration > 0 and total > 0 and 0 <= idle <= total:
            snapshot["cpu"]["sample_seconds"] = duration
            snapshot["cpu"]["utilization_percent"] = 100 * (total - idle) / total
            for coverage in snapshot["coverage"]:
                if coverage["scope"] == "cpu":
                    coverage.update(status="complete", message="CPU counters across consecutive observations")
    return Snapshot.model_validate(snapshot).model_dump()


def collect_host(config: dict, *, mode="full", previous=None) -> dict:
    started = time.monotonic()
    try:
        if mode not in {"full", "fast", "storage"}:
            raise ValueError("Invalid sampling mode")
        config = _validate_config(config)
        if config["transport"] == "adb":
            if mode != "full":
                raise ValueError("Android supports manual full observation only")
            from .android import collect_host as collect_android
            return collect_android(config)
        source = _probe_source(config, mode=mode)
        if config["transport"] == "ssh":
            command = _ssh_command(config)
            lease = LedgerBroker({config["host_id"]: Path(config["ledger"])}).hold(
                config["host_id"], owner="switchyard", scope="read-only observation; configured unit allowlists",
                worktree=str(Path(__file__).resolve().parents[1]))
        else:
            command = None
            lease = nullcontext()
        with lease:
            outcome = "failed"
            try:
                extended = mode == "full" and bool(config.get("paseo", {}).get("cli"))
                budget = 26.0 if extended else DEADLINE_SECONDS
                if command is None:
                    with host_context.execution(source, timeout=budget) as (local_command, local_source):
                        status, output = _run(local_command, local_source, started + budget)
                else:
                    status, output = _run(command, source, started + budget)
                if status != 0:
                    raise CollectionError("Observation transport or probe failed")
                snapshot = _validate_snapshot(output, config, mode=mode)
                if mode == "fast":
                    snapshot = _apply_cpu_delta(snapshot, previous)
                outcome = {"observed_at": snapshot["observed_at"], "coverage": snapshot["coverage"],
                           "snapshot_sha256": hashlib.sha256(output).hexdigest()}
                return snapshot
            finally:
                if config["transport"] == "ssh":
                    _receipt(config["ledger"], config, outcome)
    except (CollectionError, LeaseBusy):
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        raise CollectionError("Observation configuration or transport unavailable") from error


def scan_host_key(config, *, address, port):
    """Scan under the collection lease; returned public keys are not trusted."""
    started = time.monotonic()
    try:
        config = _validate_config(config)
        if config["transport"] != "ssh":
            raise ValueError("Host key scans require SSH")
        user, configured_address = config["target"].split("@", 1)
        _target(user + "@" + address)
        if address != configured_address or type(port) is not int or port != config.get("port", 22):
            raise ValueError("Host key scan must match the configured target and port")
        command = ["ssh-keyscan", "-T", "5", "-p", str(port), "-t", "ed25519,ecdsa,rsa", address]
        source = b""
        lease = LedgerBroker({config["host_id"]: Path(config["ledger"])}).hold(
            config["host_id"], owner="switchyard", scope="read-only host-key scan; no trust granted",
            worktree=str(Path(__file__).resolve().parents[1]))
        with lease:
            status, output = _run(command, source, started + 8)
            if status != 0:
                raise CollectionError("Host key scan unavailable")
            keys = host_keys.parse_keys(output.decode("utf-8"))
            if not keys or len(keys) > 32:
                raise CollectionError("Host key scan returned no usable identity")
            return {"keys": keys, "fingerprints": [host_keys.fingerprint(key) for key in keys]}
    except (CollectionError, LeaseBusy):
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        raise CollectionError("Host key scan configuration or transport unavailable") from error
