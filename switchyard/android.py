"""Passive, exact-allowlist Android observation over an existing local ADB server.

android.v1 contains only package, user_id, package_uid, version_name,
version_code, process_names, process_uids and limitations. Installed artifacts
are not execution evidence. Neither process presence nor installation measures
health, persistence, private data or cold-migration eligibility.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import socket
import subprocess
import time

from .collector import CollectionError, _stop
from .leases import LedgerBroker, LeaseBusy
from . import locks
from .models import Snapshot

SDK_ADB = Path(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
               or Path.home() / "Android/Sdk") / "platform-tools/adb"
USB_SERIAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
MAX_STDOUT = 65536
MAX_STDERR = 4096
MAX_PROCESSES = 128
DEADLINE_SECONDS = 18.0  # reserves cleanup/receipt time inside the 20-second budget
PACKAGE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\Z")
HOST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
PROPERTIES = {"ro.product.model", "ro.build.version.release", "ro.product.cpu.abi", "ro.soc.model"}
LIMITATIONS = [
    "Process presence is a sample, not application health or persistence.",
    "Custom-name and isolated-UID processes cannot be attributed by this observation.",
    "Signing, private data and cold-migration eligibility were not inspected.",
]


def validate_config(config: dict) -> dict:
    required = {"host_id", "transport", "expected_hostname", "serial", "ledger", "user_id", "packages"}
    if not isinstance(config, dict) or set(config) != required:
        raise ValueError("Invalid Android collector fields")
    if not isinstance(config["host_id"], str) or not HOST_ID.fullmatch(config["host_id"]):
        raise ValueError("Invalid host ID")
    serial = config["serial"]
    if config["transport"] != "adb" or not isinstance(serial, str) or not USB_SERIAL.fullmatch(serial):
        raise ValueError("Android observation requires an explicit shell-safe USB serial")
    if config["expected_hostname"] != serial:
        raise ValueError("Expected Android identity must equal its immutable USB serial")
    if type(config["user_id"]) is not int or config["user_id"] != 0:
        raise ValueError("Only Android user 0 is supported")
    ledger = config["ledger"]
    label = re.sub(r"[^A-Z0-9]", "", config["host_id"].upper())
    required_ledger = locks.DEFAULT_LEDGER_DIR.resolve() / f"DEVICE_ACCESS_{label}.md"
    if not isinstance(ledger, str) or ledger != str(required_ledger):
        raise ValueError("Android device requires its canonical ledger")
    path = Path(ledger)
    if not path.is_absolute() or path != path.resolve(strict=True) or not path.is_file():
        raise ValueError("Android ledger must be an existing canonical regular file")
    packages = config["packages"]
    if (not isinstance(packages, list) or len(packages) > 16
            or any(not isinstance(p, str) or len(p) > 255 or not PACKAGE.fullmatch(p) for p in packages)
            or len(set(packages)) != len(packages)):
        raise ValueError("Invalid exact Android package allowlist")
    return {**config, "packages": list(packages)}


# Only this fixed script is accepted. Package dumps are reduced ON DEVICE to a
# version-name token; package/process output crosses the boundary only as exact
# whitelisted fields. Every substantive command has an independent status (the
# optional version-name dump cannot turn a failed inventory into an empty one).
_SCRIPT = r'''printf 'switchyard-android-v1\n'
identity=$(getprop ro.serialno 2>/dev/null) || exit 10
printf 'identity\t%s\n' "$identity"
[ "$identity" = @SERIAL@ ] || exit 11
for key in ro.product.model ro.build.version.release ro.product.cpu.abi ro.soc.model; do
    value=$(getprop "$key" 2>/dev/null)
    printf 'property\t%s\t%s\n' "$key" "$value"
done
count=$(getconf _NPROCESSORS_ONLN 2>/dev/null)
case "$count" in ''|*[!0-9]*) printf 'cpu\tunavailable\n';; *) printf 'cpu\t%s\n' "$count";; esac
awk '($1=="MemTotal:" || $1=="MemAvailable:" || $1=="SwapTotal:" || $1=="SwapFree:") && $2 ~ /^[0-9]+$/ && $3=="kB" {key=$1; sub(/:$/, "", key); printf "memory\t%s\t%s\n",key,$2}' /proc/meminfo 2>/dev/null
mounts=$(awk '$2=="/data" {printf "mount\t%s\t%s\t%s\n",$1,$3,($4 ~ /(^|,)ro(,|$)/ ? "ro" : "rw")}' /proc/mounts 2>/dev/null)
printf '%s\n' "$mounts"
capacity=$(df -k /data 2>/dev/null)
if [ "$?" -eq 0 ]; then
    printf '%s\n' "$capacity" | awk 'NR>1 && NF>=6 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ {printf "capacity\t%s\t%s\t%s\t%s\n",$1,$2,$3,$4}'
fi
set -- @PACKAGES@
for p do
    inventory=$(cmd package list packages --user 0 -U --show-versioncode "$p" 2>/dev/null)
    if [ "$?" -ne 0 ]; then
        printf 'package\t%s\tunavailable\n' "$p"
        continue
    fi
    row=$(printf '%s\n' "$inventory" | awk -v target="$p" '
        NF {if ($1 !~ /^package:/) {bad=1; next}; name=substr($1,9); uid=""; version="";
            for(i=2;i<=NF;i++) {if ($i ~ /^uid:[0-9]+$/) uid=substr($i,5); else if ($i ~ /^versionCode:[0-9]+$/) version=substr($i,13); else bad=1}
            if(name==target) {count++; if(uid=="" || version=="") bad=1; result="present\t"uid"\t"version}}
        END {if(bad || count>1) print "unavailable"; else if(count==1) print result; else print "absent"}')
    printf 'package\t%s\t%s\n' "$p" "$row"
    case "$row" in present*)
        dumpsys package "$p" 2>/dev/null | awk -v target="$p" '
            /^[[:space:]]*Package \[/ {inside=($2=="["target"]")}
            inside && /^[[:space:]]*versionName=/ && !seen {seen=1; sub(/^[[:space:]]*versionName=/, "");
                if(length($0)>0 && length($0)<=128 && $0 ~ /^[A-Za-z0-9._+~() -]+$/) printf "version\t%s\t%s\n",target,$0}'
    ;; esac
done
processes=$(ps -A -n -o UID,NAME 2>/dev/null)
if [ "$?" -eq 0 ]; then
    printf '%s\n' "$processes" | awk -v wanted=@PACKAGE_TEXT@ '
        BEGIN {n=split(wanted, names, " "); for(i=1;i<=n;i++) allowed[names[i]]=1}
        NR==1 {if(NF!=2 || $1!="UID" || $2!="NAME") bad=1; next}
        {base=$2; sub(/:.*/, "",base); if(allowed[base]) {
            if(NF!=2 || $1 !~ /^[0-9]+$/) {bad=1; next}
            if($1+0>=100000) next;
            count++; if(count<=128) printf "process\t%s\t%s\n",$1,$2}}
        END {if(bad) print "process_status\tunavailable"; else if(count>128) print "process_status\tpartial"; else print "process_status\tcomplete"}'
else
    printf 'process_status\tunavailable\n'
fi
printf 'end\n'
'''


def _command(config):
    if (not SDK_ADB.is_absolute() or SDK_ADB != SDK_ADB.resolve(strict=True)
            or not SDK_ADB.is_file() or not os.access(SDK_ADB, os.X_OK)):
        raise ValueError("Android observation requires an existing canonical SDK platform-tools/adb executable")
    script = (_SCRIPT.replace("@SERIAL@", shlex.quote(config["serial"]))
              .replace("@PACKAGES@", " ".join(shlex.quote(p) for p in config["packages"]))
              .replace("@PACKAGE_TEXT@", shlex.quote(" ".join(config["packages"]))))
    # Explicit -H selects a remote-server client: it refuses a missing server
    # instead of starting one. Loopback is fixed, never a configurable target.
    return [str(SDK_ADB), "-s", config["serial"], "-H", "127.0.0.1", "-P", "5037",
            "shell", "-T", "-n", "sh", "-c", shlex.quote(script)]


def _existing_server(deadline):
    """Read-only smart-socket preflight, no adb discovery/start/version repair."""
    def receive(stream, count):
        result = b""
        while len(result) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CollectionError("Android observation deadline exceeded")
            stream.settimeout(min(0.5, remaining))
            part = stream.recv(count - len(result))
            if not part:
                raise CollectionError("Existing compatible local ADB server required")
            result += part
        return result

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CollectionError("Android observation deadline exceeded")
    try:
        with socket.create_connection(("127.0.0.1", 5037), timeout=min(0.5, remaining)) as stream:
            stream.sendall(b"000chost:version")
            # SDK v37 uses smart-socket protocol 41. Never let adb repair a
            # mismatched server (which would kill/restart shared connections).
            if receive(stream, 4) != b"OKAY" or receive(stream, 4) != b"0004" or receive(stream, 4) != b"0029":
                raise CollectionError("Existing compatible local ADB server required")
    except OSError as error:
        raise CollectionError("Existing compatible local ADB server required") from error


def _run(command, deadline):
    # Do not inherit alternate server sockets, tracing, serial selectors, key
    # configuration or startup hooks from the caller's environment.
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "LANG": "C", "LC_ALL": "C"}
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=environment, start_new_session=True, close_fds=True)
    output, errors = bytearray(), bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CollectionError("Android observation deadline exceeded")
                for key, _ in selector.select(min(0.1, remaining)):
                    part = os.read(key.fd, 8192)
                    if not part:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = output if key.fileobj is child.stdout else errors
                    buffer.extend(part)
                    if len(buffer) > (MAX_STDOUT if buffer is output else MAX_STDERR):
                        raise CollectionError("Android observation output limit exceeded")
            return child.wait(timeout=max(0.001, deadline - time.monotonic())), bytes(output)
    except subprocess.TimeoutExpired as error:
        raise CollectionError("Android observation deadline exceeded") from error
    finally:
        _stop(child)  # terminates/reaps the owned process group before receipt/unlock
        child.stdout.close()
        child.stderr.close()


def _number(value, maximum=(1 << 63) - 1):
    if not re.fullmatch(r"[0-9]{1,19}", value) or int(value) > maximum:
        raise ValueError("Invalid Android counter")
    return int(value)


def _metadata(value, limit=256):
    if len(value) > limit or any(ord(c) < 32 or ord(c) > 126 for c in value):
        raise ValueError("Invalid Android metadata")
    return value or None


def _id(host_id, backend, package):
    digest = hashlib.sha256(json.dumps([host_id, backend, "user:0", package]).encode()).hexdigest()
    return "android-" + digest[:48]


def _snapshot(output, config):
    """Reject unknown/raw payloads; only normalize the fixed on-device protocol."""
    try:
        if len(output) > MAX_STDOUT:
            raise ValueError("Android response limit")
        lines = output.decode("utf-8", errors="strict").splitlines()
        if not lines or lines[0] != "switchyard-android-v1" or lines[-1] != "end":
            raise ValueError("Incomplete Android response")
        properties, memory, packages, versions = {}, {}, {}, {}
        processes, mounts, capacities = [], [], []
        identity = cpu_count = process_status = None
        for line in lines[1:-1]:
            if not line:  # unavailable optional mount data produces an empty line
                continue
            fields = line.split("\t")
            tag = fields[0]
            if tag == "identity" and len(fields) == 2 and identity is None:
                identity = fields[1]
            elif tag == "property" and len(fields) == 3 and fields[1] in PROPERTIES and fields[1] not in properties:
                properties[fields[1]] = _metadata(fields[2])
            elif tag == "cpu" and len(fields) == 2 and cpu_count is None:
                cpu_count = fields[1] if fields[1] == "unavailable" else _number(fields[1], 4096)
                if cpu_count == 0:
                    raise ValueError("Invalid CPU count")
            elif tag == "memory" and len(fields) == 3 and fields[1] in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"} and fields[1] not in memory:
                memory[fields[1]] = _number(fields[2], ((1 << 63) - 1) // 1024) * 1024
            elif tag == "mount" and len(fields) == 4 and not mounts:
                if not re.fullmatch(r"/dev/block/[A-Za-z0-9_./-]{1,200}", fields[1]) or not re.fullmatch(r"[a-z0-9_]{1,32}", fields[2]) or fields[3] not in {"ro", "rw"}:
                    raise ValueError("Invalid data mount")
                mounts.append(fields[1:])
            elif tag == "capacity" and len(fields) == 5 and not capacities:
                if not re.fullmatch(r"/dev/block/[A-Za-z0-9_./-]{1,200}", fields[1]):
                    raise ValueError("Invalid data capacity")
                capacities.append([fields[1], *(_number(v, ((1 << 63) - 1) // 1024) * 1024 for v in fields[2:])])
            elif tag == "package" and fields[1:2] and fields[1] in config["packages"] and fields[1] not in packages:
                if len(fields) == 3 and fields[2] in {"absent", "unavailable"}:
                    packages[fields[1]] = {"status": fields[2]}
                elif len(fields) == 5 and fields[2] == "present":
                    packages[fields[1]] = {"status": "present", "uid": _number(fields[3], 99999), "version": _number(fields[4])}
                else:
                    raise ValueError("Invalid package record")
            elif tag == "version" and len(fields) == 3 and fields[1] in config["packages"] and fields[1] not in versions:
                if not re.fullmatch(r"[A-Za-z0-9._+~() -]{1,128}", fields[2]):
                    raise ValueError("Invalid version name")
                versions[fields[1]] = fields[2]
            elif tag == "process" and len(fields) == 3 and len(processes) < MAX_PROCESSES:
                name = fields[2]
                if name.partition(":")[0] not in config["packages"] or not re.fullmatch(r"[A-Za-z0-9_.]+(?::[A-Za-z0-9_.-]+)?", name) or len(name) > 383:
                    raise ValueError("Process outside configured packages")
                processes.append((_number(fields[1], (1 << 31) - 1), name))
            elif tag == "process_status" and len(fields) == 2 and process_status is None and fields[1] in {"complete", "partial", "unavailable"}:
                process_status = fields[1]
            else:
                raise ValueError("Unknown Android protocol field")
        if identity != config["expected_hostname"] or identity != config["serial"]:
            raise ValueError("Android identity mismatch")
        if set(properties) != PROPERTIES or cpu_count is None or process_status is None or set(packages) != set(config["packages"]):
            raise ValueError("Incomplete Android protocol")
        if any(packages[p]["status"] != "present" for p in versions):
            raise ValueError("Version without installed package")
        if memory.get("MemAvailable", 0) > memory.get("MemTotal", 0) or memory.get("SwapFree", 0) > memory.get("SwapTotal", 0):
            raise ValueError("Inconsistent Android memory")
        at = datetime.now(timezone.utc).isoformat()
        coverage = []
        def scope(name, status, message):
            coverage.append({"scope": name, "status": status, "message": message, "observed_at": at})
        scope("host", "complete" if all(properties.get(k) for k in PROPERTIES - {"ro.soc.model"}) else "partial", "USB serial verified; fixed model, Android release and ABI properties only.")
        scope("cpu", "unavailable" if cpu_count == "unavailable" else "complete", "Static CPU count/SoC only; utilization and available CPU capacity unknown.")
        scope("memory", "complete" if len(memory) == 4 else "unavailable", "Selected /proc/meminfo counters only; missing counters preserve prior resource evidence.")
        scope("gpus", "unavailable", "No passive GPU telemetry collected; GPU inventory and capacity unknown.")
        filesystems = []
        if mounts and capacities and mounts[0][0] == capacities[0][0]:
            source, total, used, available = capacities[0]
            if total <= 0 or used > total or available > total or used + available > total:
                raise ValueError("Inconsistent Android storage")
            filesystems.append({"id": "android-data", "source": source, "type": mounts[0][1], "mounts": ["/data"],
                                "total_bytes": total, "available_bytes": available, "used_bytes": used,
                                "read_only": mounts[0][2] == "ro", "kind": "persistent", "backing_device_ids": []})
        scope("storage", "complete" if filesystems else "unavailable", "One /data backing pool only; emulated views excluded and physical media unknown.")
        artifacts, workloads = [], []
        for package, record in packages.items():
            if record["status"] != "present":
                continue
            extension = {"package": package, "user_id": 0, "package_uid": record["uid"],
                         "version_name": versions.get(package), "version_code": record["version"],
                         "limitations": list(LIMITATIONS)}
            if package not in versions:
                extension["limitations"].append("Version name unavailable; package-manager version code observed.")
            artifacts.append({"id": _id(config["host_id"], "android-package", package), "host_id": config["host_id"],
                              "backend": "android-package", "scope": "user:0", "native_id": package, "name": package,
                              "kind": "package", "observed_at": at, "extensions": {"android.v1": extension}})
            matching = sorted({(uid, name) for uid, name in processes if name.partition(":")[0] == package and uid == record["uid"] and uid // 100000 == 0})
            if process_status != "unavailable" and matching:
                runtime = {**extension, "process_names": sorted({name for _, name in matching}),
                           "process_uids": sorted({uid for uid, _ in matching})}
                workloads.append({"id": _id(config["host_id"], "android", package), "host_id": config["host_id"],
                                  "backend": "android", "scope": "user:0", "native_id": package, "name": package,
                                  "kind": "application", "lifecycle": "running", "health": "unknown", "management": "discovered",
                                  "observed_at": at, "extensions": {"android.v1": runtime}})
        missing = sum(record["status"] == "unavailable" for record in packages.values())
        scope("android-package:user:0", "unavailable" if packages and missing == len(packages) else "partial" if missing else "complete", "Exact configured user-0 package presence/UID/version-code inventory; installation is not running.")
        # A shell process sample cannot disprove custom-name/isolated execution.
        # Never erase old active evidence solely because a package is absent from ps.
        scope("android:user:0", "unavailable" if process_status == "unavailable" else "partial", "Matching package NAME and package-manager UID establish sampled execution only; absent processes remain unknown.")
        snapshot = {"schema_version": 1, "host_id": config["host_id"], "observed_at": at, "collector": "android-v1",
                    "host": {"hostname": identity, "os": "Android", "distribution": " ".join(v for v in (properties["ro.product.model"], "Android", properties["ro.build.version.release"]) if v),
                             "architecture": properties["ro.product.cpu.abi"] or "unknown"},
                    "cpu": {"model": properties["ro.soc.model"], "logical_count": None if cpu_count == "unavailable" else cpu_count,
                            "utilization_percent": None, "sample_seconds": None, "load_1m": None},
                    "memory": dict(zip(("total_bytes", "available_bytes", "swap_total_bytes", "swap_free_bytes"),
                                       (memory.get(k) for k in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree")))),
                    "gpus": [], "storage": {"devices": [], "filesystems": filesystems}, "workloads": workloads,
                    "artifacts": artifacts, "coverage": coverage, "warnings": list(LIMITATIONS)}
        snapshot["resource_observed_at"] = {entry["scope"]: at for entry in coverage if entry["scope"] in {"host", "cpu", "memory", "storage"} and entry["status"] != "unavailable"}
        return Snapshot.model_validate(snapshot, strict=True).model_dump(mode="json")
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
        raise CollectionError("Invalid Android observation response") from error


def _receipt(config, lease, inode, outcome):
    fd = os.open(config["ledger"], os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != inode:
            raise CollectionError("Android ledger inode changed")
        record = {"at": datetime.now(timezone.utc).isoformat(), "event": "OBSERVATION", "collector": "android-v1",
                  "host_id": config["host_id"], "serial": config["serial"], "lease_id": lease["lease_id"],
                  "scope": "read-only fixed metadata and configured user-0 package/process fields; no device changes",
                  "outcome": outcome}
        view = memoryview((json.dumps(record) + "\n").encode())
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("receipt append failed")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def collect_host(config: dict) -> dict:
    deadline = time.monotonic() + DEADLINE_SECONDS
    try:
        config = validate_config(config)
        broker = LedgerBroker({config["host_id"]: Path(config["ledger"])})
        with broker.hold(config["host_id"], owner="switchyard", scope="passive Android metadata; configured user-0 packages only",
                         worktree=str(Path(__file__).resolve().parents[1])) as lease:
            opened = os.stat(config["ledger"], follow_symlinks=False)
            outcome = "failed"
            try:
                _existing_server(deadline)
                status, output = _run(_command(config), deadline)
                if status != 0:
                    raise CollectionError("Android observation transport or probe failed")
                snapshot = _snapshot(output, config)
                encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
                outcome = {"observed_at": snapshot["observed_at"], "coverage": snapshot["coverage"],
                           "snapshot_sha256": hashlib.sha256(encoded).hexdigest()}
                return snapshot
            finally:
                _receipt(config, lease, (opened.st_dev, opened.st_ino), outcome)
    except (CollectionError, LeaseBusy):
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        raise CollectionError("Android observation configuration or transport unavailable") from error
