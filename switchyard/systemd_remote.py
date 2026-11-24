"""Fixed, stdlib-only lifecycle adapter for explicitly adopted systemd services.

Only systemctl owns lifecycle, including for Quadlet. Inspection never returns unit
contents or diagnostics. Dependency checks intentionally fail closed: this is not
a general transaction planner, and unsafe/unknown unit shapes remain inspectable.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import shlex
import signal
import stat
import subprocess
import time


LIMIT = 262144
MAX_UNITS = 128
MAX_RELATIONS = 512
TOTAL_SECONDS = 85
UNIT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,230}\.service\Z")
NATIVE_UNIT = re.compile(r"(?:[A-Za-z0-9_.:@-]|\\x[0-9a-f]{2})+\Z")
ACTIONS = ("start", "stop", "restart")
FORWARD = ("Requires", "Wants", "Requisite", "BindsTo", "Upholds")
PROPAGATION = ("RequiredBy", "RequisiteOf", "BoundBy", "ConsistsOf",
               "PropagatesStopTo", "StopPropagatedFrom", "PartOf",
               "UpheldBy", "OnFailure", "OnSuccess", "Triggers", "TriggeredBy")
RELATIONS = FORWARD + PROPAGATION + ("Conflicts", "ConflictedBy", "Before", "After")
COMMON = ("Id", "Names", "LoadState", "ActiveState", "SubState", "FragmentPath",
          "SourcePath", "DropInPaths", "NeedDaemonReload", "Transient", "Job",
          "StopWhenUnneeded", "RefuseManualStart", "RefuseManualStop", "Following") + RELATIONS
SERVICE = ("Type", "RemainAfterExit", "Result", "InvocationID", "ExecMainCode",
           "ExecMainStatus", "CanStart", "CanStop", "Restart", "NRestarts",
           "SuccessAction", "FailureAction", "StartLimitAction", "BusName")
STATE_FIELDS = ("ActiveState", "SubState", "Job", "Result", "InvocationID",
                "ExecMainCode", "ExecMainStatus", "NRestarts")
GENERATORS = (
    "/usr/lib/systemd/system-generators/podman-system-generator",
    "/usr/lib/systemd/user-generators/podman-user-generator",
    "/usr/lib/systemd/user-generators/podman-system-generator",
    "/lib/systemd/system-generators/podman-system-generator",
    "/lib/systemd/user-generators/podman-user-generator",
)


class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def boot_id():
    fd = os.open("/proc/sys/kernel/random/boot_id", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        value = os.read(fd, 65).decode("ascii").strip()
    finally:
        os.close(fd)
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value),
            "Unsupported native boot identity")
    return value


def environment():
    """Never inherit manager/transport/pager redirection or arbitrary PATH."""
    user = pwd.getpwuid(os.getuid())
    return {"PATH": "/usr/bin:/bin", "HOME": user.pw_dir, "USER": user.pw_name,
            "LOGNAME": user.pw_name, "LANG": "C", "LC_ALL": "C",
            "XDG_RUNTIME_DIR": "/run/user/" + str(os.getuid()),
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/" + str(os.getuid()) + "/bus",
            "SYSTEMD_PAGER": "cat", "SYSTEMD_PAGERSECURE": "1", "SYSTEMD_COLORS": "0"}


def command(scope, args, deadline):
    remaining = deadline - time.monotonic()
    require(remaining > 0, "Remote lifecycle deadline exceeded")
    process = subprocess.Popen(
        ["/usr/bin/systemctl", "--" + scope, "--no-ask-password", "--no-pager", *args],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment(), start_new_session=True)
    output = bytearray()
    size = 0
    try:
        streams = [process.stdout, process.stderr]
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refusal("systemctl deadline exceeded")
            ready = select.select(streams, [], [], remaining)[0]
            require(ready, "systemctl deadline exceeded")
            for stream in ready:
                chunk = os.read(stream.fileno(), 16384)
                if not chunk:
                    streams.remove(stream)
                    continue
                size += len(chunk)
                require(size <= LIMIT, "systemctl response exceeds inspection bound")
                if stream is process.stdout:
                    output.extend(chunk)
        code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        require(code == 0, "systemctl command failed (diagnostics withheld)")
        return output.decode("utf-8", "strict")
    finally:
        if process.poll() is None:
            # Only our CLI/process group, never the manager job. Its uncertain
            # outcome must be reconciled by a separate explicit inspection.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
        process.stdout.close()
        process.stderr.close()


def properties(scope, names, deadline, unit=None):
    args = ["show", "--all", "--property=" + ",".join(names)]
    if unit is not None:
        args += ["--", unit]
    text = command(scope, args, deadline)
    result = {}
    for line in text.splitlines():
        require("=" in line, "Unsupported systemctl property encoding")
        key, value = line.split("=", 1)
        require(key in names and key not in result and len(value) <= 32768,
                "Unsupported systemctl property response")
        require(not any(ord(c) < 32 or ord(c) == 127 for c in value),
                "Unsupported control characters in unit properties")
        result[key] = value
    require(set(result) == set(names), "Unsupported systemd properties; upgrade or use a supported manager")
    return result


def words(value):
    # systemctl quotes and doubles backslashes in escaped desktop unit names.
    # Keep the native \xHH spelling; never decode it into path characters.
    result = shlex.split(value)
    require(len(result) <= MAX_RELATIONS and all(len(x) <= 255 and NATIVE_UNIT.fullmatch(x) for x in result),
            "Unsupported dependency names or dependency count")
    return sorted(set(result))


def file_record(path, *, executable=False):
    require(isinstance(path, str) and path.startswith("/") and len(path) <= 4096
            and not any(c.isspace() or ord(c) < 32 for c in path),
            "Unsupported definition path")
    # Resolve vendor /lib aliases, but pin both the manager's path and its target.
    resolved = Path(path).resolve(strict=True)
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        maximum = 64 * 1024 * 1024 if executable else LIMIT
        require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid())
                and not info.st_mode & 0o022 and 0 < info.st_size <= maximum,
                "Unsafe or oversized definition file")
        if executable:
            require(info.st_uid == 0 and info.st_mode & 0o111,
                    "Unsupported Quadlet generator ownership")
        body, digest, size = bytearray(), hashlib.sha256(), 0
        while size <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
            if not executable:
                body.extend(chunk)
        after = os.fstat(fd)
        require(size <= maximum and (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "Definition changed while reading")
        require(str(Path(path).resolve(strict=True)) == str(resolved), "Definition symlink changed")
        return {"path": path, "resolved_path": str(resolved),
                "sha256": digest.hexdigest()}, bytes(body), info.st_mtime_ns
    finally:
        os.close(fd)


def quadlet_roots(scope):
    if scope == "system":
        return [Path(x) for x in ("/run/containers/systemd", "/etc/containers/systemd",
                                 "/usr/share/containers/systemd")]
    uid = str(os.getuid())
    return [Path("/run/user") / uid / "containers/systemd",
            Path(pwd.getpwuid(os.getuid()).pw_dir) / ".config/containers/systemd",
            Path("/etc/containers/systemd/users") / uid,
            Path("/etc/containers/systemd/users"),
            Path("/usr/share/containers/systemd/users") / uid,
            Path("/usr/share/containers/systemd/users")]


def sections(body):
    """Small deliberately restricted reader, not a replacement systemd parser."""
    result, section = {}, None
    for line in body.decode("utf-8", "strict").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        require(not line.endswith("\\"), "Unsupported Quadlet continuation syntax")
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            result.setdefault(section, [])
        else:
            require(section is not None and "=" in line, "Unsupported Quadlet syntax")
            key, value = line.split("=", 1)
            result[section].append([key.strip(), value.strip()])
    return result


def quadlet_identity(config, unit, fragment, body, fragment_mtime):
    source = unit["SourcePath"]
    require(source.endswith(".container") and "@" not in source
            and Path(source).stem + ".service" == config["unit"],
            "Unsupported Quadlet source: requires an exact non-template .container")
    runtime = Path("/run/systemd" if config["scope"] == "system"
                   else "/run/user/" + str(os.getuid()) + "/systemd")
    require(Path(fragment["path"]).parent in [runtime / "generator", runtime / "generator.early", runtime / "generator.late"],
            "Quadlet service is not in a native generator directory")
    marker = re.search(rb"(?m)^# Automatically generated by ([^\r\n]+)\r?$", body)
    require(marker is not None, "Missing Quadlet generator provenance")
    generator = marker.group(1).decode("utf-8", "strict")
    require(generator in GENERATORS, "Unsupported Quadlet generator provenance")
    generator_record, _, _ = file_record(generator, executable=True)
    source_record, source_body, source_mtime = file_record(source)
    roots = quadlet_roots(config["scope"])
    source_path = Path(source)
    require(source_path.parent in roots, "Unsupported nested Quadlet source search path")
    for root in roots:
        candidate = root / source_path.name
        require(candidate == source_path or (not candidate.exists() and not candidate.is_symlink()),
                "Unsupported shadowed Quadlet sources")
    # Source drop-ins, including type/dash-prefix and higher-precedence paths,
    # are explicitly unsupported rather than silently left outside identity.
    base = source_path.name
    directories = {base + ".d", "container.d"}
    stem = source_path.stem
    for index, character in enumerate(stem):
        if character == "-":
            directories.add(stem[:index + 1] + ".container.d")
    candidates = set(roots + [source_path.parent])
    for root in roots:
        try:
            relative = source_path.parent.relative_to(root)
        except ValueError:
            continue
        candidates.update(other / relative for other in roots)
    for root in candidates:
        for directory in directories:
            path = root / directory
            require(not path.exists() and not path.is_symlink(),
                    "Unsupported Quadlet source drop-ins; no lifecycle action allowed")
    require(source_mtime <= fragment_mtime, "Quadlet source is newer than generated definition; operator reload required")
    generated_sections, source_sections = sections(body), sections(source_body)
    require(source_sections.get("Container") and generated_sections.get("X-Container") == source_sections["Container"],
            "Quadlet generated container provenance does not match source")
    require(["SourcePath", source] in generated_sections.get("Unit", []),
            "Quadlet generated SourcePath does not match manager")
    return {"source": source_record, "generator": generator_record}


def unit_snapshot(scope, name, deadline, *, service=False, allow_absent=False):
    values = properties(scope, COMMON + (SERVICE if service else ()), deadline, name)
    require(values["Id"] == name and words(values["Names"]) == [name] and not values["Following"],
            "Aliases or ambiguous native unit identities are unsupported")
    acceptable_load = values["LoadState"] == "loaded" or (
        allow_absent and values["LoadState"] in ("not-found", "masked")
        and values["ActiveState"] in ("inactive", "failed"))
    require(acceptable_load and values["Transient"] == "no"
            and values["NeedDaemonReload"] == "no", "Unsafe loaded definition or daemon reload required: " + name)
    require(values["Job"] in ("", "0", "0 /"), "Unit has a pending manager job")
    require(values["ActiveState"] in ("active", "inactive", "failed"),
            "Unit is not in a stable lifecycle state")
    for key in RELATIONS:
        values[key] = words(values[key])
    return values


def _dependency_view(values, owner):
    # Inactive units are garbage-collected. Starting/stopping our own unit adds
    # or removes its reverse edges from parent targets/slices, not their definitions.
    reverse = {"RequiredBy", "RequisiteOf", "BoundBy", "ConflictedBy", "Before", "After"}
    return {key: [name for name in value if name != owner] if key in reverse else value
            for key, value in values.items()}


def inspect(config, deadline):
    scope, name = config["scope"], config["unit"]
    manager = properties(scope, ("Version", "SystemState", "NJobs"), deadline)
    require(manager["Version"] and manager["SystemState"] in ("running", "degraded")
            and manager["NJobs"] == "0", "Manager is busy or not in a supported running state")
    unit = unit_snapshot(scope, name, deadline, service=True)
    require(Path(unit["FragmentPath"]).name == name, "Fragment name differs from adopted service")
    fragment, body, mtime = file_record(unit["FragmentPath"])
    dropins = unit["DropInPaths"].split()
    require(len(dropins) <= 32 and len(set(dropins)) == len(dropins), "Unsupported drop-in count")
    files = [file_record(path)[0] for path in dropins]
    identity = {"scope": scope, "unit": name, "manager_version": manager["Version"],
                "manager_uid": os.getuid() if scope == "user" else 0, "boot_id": boot_id(),
                "fragment": fragment, "dropins": files,
                "properties": {key: unit[key] for key in COMMON if key not in
                               ("ActiveState", "SubState", "Job")},
                "service": {key: unit[key] for key in SERVICE if key not in
                            ("Result", "InvocationID", "ExecMainCode", "ExecMainStatus", "NRestarts")}}
    if config["backend"] == "quadlet":
        identity["quadlet"] = quadlet_identity(config, unit, fragment, body, mtime)
    else:
        require(not unit["SourcePath"] and not re.search(rb"(?m)^# Automatically generated by ", body),
                "Generated/source-backed units require explicit supported backend adoption")
    state = {key: unit[key] for key in ("ActiveState", "SubState", "Result", "InvocationID",
                                      "ExecMainCode", "ExecMainStatus", "NRestarts")}
    warnings = ["Native systemd runtime state is not application health."]
    blockers = []
    if unit["Type"] not in ("simple", "exec", "forking", "notify", "notify-reload") or unit["RemainAfterExit"] != "no":
        blockers.append("Unsupported persistent-service shape (oneshot/exited services are not running workloads).")
    if unit["StopWhenUnneeded"] != "no":
        blockers.append("Automatic stop-when-unneeded lifecycle is unsupported.")
    if unit["BusName"]:
        blockers.append("D-Bus activation ownership is unsupported.")
    for key in PROPAGATION + ("Upholds",):
        if unit[key]:
            blockers.append("Unadopted activation or propagation edge: " + key + ".")
    for key in ("SuccessAction", "FailureAction", "StartLimitAction"):
        if unit[key] != "none":
            blockers.append("Unadopted manager side effect: " + key + ".")
    # systemd's transaction_drop_redundant + transaction_collect_garbage prune
    # starts of active prerequisites and their orphan descendants. Require every
    # direct prerequisite active; still inspect the full closure conservatively
    # for cross-conflicts that could prevent that pruning. Never ignore dependencies.
    direct = set(x for key in FORWARD for x in unit[key])
    pending = set(direct)
    seen = {name: unit}
    positive = {name}
    conflicts = set(unit["Conflicts"]) | set(unit["ConflictedBy"])
    dependencies = {}
    while pending:
        target = min(pending)
        pending.remove(target)
        if target in positive:
            continue
        require(len(seen) < MAX_UNITS, "Dependency closure exceeds supported inspection bound")
        # An absent unit has no relations of its own. Absent direct prerequisites are inactive and
        # already blocked below; absent transitive ones sit beneath active prerequisites whose jobs systemd prunes.
        other = unit_snapshot(scope, target, deadline, service=target.endswith(".service"), allow_absent=True)
        seen[target] = other
        positive.add(target)
        dependencies[target] = other
        if other["StopWhenUnneeded"] != "no":
            blockers.append("Dependency may stop automatically: " + target + ".")
        if target in direct and other["ActiveState"] != "active":
            blockers.append("Start transaction would activate an unadopted dependency: " + target + ".")
        pending.update(x for key in FORWARD for x in other[key] if x not in positive)
        conflicts.update(other["Conflicts"])
        conflicts.update(other["ConflictedBy"])
    for target in sorted(conflicts):
        if target not in seen:
            require(len(seen) < MAX_UNITS, "Dependency closure exceeds supported inspection bound")
            seen[target] = unit_snapshot(scope, target, deadline, service=target.endswith(".service"), allow_absent=True)
            dependencies[target] = seen[target]
        if target in positive or seen[target]["ActiveState"] not in ("inactive", "failed"):
            blockers.append("Transaction has an active unadopted conflict: " + target + ".")
    # Pin every observed relation without expanding shared desktop-target graphs
    # into the broker's bounded evidence document. Runtime state stays readable.
    state["dependencies"] = {key: {field: value[field] for field in STATE_FIELDS if field in value}
                             for key, value in sorted(dependencies.items())}
    identity["dependencies"] = {
        key: {"load_state": value["LoadState"], "properties_sha256": hashlib.sha256(
            json.dumps({field: item for field, item in _dependency_view(value, name).items() if field not in STATE_FIELDS},
                       sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
        for key, value in sorted(dependencies.items())}
    supported = list(ACTIONS) if not blockers else []
    if unit["RefuseManualStart"] != "no" or unit["CanStart"] != "yes":
        supported = [x for x in supported if x == "stop"]
    if unit["RefuseManualStop"] != "no" or unit["CanStop"] != "yes":
        supported = [x for x in supported if x == "start"]
    # Re-read native state/definition properties after the graph/file walk, so
    # an observation spanning a concurrent transition is not approvable.
    require(unit_snapshot(scope, name, deadline, service=True) == unit,
            "Unit changed during inspection")
    for target, snapshot in dependencies.items():
        current = unit_snapshot(scope, target, deadline, service=target.endswith(".service"),
                                allow_absent=snapshot["LoadState"] != "loaded")
        require(_dependency_view(current, name) == _dependency_view(snapshot, name),
                "Dependency changed during inspection")
    # Recheck definition bytes as well as manager properties. NeedDaemonReload
    # alone need not notice a rewritten Quadlet input or a preserved timestamp.
    require(file_record(unit["FragmentPath"])[0] == fragment
            and [file_record(path)[0] for path in dropins] == files,
            "Definition changed during inspection")
    if config["backend"] == "quadlet":
        require(quadlet_identity(config, unit, fragment, body, mtime) == identity["quadlet"],
                "Quadlet inputs changed during inspection")
    final_manager = properties(scope, ("Version", "SystemState", "NJobs"), deadline)
    require(final_manager == manager, "Manager changed during inspection")
    lifecycle = {"active": "running", "inactive": "stopped", "failed": "failed"}.get(unit["ActiveState"], "unknown")
    if unit["ActiveState"] == "active" and unit["SubState"] != "running":
        lifecycle = "unknown"
    result = {"backend": config["backend"], "identity": identity, "state": state,
            "resources": [{"backend": "systemd", "scope": "system" if scope == "system" else "user:" + str(os.getuid()),
                           "native_id": name, "name": name}],
            "lifecycle": lifecycle, "health": "unknown",
            "warnings": warnings + sorted(set(blockers)), "supported_actions": supported}
    require(len(json.dumps(result, sort_keys=True).encode("utf-8")) <= 131072,
            "Inspection exceeds supported evidence bound")
    return result


def validate(request):
    require(isinstance(request, dict) and set(request) <= {"action", "config", "expected"}, "Invalid lifecycle request")
    require(request.get("action") in ("inspect", *ACTIONS), "Unsupported lifecycle action")
    config = request.get("config")
    require(isinstance(config, dict) and set(config) == {"backend", "name", "host_id", "scope", "unit"},
            "Invalid exact systemd lifecycle configuration")
    require(config["backend"] in ("systemd", "quadlet") and config["scope"] in ("user", "system")
            and isinstance(config["unit"], str) and UNIT.fullmatch(config["unit"]),
            "Requires exact non-template .service and explicit system/user scope")
    require(all(isinstance(config[key], str) and 0 < len(config[key]) <= 256
                and not any(ord(c) < 32 for c in config[key]) for key in ("name", "host_id")),
            "Invalid workload name or host identity")
    return config


def run(request):
    mutated = False
    current = None
    try:
        config = validate(request)
        deadline = time.monotonic() + TOTAL_SECONDS
        current = inspect(config, deadline)
        action = request["action"]
        if action == "inspect":
            return {"status": "succeeded", "inspection": current}
        expected = request.get("expected")
        require(isinstance(expected, dict) and expected.get("backend") == config["backend"]
                and expected.get("identity") == current["identity"] and expected.get("state") == current["state"],
                "Inspection preconditions changed; inspect and approve again")
        require(action in current["supported_actions"], "Unsupported lifecycle impact; inspect warnings before adopting a different shape")
        # This bookkeeping is deliberately before invocation: a transport/CLI
        # error cannot prove whether the manager accepted the requested job.
        mutated = True
        command(config["scope"], ["--job-mode=fail", action, "--", config["unit"]], deadline)
        after = inspect(config, deadline)
        require(after["identity"] == current["identity"], "Definition changed during lifecycle operation")
        require(after["state"]["dependencies"] == current["state"]["dependencies"],
                "Unadopted dependency state changed during lifecycle operation")
        state = after["state"]
        if action == "stop":
            require(state["ActiveState"] == "inactive" and state["SubState"] == "dead",
                    "Native stopped postcondition was not observed")
        else:
            require(state["ActiveState"] == "active" and state["SubState"] == "running" and state["Result"] == "success"
                    and re.fullmatch(r"[0-9a-f]{32}", state["InvocationID"] or ""),
                    "Native persistent-running postcondition was not observed")
            if action == "restart" and current["state"]["ActiveState"] == "active":
                require(state["InvocationID"] != current["state"]["InvocationID"], "Restart did not establish a fresh invocation")
        return {"status": "succeeded", "inspection": after}
    except (Refusal, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        # Exception arguments and subprocess diagnostics may contain secrets.
        # Only our bounded, constant-authored refusals are consumer-visible.
        message = str(error) if isinstance(error, Refusal) else "Remote systemd inspection or command failed (details withheld)"
        result = {"status": "needs-inspection" if mutated else "failed", "error": message}
        if current is not None:
            result["inspection"] = current
        return result
