"""Bounded, opt-in local container metadata; stdlib-only for stdin composition.

container.v1 workload whitelist: state, image_reference, image_id, project,
service, compose_directory, compose_files, systemd_unit, mounts, environment.
Mounts contain only source, destination, type and read_only. environment is
'distrobox' only with an explicit manager label. Origin fields are the labels
Compose/Quadlet write when creating a container: claims about provenance, not
proof that the manifest or unit still exists or matches.
Image artifact whitelist: image_id, references. Compose labels are grouping
hints, never adoption, health or atomic migration evidence.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time

ENGINES = ("podman", "docker")
FULL_ID = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
MAX_CONTAINERS = 32
MAX_IMAGES = 64
MAX_MOUNTS = 64
MAX_ENGINE_BYTES = 65536
WORKLOAD_FIELDS = {"state", "image_reference", "image_id", "project", "service", "compose_directory", "compose_files",
                   "systemd_unit", "mounts", "environment"}
MAX_COMPOSE_FILES = 16
IMAGE_FIELDS = {"image_id", "references"}
# JSON is applied to individual selected values, never to an inspect object.
INSPECT_FORMAT = ('{"id":{{json .Id}},"name":{{json .Name}},"state":{{json .State.Status}},'
                  '"image_reference":{{json .Config.Image}},"image_id":{{json .Image}},'
                  '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
                  '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
                  '"podman_project":{{json (index .Config.Labels "io.podman.compose.project")}},'
                  '"podman_service":{{json (index .Config.Labels "io.podman.compose.service")}},'
                  '"compose_directory":{{json (index .Config.Labels "com.docker.compose.project.working_dir")}},'
                  '"compose_files":{{json (index .Config.Labels "com.docker.compose.project.config_files")}},'
                  '"systemd_unit":{{json (index .Config.Labels "PODMAN_SYSTEMD_UNIT")}},'
                  '"distrobox":{{eq (index .Config.Labels "manager") "distrobox"}},'
                  '"mounts":[{{range $i,$m := .Mounts}}{{if $i}},{{end}}'
                  '{"source":{{json $m.Source}},"destination":{{json $m.Destination}},'
                  '"type":{{json $m.Type}},"read_only":{{not $m.RW}}}{{end}}]}')
IMAGES_FORMAT = '{"id":{{json .ID}},"repository":{{json .Repository}},"tag":{{json .Tag}}}'


def validate_engines(engines):
    if not isinstance(engines, list) or len(engines) > 2 or any(not isinstance(e, str) or e not in ENGINES for e in engines) or len(set(engines)) != len(engines):
        raise ValueError("Invalid container engine allowlist")
    return list(engines)


def _string(value, maximum=1024, nullable=False):
    if value is None and nullable:
        return value
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Invalid selected container text")
    return value


def _image_id(value):
    if not isinstance(value, str) or not IMAGE_ID.fullmatch(value):
        raise ValueError("Invalid full image ID")
    return "sha256:" + value.removeprefix("sha256:")


def stable_id(host_id, backend, scope, native_id, kind):
    digest = hashlib.sha256("\0".join((host_id, backend, scope, kind, native_id)).encode()).hexdigest()
    return "container:" + digest


def workload(host_id, backend, scope, native_id, name, fields, at):
    """Validate the entire extension whitelist and derive all normalized claims."""
    if not isinstance(native_id, str) or not FULL_ID.fullmatch(native_id) or not isinstance(fields, dict) or set(fields) != WORKLOAD_FIELDS:
        raise ValueError("Invalid container metadata")
    name = _string(name, 256)
    state = _string(fields["state"], 32)
    _string(fields["image_reference"])
    if fields["image_id"] != _image_id(fields["image_id"]):
        raise ValueError("Noncanonical image ID")
    for key in ("project", "service"):
        _string(fields[key], 256, nullable=True)
    _string(fields["compose_directory"], 1024, nullable=True)
    _string(fields["systemd_unit"], 256, nullable=True)
    files = fields["compose_files"]
    if not isinstance(files, list) or len(files) > MAX_COMPOSE_FILES or len(set(files)) != len(files):
        raise ValueError("Invalid compose file labels")
    for path in files:
        _string(path, 1024)
    if fields["environment"] not in (None, "distrobox"):
        raise ValueError("Unknown container environment")
    mounts = fields["mounts"]
    if not isinstance(mounts, list) or len(mounts) > MAX_MOUNTS:
        raise ValueError("Invalid mounts")
    for mount in mounts:
        if not isinstance(mount, dict) or set(mount) != {"source", "destination", "type", "read_only"} or type(mount["read_only"]) is not bool:
            raise ValueError("Invalid mount fields")
        for key in ("source", "destination", "type"):
            if key != "source" or mount[key] != "":
                _string(mount[key], 32 if key == "type" else 1024)
    lifecycle = {"running": "running", "paused": "idle", "created": "stopped", "configured": "stopped",
                 "exited": "stopped", "stopped": "stopped", "restarting": "starting", "stopping": "stopping",
                 "removing": "stopping", "dead": "failed"}.get(state, "unknown")
    return {"id": stable_id(host_id, backend, scope, native_id, "container"), "host_id": host_id,
            "backend": backend, "scope": scope, "native_id": native_id, "name": name,
            "kind": "environment" if fields["environment"] else "service", "lifecycle": lifecycle,
            "health": "unknown", "management": "discovered", "observed_at": at,
            "extensions": {"container.v1": fields}}


def artifact(host_id, backend, scope, native_id, fields, at):
    if not isinstance(fields, dict) or set(fields) != IMAGE_FIELDS or fields["image_id"] != native_id or native_id != _image_id(native_id):
        raise ValueError("Invalid image metadata")
    refs = fields["references"]
    if not isinstance(refs, list) or len(refs) > 64 or refs != sorted(set(_string(r) for r in refs)):
        raise ValueError("Invalid image references")
    return {"id": stable_id(host_id, backend, scope, native_id, "image"), "host_id": host_id,
            "backend": backend, "scope": scope, "native_id": native_id, "name": refs[0] if refs else native_id,
            "kind": "image", "observed_at": at, "extensions": {"container.v1": fields}}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate metadata key")
        result[key] = value
    return result


def _rows(output):
    return [json.loads(line, object_pairs_hook=_object) for line in output.splitlines() if line.strip()]


def parse_containers(output, allowed, host_id, backend, scope, at):
    rows = _rows(output)
    result, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"id", "name", "state", "image_reference", "image_id", "project", "service", "podman_project", "podman_service",
                                                    "compose_directory", "compose_files", "systemd_unit", "distrobox", "mounts"}:
            raise ValueError("Unexpected selected inspect fields")
        ident = row["id"]
        if ident not in allowed or ident in seen or type(row["distrobox"]) is not bool:
            raise ValueError("Container identity mismatch")
        seen.add(ident)
        fields = {key: row[key] for key in ("state", "image_reference", "mounts")}
        fields["image_id"] = _image_id(row["image_id"])
        for key in ("project", "service"):
            first, second = row[key], row["podman_" + key]
            for value in (first, second):
                if value not in (None, ""):
                    _string(value, 256)
            if first and second and first != second:
                raise ValueError("Ambiguous compose labels")
            fields[key] = first or second or None
        for key in ("compose_directory", "systemd_unit"):
            fields[key] = row[key] or None
        # Compose joins every -f manifest with commas; an empty label means no manifest was recorded.
        files = row["compose_files"]
        if files not in (None, "") and not isinstance(files, str):
            raise ValueError("Invalid compose file labels")
        fields["compose_files"] = [path for path in (files or "").split(",") if path]
        fields["environment"] = "distrobox" if row["distrobox"] else None
        name = _string(row["name"], 257).removeprefix("/")
        result.append(workload(host_id, backend, scope, ident, name, fields, at))
    return result


def parse_images(output, host_id, backend, scope, at):
    images = {}
    for row in _rows(output):
        if not isinstance(row, dict) or set(row) != {"id", "repository", "tag"}:
            raise ValueError("Unexpected selected image fields")
        ident = _image_id(row["id"])
        repository, tag = _string(row["repository"]), _string(row["tag"], 256)
        refs = images.setdefault(ident, set())
        if repository != "<none>" and tag != "<none>":
            refs.add(repository + ":" + tag)
        if len(images) > MAX_IMAGES:
            raise ValueError("Image inventory limit")
    return [artifact(host_id, backend, scope, ident, {"image_id": ident, "references": sorted(refs)}, at)
            for ident, refs in sorted(images.items())]


def command(engine, arguments):
    # Explicit local endpoints defeat inherited contexts and never request activation.
    if engine == "podman":
        return ["/usr/bin/podman", "--remote=false", *arguments]
    if engine == "docker":
        return ["/usr/bin/docker", "--host=unix:///var/run/docker.sock", *arguments]
    raise ValueError("Unknown engine")


def _run_command(arguments, deadline):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "LANG": "C.UTF-8",
           "XDG_RUNTIME_DIR": "/run/user/" + str(os.getuid())}
    if time.monotonic() >= deadline:
        raise ValueError("Container deadline")
    child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, close_fds=True, env=env)
    output = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("Container deadline")
                for key, _ in selector.select(min(0.05, remaining)):
                    part = os.read(key.fd, 8192)
                    if not part:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(part)
                        if len(output) > MAX_ENGINE_BYTES:
                            raise ValueError("Container output limit")
        status = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        return output.decode("utf-8"), status
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()


def run(engine, arguments, deadline):
    return _run_command(command(engine, arguments), deadline)


def docker_socket_safe(deadline):
    # Connecting to an active docker.socket can start a stopped daemon. Refuse
    # socket-activated Docker, even if it currently appears to be running.
    output, status = _run_command(
        ["/usr/bin/systemctl", "--no-pager", "--no-ask-password", "show",
         "--property=LoadState,ActiveState", "--", "docker.socket"], deadline)
    properties = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in ("LoadState", "ActiveState") or key in properties:
            return False
        properties[key] = value
    return (status == 0 or properties.get("LoadState") == "not-found") and (
        properties.get("LoadState") in ("loaded", "not-found") and properties.get("ActiveState") == "inactive")


def observe_containers(host_id, engines, at, deadline=None):
    engines = validate_engines(engines)
    if os.geteuid() == 0 or os.getuid() != os.geteuid():
        raise ValueError("Unprivileged current-user runtime required")
    workloads, artifacts, coverage = [], [], []
    # Three seconds for ALL configured engines, inside the existing 12s probe alarm.
    start = time.monotonic()
    end = min(start + 3.0, deadline) if deadline is not None else start + 3.0
    for index, engine in enumerate(engines):
        scope = "user:" + str(os.getuid()) if engine == "podman" else "system"
        engine_deadline = start + max(0.0, end - start) * (index + 1) / len(engines)
        if engine == "docker":
            try:
                safe = docker_socket_safe(engine_deadline)
            except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
                safe = False
            if not safe:
                coverage.append({"scope": "docker:system", "status": "unavailable",
                                 "message": "Docker socket activation safety not established"})
                continue
        works, images, succeeded, complete = [], [], False, True
        try:
            output, status = run(engine, ["ps", "--all", "--no-trunc", "--format", "{{.ID}}"], engine_deadline)
            ids = output.splitlines()
            if status != 0 or len(ids) > MAX_CONTAINERS or len(set(ids)) != len(ids) or any(not FULL_ID.fullmatch(i) for i in ids):
                raise ValueError("Container inventory unavailable")
            succeeded = True
            if ids:
                template = INSPECT_FORMAT.replace("json .Id", "json .ID") if engine == "podman" else INSPECT_FORMAT
                output, status = run(engine, ["container", "inspect", "--format", template, *ids], engine_deadline)
                works = parse_containers(output, ids, host_id, engine, scope, at)
                complete = status == 0 and len(works) == len(ids)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, subprocess.SubprocessError):
            complete = False
        try:
            output, status = run(engine, ["images", "--all", "--no-trunc", "--format", IMAGES_FORMAT], engine_deadline)
            images = parse_images(output, host_id, engine, scope, at)
            succeeded = succeeded or status == 0 or bool(images)
            complete = complete and status == 0
        except (OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError):
            complete = False
        if len(json.dumps([works, images]).encode()) > MAX_ENGINE_BYTES:
            works, images, complete = [], [], False
        workloads.extend(works)
        artifacts.extend(images)
        coverage.append({"scope": engine + ":" + scope,
                         "status": "complete" if complete else "partial" if succeeded else "unavailable",
                         "message": "Selected local container and image metadata" if complete else "Some local engine metadata unavailable"})
    return workloads, artifacts, coverage
