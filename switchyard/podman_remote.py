"""Fixed remote program for the single, explicitly owned foobar rehearsal.

The broker supplies PAYLOAD and holds every host lease. There is deliberately no
shell command interpolation and no generic container execution entry point.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import pwd
import re
import select
import socket
import stat
import subprocess
import time
import uuid


NAME = "switchyard-foobar"
LABEL = "io.switchyard.ownership"
WORKLOAD_LABEL = "io.switchyard.workload"
IMAGE = "docker.io/nginxinc/nginx-unprivileged:1.28.0-alpine"
CONTENT_PATH = "/usr/share/nginx/html/index.html"
LIMIT = 65536


class Refusal(Exception):
    pass


class CommandFailure(Refusal):
    def __init__(self, action, diagnostics):
        super().__init__("Podman command failed: " + action)
        self.diagnostics = diagnostics


def require(condition, message):
    if not condition:
        raise Refusal(message)


def podman(*args, timeout=45):
    env = os.environ.copy()
    for name in ("CONTAINER_HOST", "CONTAINER_CONNECTION", "DOCKER_HOST",
                 "DOCKER_CONTEXT", "PODMAN_CONNECTIONS_CONF"):
        env.pop(name, None)
    process = subprocess.Popen(["/usr/bin/podman", "--remote=false", *args],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env)
    deadline, output, diagnostics = time.monotonic() + timeout, bytearray(), bytearray()
    try:
        streams = [process.stdout, process.stderr]
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("podman", timeout)
            ready = select.select(streams, [], [], remaining)[0]
            if not ready:
                raise subprocess.TimeoutExpired("podman", timeout)
            for stream in ready:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    streams.remove(stream)
                elif stream is process.stdout:
                    output.extend(chunk)
                    require(len(output) <= 2 * 1024 * 1024, "Podman response exceeds bound")
                else:
                    diagnostics.extend(chunk[:max(0, 16384 - len(diagnostics))])
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if code != 0:
            # Returned only to the invoking operator, never stored in receipts.
            raise CommandFailure(args[0], diagnostics.decode("utf-8", "replace"))
        return output.decode("utf-8")
    finally:
        if process.poll() is None:
            # Kill only our CLI. Container effects may survive and must be
            # reconciled by an explicit operation, never an automatic retry.
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def json_command(*args, timeout=45):
    return json.loads(podman(*args, timeout=timeout))


def read_file(path, limit=LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and info.st_size <= limit,
                "Content must be a bounded, owned regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            value = stream.read(limit + 1)
        require(len(value) <= limit, "Content exceeds bound")
        return value
    finally:
        os.close(fd)


def paths(owner):
    root = Path.home().resolve()
    for part in (".local", "share", "switchyard", "workloads", "foobar"):
        root = root / part
        if root.exists() or root.is_symlink():
            info = root.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(),
                    "Workload path contains a symlink or unowned directory")
    marker = root / "owner.json"
    if root.exists():
        require(marker.exists(), "Refusing an unowned workload directory")
        require(json.loads(read_file(marker, 2048)) == {
            "ownership_id": owner, "workload_id": "foobar", "uid": os.getuid()},
            "Workload directory belongs to a different owner")
        require(set(os.listdir(root)) <= {"owner.json", "index.html"},
                "Unexpected files in dedicated workload directory")
    return root, root / "index.html"


def write_new(path, value, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(value)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def provision_content(owner, content, expected_hash):
    require(hashlib.sha256(content).hexdigest() == expected_hash, "Content hash mismatch")
    root, site = paths(owner)
    if not root.exists():
        # Existing shared ancestors were checked above; never replace anything.
        root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        root.mkdir(mode=0o700)
        write_new(root / "owner.json", json.dumps({"ownership_id": owner,
                  "workload_id": "foobar", "uid": os.getuid()}, sort_keys=True).encode(), 0o600)
    if site.exists() or site.is_symlink():
        require(read_file(site) == content, "Refusing to overwrite existing workload content")
    else:
        write_new(site, content, 0o644)
    return site


def container_record():
    records = json_command("ps", "--all", "--no-trunc", "--format", "json")
    matches = [entry for entry in records if NAME in entry.get("Names", [])]
    require(len(matches) <= 1, "Ambiguous container name")
    if not matches:
        return None
    records = json_command("container", "inspect", NAME)
    require(isinstance(records, list) and len(records) == 1, "Ambiguous container inspect")
    return records[0]


def image_record(reference):
    records = json_command("image", "inspect", reference)
    require(isinstance(records, list) and len(records) == 1, "Ambiguous image inspect")
    record = records[0]
    image_id = record.get("Id", "")
    if not image_id.startswith("sha256:"):
        image_id = "sha256:" + image_id
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "Missing immutable image ID")
    digests = record.get("RepoDigests", [])
    require(isinstance(digests, list) and digests
            and all(isinstance(value, str) and re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", value)
                    for value in digests), "Missing actual image RepoDigest")
    return {"image_id": image_id, "image_digest": sorted(digests)[0],
            "repo_digests": digests, "architecture": record.get("Architecture")}


def architecture(value):
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(value, value)


def port_free():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 18080))


def runtime(payload):
    require(os.getuid() != 0, "Rootful execution is forbidden")
    require(pwd.getpwuid(os.getuid()).pw_name == payload["expected_user"], "SSH user identity mismatch")
    require(platform.system() == "Linux", "Linux rootless Podman is required")
    info = json_command("info", "--format", "json")
    host = info.get("host", info.get("Host", {}))
    security = host.get("security", host.get("Security", {}))
    require(security.get("rootless", security.get("Rootless")) is True, "Rootless runtime required")
    store = info.get("store", info.get("Store", {}))
    graph = store.get("graphRoot", store.get("GraphRoot"))
    require(isinstance(graph, str) and os.path.isabs(graph), "Unknown runtime storage")
    require(os.statvfs(graph).f_bavail * os.statvfs(graph).f_frsize >= 256 * 1024 * 1024,
            "Insufficient runtime storage reserve")
    return architecture(platform.machine())


def validate_container(record, payload):
    require(record is not None, "Owned container is absent")
    cfg, host = record.get("Config", {}), record.get("HostConfig", {})
    labels = cfg.get("Labels") or {}
    require(labels.get(LABEL) == payload["ownership_id"]
            and labels.get(WORKLOAD_LABEL) == "foobar", "Container ownership mismatch")
    require(record.get("Name", "").lstrip("/") == NAME, "Container name mismatch")
    native_id = record.get("Id", "")
    require(re.fullmatch(r"[0-9a-f]{64}", native_id), "Missing full native container ID")
    if payload.get("native_id"):
        require(native_id == payload["native_id"], "Container incarnation changed")
    actual_image = record.get("Image", "")
    if not actual_image.startswith("sha256:"):
        actual_image = "sha256:" + actual_image
    require(actual_image == payload["image_id"], "Container image ID mismatch")
    require(cfg.get("User") == "101:101" and host.get("ReadonlyRootfs") is True
            and host.get("Privileged") is False, "Unsafe container user/root filesystem")
    # Podman expands CapDrop against its defaults; the actual OCI sets, not an
    # imaginary Docker-style "ALL" inspect value, prove no capabilities.
    require(all(key in record and record[key] in ([], None)
                for key in ("EffectiveCaps", "BoundingCaps"))
            and not host.get("CapAdd"), "Unsafe container capabilities")
    require(any(value in ("no-new-privileges", "no-new-privileges:true")
                for value in host.get("SecurityOpt", [])), "Missing no-new-privileges")
    require(host.get("RestartPolicy", {}).get("Name") in ("no", ""), "Unexpected restart policy")
    require(host.get("Memory") == 64 * 1024 * 1024
            and host.get("MemorySwap") == 64 * 1024 * 1024
            and host.get("CpuPeriod") == 100000 and host.get("CpuQuota") == 50000
            and host.get("PidsLimit") == 32, "Resource limits mismatch")
    require(host.get("NetworkMode") in ("bridge", "private", "slirp4netns", "pasta"),
            "Unsafe network namespace")
    require(host.get("PortBindings") == {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]},
            "Unexpected host port bindings")
    root, site = paths(payload["ownership_id"])
    mounts = record.get("Mounts", [])
    binds = [mount for mount in mounts if mount.get("Type") == "bind"]
    require(len(binds) == 1 and binds[0].get("Source") == str(site)
            and binds[0].get("Destination") == CONTENT_PATH and binds[0].get("RW") is False,
            "Unexpected content bind")
    require(not any(mount.get("Type") not in ("bind", "tmpfs") for mount in mounts),
            "Unexpected persistent mount")
    tmpfs = host.get("Tmpfs", {})
    options = set(tmpfs.get("/tmp", "").split(","))
    require(set(tmpfs) == {"/tmp"}
            and {"rw", "noexec", "nosuid", "nodev"} <= options
            and options <= {"rw", "noexec", "nosuid", "nodev", "size=16777216", "size=16m",
                            "mode=1777", "mode=01777", "rprivate", "tmpcopyup"}
            and {value for value in options if value.startswith("size=")} in
                ({"size=16777216"}, {"size=16m"})
            and {value for value in options if value.startswith("mode=")} in
                ({"mode=1777"}, {"mode=01777"}),
            "Unexpected temporary filesystem")
    log = host.get("LogConfig", {})
    # Podman 4.9 emits docker/go-units HumanSize in Size and leaves Config nil.
    require(log.get("Type") == "k8s-file" and log.get("Size") == "1.049MB",
            "Unbounded or unexpected container logs")
    content = read_file(site)
    require(hashlib.sha256(content).hexdigest() == payload["content_sha256"], "Content hash mismatch")
    return native_id, content


def verify_http(expected_hash):
    # http.client never follows redirects or uses proxy environment variables.
    deadline = time.monotonic() + 12
    while True:
        connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=2)
        try:
            connection.request("GET", "/", headers={"Connection": "close"})
            response = connection.getresponse()
            body = response.read(LIMIT + 1)
            require(response.status == 200, "HTTP response was not 200 (redirects forbidden)")
            require(len(body) <= LIMIT and hashlib.sha256(body).hexdigest() == expected_hash,
                    "HTTP body hash mismatch")
            return
        except (ConnectionError, OSError, http.client.HTTPException):
            if time.monotonic() >= deadline:
                raise Refusal("HTTP endpoint did not become ready")
            time.sleep(0.2)
        finally:
            connection.close()


def snapshot(record, payload, *, http=False, content=False):
    native_id, body = validate_container(record, payload)
    running = record.get("State", {}).get("Running")
    require(type(running) is bool, "Unknown container state")
    if http:
        require(running, "Source is not running")
        verify_http(payload["content_sha256"])
    result = {"native_id": native_id, "running": running, "content_sha256": payload["content_sha256"],
              "scope": "user:" + str(os.getuid())}
    if content:
        result["content_b64"] = base64.b64encode(body).decode("ascii")
    return result


def execute(payload):
    mutated = False
    try:
        require(payload.get("workload_id") == "foobar" and payload.get("container_name") == NAME
                and type(payload.get("port")) is int and payload["port"] == 18080 and payload.get("image") == IMAGE,
                "Unsupported workload configuration")
        require(str(uuid.UUID(payload["ownership_id"])) == payload["ownership_id"], "Invalid ownership UUID")
        arch = runtime(payload)
        if payload.get("expected_scope"):
            require(payload["expected_scope"] == "user:" + str(os.getuid()), "Rootless native user scope changed")
        paths(payload["ownership_id"])
        action = payload["action"]
        if action == "preflight":
            record = container_record()
            result = {}
            _, site = paths(payload["ownership_id"])
            if site.exists() or site.is_symlink():
                require(hashlib.sha256(read_file(site)).hexdigest() == payload["content_sha256"],
                        "Existing destination content hash mismatch")
            if record is not None:
                require(payload.get("allow_owned") is True, "Container name collision")
                result = snapshot(record, payload)
                require(not result["running"], "Destination owned container is still running")
            port_free()
            return {"status": "succeeded", "architecture": arch, "scope": "user:" + str(os.getuid()), **result}
        if action == "prestage":
            reference = payload.get("image_digest") or IMAGE
            require(reference == IMAGE or re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", reference),
                    "Invalid immutable image reference")
            mutated = True
            podman("pull", reference, timeout=100)
            image = image_record(reference)
            require(architecture(image["architecture"]) == arch, "Image architecture mismatch")
            if payload.get("image_id"):
                require(image["image_id"] == payload["image_id"], "Immutable image ID differs on destination")
                require(payload["image_digest"] in image["repo_digests"],
                        "Immutable image digest differs on destination")
                image["image_digest"] = payload["image_digest"]
            return {"status": "succeeded", "scope": "user:" + str(os.getuid()), **image}
        record = container_record()
        if action in ("absent-or-stopped", "inspect-target"):
            if record is None:
                return {"status": "succeeded", "absent": True, "running": False}
            result = snapshot(record, payload)
            if action == "absent-or-stopped":
                require(not result["running"], "Destination is still running; recovery must not restart source")
            return {"status": "succeeded", **result}
        if action == "deploy":
            body = base64.b64decode(payload["content_b64"], validate=True)
            require(len(body) <= LIMIT, "Content exceeds bound")
            if record is not None:
                result = snapshot(record, payload)
                require(not result["running"], "Owned container already running")
                port_free()
                mutated = True
                podman("start", result["native_id"])
            else:
                port_free()
                image = image_record(payload["image_id"])
                require(image["image_id"] == payload["image_id"] and payload["image_digest"] in image["repo_digests"],
                        "Prestaged image identity changed")
                mutated = True
                site = provision_content(payload["ownership_id"], body, payload["content_sha256"])
                # Podman 4.9 rejects tmpfs uid/gid options; private sticky /tmp serves UID 101.
                podman("run", "--detach", "--pull=never", "--name", NAME,
                       "--label", LABEL + "=" + payload["ownership_id"], "--label", WORKLOAD_LABEL + "=foobar",
                       "--user", "101:101", "--read-only", "--read-only-tmpfs=false",
                       "--cap-drop=ALL", "--security-opt=no-new-privileges",
                       "--memory=64m", "--memory-swap=64m", "--cpu-period=100000", "--cpu-quota=50000",
                       "--pids-limit=32", "--restart=no", "--log-driver=k8s-file", "--log-opt=max-size=1048576",
                       "--publish", "127.0.0.1:18080:8080/tcp", "--mount",
                       "type=bind,src=" + str(site) + ",dst=" + CONTENT_PATH + ",ro=true",
                       "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777",
                       payload["image_id"])
            return {"status": "succeeded", **snapshot(container_record(), payload, http=True)}
        result = snapshot(record, payload, http=action == "inspect-running", content=action == "inspect-running")
        if action in ("inspect", "inspect-running"):
            return {"status": "succeeded", "architecture": arch, **result}
        if action == "stop":
            if result["running"]:
                mutated = True
                podman("stop", "--time=10", result["native_id"], timeout=20)
            result = snapshot(container_record(), payload)
            require(not result["running"], "Container did not stop")
            return {"status": "succeeded", **result}
        if action == "start":
            require(not result["running"], "Container is already running")
            port_free()
            mutated = True
            podman("start", result["native_id"])
            return {"status": "succeeded", **snapshot(container_record(), payload, http=True)}
        raise Refusal("Unsupported remote action")
    except Exception as error:
        # After any mutating command has begun, absence of verification is not a
        # confirmed failure and never authorizes an automatic source restart.
        return {"status": "needs-inspection" if mutated else "failed",
                "error": str(error)[:512] if isinstance(error, Refusal) else type(error).__name__,
                "stderr": getattr(error, "diagnostics", "")}


if "PAYLOAD" in globals():
    print(json.dumps(execute(PAYLOAD), sort_keys=True))
else:
    SOURCE = Path(__file__).read_text(encoding="utf-8")
