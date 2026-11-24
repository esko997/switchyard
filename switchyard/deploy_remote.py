"""Fixed remote program for Switchyard-deployed Quadlet `.kube` workloads.

Executed through `switchyard.remote.run_remote` while the caller holds the host's
canonical lease; the controller appends `print(json.dumps(main(PAYLOAD)))`.
Stdlib only, no shell interpolation. Only files and pods carrying this
deployment's ownership ID are changed. Diagnostics from native tools are never
returned (they could contain secrets); refusals are constant-authored text.
"""
import grp
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import select
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

PODMAN = "/usr/bin/podman"
SYSTEMCTL = "/usr/bin/systemctl"
# Distributions install the Quadlet generator in different places (Debian/Fedora: libexec; Arch/CachyOS: lib).
# This program runs on the target host, so the first one present there is used.
QUADLET_CANDIDATES = ("/usr/libexec/podman/quadlet", "/usr/lib/podman/quadlet", "/usr/local/libexec/podman/quadlet",
                      "/usr/local/lib/podman/quadlet")
QUADLET = next((path for path in QUADLET_CANDIDATES if os.access(path, os.X_OK)), QUADLET_CANDIDATES[0])
SKOPEO_CANDIDATES = ("/usr/bin/skopeo", "/usr/local/bin/skopeo")
CATATONIT_CANDIDATES = ("/usr/libexec/podman/catatonit", "/usr/local/libexec/podman/catatonit", "/usr/local/lib/podman/catatonit",
                        "/usr/lib/podman/catatonit", "/usr/bin/catatonit", "/usr/local/bin/catatonit", "/bin/catatonit")
TOKEN_FORMAT = "switchyard-generation-token/v1"
LABEL = "io.switchyard/"
OUTPUT_LIMIT = 4 * 1024 * 1024
QUADLET_SUFFIXES = (".container", ".kube", ".pod", ".volume", ".network", ".image", ".build")
CLEANUP_SECONDS = 45  # stop grace + kube down + verification, reserved inside a start step
IP_CANDIDATES = ("/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip")
CONFIG_LIMIT = 65536  # bytes per configuration file
CONFIG_TEXT_BUDGET = 196608  # file texts returned by one read (transport output bound is 256 KiB)
SYSTEMD_RUN = "/usr/bin/systemd-run"
PULLS = ".local/share/switchyard/pulls"  # detached image pulls: request.json, log, result per image digest
PULL_MAX_SECONDS = 6 * 3600  # RuntimeMaxSec of a detached pull: systemd stops it after this
GIB = 1024 ** 3
# `sh -c` body of a detached pull; every value arrives as a positional argument (no interpolation):
# $1 podman, $2 reference, $3 pull directory. The exit code is written atomically as the outcome.
PULL_SCRIPT = ('"$1" pull "$2" >"$3/log" 2>&1; code=$?; printf "%s\\n" "$code" >"$3/result.tmp" '
               '&& mv -f "$3/result.tmp" "$3/result"; exit "$code"')


class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def home():
    return pwd.getpwuid(os.getuid()).pw_dir


def environment():
    uid = str(os.getuid())
    user = pwd.getpwuid(os.getuid())
    return {"PATH": "/usr/bin:/bin", "HOME": home(), "USER": user.pw_name, "LOGNAME": user.pw_name,
            "LANG": "C", "LC_ALL": "C", "XDG_RUNTIME_DIR": "/run/user/" + uid,
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/" + uid + "/bus",
            "SYSTEMD_PAGER": "cat", "SYSTEMD_COLORS": "0"}


def run(argv, timeout, env_extra=None, *, stdin=None):
    """Bounded child; returns (exit code, stdout bytes). Diagnostics are discarded."""
    env = environment()
    env.update(env_extra or {})
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL if stdin is None else stdin,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=env, start_new_session=True)
    output, deadline = bytearray(), time.monotonic() + timeout
    try:
        streams = [process.stdout, process.stderr]
        while streams:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "Native command deadline exceeded: " + os.path.basename(argv[0]))
            for stream in select.select(streams, [], [], remaining)[0]:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    streams.remove(stream)
                elif stream is process.stdout:
                    output.extend(chunk)
                    require(len(output) <= OUTPUT_LIMIT, "Native command output exceeds bound")
        return process.wait(timeout=max(0.01, deadline - time.monotonic())), bytes(output)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, 9)
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def podman(*args, timeout=60):
    return run([PODMAN, *args], timeout)


def systemctl(*args, timeout=60):
    return run([SYSTEMCTL, "--user", "--no-ask-password", "--no-pager", *args], timeout)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------------- facts

def architecture(value):
    return {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "arm"}.get(value, value)


def linger():
    try:
        return (Path("/var/lib/systemd/linger") / pwd.getpwuid(os.getuid()).pw_name).exists()
    except OSError:
        return None


def unprivileged_port_start():
    """net.ipv4.ip_unprivileged_port_start of this network namespace (applies to IPv6 too)."""
    try:
        return int(Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text().strip())
    except (OSError, ValueError):
        return None


def host_addresses():
    """Addresses assigned in the host network namespace (`ip -j address show`), or None if unknown."""
    tool = next((path for path in IP_CANDIDATES if os.access(path, os.X_OK)), None)
    if tool is None:
        return None
    code, out = run([tool, "-j", "address", "show"], 15)
    if code != 0:
        return None
    result = []
    for link in json.loads(out or b"[]"):
        for info in link.get("addr_info") or []:
            local, prefix = info.get("local"), info.get("prefixlen")
            if isinstance(local, str) and type(prefix) is int:
                try:
                    network = str(ipaddress.ip_network(local + "/" + str(prefix), strict=False))
                except ValueError:
                    continue
                result.append({"ifname": link.get("ifname"), "address": local, "prefixlen": prefix,
                               "network": network, "scope": info.get("scope")})
    return result


def facts(payload):
    require(os.getuid() != 0, "Rootful execution is forbidden")
    code, out = podman("--version", timeout=15)
    require(code == 0, "Podman is not available")
    version = out.decode().strip().rsplit(" ", 1)[-1]
    code, info = podman("info", "--format", "json", timeout=30)
    require(code == 0, "podman info failed")
    info = json.loads(info)
    host = info.get("host", {})
    rootless = host.get("security", {}).get("rootless")
    code, state = systemctl("is-system-running", timeout=15)
    return {"uid": os.getuid(), "user": pwd.getpwuid(os.getuid()).pw_name, "home": home(),
            "architecture": architecture(platform.machine()), "podman_version": version,
            "podman_arch": host.get("arch"), "rootless": rootless is True,
            "quadlet": os.access(QUADLET, os.X_OK),
            "skopeo": next((path for path in SKOPEO_CANDIDATES if os.access(path, os.X_OK)), None),
            "user_manager": state.decode().strip() or "unknown", "linger": linger(),
            "grep": os.access("/usr/bin/grep", os.X_OK),
            # Pods need the pause binary: Podman builds its pause/service image from `catatonit`,
            # found in its helper directories or on PATH. Debian ships it as a separate package.
            "catatonit": next((path for path in CATATONIT_CANDIDATES if os.access(path, os.X_OK)), None),
            # Rootless Podman binds host ports from the user's own process in this namespace.
            "unprivileged_port_start": unprivileged_port_start(), "addresses": host_addresses(),
            "storage": storage_space((info.get("store") or {}).get("graphRoot"))}


def storage_space(graph_root):
    """Podman's image storage (graphRoot) and the space free there, or None when unknown."""
    if not isinstance(graph_root, str) or not graph_root.startswith("/"):
        return None
    try:
        info = os.statvfs(graph_root)
    except OSError:
        return {"graph_root": graph_root, "free_bytes": None}
    return {"graph_root": graph_root, "free_bytes": info.f_bavail * info.f_frsize, "size_bytes": info.f_blocks * info.f_frsize}


def device_state(path):
    """Read-only facts of one host device node (never opened): type, numbers, ownership, mode, who can open it
    and, for a DRM render node, the GPU behind it."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {"path": path, "exists": False}
    except OSError as error:
        return {"path": path, "exists": None, "error": type(error).__name__}
    mode = stat.S_IMODE(info.st_mode)
    state = {"path": path, "exists": True, "symlink": stat.S_ISLNK(info.st_mode), "char": stat.S_ISCHR(info.st_mode),
             "block": stat.S_ISBLK(info.st_mode), "uid": info.st_uid, "gid": info.st_gid, "mode": "%04o" % mode,
             "readable": os.access(path, os.R_OK), "writable": os.access(path, os.W_OK)}
    if state["char"] or state["block"]:
        state.update(major=os.major(info.st_rdev), minor=os.minor(info.st_rdev))
    try:
        state["owner"] = pwd.getpwuid(info.st_uid).pw_name
    except KeyError:
        state["owner"] = None
    try:
        group = grp.getgrgid(info.st_gid)
        state.update(group=group.gr_name, group_members=sorted(group.gr_mem)[:32])
    except KeyError:
        state.update(group=None, group_members=[])
    if path.startswith("/dev/dri/") and state["char"]:
        sysfs = Path("/sys/class/drm") / Path(path).name / "device"
        gpu = {}
        for key in ("vendor", "device", "mem_info_vram_total", "mem_info_vram_used"):
            try:
                gpu[key] = (sysfs / key).read_text().strip()[:64]
            except OSError:
                gpu[key] = None
        try:
            gpu["driver"] = os.path.basename(os.readlink(sysfs / "driver"))
            gpu["pci"] = os.path.basename(os.path.realpath(sysfs))
        except OSError:
            gpu.update(driver=None, pci=None)
        state["gpu"] = gpu
    return state


def sub_path_state(base, sub_path):
    """Read-only: `base/sub_path` must be a directory reached without any symlink (it cannot leave the dataset)."""
    target = os.path.join(base, sub_path)
    state = {"sub_path": sub_path, "path": target}
    current, info = base, None
    for part in sub_path.split("/"):
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return {**state, "exists": False}
        except OSError as error:
            return {**state, "exists": None, "error": type(error).__name__}
        if stat.S_ISLNK(info.st_mode):
            return {**state, "exists": True, "symlink": True}
    mode = stat.S_IMODE(info.st_mode)
    state.update(exists=True, symlink=False, directory=stat.S_ISDIR(info.st_mode), owner_uid=info.st_uid, mode="%04o" % mode,
                 readable=os.access(target, os.R_OK | os.X_OK), other_readable=mode & 0o005 == 0o005)
    if state["directory"] and state["readable"]:
        entries = []
        with os.scandir(target) as found:
            for entry in found:
                if len(entries) >= 64:
                    break
                item = entry.stat(follow_symlinks=False)
                entries.append({"name": entry.name[:255], "size": item.st_size, "mode": "%04o" % stat.S_IMODE(item.st_mode),
                                "regular": stat.S_ISREG(item.st_mode)})
        state["entries"] = sorted(entries, key=lambda item: item["name"])
    return state


# ----------------------------------------------------------------- listeners

def _address(hex_value):
    raw = bytes.fromhex(hex_value)
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw[::-1])
    words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    value = socket.inet_ntop(socket.AF_INET6, words)
    return value[7:] if value.startswith("::ffff:") and "." in value else value


def listeners():
    """Listening TCP and bound UDP sockets in this (host) network namespace."""
    result = set()
    for name, protocol in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
        try:
            lines = Path("/proc/net/" + name).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 4:
                continue
            local, state = fields[1], fields[3]
            if protocol == "tcp" and state != "0A":
                continue
            address, port = local.split(":")
            port = int(port, 16)
            if port:
                result.add((protocol, _address(address), port))
    return [{"protocol": p, "address": a, "port": n} for p, a, n in sorted(result)]


def port_conflicts(claims, observed=None):
    observed = listeners() if observed is None else observed
    wild = {"0.0.0.0", "::"}
    found = []
    for claim in claims:
        for item in observed:
            if item["protocol"] == claim["protocol"] and item["port"] == claim["port"] and (
                    item["address"] == claim["address"] or item["address"] in wild or claim["address"] in wild):
                found.append(item)
    return found


def upgrade_listeners(previous):
    """Only exact non-wildcard claims of the proven active old generation may be ignored."""
    observed = listeners()
    if previous["state"] != "active":
        return observed
    claims = {(c["protocol"], c["address"], c["port"]) for c in previous["claims"]}
    return [item for item in observed if item["address"] in ("0.0.0.0", "::")
            or (item["protocol"], item["address"], item["port"]) not in claims]


# ----------------------------------------------------------------- images

ACCEPT = ", ".join(["application/vnd.oci.image.index.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json"])


def split_reference(reference):
    name, _, digest = reference.partition("@")
    tag = None
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = name.rsplit(":", 1)
    registry, _, repository = name.partition("/")
    require("." in registry or ":" in registry or registry == "localhost", "Image references must be fully qualified")
    return registry, repository, tag, digest or None


def _platforms(body):
    document = json.loads(body)
    if "manifests" in document:
        return sorted({(m.get("platform") or {}).get("os", "?") + "/" + (m.get("platform") or {}).get("architecture", "?")
                       for m in document["manifests"]})
    return None


def registry_document(reference, timeout=10):
    """Anonymous read-only registry v2 manifest fetch; no credentials are used. Returns (bytes, sha256 digest)."""
    registry, repository, tag, digest = split_reference(reference)
    api = "registry-1.docker.io" if registry == "docker.io" else registry
    url = "https://" + api + "/v2/" + repository + "/manifests/" + (digest or tag)
    context = ssl.create_default_context()

    def fetch(token=None):
        request = urllib.request.Request(url, headers={"Accept": ACCEPT, **({"Authorization": "Bearer " + token} if token else {})})
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(OUTPUT_LIMIT + 1)
            require(len(body) <= OUTPUT_LIMIT, "Registry manifest exceeds bound")
            return body, response.headers.get("Docker-Content-Digest")

    try:
        body, header = fetch()
    except urllib.error.HTTPError as error:
        challenge = error.headers.get("WWW-Authenticate", "")
        require(error.code == 401 and challenge.lower().startswith("bearer "), "Registry refused anonymous manifest access")
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        require(params.get("realm", "").startswith("https://"), "Registry token realm must use HTTPS")
        query = urllib.parse.urlencode({key: params[key] for key in ("service", "scope") if key in params})
        with urllib.request.urlopen(params["realm"] + ("?" + query if query else ""), timeout=timeout, context=context) as response:
            token = json.loads(response.read(65536)).get("token") or ""
        require(token, "Registry did not issue an anonymous token")
        body, header = fetch(token)
    computed = "sha256:" + sha256(body)
    require(header in (None, computed), "Registry digest header does not match manifest bytes")
    require(digest in (None, computed), "Registry manifest bytes do not match the requested digest")
    return body, computed


def registry_manifest(reference, timeout=10):
    body, computed = registry_document(reference, timeout)
    return computed, _platforms(body)


def registry_size(reference, arch, timeout=10):
    """Compressed size (config + layers) of the linux/<arch> image that `reference` (pinned by digest) names, from
    anonymous registry reads; None when the registry does not report it."""
    document = json.loads(registry_document(reference, timeout)[0])
    if "manifests" in document:
        match = next((m for m in document["manifests"] if isinstance(m, dict) and (m.get("platform") or {}).get("os") == "linux"
                      and (m.get("platform") or {}).get("architecture") == arch), None)
        if match is None or not isinstance(match.get("digest"), str):
            return None
        registry, repository, _, _ = split_reference(reference)
        document = json.loads(registry_document(registry + "/" + repository + "@" + match["digest"], timeout)[0])
    layers = document.get("layers")
    sizes = [item.get("size") if isinstance(item, dict) else None for item in layers or []]
    sizes.append((document.get("config") or {}).get("size"))
    if not isinstance(layers, list) or not all(type(size) is int and size >= 0 for size in sizes):
        return None
    return {"bytes": sum(sizes), "layers": len(layers)}


def image_facts(repository, digest, arch):
    """Pinned image: compressed size where the registry reports it, and whether the local store holds that digest."""
    reference = repository + "@" + digest
    try:
        size = registry_size(reference, arch)
    except (Refusal, OSError, ValueError, KeyError, urllib.error.URLError):
        size = None
    local = local_image(reference)
    present = bool(local and digest in [d.split("@", 1)[1] for d in local["repo_digests"]])
    return {"size": size, "local": present, "image_id": local["image_id"] if present else None}


def resolve_image(image, arch):
    """Tag → digest without pulling: skopeo, then anonymous registry API, then local store."""
    reference = image["reference"]
    attempts = []
    skopeo = next((path for path in SKOPEO_CANDIDATES if os.access(path, os.X_OK)), None)
    if skopeo:
        code, out = run([skopeo, "inspect", "--raw", "docker://" + reference], 45)
        if code == 0 and out:
            return {"method": "skopeo", "digest": "sha256:" + sha256(out), "platforms": _platforms(out)}
        attempts.append("skopeo inspect failed")
    try:
        digest, platforms = registry_manifest(reference)
        return {"method": "registry-api", "digest": digest, "platforms": platforms}
    except (Refusal, OSError, ValueError, KeyError, urllib.error.URLError) as error:
        attempts.append("registry API: " + (str(error) if isinstance(error, Refusal) else type(error).__name__))
    local = local_image(reference)
    if local and local.get("digest"):
        return {"method": "local-store", "digest": local["digest"], "platforms": ["linux/" + str(local.get("architecture"))],
                "warning": "Resolved from the local image store; the registry tag may have moved", "attempts": attempts}
    return {"method": "pull-at-apply", "digest": None, "platforms": None, "attempts": attempts}


def local_image(reference):
    code, out = podman("image", "inspect", reference, timeout=30)
    if code != 0:
        return None
    records = json.loads(out)
    record = records[0] if isinstance(records, list) and len(records) == 1 else None
    if record is None:
        return None
    registry, repository, _, _ = split_reference(reference)
    names = {registry + "/" + repository}
    if registry == "docker.io":
        names.add("docker.io/library/" + repository)
    digests = sorted(d for d in record.get("RepoDigests") or [] if d.split("@")[0] in names)
    image_id = record.get("Id", "")
    return {"image_id": image_id if image_id.startswith("sha256:") else "sha256:" + image_id,
            "digest": digests[0].split("@", 1)[1] if digests else None, "repo_digests": digests,
            "architecture": record.get("Architecture"), "os": record.get("Os")}


def pull(payload):
    reference = payload["image"]["pull_reference"]
    if payload.get("local_only"):
        # A large image is pulled beforehand by a detached pull (`deploy pull-start`); apply only verifies it is there.
        require(payload["image"].get("digest"), "A local-only image needs its pinned digest")
    else:
        code, _ = podman("pull", "--quiet", reference, timeout=payload.get("timeout", 150))
        require(code == 0, "Image pull failed (diagnostics withheld)")
    record = local_image(reference)
    require(record and record["digest"], "Image is not in the local store" if payload.get("local_only")
            else "Pulled image has no registry digest")
    expected = payload["image"].get("digest")
    if expected:
        require(expected in [d.split("@", 1)[1] for d in record["repo_digests"]], "Pulled image digest differs from plan")
        record["digest"] = expected
    require(architecture(record["architecture"] or "") == payload["architecture"] and record["os"] == "linux",
            "Pulled image platform does not match host architecture")
    return {"status": "succeeded", "image": record}


# ----------------------------------------------------------------- detached pulls

def pull_paths(digest):
    require(isinstance(digest, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is not None,
            "Detached pulls are by sha256 digest")
    short = digest.split(":", 1)[1][:16]
    return {"directory": Path(home()) / PULLS / short, "unit": "switchyard-pull-" + short + ".service"}


def _pull_progress(directory):
    """Counts read from the pull's log; the log text itself is never returned."""
    try:
        data = read_bytes(directory / "log", 4 * 1024 * 1024)
    except FileNotFoundError:
        return None
    except Refusal:
        return {"unreadable": True}
    text = data.decode("utf-8", "replace")
    return {"blobs_started": len(set(re.findall(r"Copying blob (?:sha256:)?([a-f0-9]{12,64})", text))),
            "config_copied": "Copying config" in text, "manifest_written": "Writing manifest" in text, "log_bytes": len(data)}


def pull_state(payload):
    """Read-only: one image's detached pull on this host (unit, request, outcome, progress) and the local store."""
    repository, digest = payload["repository"], payload["digest"]
    paths = pull_paths(digest)
    directory = paths["directory"]
    unit = unit_state(paths["unit"])
    running = unit.get("LoadState") == "loaded" and unit.get("ActiveState") in ("active", "activating", "deactivating", "reloading")
    try:
        request = json.loads(read_bytes(directory / "request.json", 65536))
    except FileNotFoundError:
        request = None
    except (Refusal, ValueError):
        request = "unreadable"
    try:
        result = read_bytes(directory / "result", 64).decode().strip()
    except FileNotFoundError:
        result = None
    except (Refusal, UnicodeDecodeError):
        result = "unreadable"
    local = local_image(repository + "@" + digest)
    present = bool(local and digest in [d.split("@", 1)[1] for d in local["repo_digests"]])
    if running:
        state = "running"
    elif present:
        state = "present" if request is None else "succeeded"
    elif request is None:
        state = "absent"
    elif result is None:
        state = "interrupted"  # stopped before podman returned (RuntimeMaxSec, reboot, session end, kill)
    else:
        state = "failed"
    return {"state": state, "unit": paths["unit"],
            "unit_state": {key: unit.get(key) for key in ("LoadState", "ActiveState", "SubState", "Result")},
            "present": present, "image_id": local["image_id"] if present else None, "exit_code": result,
            "request": request if isinstance(request, dict) else None, "progress": _pull_progress(directory),
            "observed_at": stamp()}


def pull_status(payload):
    return {"status": "succeeded", "pull": pull_state(payload)}


def pull_start(payload):
    """Start one detached `podman pull` of a pinned image under the user's systemd manager (transient unit, bounded
    by RuntimeMaxSec), after bounded disk checks. At most one per image digest: a running or finished pull is
    reported, never started twice. Its outcome is written to a file, so it is readable after any disconnect."""
    state = pull_state(payload)
    if state["state"] in ("running", "present", "succeeded"):
        return {"status": "succeeded", "started": False, "pull": state}
    space = facts(payload)["storage"]
    require(space is not None and space.get("free_bytes") is not None,
            "Free space in Podman's image storage is unknown; no pull started")
    size = payload.get("size_bytes")
    # Layers unpack to more than their compressed size; without a registry size, demand a fixed floor.
    required = 3 * size + GIB if isinstance(size, int) else 20 * GIB
    require(space["free_bytes"] >= required, "Not enough free space in " + space["graph_root"] + ": "
            + str(space["free_bytes"]) + " bytes free, " + str(required) + " required; no pull started")
    paths = pull_paths(payload["digest"])
    reference = payload["repository"] + "@" + payload["digest"]
    directory = owned_dir(paths["directory"], create=True)
    for name in ("result", "result.tmp"):
        remove_file(directory / name)  # an earlier attempt's outcome
    request = {"repository": payload["repository"], "digest": payload["digest"], "reference": reference,
               "size_bytes": size, "layers": payload.get("layers"), "required_free_bytes": required,
               "free_bytes_at_start": space["free_bytes"], "graph_root": space["graph_root"],
               "operation_id": payload.get("operation_id"), "started_at": stamp(), "max_seconds": PULL_MAX_SECONDS}
    replace_file(directory / "request.json", json.dumps(request, sort_keys=True).encode(), 0o600)
    try:
        code, _ = run([SYSTEMD_RUN, "--user", "--quiet", "--collect", "--unit=" + paths["unit"],
                       "--description=Switchyard image pull " + reference,
                       "--property=RuntimeMaxSec=" + str(PULL_MAX_SECONDS), "--",
                       "/bin/sh", "-c", PULL_SCRIPT, "switchyard-pull", PODMAN, reference, str(directory)], 30)
    except Exception as error:
        return {"status": "needs-inspection", "started": None, "error": "Starting the detached pull did not finish ("
                + (str(error) if isinstance(error, Refusal) else type(error).__name__) + "); read its status"}
    if code != 0:
        return {"status": "failed", "started": False, "error": "systemd-run could not start the detached pull",
                "pull": pull_state(payload)}
    time.sleep(1)
    return {"status": "succeeded", "started": True, "pull": pull_state(payload)}


# ----------------------------------------------------------------- files

def owned_dir(path, *, create=False, mode=0o700):
    """Every component below $HOME must be a real directory owned by this user."""
    path, root = Path(path), Path(home())
    require(path == root or root in path.parents, "Owned paths must be below the account home")
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            require(create, "Missing directory: " + str(current))
            os.mkdir(current, mode)
            info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), "Symlink or foreign directory in owned path: " + str(current))
    return path


def read_bytes(path, limit=1048576):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_size <= limit,
                "Owned file must be a bounded regular file: " + str(path))
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read(limit + 1)
    finally:
        os.close(fd)


def file_sha(path):
    try:
        return sha256(read_bytes(path))
    except FileNotFoundError:
        return None


def _temp(path, data, mode):
    temp = path.parent / ("." + path.name + ".switchyard-" + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return temp


def _sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_file(path, data, mode):
    """Atomic create that never replaces an existing name (link fails on EEXIST)."""
    path = Path(path)
    temp = _temp(path, data, mode)
    try:
        os.link(temp, path)
    finally:
        os.unlink(temp)
    _sync_dir(path.parent)


def replace_file(path, data, mode):
    path = Path(path)
    temp = _temp(path, data, mode)
    os.replace(temp, path)
    _sync_dir(path.parent)


def remove_file(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), "Refusing to remove non-regular file: " + str(path))
    os.unlink(path)
    _sync_dir(Path(path).parent)
    return True


def tree_size(path, limit=200000):
    total, files, count, partial = 0, 0, 0, False
    stack = [str(path)]
    while stack:
        with os.scandir(stack.pop()) as entries:
            for entry in entries:
                count += 1
                if count > limit:
                    return {"bytes": total, "files": files, "partial": True}
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    stack.append(entry.path)
                else:
                    files += 1
                    total += info.st_size
    return {"bytes": total, "files": files, "partial": partial}


def dataset_state(item):
    path = Path(item["path"])
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {**item, "exists": False}
    state = {**item, "exists": True, "directory": stat.S_ISDIR(info.st_mode), "symlink": stat.S_ISLNK(info.st_mode),
             "owner_uid": info.st_uid, "mode": oct(stat.S_IMODE(info.st_mode))}
    if state["directory"] and not state["symlink"]:
        state["readable"] = os.access(path, os.R_OK | os.X_OK)
        state["empty"] = not any(os.scandir(path))
        state.update(size=tree_size(path))
    return state


# ----------------------------------------------------------------- tokens

def identity_line(payload):
    return (TOKEN_FORMAT + " application=" + payload["instance_id"] + " component=" + payload["component"]
            + " generation=" + str(payload["generation"]) + " ownership-id=" + payload["ownership_id"])


def token_state(payload):
    try:
        lines = read_bytes(payload["paths"]["token"], 4096).decode().splitlines()
    except FileNotFoundError:
        return {"state": "absent"}
    if lines and lines[0] == identity_line(payload):
        return {"state": "valid", "issued_at": lines[1].partition("=")[2] if len(lines) > 1 else None}
    revoked = TOKEN_FORMAT + " revoked " + identity_line(payload)[len(TOKEN_FORMAT) + 1:]
    if lines and lines[0] == revoked:
        return {"state": "revoked", "revoked_at": lines[1].partition("=")[2] if len(lines) > 1 else None}
    return {"state": "foreign"}


def issue_token(payload, *, create=False):
    issued = stamp()
    data = (identity_line(payload) + "\nissued_at=" + issued + "\n").encode()
    (create_file if create else replace_file)(payload["paths"]["token"], data, 0o600)
    return issued


def revoke_token(payload):
    revoked = stamp()
    line = TOKEN_FORMAT + " revoked " + identity_line(payload)[len(TOKEN_FORMAT) + 1:]
    replace_file(payload["paths"]["token"], (line + "\nrevoked_at=" + revoked + "\n").encode(), 0o600)
    require(token_state(payload)["state"] == "revoked", "Token revocation did not verify")
    return revoked


# ----------------------------------------------------------------- native state

def unit_state(service):
    code, out = systemctl("show", "--property=LoadState,ActiveState,SubState,FragmentPath,SourcePath,InvocationID,NeedDaemonReload,Result,DropInPaths",
                          "--", service, timeout=30)
    require(code == 0, "systemctl show failed")
    return dict(line.split("=", 1) for line in out.decode().splitlines() if "=" in line)


def pod_record(name):
    code, _ = podman("pod", "exists", name, timeout=30)
    if code != 0:
        return None
    code, out = podman("pod", "inspect", name, timeout=30)
    require(code == 0, "podman pod inspect failed")
    value = json.loads(out)
    if isinstance(value, list):
        require(len(value) == 1, "Ambiguous pod inspect")
        value = value[0]
    return {"id": value.get("Id"), "name": value.get("Name"), "state": value.get("State"),
            "labels": value.get("Labels") or {},
            "containers": sorted(({"id": c.get("Id"), "name": c.get("Name"), "state": c.get("State")}
                                  for c in value.get("Containers") or []), key=lambda c: c["name"] or ""),
            "service_container_id": value.get("ServiceContainerID") or value.get("ServiceContainerId"),
            "infra_container_id": value.get("InfraContainerID") or value.get("InfraContainerId")}


def container_devices(pod, names):
    """Devices the running containers `names` of `pod` really have, read from each container's OCI runtime
    configuration (rootless Podman bind-mounts device nodes; rootful Podman lists them as devices):
    `{container name: [{"host", "container", "access"}]}`, or None for a container whose configuration is unreadable."""
    result = {}
    for container in pod["containers"]:
        if container["name"] not in names:
            continue
        code, out = podman("container", "inspect", container["id"], timeout=30)
        try:
            record = json.loads(out)[0] if code == 0 else {}
            config = json.loads(read_bytes(record["OCIConfigPath"], 4 * 1024 * 1024))
        except (Refusal, OSError, ValueError, KeyError, IndexError, TypeError):
            result[container["name"]] = None
            continue
        found = []
        for mount in config.get("mounts") or []:
            source = mount.get("source") or ""
            if mount.get("type") == "bind" and source.startswith("/dev/") and is_device_node(source):
                options = mount.get("options") or []
                found.append({"host": source, "container": mount.get("destination"),
                              "access": "read" if "ro" in options else "read-write"})
        for device in (config.get("linux") or {}).get("devices") or []:
            found.append({"host": None, "container": device.get("path"), "access": None})
        result[container["name"]] = sorted(found, key=lambda item: str(item["container"]))
    return result


def is_device_node(path):
    try:
        kind = os.stat(path).st_mode
    except OSError:
        return False
    return stat.S_ISCHR(kind) or stat.S_ISBLK(kind)


def labelled(key, value):
    code, out = podman("ps", "--all", "--no-trunc", "--filter", "label=" + key + "=" + value, "--format", "json", timeout=30)
    require(code == 0, "podman ps failed")
    return sorted(({"id": entry.get("Id"), "state": str(entry.get("State", "unknown")).lower()}
                   for entry in json.loads(out or b"[]") if entry.get("Id")), key=lambda item: item["id"])


def leftovers(payload):
    pod = pod_record(payload["names"]["pod"])
    return {"pod": pod, "owned_containers": labelled(LABEL + "ownership-id", payload["ownership_id"]),
            "unit_containers": labelled("PODMAN_SYSTEMD_UNIT", payload["names"]["service"])}


def verify_pod_owner(pod, payload):
    labels = pod["labels"]
    require(labels.get(LABEL + "ownership-id") == payload["ownership_id"]
            and labels.get(LABEL + "instance") == payload["instance_id"]
            and labels.get(LABEL + "generation") == str(payload["generation"]),
            "Pod with the deployment's name lacks this deployment's ownership labels")


def stop_and_verify(payload, timeout=120):
    """Stop the generated unit and prove nothing of this deployment keeps running."""
    service = payload["names"]["service"]
    state = unit_state(service)
    if state.get("LoadState") == "loaded" and state.get("ActiveState") not in ("inactive", "failed"):
        code, _ = systemctl("--job-mode=fail", "stop", "--", service, timeout=timeout)
        require(code == 0, "systemctl stop failed")
    state = unit_state(service)
    require(state.get("ActiveState") in ("inactive", "failed", None), "Unit did not stop")
    rest = leftovers(payload)
    require(rest["pod"] is None and not rest["owned_containers"], "Pod or owned containers of this deployment still exist after stop")
    # The kube service container carries only the unit label; it must not run, and is reported if left.
    running = [c for c in rest["unit_containers"] if c["state"] not in ("exited", "stopped", "created", "configured")]
    require(not running, "A container of the generated unit is still running after stop")
    return {"unit": {key: state.get(key) for key in ("LoadState", "ActiveState", "SubState")},
            "pod_absent": True, "containers_absent": True, "verified_at": stamp(),
            "unit_containers_left": [c["id"] for c in rest["unit_containers"]]}


DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33}
DNS_TYPE_NAMES = {value: key for key, value in DNS_TYPES.items()}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class _NotYet(Exception):
    """A check answered but did not pass yet (retried until the deadline)."""


def _dns_wire_name(name):
    data = b""
    for label in name.rstrip(".").split(".") if name.rstrip(".") else []:
        raw = label.encode("ascii")
        require(0 < len(raw) <= 63, "Invalid DNS name in check")
        data += bytes([len(raw)]) + raw
    return data + b"\0"


def _dns_read_name(message, offset):
    labels, end, jumps = [], None, 0
    while True:
        require(offset < len(message), "Truncated DNS name")
        length = message[offset]
        if length & 0xC0 == 0xC0:
            require(offset + 1 < len(message) and jumps < 32, "Invalid DNS name compression")
            end = offset + 2 if end is None else end
            offset, jumps = ((length & 0x3F) << 8) | message[offset + 1], jumps + 1
            continue
        require(length & 0xC0 == 0, "Unsupported DNS label type")
        offset += 1
        if length == 0:
            return ".".join(labels).lower(), end if end is not None else offset
        labels.append(message[offset:offset + length].decode("ascii", "replace"))
        offset += length


def _recv_exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        require(part, "DNS connection closed early")
        data += part
    return data


def dns_query(address, port, name, record_type, timeout, protocol="udp"):
    """One recursive-desired query (stdlib only); returns rcode and parsed answers."""
    qtype = DNS_TYPES[record_type]
    ident = int.from_bytes(os.urandom(2), "big")
    message = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + _dns_wire_name(name) + struct.pack("!HH", qtype, 1)
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    deadline = time.monotonic() + timeout
    if protocol == "udp":
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect((address, port))  # only datagrams from the server itself are received
            sock.send(message)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout("DNS reply timeout")
                sock.settimeout(remaining)
                reply = sock.recv(65535)
                if len(reply) >= 12 and reply[:2] == message[:2]:
                    break
    else:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            sock.sendall(struct.pack("!H", len(message)) + message)
            reply = _recv_exact(sock, struct.unpack("!H", _recv_exact(sock, 2))[0])
    require(len(reply) >= 12, "Short DNS reply")
    rid, flags, questions, count = struct.unpack("!HHHH", reply[:8])
    require(rid == ident and flags & 0x8000, "DNS reply does not answer the query")
    offset = 12
    for _ in range(questions):
        offset = _dns_read_name(reply, offset)[1] + 4
    answers = []
    for _ in range(count):
        owner, offset = _dns_read_name(reply, offset)
        require(offset + 10 <= len(reply), "Truncated DNS record")
        rtype, _, ttl, length = struct.unpack("!HHIH", reply[offset:offset + 10])
        start, offset = offset + 10, offset + 10 + length
        require(offset <= len(reply), "Truncated DNS record data")
        value = None
        if rtype == 1 and length == 4:
            value = socket.inet_ntop(socket.AF_INET, reply[start:offset])
        elif rtype == 28 and length == 16:
            value = socket.inet_ntop(socket.AF_INET6, reply[start:offset])
        elif rtype in (2, 5, 12):
            value = _dns_read_name(reply, start)[0]
        elif rtype == 16:
            parts, index = [], start
            while index < offset:
                parts.append(reply[index + 1:index + 1 + reply[index]].decode("utf-8", "replace"))
                index += 1 + reply[index]
            value = "".join(parts)
        answers.append({"name": owner, "type": DNS_TYPE_NAMES.get(rtype, str(rtype)), "ttl": ttl, "value": value})
    return {"rcode": DNS_RCODES.get(flags & 0xF, str(flags & 0xF)), "authoritative": bool(flags & 0x0400),
            "truncated": bool(flags & 0x0200), "answers": answers[:32]}


def dns_check(address, check):
    """`ok` when the reply is NOERROR with at least one answer of the type and every expected value."""
    reply = dns_query(address, check["port"], check["name"], check["record_type"], check["timeout_seconds"],
                      check.get("protocol", "udp"))
    values = [a["value"] for a in reply["answers"] if a["type"] == check["record_type"]]
    present = {str(v).rstrip(".").lower() for v in values if v is not None}
    missing = [e for e in check.get("expect", []) if e.rstrip(".").lower() not in present]
    ok = reply["rcode"] == "NOERROR" and bool(values) and not missing
    return ok, {"rcode": reply["rcode"], "answers": [v for v in values if v is not None][:8], "missing": missing}


def ready_deadline(check, deadline):
    """Retry deadline of one check: its declared readiness window from now (a model loading answers 503), inside the
    step deadline. Without a window, the step deadline (unchanged behaviour)."""
    window = check.get("ready_within_seconds")
    return min(deadline, time.monotonic() + window) if window else deadline


def expected_devices(payload):
    """`{native container name: [{host, container, access}]}` journaled for this deployment; None when it declares
    no device (nothing to compare)."""
    if not payload.get("devices"):
        return None
    result = {name: [] for name in payload["names"]["containers"]}
    for device in payload["devices"]:
        result.setdefault(device["container_name"], []).append(
            {"host": device["host"], "container": device["container"], "access": device["access"]})
    return {name: sorted(items, key=lambda item: item["container"]) for name, items in result.items()}


def check_devices(pod, payload):
    """The running containers must have exactly the journaled devices (read from their OCI configuration)."""
    expected = expected_devices(payload)
    if expected is None:
        return None
    observed = container_devices(pod, set(expected))
    drift = sorted(name for name in expected if observed.get(name) != expected[name])
    require(not drift, "Running container(s) " + ", ".join(drift) + " do not have exactly the declared devices")
    return observed


def health(check, deadline):
    """One declared http/tcp/dns check against the claimed bind, retried until the step deadline."""
    address = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(check["address"], check["address"])
    attempts, last = 0, None
    while True:
        attempts += 1
        try:
            if check["type"] == "tcp":
                with socket.create_connection((address, check["port"]), timeout=check["timeout_seconds"]):
                    return {"ok": True, "attempts": attempts, "type": "tcp", "at": stamp()}
            if check["type"] == "dns":
                ok, last = dns_check(address, check)
                if ok:
                    return {"ok": True, "attempts": attempts, "type": "dns", **last, "at": stamp()}
                raise _NotYet()
            factory = http.client.HTTPSConnection if check["scheme"] == "https" else http.client.HTTPConnection
            connection = factory(address, check["port"], timeout=check["timeout_seconds"])
            try:
                connection.request("GET", check["path"])
                response = connection.getresponse()
                body = response.read(1048577)
                status = response.status
            finally:
                connection.close()
            body_ok = check.get("body_sha256") is None or sha256(body) == check["body_sha256"]
            last = {"status": status, "body_sha256": sha256(body)}
            if status == check["status"] and body_ok:
                return {"ok": True, "attempts": attempts, "type": "http", "status": status,
                        "body_sha256": sha256(body), "at": stamp()}
        except _NotYet:
            pass
        except (OSError, http.client.HTTPException, Refusal, struct.error, UnicodeError) as error:
            last = {"error": str(error) if isinstance(error, Refusal) else type(error).__name__}
        if time.monotonic() + 1 >= deadline:
            return {"ok": False, "attempts": attempts, "last": last, "at": stamp()}
        time.sleep(1)


# ----------------------------------------------------------------- inspection

def collisions(payload, *, allow_owned=False):
    found = []
    names, paths = payload["names"], payload["paths"]
    roots = [Path(home()) / ".config/containers/systemd", Path("/etc/containers/systemd/users") / str(os.getuid()),
             Path("/etc/containers/systemd/users"), Path(home()) / ".config/systemd/user"]
    stem = names["unit_file"][:-len(".kube")]
    for root in roots:
        for suffix in QUADLET_SUFFIXES + (".service",):
            candidate = root / (stem + suffix)
            if candidate.exists() or candidate.is_symlink():
                if not (allow_owned and str(candidate) == paths["unit"]):
                    found.append("file exists: " + str(candidate))
    state = unit_state(names["service"])
    if state.get("LoadState") not in ("not-found", None) and not allow_owned:
        found.append("systemd unit already known: " + names["service"] + " (" + state.get("LoadState", "?") + ")")
    pod = pod_record(names["pod"])
    if pod is not None and not (allow_owned and pod["labels"].get(LABEL + "ownership-id") == payload["ownership_id"]):
        found.append("pod exists: " + names["pod"])
    for container in names["containers"]:
        code, _ = podman("container", "exists", container, timeout=30)
        if code == 0 and not allow_owned:
            found.append("container exists: " + container)
    app = Path(paths["app_dir"])
    if (app.exists() or app.is_symlink()) and not allow_owned:
        entries = sorted(os.listdir(app)) if app.is_dir() and not app.is_symlink() else ["<not a directory>"]
        retained = set(payload.get("retained_entries") or [])
        if not set(entries) <= retained:
            found.append("application directory exists with unexpected entries: " + str(app) + " " + ", ".join(entries))
    return found


def host_generation(payload):
    try:
        return int(read_bytes(Path(payload["paths"]["app_dir"]) / "generation", 64).decode().strip())
    except FileNotFoundError:
        return None


def quadlet_dryrun(payload):
    """Render the exact unit into a private temp dir and ask Quadlet what it would generate."""
    if not os.access(QUADLET, os.X_OK):
        return {"ok": False, "reason": "quadlet generator not found"}
    import tempfile
    directory = tempfile.mkdtemp(prefix="switchyard-quadlet-")
    try:
        Path(directory, payload["names"]["unit_file"]).write_text(payload["unit_text"])
        code, out = run([QUADLET, "-dryrun", "-user"], 30, {"QUADLET_UNIT_DIRS": directory})
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    text = out.decode("utf-8", "replace")
    marker = "---" + payload["names"]["service"] + "---"
    body = text.split(marker, 1)[1] if marker in text else ""
    lines = set(body.splitlines())
    gate = "ExecStartPre=" + payload["gate_command"]
    execs = [line for line in lines if line.startswith("ExecStart=") and " kube play " in line]
    return {"ok": code == 0 and bool(body) and gate in lines and any(line.endswith(" " + payload["paths"]["yaml"]) for line in execs),
            "generated_sha256": sha256(body.encode()) if body else None, "gate_present": gate in lines,
            "exec_start": execs[0] if execs else None,
            "exec_stop_post": next((line for line in lines if line.startswith("ExecStopPost=")), None),
            # Podman 5.3+ orders rootless Quadlet units after this helper, which polls the SYSTEM manager's
            # network-online.target for up to 90 s before every start.
            "waits_network_online": "podman-user-wait-network-online.service" in body}


def network_online():
    """Whether the system manager's network-online.target is active (read-only)."""
    _, out = run([SYSTEMCTL, "--no-pager", "is-active", "network-online.target"], 15)
    return out.decode("utf-8", "replace").strip() == "active"


def inspect(payload):
    if "previous" in payload:
        upgrade_check(payload)
    datasets = []
    for item in payload["datasets"]:
        state = dataset_state({k: v for k, v in item.items() if k != "sub_paths"})
        if item.get("sub_paths") and state.get("directory") and not state.get("symlink"):
            state["sub_paths"] = [sub_path_state(item["path"], sub) for sub in item["sub_paths"]]
        datasets.append(state)
    observed = upgrade_listeners(payload["previous"]) if "previous" in payload else listeners()
    result = {"facts": facts(payload), "listeners": observed,
              "collisions": [] if "previous" in payload else collisions(payload),
              "datasets": datasets, "devices": [device_state(path) for path in payload.get("devices") or []],
              "host_generation": host_generation(payload), "quadlet": quadlet_dryrun(payload)}
    if result["quadlet"].get("waits_network_online"):
        result["network_online"] = network_online()
    image = payload["image"]
    local = local_image(image["pull_reference"]) if image.get("digest") else None
    if image.get("digest"):
        result["image"] = {"method": "pinned", "digest": image["digest"], "local": local is not None}
    else:
        result["image"] = resolve_image(image, result["facts"]["architecture"])
    if result["image"].get("digest"):
        result["image"]["store"] = image_facts(image["repository"], result["image"]["digest"], result["facts"]["architecture"])
    return {"status": "succeeded", "inspection": result}


# ----------------------------------------------------------------- ownership

def owner_record(payload):
    return {"ownership_id": payload["ownership_id"], "instance": payload["instance_id"],
            "component": payload["component"], "generation": payload["generation"], "uid": os.getuid()}


def verify_owned(payload):
    """Present resources must all carry this deployment's identity; missing files are reported."""
    paths, expected = payload["paths"], payload["files"]
    report = {"present": {}, "missing": []}
    try:
        owner = json.loads(read_bytes(paths["owner"], 4096))
    except FileNotFoundError:
        owner = None
    if owner is not None:
        require(owner == owner_record(payload), "owner.json belongs to a different deployment")
    for key in ("unit", "yaml"):
        digest = file_sha(paths[key])
        if digest is None:
            report["missing"].append(key)
        else:
            require(digest == expected[key], "Refusing: " + key + " file differs from the recorded deployment hash")
            report["present"][key] = digest
    token = token_state(payload)
    require(token["state"] != "foreign", "Token file belongs to a different deployment")
    pod = pod_record(payload["names"]["pod"])
    if pod is not None:
        verify_pod_owner(pod, payload)
    require(owner is not None or not report["present"], "Deployment files exist without an ownership marker")
    report.update(owner_present=owner is not None, token=token, pod=pod, unit_state=unit_state(payload["names"]["service"]))
    return report


# ----------------------------------------------------------------- configuration files

def config_state(payload, *, texts_for=()):
    """Recorded configuration files on the host: sha256, `missing` or `unreadable`, plus unexpected names.
    `texts_for`: names whose UTF-8 text is returned (bounded), for plan diffs."""
    recorded = payload.get("config") or []
    directory = payload["paths"].get("config_dir")
    if not recorded or not directory:
        return {"files": {}, "extra": [], "texts": {}}
    files, texts, budget = {}, {}, CONFIG_TEXT_BUDGET
    try:
        info = os.lstat(directory)
        usable = stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
    except FileNotFoundError:
        return {"files": {item["name"]: "missing" for item in recorded}, "extra": [], "texts": {}}
    if not usable:
        return {"files": {item["name"]: "unreadable" for item in recorded}, "extra": [], "texts": {}}
    for item in recorded:
        try:
            data = read_bytes(Path(directory) / item["name"], CONFIG_LIMIT)
        except FileNotFoundError:
            files[item["name"]] = "missing"
            continue
        except (Refusal, OSError):
            files[item["name"]] = "unreadable"
            continue
        files[item["name"]] = sha256(data)
        if item["name"] in texts_for and len(data) <= budget:
            try:
                texts[item["name"]] = data.decode()
                budget -= len(data)
            except UnicodeDecodeError:
                pass
    names = {item["name"] for item in recorded}
    extra = sorted(name for name in os.listdir(directory) if name not in names)[:32]
    return {"files": files, "extra": extra, "texts": texts}


def write_config(payload, files, *, create):
    """Write configuration files atomically (create: never replace; else rename over); verify each hash."""
    directory = Path(payload["paths"]["config_dir"])
    written = []
    for item in files:
        data = item["text"].encode()
        require(len(data) <= CONFIG_LIMIT and sha256(data) == item["sha256"], "Configuration file does not match the plan: " + item["name"])
        require("/" not in item["name"] and item["name"] not in (".", ".."), "Invalid configuration file name")
        (create_file if create else replace_file)(directory / item["name"], data, 0o644)
        written.append(item["name"])
        require(file_sha(directory / item["name"]) == item["sha256"], "Written configuration file does not verify: " + item["name"])
    return written


def address_assigned(address, addresses):
    if address in ("0.0.0.0", "::") or ipaddress.ip_address(address).is_loopback:
        return True
    return addresses is not None and any(item["address"] == address for item in addresses)


def upgrade_check(payload):
    """Read-only proof that the exact old generation can be replaced without touching foreign state."""
    previous = payload["previous"]
    names, paths = previous["names"], previous["paths"]
    require(previous.get("state") in ("active", "staged", "fenced"), "Unsupported previous placement state")
    expected_token = previous.get("expected_token")
    require(expected_token in ("valid", "revoked"), "Previous token expectation is required")
    require(previous["state"] != "active" or expected_token == "valid", "Active placement must have a valid token")
    require(previous["state"] != "fenced" or expected_token == "revoked", "Fenced placement must have a revoked token")
    require(all(payload["names"].get(key) == names[key] for key in ("unit_file", "service", "pod")),
            "Upgrade must preserve native unit and pod names")
    require(payload["paths"] == paths, "Upgrade must preserve native paths")
    owned_dir(paths["app_dir"])
    owned_dir(Path(paths["unit"]).parent)
    owned = verify_owned(previous)
    require(owned["owner_present"] and not owned["missing"], "Previous deployment files are incomplete")
    require(host_generation(previous) == previous["generation"], "Previous host generation differs from the journal")
    require(owned["token"]["state"] == expected_token, "Previous generation token differs from the journal")
    unit = owned["unit_state"]
    require(unit.get("LoadState") == "loaded" and unit.get("SourcePath") == paths["unit"]
            and unit.get("NeedDaemonReload") == "no" and not unit.get("DropInPaths"),
            "Previous generated unit is missing, competing or stale")
    generated = set(read_bytes(unit["FragmentPath"]).decode().splitlines())
    require("ExecStartPre=" + previous["gate_command"] in generated
            and any(line.startswith("ExecStart=") and " kube play " in line and line.endswith(" " + paths["yaml"])
                    for line in generated), "Previous generated unit differs from its source")
    current = config_state(previous)
    require(not current["extra"] and all(current["files"].get(item["name"]) == item["sha256"]
            for item in previous.get("config") or []), "Previous configuration differs from the journal")
    app_entries = {Path(paths[key]).name for key in ("owner", "yaml", "token")} | {"generation", "data"}
    config_dir = paths.get("config_dir")
    if config_dir and os.path.lexists(Path(config_dir).parent):
        root = owned_dir(Path(config_dir).parent)
        require(set(os.listdir(root)) <= ({Path(config_dir).name} if previous.get("config") else set()),
                "Unexpected entries in the previous configuration root")
        if previous.get("config"):
            owned_dir(config_dir)
        app_entries.add(root.name)
    require(set(os.listdir(paths["app_dir"])) <= app_entries, "Unexpected entries in the previous application directory")
    pod = owned["pod"]
    owned_containers = labelled(LABEL + "ownership-id", previous["ownership_id"])
    unit_containers = labelled("PODMAN_SYSTEMD_UNIT", names["service"])
    owned_ids = {item["id"] for item in owned_containers}
    for key, value in (("instance", previous["instance_id"]), ("component", previous["component"]),
                       ("generation", str(previous["generation"]))):
        require(owned_ids <= {item["id"] for item in labelled(LABEL + key, value)},
                "Containers carry foreign previous-generation labels")
    pod_containers = {item["name"]: item["id"] for item in pod["containers"]} if pod else {}
    pod_ids = set(pod_containers.values()) | ({pod.get("service_container_id")} if pod else set())
    require(owned_ids <= pod_ids, "Owned containers exist outside the previous pod")
    if previous["state"] == "active":
        require(unit.get("ActiveState") == "active" and pod is not None
                and str(pod["state"]).lower() == "running", "Previous active placement is not running consistently")
        require(pod["labels"].get(LABEL + "component") == previous["component"],
                "Previous pod has foreign component labels")
        require(set(names["containers"]) <= set(pod_containers)
                and {pod_containers[name] for name in names["containers"]} <= owned_ids,
                "Previous pod is missing its owned containers")
        require(set(pod_containers.values()) <= owned_ids | {pod.get("infra_container_id")}
                and all(str(item["state"]).lower() == "running" for item in pod["containers"]
                        if item["name"] in names["containers"]),
                "Previous pod contains foreign or stopped containers")
        allowed_unit_ids = pod_ids
        require(all(item["id"] in allowed_unit_ids for item in unit_containers),
                "Foreign container carries the previous unit label")
    else:
        require(unit.get("ActiveState") in ("inactive", "failed") and pod is None and not owned_containers,
                "Previous stopped placement has running native state")
        require(all(item["state"] in ("exited", "stopped", "created", "configured") for item in unit_containers),
                "A container of the previous stopped unit is still running")
    # allow_owned only skips the already-proven old files/pod; never trust it for container names.
    found = collisions({**payload, "ownership_id": previous["ownership_id"]}, allow_owned=True)
    for name in payload["names"]["containers"]:
        code, _ = podman("container", "exists", name, timeout=30)
        if code == 0 and (name not in names["containers"] or name not in pod_containers
                          or pod_containers[name] not in owned_ids):
            found.append("container exists: " + name)
    require(not found, "Upgrade collision: " + "; ".join(found))
    if "claims" in payload:
        # Apply-only checks: refuse environmental drift before stopping a healthy old generation.
        addresses = host_addresses()
        require(all(address_assigned(claim["address"], addresses) for claim in payload["claims"]),
                "Claimed address is no longer assigned on the host")
        require(not port_conflicts(payload["claims"], upgrade_listeners(previous)),
                "Claimed port is now in use by another listener")
        if "datasets" in payload:
            binding = lambda items: {item["id"]: (item["path"], bool(item.get("default"))) for item in items}
            require(binding(payload["datasets"]) == binding(previous["datasets"]),
                    "Upgrade dataset bindings differ from the previous generation")
            for item in payload["datasets"]:
                path = Path(item["path"])
                if item.get("default"):
                    owned_dir(path)
                info = path.lstat()
                require(stat.S_ISDIR(info.st_mode) and os.access(path, os.R_OK | os.X_OK),
                        "Upgrade dataset is no longer a readable directory: " + item["id"])
                for sub in item.get("sub_paths") or []:
                    state = sub_path_state(item["path"], sub)
                    require(state.get("directory") and state.get("symlink") is False and state.get("readable"),
                            "Upgrade dataset sub-path is no longer readable without symlinks: " + item["id"] + "/" + sub)
        for device in payload.get("devices") or []:
            path = device.get("host") or device["host_path"]
            state = device_state(path)
            expected = (device["major"], device["minor"]) if "major" in device else tuple(
                int(part) for part in (device.get("major_minor") or "").split(":"))
            require(state.get("char") and not state.get("symlink") and state.get("readable") and state.get("writable")
                    and (state.get("major"), state.get("minor")) == expected,
                    "Upgrade device changed since planning or cannot be opened: " + path)
    return {"status": "succeeded", "previous": {"generation": previous["generation"], "state": previous["state"],
            "token": owned["token"]}, "collisions": []}


# ----------------------------------------------------------------- mutations

def prepare(payload):
    written = []
    paths = payload["paths"]
    try:
        found = collisions(payload, allow_owned=False)
        require(not found, "Collision since planning: " + "; ".join(found))
        conflicts = port_conflicts(payload["claims"])
        require(not conflicts, "Port is now in use on the host")
        generation = host_generation(payload)
        require(generation == payload.get("expected_host_generation"), "Host generation high-water mark changed")
        addresses = host_addresses()
        missing = [c["address"] for c in payload["claims"] if not address_assigned(c["address"], addresses)]
        require(not missing, "Claimed address is no longer assigned on the host: " + ", ".join(sorted(set(missing))))
        for device in payload.get("devices") or []:
            state = device_state(device["host"])
            require(state.get("char") and not state.get("symlink") and state.get("readable") and state.get("writable")
                    and [state.get("major"), state.get("minor")] == [device.get("major"), device.get("minor")],
                    "Device " + device["host"] + " changed since planning or cannot be opened")
        for item in payload["datasets"]:
            for sub in item.get("sub_paths") or []:
                state = sub_path_state(item["path"], sub)
                require(state.get("directory") and state.get("symlink") is False and state.get("readable"),
                        "Dataset sub-path " + item["id"] + "/" + sub + " is no longer a readable directory without symlinks")
        app = owned_dir(paths["app_dir"], create=True)
        written.append("app_dir")
        create_file(paths["owner"], json.dumps(owner_record(payload), sort_keys=True).encode(), 0o600)
        written.append("owner")
        replace_file(app / "generation", (str(payload["generation"]) + "\n").encode(), 0o600)
        for item in payload["datasets"]:
            if item["default"]:
                owned_dir(item["path"], create=True, mode=0o755)
            else:
                state = dataset_state(item)
                require(state.get("directory") and not state.get("symlink") and state.get("readable"),
                        "Operator dataset path must be an existing readable directory: " + item["id"])
        if payload.get("config_files"):
            directory = owned_dir(paths["config_dir"], create=True, mode=0o755)
            os.chmod(directory, 0o755)  # readable by the container's user (mounted read-only)
            written.append("config")
            write_config(payload, payload["config_files"], create=True)
        create_file(paths["yaml"], payload["yaml_text"].encode(), 0o644)
        written.append("yaml")
        issued = issue_token(payload, create=True)
        written.append("token")
        revoked = None
        if payload.get("install") in ("fenced", "staged-revoked"):
            # Installed fenced: the token is revoked before the unit exists, so no start path ever opens.
            revoked = revoke_token(payload)
            written.append("token-revoked")
        owned_dir(Path(paths["unit"]).parent, create=True, mode=0o755)
        create_file(paths["unit"], payload["unit_text"].encode(), 0o644)
        written.append("unit")
        code, _ = systemctl("daemon-reload", timeout=45)
        require(code == 0, "systemctl daemon-reload failed")
        state = unit_state(payload["names"]["service"])
        require(state.get("LoadState") == "loaded" and state.get("SourcePath") == paths["unit"]
                and state.get("ActiveState") in ("inactive", "failed"), "Generated unit did not load from the written source")
        fragment = read_bytes(state["FragmentPath"])
        lines = set(fragment.decode().splitlines())
        require("ExecStartPre=" + payload["gate_command"] in lines, "Generated unit lacks the generation gate")
        files = {key: file_sha(paths[key]) for key in ("unit", "yaml", "owner")}
        require(files["unit"] == payload["files"]["unit"] and files["yaml"] == payload["files"]["yaml"],
                "Written files differ from the planned hashes")
        return {"status": "succeeded", "written": True, "files": files, "token_issued_at": issued, "token_revoked_at": revoked,
                "generated": {"fragment_path": state["FragmentPath"], "sha256": sha256(fragment)}}
    except Exception as error:
        cleanup = {}
        if "unit" in written:
            # The unit may have loaded: observe (and if needed stop) rather than assume it is down.
            cleanup.update(cleanup_after_failure(payload, revoke=False))
        if "token" in written:
            try:
                cleanup["token_revoked_at"] = revoke_token(payload)
            except Exception:
                cleanup["token_revoked_at"] = None
        message = str(error) if isinstance(error, Refusal) else "Preparation failed (" + type(error).__name__ + ")"
        uncertain = (("token" in written and not cleanup.get("token_revoked_at"))
                     or ("unit" in written and "stop" not in cleanup))
        return {"status": "needs-inspection" if uncertain else "failed", "written": bool(written),
                "written_steps": written, "cleanup": cleanup, "error": message}


def cleanup_after_failure(payload, *, revoke):
    """Prove nothing of this deployment runs (stopping it if needed); optionally revoke the token."""
    cleanup = {}
    try:
        cleanup["stop"] = stop_and_verify(payload, timeout=CLEANUP_SECONDS - 10)
    except Exception as stop_error:
        cleanup["stop_error"] = str(stop_error) if isinstance(stop_error, Refusal) else type(stop_error).__name__
    if revoke:
        try:
            cleanup["token_revoked_at"] = revoke_token(payload)
        except Exception:
            cleanup["token_revoked_at"] = None
    return cleanup


def start(payload):
    started, owned_ok, probes = False, False, []
    try:
        owned = verify_owned(payload)
        owned_ok = True
        require(not owned["missing"] and owned["owner_present"], "Deployment files are incomplete")
        require(owned["token"]["state"] == "valid", "Generation token is not valid (fenced or revoked): refusing start")
        require(owned["unit_state"].get("LoadState") == "loaded", "Generated unit is not loaded")
        conflicts = port_conflicts(payload["claims"]) if owned["unit_state"].get("ActiveState") != "active" else []
        require(not conflicts, "Claimed port is in use by another listener")
        # Reserve the tail of the step for failure cleanup (stop + verify + revoke).
        deadline = time.monotonic() + payload.get("timeout", 110) - CLEANUP_SECONDS
        started = True
        code, _ = systemctl("--job-mode=fail", "start", "--", payload["names"]["service"],
                            timeout=max(5, min(60, int(deadline - time.monotonic()) - 5)))
        require(code == 0, "systemctl start failed (gate refusal, pull or pod error; see journalctl --user -u)")
        state = unit_state(payload["names"]["service"])
        require(state.get("ActiveState") == "active", "Unit is not active after start")
        pod = pod_record(payload["names"]["pod"])
        require(pod is not None, "Pod is missing after start")
        verify_pod_owner(pod, payload)
        devices = check_devices(pod, payload)
        for check in payload["health_checks"]:
            probes.append({"id": check["id"], **health(check, ready_deadline(check, deadline))})
            require(probes[-1]["ok"], "Health check " + check["id"] + " did not pass within the bounded window")
        return {"status": "succeeded", "native": {"service": payload["names"]["service"],
                "invocation_id": state.get("InvocationID"), "pod": pod}, "health": probes, "devices": devices}
    except Exception as error:
        message = str(error) if isinstance(error, Refusal) else "Start failed (" + type(error).__name__ + ")"
        revoke = bool(payload.get("revoke_on_failure"))
        if not started and not revoke:
            # A refused direct start changed nothing; the token stays as it was.
            return {"status": "failed", "error": message, "cleanup": {"stopped": "not-started"}, "health": probes}
        if not owned_ok:
            # Ownership unproven: touching the token or unit could affect another deployment.
            return {"status": "needs-inspection", "error": message + "; ownership unverified, token not revoked",
                    "cleanup": {"skipped": "ownership unverified"}, "health": probes}
        cleanup = cleanup_after_failure(payload, revoke=revoke)
        if not started:
            cleanup["started"] = False
        verified = "stop" in cleanup and (not revoke or cleanup.get("token_revoked_at"))
        return {"status": "failed" if verified else "needs-inspection", "error": message, "cleanup": cleanup,
                "health": probes}


def mutation(step):
    """Refusals before the first native change are `failed`; anything after is uncertain."""
    def wrapped(payload):
        state = {"mutated": False}
        try:
            return step(payload, state)
        except Exception as error:
            message = str(error) if isinstance(error, Refusal) else step.__name__ + " failed (" + type(error).__name__ + ")"
            return {"status": "needs-inspection" if state["mutated"] else "failed", "error": message}
    wrapped.__name__ = step.__name__
    return wrapped


@mutation
def stop(payload, state):
    owned = verify_owned(payload)
    state["mutated"] = True
    return {"status": "succeeded", "stop": stop_and_verify(payload), "token": owned["token"]}


@mutation
def fence(payload, state):
    owned = verify_owned(payload)
    state["mutated"] = True
    stopped = stop_and_verify(payload)
    if owned["token"]["state"] != "absent" or owned["owner_present"]:
        revoked = revoke_token(payload)
    else:
        # Nothing was ever written: a missing token already denies the gate.
        revoked = stamp()
    return {"status": "succeeded", "stop": stopped, "revoked_at": revoked, "host_generation": host_generation(payload),
            "files": owned["present"], "before": {"unit": owned["unit_state"].get("ActiveState"),
                                                  "pod": owned["pod"] is not None, "token": owned["token"]["state"]}}


@mutation
def unfence(payload, state):
    owned = verify_owned(payload)
    require(not owned["missing"] and owned["owner_present"], "Deployment files are incomplete; undeploy instead")
    require(owned["unit_state"].get("ActiveState") in ("inactive", "failed"), "Unit is unexpectedly active")
    require(host_generation(payload) == payload["generation"], "Host generation high-water mark differs; reconcile first")
    state["mutated"] = True
    issued = issue_token(payload)
    require(token_state(payload)["state"] == "valid", "Token issue did not verify")
    return {"status": "succeeded", "issued_at": issued}


def observe(payload):
    owned = verify_owned(payload)
    owned["datasets"] = [dataset_state(item) for item in payload["datasets"]]
    owned["host_generation"] = host_generation(payload)
    owned["leftovers"] = leftovers(payload)
    return {"status": "succeeded", "observation": owned}


def _guarded(read):
    """A read that reports a bad path (symlink, foreign owner, oversized) instead of refusing."""
    try:
        return read()
    except Refusal:
        return "unreadable"


def raw_state(payload):
    """Read-only, never refusing on mismatch: what exists on the host for one deployment record."""
    paths = payload["paths"]

    def owner():
        try:
            value = json.loads(read_bytes(paths["owner"], 4096))
        except FileNotFoundError:
            return "missing"
        except ValueError:
            return "mismatch"
        return "match" if value == owner_record(payload) else "mismatch"

    def token():
        return token_state(payload)

    unit = unit_state(payload["names"]["service"])
    pod = pod_record(payload["names"]["pod"])
    if pod is not None:
        labels = pod.pop("labels")
        pod["labels"] = {key: labels.get(LABEL + key) for key in ("ownership-id", "instance", "generation")}
    expected = expected_devices(payload)
    devices = None
    if expected is not None and pod is not None and str(pod.get("state")).lower() in ("running", "degraded"):
        devices = {"expected": expected, "observed": container_devices(pod, set(expected))}
    return {"owner": _guarded(owner), "token": _guarded(token),
            "files": {key: _guarded(lambda key=key: file_sha(paths[key])) for key in ("unit", "yaml")},
            "unit": {key: unit.get(key) for key in ("LoadState", "ActiveState", "SubState", "InvocationID")},
            "pod": pod, "owned_containers": labelled(LABEL + "ownership-id", payload["ownership_id"]),
            "unit_containers": labelled("PODMAN_SYSTEMD_UNIT", payload["names"]["service"]),
            "config": config_state(payload), "host_generation": _guarded(lambda: _host_generation_or_unreadable(payload)),
            "devices": devices, "observed_at": stamp()}


def _host_generation_or_unreadable(payload):
    try:
        return host_generation(payload)
    except ValueError:
        return "unreadable"


def verify(payload):
    """Observe several deployments on this host; changes nothing. Per-item failures are reported, not raised.
    Items marked `run_health` (active placements) also get one attempt of each declared health check,
    inside a shared time budget; checks beyond it are reported as skipped."""
    results = []
    budget = time.monotonic() + payload.get("health_budget", 30)
    for item in payload["items"]:
        try:
            observation = raw_state(item)
            if item.get("run_health"):
                observation["health"] = [
                    {"id": check["id"], **(health(check, ready_deadline(check, budget) if check.get("ready_within_seconds") else 0)
                                           if time.monotonic() + check["timeout_seconds"] < budget
                                           else {"ok": None, "skipped": "verify time budget exhausted"})}
                    for check in item["health_checks"]]
            results.append({"instance_id": item["instance_id"], "observation": observation})
        except Exception as error:
            results.append({"instance_id": item["instance_id"],
                            "error": str(error) if isinstance(error, Refusal) else "observation failed (" + type(error).__name__ + ")"})
    return {"status": "succeeded", "results": results}


def config_read(payload):
    """Read-only, for a refresh plan: ownership state, recorded file hashes and texts of the files that change."""
    if "caddyfile" in payload:
        # Validate the exact typed renderer output with the installed Caddy, without loading it.
        owned = verify_owned(payload)
        require(owned.get("pod") is not None and len(payload["names"]["containers"]) == 1,
                "Caddy validation needs its running owned container")
        text = payload["caddyfile"].encode()
        require(0 < len(text) <= CONFIG_LIMIT, "Invalid Caddyfile length")
        with tempfile.TemporaryFile() as source:
            source.write(text)
            source.seek(0)
            code, _ = run([PODMAN, "exec", "-i", payload["names"]["containers"][0],
                           "caddy", "adapt", "--adapter", "caddyfile", "--config", "-"], 20, stdin=source)
        require(code == 0, "Caddy rejected the candidate configuration; nothing written")
    return {"status": "succeeded", "observation": raw_state(payload),
            "config": config_state(payload, texts_for=set(payload.get("texts_for") or []))}


def refresh(payload):
    """Rewrite changed configuration files of one owned deployment, then do what the files declare.

    Nothing is written unless ownership, the unit/YAML hashes and every current file hash match the journal.
    Files are replaced atomically (rename). `restart` restarts an active unit; otherwise a running service
    reloads the files itself. Health checks run when the unit is active. Never retried."""
    service = payload["names"]["service"]
    try:
        owned = verify_owned(payload)
        require(not owned["missing"] and owned["owner_present"], "Deployment files are incomplete")
        current = config_state(payload)
        drifted = sorted(name for name, value in current["files"].items()
                         if value != next(i["sha256"] for i in payload["config"] if i["name"] == name))
        require(not drifted, "Configuration files on the host differ from the journal: " + ", ".join(drifted) + "; nothing written")
        require(not current["extra"], "Unexpected files in the configuration directory: "
                + ", ".join(sorted(current["extra"])) + "; nothing written")
        require({i["name"] for i in payload["config_files"]} == {i["name"] for i in payload["config"]},
                "Refresh cannot add or remove configuration files")
        owned_dir(payload["paths"]["config_dir"])
        recorded = {i["name"]: i["sha256"] for i in payload["config"]}
        changed = [item for item in payload["config_files"] if item["sha256"] != recorded[item["name"]]]
        require(changed, "No configuration file changes; nothing written")
        active = owned["unit_state"].get("ActiveState") == "active"
    except Exception as error:
        return {"status": "failed", "written": False,
                "error": str(error) if isinstance(error, Refusal) else "Refresh precheck failed (" + type(error).__name__ + ")"}
    written = []
    try:
        for item in changed:
            written += write_config(payload, [item], create=False)
        files = config_state({**payload, "config": payload["config_files"]})["files"]
    except Exception as error:
        # Once the write phase started, any failure (even before the first file was recorded as written: a rename
        # can land and its fsync or hash check then fail) leaves the host state unknown.
        return {"status": "needs-inspection", "written": True, "write_phase_entered": True, "verified_files": written,
                "error": (str(error) if isinstance(error, Refusal) else "Write failed (" + type(error).__name__ + ")")
                + "; configuration files may be partly written"}
    result = {"status": "succeeded", "written": True, "written_files": written, "files": files,
              "active": active, "restarted": False, "health": []}
    deadline = time.monotonic() + payload.get("timeout", 110) - CLEANUP_SECONDS
    if payload.get("restart") and active:
        try:
            code, _ = systemctl("--job-mode=fail", "restart", "--", service,
                                timeout=max(5, min(60, int(deadline - time.monotonic()) - 5)))
            require(code == 0, "systemctl restart failed (see journalctl --user -u " + service + ")")
            state = unit_state(service)
            require(state.get("ActiveState") == "active", "Unit is not active after restart")
            pod = pod_record(payload["names"]["pod"])
            require(pod is not None, "Pod is missing after restart")
            verify_pod_owner(pod, payload)
            result.update(restarted=True, native={"invocation_id": state.get("InvocationID"), "pod": pod})
        except Exception as error:
            cleanup = cleanup_after_failure(payload, revoke=False)
            return {**result, "status": "failed" if "stop" in cleanup else "needs-inspection", "restart_failed": True,
                    "cleanup": cleanup, "error": (str(error) if isinstance(error, Refusal) else "Restart failed ("
                                                  + type(error).__name__ + ")") + "; configuration written, unit stopped"}
    if active:
        for check in payload["health_checks"]:
            result["health"].append({"id": check["id"], **health(check, ready_deadline(check, deadline))})
        failed = [probe["id"] for probe in result["health"] if not probe["ok"]]
        if failed:
            result.update(status="failed", error="Health check(s) " + ", ".join(failed) + " did not pass after the refresh; "
                                                 "configuration written, service left running")
    return result


def undeploy(payload):
    mutated = False
    try:
        owned = verify_owned(payload)
        mutated = True
        revoked_first = payload.get("revoke_first") is True and owned["token"]["state"] == "valid"
        if revoked_first:
            revoke_token(payload)
        stopped = stop_and_verify(payload)
        removed = []
        if owned["token"]["state"] == "valid" and not revoked_first:
            revoke_token(payload)
        if remove_file(payload["paths"]["unit"]):
            removed.append(payload["paths"]["unit"])
        code, _ = systemctl("daemon-reload", timeout=45)
        require(code == 0, "systemctl daemon-reload failed")
        # A fenced unit that refused to start (at boot, or by hand) stays listed as failed after its file
        # is gone and keeps the user manager "degraded". Best effort: nothing to reset is not an error.
        systemctl("reset-failed", payload["names"]["service"], timeout=15)
        state = unit_state(payload["names"]["service"])
        require(state.get("LoadState") in ("not-found", None), "Generated unit is still loaded after removal")
        for key in ("yaml", "token", "owner"):
            if remove_file(payload["paths"][key]):
                removed.append(payload["paths"][key])
        config_dir = payload["paths"].get("config_dir")
        if config_dir and payload.get("config"):
            for item in payload["config"]:
                if remove_file(Path(config_dir) / item["name"]):
                    removed.append(str(Path(config_dir) / item["name"]))
            for directory in (Path(config_dir), Path(config_dir).parent):
                if directory.is_dir() and not directory.is_symlink() and not any(os.scandir(directory)):
                    os.rmdir(directory)
        deleted = []
        if payload.get("delete_data"):
            for item in payload["datasets"]:
                if item["default"] and os.path.lexists(item["path"]):
                    owned_dir(item["path"])
                    shutil.rmtree(item["path"])
                    deleted.append(item["path"])
            data_root = Path(payload["paths"]["app_dir"]) / "data"
            if data_root.is_dir() and not data_root.is_symlink() and not any(os.scandir(data_root)):
                os.rmdir(data_root)
        return {"status": "succeeded", "stop": stopped, "removed": removed, "deleted_data": deleted,
                "kept": sorted(os.listdir(payload["paths"]["app_dir"])) if os.path.isdir(payload["paths"]["app_dir"]) else []}
    except Exception as error:
        message = str(error) if isinstance(error, Refusal) else "Undeploy failed (" + type(error).__name__ + ")"
        return {"status": "needs-inspection" if mutated else "failed", "error": message}


def image_info(payload):
    """Read-only: an image's digest (resolved from its tag without pulling when not pinned), its compressed size and
    whether the local store holds it."""
    image, arch = payload["image"], architecture(platform.machine())
    resolution = {"method": "pinned", "digest": image["digest"]} if image.get("digest") else resolve_image(image, arch)
    require(resolution.get("digest"), "The image tag could not be resolved to a digest without pulling")
    return {"status": "succeeded", "image": {**resolution, "architecture": arch,
                                             "store": image_facts(image["repository"], resolution["digest"], arch)}}


def lan_route_probe(payload):
    """Check exact HTTPS/SNI route markers on the owned gateway, without contacting app backends."""
    owned = verify_owned(payload)
    require(owned["owner_present"] and not owned["missing"] and owned["pod"] is not None and
            owned["unit_state"].get("ActiveState") == "active" and owned["token"]["state"] == "valid",
            "Gateway identity or running state could not be verified")
    address = ipaddress.IPv4Address(payload["address"])
    require(address in ipaddress.IPv4Network("10.0.0.0/8") or
            address in ipaddress.IPv4Network("172.16.0.0/12") or
            address in ipaddress.IPv4Network("192.168.0.0/16"), "Gateway address is not private LAN IPv4")
    require({"address": str(address), "port": 443, "protocol": "tcp"} in payload["claims"] and
            {"address": str(address), "port": 80, "protocol": "tcp"} in payload["claims"],
            "Gateway does not own the HTTP and HTTPS listeners")
    probes = payload["probes"]
    require(0 < len(probes) <= 64, "Invalid route probe count")
    for name, value in probes.items():
        require(len(name) <= 253 and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                         for label in name.split(".")) and re.fullmatch(r"[0-9a-f]{64}", value),
                "Invalid route probe")
    ca = http.client.HTTPConnection(str(address), 80, timeout=3)
    try:
        ca.request("GET", "/caddy-root.crt", headers={"Connection": "close"})
        with ca.getresponse() as response:
            require(response.status == 200, "Gateway CA download failed")
            pem = response.read(8193).decode("ascii")
        require(len(pem) <= 8192 and pem.count("-----BEGIN CERTIFICATE-----") == 1
                and pem.count("-----END CERTIFICATE-----") == 1, "Invalid gateway CA PEM")
        der = ssl.PEM_cert_to_DER_cert(pem)
        require(hashlib.sha256(der).hexdigest() == payload["ca_sha256"], "Gateway CA fingerprint changed")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_verify_locations(cadata=pem)
    finally:
        ca.close()
    deadline = time.monotonic() + 34
    verified = []
    for name, value in probes.items():
        encoded = value.encode("ascii")
        request = ("GET /.well-known/switchyard-route HTTP/1.1\r\nHost: " + name + "\r\nConnection: close\r\n\r\n").encode("ascii")
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((str(address), 443), timeout=max(0.01, min(2, deadline - time.monotonic()))) as sock:
                    with ctx.wrap_socket(sock, server_hostname=name) as tls:
                        tls.sendall(request)
                        with http.client.HTTPResponse(tls) as response:
                            response.begin()
                            if response.status != 200 or response.read(len(encoded) + 1) != encoded:
                                return {"status": "failed", "error": "Caddy route did not match the plan: " + name,
                                        "verified": verified}
                verified.append(name)
                break
            except (OSError, http.client.HTTPException):
                # A newly restarted Caddy may still be issuing the host certificate.
                time.sleep(min(0.25, max(0, deadline - time.monotonic())))
        else:
            return {"status": "failed", "error": "Could not verify HTTPS route: " + name, "verified": verified}
    return {"status": "succeeded", "verified": verified}


def lan_dns_probe(payload):
    """Confirm the locally served DNS answer after CoreDNS reloads its hosts file."""
    owned = verify_owned(payload)
    require(owned["owner_present"] and not owned["missing"] and owned["pod"] is not None and
            owned["unit_state"].get("ActiveState") == "active" and owned["token"]["state"] == "valid",
            "DNS identity or running state could not be verified")
    claims = {}
    for claim in payload["claims"]:
        if claim["port"] == 53 and claim["protocol"] in ("tcp", "udp"):
            claims.setdefault(claim["address"], set()).add(claim["protocol"])
    addresses = [address for address, protocols in claims.items() if protocols == {"udp", "tcp"}]
    require(len(addresses) == 1, "DNS placement does not own a common UDP and TCP port 53 address")
    address = str(ipaddress.IPv4Address(addresses[0]))
    require(address != "0.0.0.0", "DNS route probes require an exact listener address")
    expected = payload["records"]
    require(0 < len(expected) <= 2, "Invalid DNS route probe count")
    for name, value in expected.items():
        require(len(name) <= 253 and name.endswith("." + payload["zone"]) and
                all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in name.split(".")),
                "Invalid DNS route probe name")
        if value is not None:
            require("%" not in value, "DNS record addresses cannot include a scope ID")
            ipaddress.ip_address(value)
    checks = {(name, protocol, kind) for name, value in expected.items() for protocol in ("udp", "tcp")
              for kind in (("A", "AAAA") if value is None else
                           ("A",) if ipaddress.ip_address(value).version == 4 else ("AAAA",))}
    deadline = time.monotonic() + 12
    while checks and time.monotonic() < deadline:
        for name, protocol, kind in sorted(checks):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                reply = dns_query(address, 53, name, kind, min(1, remaining), protocol)
            except OSError:
                continue
            if reply["truncated"]:
                continue
            value = expected[name]
            answers = reply["answers"]
            if value is None:
                passed = reply["authoritative"] and reply["rcode"] == "NXDOMAIN" and not answers
            else:
                passed = (reply["rcode"] == "NOERROR" and bool(answers) and
                          all((item["name"], item["type"], item["value"]) == (name, kind, value) for item in answers))
            if passed:
                checks.remove((name, protocol, kind))
        if checks:
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    if checks:
        return {"status": "failed", "error": "Could not verify DNS: " +
                ", ".join(name + " " + kind + " over " + protocol.upper() for name, protocol, kind in sorted(checks))}
    return {"status": "succeeded", "verified": expected}


ACTIONS = {"facts": lambda p: {"status": "succeeded", "facts": facts(p)}, "inspect": inspect, "pull": pull,
           "prepare": prepare, "upgrade-check": upgrade_check, "start": start, "stop": stop, "fence": fence, "unfence": unfence,
           "observe": observe, "undeploy": undeploy, "verify": verify, "config-read": config_read, "refresh": refresh,
           "pull-start": pull_start, "pull-status": pull_status, "image-info": image_info,
           "lan-route-probe": lan_route_probe, "lan-dns-probe": lan_dns_probe,
           "devices": lambda p: {"status": "succeeded", "devices": [device_state(path) for path in p["paths"]]}}


def main(payload):
    try:
        require(isinstance(payload, dict) and payload.get("action") in ACTIONS, "Unsupported deploy action")
        require(os.getuid() != 0, "Rootful execution is forbidden")
        return ACTIONS[payload["action"]](payload)
    except Refusal as error:
        return {"status": "failed", "error": str(error)}
    except Exception as error:
        return {"status": "failed", "error": "Remote deploy step failed (" + type(error).__name__ + ")"}
