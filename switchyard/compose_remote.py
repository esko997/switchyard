"""Fixed, local-only lifecycle adapter for existing complete Compose projects.

No imports from Switchyard: this file is also sent verbatim to a remote Python.
Podman Compose's YAML config is hashed, not parsed as an invented JSON API.
Its native dry-run start resolves targets (including replicas/container_name).
Capabilities verified against containers/podman-compose v1.0.6 and v1.6.0
podman_compose.py; unfamiliar output fails closed. Docker uses Compose v2's
config --format json and explicitly pins the local Unix endpoint.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import stat
import subprocess
import tempfile
import time


LIMIT = 1024 * 1024
MAX_CONTAINERS = 64
ID = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}\Z")
ACTIONS = ("start", "stop", "restart")
WARNING = "Native container runtime state only; application health is not verified."
LABELS = {
    "project": "com.docker.compose.project",
    "service": "com.docker.compose.service",
    "directory": "com.docker.compose.project.working_dir",
    "files": "com.docker.compose.project.config_files",
    "number": "com.docker.compose.container-number",
    "oneoff": "com.docker.compose.oneoff",
    "docker_hash": "com.docker.compose.config-hash",
    "podman_project": "io.podman.compose.project",
    "podman_service": "io.podman.compose.service",
    "quadlet": "io.containers.quadlet",
    "systemd_owner": "io.containers.systemd.unit",
    "podman_hash": "io.podman.compose.config-hash",
    "systemd_unit": "PODMAN_SYSTEMD_UNIT",
    "autoupdate": "io.containers.autoupdate",
    "manager": "manager",
}
# Select fields individually: State contains health logs; Config contains env.
INSPECT = ('{"id":{{json .Id}},"name":{{json .Name}},'
           '"status":{{json .State.Status}},"running":{{json .State.Running}},'
           '"paused":{{json .State.Paused}},"started":{{json .State.StartedAt}},'
           '"finished":{{json .State.FinishedAt}},"exit_code":{{json .State.ExitCode}},'
           '"labels":{' + ",".join(
               json.dumps(key) + ':{{json (index .Config.Labels ' + json.dumps(value) + ')}}'
               for key, value in LABELS.items()) + '}}')


class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def text(value, maximum=4096):
    require(isinstance(value, str) and len(value) <= maximum and
            not any(ord(c) < 32 or ord(c) == 127 for c in value),
            "Invalid bounded native metadata")
    return value


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read_file(path, maximum=4 * LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "Definition is not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            body = stream.read(maximum + 1)
        require(len(body) <= maximum, "Definition exceeds size limit")
        return body
    finally:
        os.close(fd)


def file_hash(path, maximum=4 * LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "Definition or executable is not a regular file")
        result, size = hashlib.sha256(), 0
        while True:
            part = os.read(fd, 65536)
            if not part:
                break
            size += len(part)
            require(size <= maximum, "Definition or executable exceeds size limit")
            result.update(part)
        return result.hexdigest()
    finally:
        os.close(fd)


def canonical_path(value):
    text(value)
    require(value.startswith("/") and "," not in value and
            str(Path(value).resolve(strict=True)) == value, "Paths must be absolute and canonical")
    return value


def validate(config):
    require(isinstance(config, dict) and config.get("backend") == "compose", "Invalid Compose authority")
    require(config.get("provider") in ("docker-compose-v2", "podman-compose"), "Unsupported Compose provider")
    require(isinstance(config.get("project_name"), str) and PROJECT.fullmatch(config["project_name"]),
            "Invalid exact project name")
    directory = canonical_path(config.get("project_directory"))
    require(Path(directory).is_dir(), "Project directory is absent")
    files, services = config.get("files"), config.get("services")
    require(isinstance(files, list) and 0 < len(files) <= 16 and len(set(files)) == len(files),
            "Invalid complete manifest list")
    for path in files:
        canonical_path(path)
    require(isinstance(services, list) and 0 < len(services) <= 32 and
            all(isinstance(s, str) and NAME.fullmatch(s) for s in services) and
            len(set(services)) == len(services), "Invalid exact service set")
    # podman-compose uses the first manifest's directory, not --project-directory.
    if config["provider"] == "podman-compose":
        require(str(Path(files[0]).parent) == directory,
                "Unsupported podman-compose project-directory mismatch")
    return config


class Runtime:
    def __init__(self, config):
        self.config = config
        self.deadline = time.monotonic() + 90
        self.mutation_issued = False
        self.scratch = None
        self.dotenv = Path(config["project_directory"]) / ".env"
        self.dotenv_hash = None
        self.owners_checked = set()
        self.env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()),
                    "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        # Never forward DOCKER_*, CONTAINER_*, COMPOSE_* or PODMAN_* variables.
        uid = os.getuid()
        if Path("/run/user/" + str(uid)).is_dir():
            self.env["XDG_RUNTIME_DIR"] = "/run/user/" + str(uid)
        self.podman = config["provider"] == "podman-compose"
        self.engine = (["/usr/bin/podman", "--remote=false"] if self.podman else
                       ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"])
        common = ["--env-file", "/dev/null", "--project-name", config["project_name"]]
        for path in config["files"]:
            common += ["--file", path]
        if self.podman:
            self.compose = ["/usr/bin/podman-compose", "--podman-path", "/usr/bin/podman", *common]
        else:
            self.compose = [*self.engine, "compose", "--project-directory", config["project_directory"], *common]

    def environment_input(self):
        require(not self.dotenv.is_symlink(), "Unsupported symlinked .env input")
        body = read_file(self.dotenv, LIMIT) if self.dotenv.exists() or self.dotenv.is_symlink() else None
        if self.scratch is None:
            # Ordinary application interpolation is supported. Provider-control
            # names (even quoted/exported ones) are intentionally unsupported.
            require(body is None or not re.search(rb"(?:DOCKER_|CONTAINER_|COMPOSE_|PODMAN_)", body),
                    "Unsupported provider-control variable in .env")
            self.dotenv_hash = digest(body) if body is not None else None
            self.scratch = tempfile.TemporaryDirectory(prefix="switchyard-compose-")
            path = Path(self.scratch.name) / "environment"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(body or b"")
            # Providers read a private immutable snapshot, never a concurrently
            # replaceable .env that could redirect engine/context after checking.
            self.compose[self.compose.index("--env-file") + 1] = str(path)
            if self.podman:
                # 1.0.6 inserts --podman-args AFTER the subcommand, where the
                # global --remote flag is invalid. Pin the endpoint before argv
                # through a private, operation-scoped launcher instead.
                launcher = Path(self.scratch.name) / "podman-local"
                fd = os.open(launcher, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
                with os.fdopen(fd, "w") as stream:
                    stream.write("#!/bin/sh\nexec " + shlex.join(self.engine) + ' "$@"\n')
                self.compose[self.compose.index("--podman-path") + 1] = str(launcher)
        require((digest(body) if body is not None else None) == self.dotenv_hash,
                ".env changed during Compose operation")
        return {"path": str(self.dotenv), "sha256": self.dotenv_hash}

    def close(self):
        if self.scratch is not None:
            self.scratch.cleanup()

    def command(self, args, *, mutation=False, diagnostics=False, allow_failure=False):
        require(time.monotonic() < self.deadline, "Compose operation deadline exceeded")
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=self.env,
                                 cwd=self.config["project_directory"], start_new_session=True,
                                 close_fds=True)
        if mutation:
            self.mutation_issued = True
        output, errors = bytearray(), bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ, output)
                selector.register(child.stderr, selectors.EVENT_READ, errors)
                while selector.get_map():
                    remaining = self.deadline - time.monotonic()
                    require(remaining > 0, "Compose operation deadline exceeded")
                    for key, _ in selector.select(min(0.1, remaining)):
                        part = os.read(key.fd, 8192)
                        if not part:
                            selector.unregister(key.fileobj)
                        else:
                            key.data.extend(part)
                            require(len(output) + len(errors) <= LIMIT, "Compose output exceeds limit")
            code = child.wait(timeout=max(0.001, self.deadline - time.monotonic()))
            require(allow_failure or code == 0, "Compose command failed or capability unsupported")
            result = output.decode("utf-8")
            return (result, errors.decode("utf-8"), code) if diagnostics else result
        finally:
            if child.poll() is None:
                # The provider can spawn engine children: contain the whole call.
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            child.wait()
            child.stdout.close()
            child.stderr.close()

    def properties(self, unit, scope):
        out, _, code = self.command(
            ["/usr/bin/systemctl", "--" + scope, "--no-pager", "--no-ask-password", "show",
             "--property=LoadState,ActiveState", "--", unit], diagnostics=True, allow_failure=True)
        props = {}
        for line in out.splitlines():
            key, sep, value = line.partition("=")
            require(sep and key in ("LoadState", "ActiveState") and key not in props,
                    "Cannot establish systemd ownership/socket safety")
            props[key] = value
        require(set(props) == {"LoadState", "ActiveState"} and
                (code == 0 or props["LoadState"] == "not-found"),
                "Cannot establish systemd ownership/socket safety")
        return props

    def local_identity(self):
        require(os.getuid() == os.geteuid() and os.getuid() != 0,
                "Unprivileged current-user execution required")
        self.environment_input()
        if self.podman:
            version = self.command(["/usr/bin/podman-compose", "--version"])
            matches = re.findall(r"(?m)^podman-compose version:?\s*(\d+\.\d+\.\d+)\s*$", version)
            require(len(matches) == 1 and matches[0] in ("1.0.6", "1.6.0"),
                    "Unsupported podman-compose version/target-proof capability")
            self.provider_version = matches[0]
            if self.provider_version == "1.6.0" and "--verbose" not in self.compose:
                self.compose.insert(1, "--verbose")
            info = json.loads(self.command([*self.engine, "info", "--format",
                              '{"graph":{{json .Store.GraphRoot}},"run":{{json .Store.RunRoot}},'
                              '"rootless":{{json .Host.Security.Rootless}},"version":{{json .Version.Version}}}']))
            require(info.get("rootless") is True, "Rootless local Podman required")
            for key in ("graph", "run"):
                require(text(info.get(key)).startswith("/"), "Invalid local Podman store identity")
            require(re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?", text(info.get("version"))),
                    "Unsupported Podman engine version")
            return {"provider_version": self.provider_version,
                    "provider_sha256": file_hash("/usr/bin/podman-compose", 64 * LIMIT),
                    "engine_sha256": file_hash("/usr/bin/podman", 128 * LIMIT), "runtime": info}
        # Never contact a socket that might start Docker on connection. No fallback
        # to another context, socket, rootless daemon or engine is permitted.
        socket_state = self.properties("docker.socket", "system")
        require(socket_state["LoadState"] in ("loaded", "not-found") and
                socket_state["ActiveState"] == "inactive", "Docker socket activation safety not established")
        require(self.properties("docker.service", "system") ==
                {"LoadState": "loaded", "ActiveState": "active"}, "Existing Docker daemon must already be active")
        sock = Path("/var/run/docker.sock").stat()
        require(stat.S_ISSOCK(sock.st_mode), "Local Docker socket is absent")
        version = self.command([*self.engine, "compose", "version", "--short"]).strip()
        require(re.fullmatch(r"v?2\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?", version),
                "Docker Compose v2 required")
        info = json.loads(self.command([*self.engine, "info", "--format",
                          '{"id":{{json .ID}},"plugins":{{json .ClientInfo.Plugins}}}']))
        daemon = text(info.get("id"), 256)
        require(daemon, "Missing Docker daemon identity")
        plugins = info.get("plugins")
        require(isinstance(plugins, list), "Compose plugin identity unsupported")
        plugins = [p for p in plugins if isinstance(p, dict) and p.get("Name") == "compose"]
        require(len(plugins) == 1, "Compose plugin identity is ambiguous")
        plugin_path = text(plugins[0].get("Path"))
        require(plugin_path.startswith("/"), "Invalid Compose plugin path")
        plugin = str(Path(plugin_path).resolve(strict=True))
        return {"provider_version": version, "provider_path": plugin,
                "provider_sha256": file_hash(plugin, 128 * LIMIT),
                "engine_sha256": file_hash("/usr/bin/docker", 128 * LIMIT), "daemon_id": daemon,
                "socket": {"device": sock.st_dev, "inode": sock.st_ino, "uid": sock.st_uid}}

    def definitions(self):
        definitions = []
        for path in self.config["files"]:
            body = read_file(path)
            # Fail closed before invoking a provider that might fetch an imported
            # model. This intentionally conservative lexical subset also refuses
            # these words in comments/values, rather than implementing partial YAML.
            require(not re.search(rb"\b(?:include|extends)\b", body),
                    "Unsupported imported Compose manifests (include/extends)")
            require(not re.search(rb"[\"'][^\r\n]*\\[^\r\n]*[\"']\s*:", body),
                    "Unsupported escaped YAML mapping keys")
            if self.podman:
                require(not re.search(rb"\benv_file\b", body),
                        "Unsupported podman-compose service env_file; effective values cannot be pinned")
            definitions.append({"path": path, "sha256": digest(body)})
        return definitions

    def rendered(self):
        if not self.podman:
            value = json.loads(self.command([*self.compose, "config", "--format", "json"]))
            require(isinstance(value, dict) and isinstance(value.get("services"), dict),
                    "Unsupported rendered Compose model")
            services = value["services"]
            require(set(services) == set(self.config["services"]), "Configured services must be the complete project")
            # Lifecycle hooks can create command runners outside the adopted set.
            counts = {}
            for name, service in services.items():
                require(isinstance(service, dict) and not any(service.get(k) for k in
                        ("post_start", "pre_stop", "pre_start", "use_api_socket", "provider", "profiles")),
                        "Unsupported Compose lifecycle hooks/provider services/profiles")
                deploy = service.get("deploy") or {}
                require(isinstance(deploy, dict) and deploy.get("mode", "replicated") == "replicated",
                        "Unsupported Compose deployment mode")
                count = service.get("scale", deploy.get("replicas", 1))
                require(type(count) is int and 0 < count <= MAX_CONTAINERS,
                        "Unsupported Compose replica count")
                counts[name] = count
            self.replica_counts = counts
            canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            return digest(canonical), None
        rendered = self.command([*self.compose, "config"])
        require(rendered.strip(), "Missing rendered Compose configuration")
        services = self.command([*self.compose, "config", "--services"]).splitlines()
        require(len(services) == len(set(services)) and set(services) == set(self.config["services"]),
                "Configured services must be the complete project")
        # There is no JSON config API in these podman-compose versions. Its actual
        # dry-run transfer path resolves custom names and replicas without starting
        # anything. Refuse any output shape/command we cannot prove safe.
        targets = {}
        launcher = self.compose[self.compose.index("--podman-path") + 1]
        for service in sorted(services):
            out, errors, _ = self.command([*self.compose, "--dry-run", "start", service], diagnostics=True)
            names = []
            for line in (out + "\n" + errors).splitlines():
                if self.provider_version == "1.6.0":
                    line = re.sub(r"^INFO:(?:podman_compose|__main__):", "", line)
                if not line.startswith(launcher + " "):
                    continue
                parts = shlex.split(line)
                require(len(parts) == 3 and parts[:2] == [launcher, "start"] and NAME.fullmatch(parts[2]),
                        "Unsupported podman-compose native target plan")
                names.append(parts[2])
            require(names and len(names) <= MAX_CONTAINERS and len(names) == len(set(names)),
                    "Unsupported podman-compose native target proof")
            targets[service] = sorted(names)
        require(sum(map(len, targets.values())) <= MAX_CONTAINERS and
                len({name for names in targets.values() for name in names}) == sum(map(len, targets.values())),
                "Ambiguous podman-compose native targets")
        return digest(rendered.encode()), targets

    def external_owner(self, labels):
        unit = labels.get("systemd_unit") or ""
        if self.podman:
            require(unit == "podman-compose@" + self.config["project_name"] + ".service",
                    "Missing or foreign native systemd owner marker")
            registration = Path.home() / ".config/containers/compose/projects" / (self.config["project_name"] + ".env")
            require(not registration.exists() and not registration.is_symlink(), "Project has an external systemd owner")
            if unit not in self.owners_checked:
                for scope in ("user", "system"):
                    require(self.properties(unit, scope)["LoadState"] == "not-found",
                            "Project has an external systemd owner")
                self.owners_checked.add(unit)
        else:
            require(not unit, "Container has an external systemd/Quadlet owner")
        require(not any(labels.get(key) for key in ("autoupdate", "manager", "quadlet", "systemd_owner")),
                "Container has an external lifecycle owner")

    def containers(self, targets):
        # Project-filtered inventory only; never list unrelated containers/images.
        ids = set()
        keys = ["com.docker.compose.project"]
        if self.podman:
            keys.append("io.podman.compose.project")
        for key in keys:
            values = self.command([*self.engine, "ps", "--all", "--no-trunc", "--filter",
                                   "label=" + key + "=" + self.config["project_name"], "--format", "{{.ID}}"]).splitlines()
            require(len(values) <= MAX_CONTAINERS and len(values) == len(set(values)) and
                    all(ID.fullmatch(i) for i in values), "Invalid project-filtered native inventory")
            ids.update(values)
        require(ids and len(ids) <= MAX_CONTAINERS, "Existing complete project containers are required")
        template = INSPECT.replace("json .Id", "json .ID") if self.podman else INSPECT
        output = self.command([*self.engine, "container", "inspect", "--format", template, *sorted(ids)])
        records = [json.loads(line) for line in output.splitlines()]
        require(len(records) == len(ids) and {r.get("id") for r in records} == ids,
                "Native container inspection does not match inventory")
        identities, states, found = [], [], {s: set() for s in self.config["services"]}
        numbers = set()
        for record in sorted(records, key=lambda r: r["id"]):
            labels = record.get("labels")
            require(isinstance(labels, dict), "Missing Compose ownership labels")
            service = labels.get("service")
            require(labels.get("project") == self.config["project_name"] and service in found,
                    "Foreign/orphan/missing service ownership")
            require(labels.get("directory") == self.config["project_directory"] and
                    labels.get("files") == ",".join(self.config["files"]), "Compose manifest ownership mismatch")
            require(labels.get("oneoff") in
                    ((None, "", "False", "false") if self.podman else ("False", "false")),
                    "Oneoff containers or ambiguous oneoff ownership are not adopted")
            number = labels.get("number")
            require(isinstance(number, str) and re.fullmatch(r"[1-9][0-9]{0,3}", number) and
                    (service, number) not in numbers, "Ambiguous Compose service replica ownership")
            numbers.add((service, number))
            native_hash = labels.get("podman_hash" if self.podman else "docker_hash")
            require(isinstance(native_hash, str) and ID.fullmatch(native_hash), "Missing native Compose config identity")
            if self.podman:
                require(labels.get("podman_project") == self.config["project_name"] and
                        labels.get("podman_service") in
                        ((None, "", service) if self.provider_version == "1.0.6" else (service,)),
                        "Conflicting native provider ownership")
            else:
                require(not labels.get("podman_project") and not labels.get("podman_service"),
                        "Conflicting native provider ownership")
            self.external_owner(labels)
            name = text(record.get("name"), 256).removeprefix("/")
            require(NAME.fullmatch(name) and name not in found[service], "Invalid native container name")
            found[service].add(name)
            for key in ("status", "started", "finished"):
                text(record.get(key), 128)
            require(record["status"] in ("created", "configured", "running", "exited", "stopped") and
                    isinstance(record.get("running"), bool) and record.get("paused") is False and
                    (record["status"] == "running") == record["running"] and
                    type(record.get("exit_code")) is int, "Unsupported/unstable native container state")
            identities.append({"id": record["id"], "name": name, "service": service,
                               "number": number, "config_hash": native_hash})
            states.append({key: record[key] for key in
                           ("id", "status", "running", "started", "finished", "exit_code")})
        require(all(found.values()), "Missing project service containers")
        if targets is not None:
            require({s: sorted(v) for s, v in found.items()} == targets,
                    "Native containers do not exactly match Compose targets")
        else:
            require(numbers == {(service, str(n)) for service, count in self.replica_counts.items()
                                for n in range(1, count + 1)},
                    "Native service replicas do not exactly match complete Compose project")
        return identities, states

    def inspect(self):
        self.owners_checked.clear()
        runtime = self.local_identity()
        definitions = self.definitions()
        rendered_hash, targets = self.rendered()
        containers, states = self.containers(targets)
        # Catch definition edits during rendering/ownership observation as well.
        require(self.definitions() == definitions, "Manifest changed during inspection")
        again, again_targets = self.rendered()
        require(again == rendered_hash and again_targets == targets, "Effective Compose config changed during inspection")
        environment = self.environment_input()
        lifecycle = ("running" if all(s["running"] for s in states) else
                     "failed" if any(s["exit_code"] != 0 for s in states) else
                     "stopped" if all(not s["running"] for s in states) else "unknown")
        return {"backend": "compose", "identity": {
                    "provider": self.config["provider"], "project_name": self.config["project_name"],
                    "project_directory": self.config["project_directory"], "manifests": definitions,
                    "services": sorted(self.config["services"]), "rendered_sha256": rendered_hash,
                    "runtime": runtime, "environment_input": environment, "containers": containers},
                "state": {"containers": states}, "warnings": [WARNING], "supported_actions": list(ACTIONS),
                "lifecycle": lifecycle, "health": "unknown",
                "resources": [{"backend": "podman" if self.podman else "docker",
                               "scope": "user:" + str(os.getuid()) if self.podman else "system",
                               "native_id": c["id"], "name": c["name"]} for c in containers]}


def run(request):
    runtime = None
    try:
        require(isinstance(request, dict), "Invalid Compose request")
        action = request.get("action")
        require(action in ("inspect", *ACTIONS), "Unsupported Compose lifecycle action")
        config = validate(request.get("config"))
        runtime = Runtime(config)
        before = runtime.inspect()
        if action == "inspect":
            return {"status": "succeeded", "inspection": before}
        expected = request.get("expected")
        require(isinstance(expected, dict) and expected.get("backend") == "compose" and
                expected.get("identity") == before["identity"] and expected.get("state") == before["state"],
                "Stale or mismatched Compose inspection; inspect and approve again")
        runtime.command([*runtime.compose, action, *sorted(config["services"])], mutation=True)
        after = runtime.inspect()
        require(after["identity"] == before["identity"], "Native/definition identity changed after action")
        states = after["state"]["containers"]
        require(all(s["running"] == (action != "stop") for s in states),
                "Compose native runtime postcondition not established")
        if action == "restart":
            old = {s["id"]: s for s in before["state"]["containers"]}
            require(all(s["started"] and s["started"] != old[s["id"]]["started"] for s in states),
                    "Compose restart incarnation postcondition not established")
        return {"status": "succeeded", "inspection": after}
    except Refusal as error:
        return {"status": "needs-inspection" if runtime and runtime.mutation_issued else "failed", "error": str(error)}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
        # Provider stderr, exception strings, rendered config and environment are
        # deliberately absent, even on an invalid/unsupported provider response.
        return {"status": "needs-inspection" if runtime and runtime.mutation_issued else "failed",
                "error": "Compose observation/transport unavailable or capability unsupported"}
    finally:
        if runtime is not None:
            runtime.close()
