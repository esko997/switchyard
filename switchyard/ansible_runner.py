"""Pinned ansible-core runner for Switchyard's Ansible backend.

ansible-core runs from uv's cache via `uvx --from ansible-core==<pin>`; Switchyard owns a private
Ansible home, collections path, callback plugin and config under the state directory, and disk
scratch under ~/.cache/switchyard/ansible. Runs are bounded: one fork, a hard deadline that kills
the runner's whole process group, and bounded retained output. Nothing here retries.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import select
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time

UVX_DEFAULT = Path.home() / ".local/bin/uvx"
CALLBACK = "switchyard_events"
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
COLLECTION = re.compile(r"[a-z][a-z0-9_]{1,63}\.[a-z][a-z0-9_]{1,63}\Z")
STDERR_TAIL = 4096
PASSTHROUGH = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "SSH_AUTH_SOCK", "UV_CACHE_DIR", "XDG_CACHE_HOME")
MAX_TASKS = 400


def private_dir(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError(f"{path} must be an owned directory")
    path.chmod(0o700)
    return path


def write_private(path, data):
    """Atomic 0600 write in an owned private directory."""
    path = Path(path)
    if isinstance(data, str):
        data = data.encode()
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def uvx_path():
    explicit = os.environ.get("SWITCHYARD_UVX")
    candidates = [explicit] if explicit else [shutil.which("uvx"), str(UVX_DEFAULT)]
    for candidate in candidates:
        if candidate and os.path.isabs(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise ValueError("uvx not found: install uv or set SWITCHYARD_UVX to its absolute path")


@dataclass
class RunResult:
    exit_code: int | None
    timed_out: bool
    stdout: bytes
    stdout_overflow: bool
    stderr_tail: str
    started: float
    finished: float
    cancelled: bool = False


@contextmanager
def _signals_as_exit():
    """SIGTERM/SIGHUP raise SystemExit so `finally` blocks reap the runner group, record the receipt and
    release the lease, instead of the runner outliving Switchyard (it runs in its own session)."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def handler(signum, _frame):
        raise SystemExit(128 + signum)

    previous = {signum: signal.signal(signum, handler) for signum in (signal.SIGTERM, signal.SIGHUP)}
    try:
        yield
    finally:
        for signum, value in previous.items():
            signal.signal(signum, value)


def run_process(argv, *, cwd, env, timeout, stdout_limit=0, grace=5.0, stdin_data=None, stdin_fd=None, tick=None,
                cancel=None):
    """Run argv in its own session; keep at most stdout_limit bytes of stdout and a stderr tail.

    On deadline the process group is terminated (then killed); `timed_out` is set. The group is
    always reaped before returning, so a caller may release its device lease afterwards.

    `stdin_data` (at most 32 KiB) reaches the child through an anonymous pipe that is written and closed
    before the child starts: never argv, the environment or a file. `stdin_fd` is such a pipe's read end,
    already filled (`_stdin_pipe`); it is closed here once the child has it. `tick` is called about once a
    second while the child runs (progress); setting the `cancel` event stops the group like a deadline."""
    if stdin_data is not None:
        stdin_fd = _stdin_pipe(stdin_data)
    with _signals_as_exit():
        return _run(argv, cwd=cwd, env=env, timeout=timeout, stdout_limit=stdout_limit, grace=grace,
                    stdin_fd=stdin_fd, tick=tick, cancel=cancel)


def _stdin_pipe(data):
    """Read end of an anonymous pipe already holding `data` (the write end is closed: the reader sees EOF)."""
    if len(data) > 32768:
        raise ValueError("Runner input exceeds 32 KiB")
    read_fd, write_fd = os.pipe()  # Both ends are non-inheritable; Popen dup2s the read end onto fd 0.
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(write_fd, view):]  # Fits in the pipe buffer; nothing blocks.
    except BaseException:
        os.close(read_fd)
        raise
    finally:
        os.close(write_fd)
    return read_fd


def _run(argv, *, cwd, env, timeout, stdout_limit, grace, stdin_fd=None, tick=None, cancel=None):
    started = time.time()
    try:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL if stdin_fd is None else stdin_fd,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
    finally:
        if stdin_fd is not None:
            os.close(stdin_fd)
    stdout, stderr = bytearray(), bytearray()
    overflow = timed_out = cancelled = False
    deadline = time.monotonic() + timeout
    ticked = time.monotonic()
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            exited_at = None
            while selector.get_map():
                now = time.monotonic()
                if now >= deadline:
                    timed_out = True
                    break
                if cancel is not None and cancel.is_set():
                    cancelled = True
                    break
                if tick is not None and now - ticked >= 1:
                    ticked = now
                    tick()
                if child.poll() is not None:
                    # Descendants may keep the pipes open after the runner exits; drain briefly only.
                    exited_at = exited_at or now
                    if now - exited_at > 2:
                        break
                for key, _ in selector.select(min(0.2, deadline - now)):
                    part = os.read(key.fd, 65536)
                    if not part:
                        selector.unregister(key.fileobj)
                    elif key.fileobj is child.stdout:
                        room = max(0, stdout_limit - len(stdout))
                        stdout.extend(part[:room])
                        overflow = overflow or len(part) > room
                    else:
                        stderr.extend(part)
                        del stderr[:-STDERR_TAIL]
        if not timed_out and not cancelled:
            try:
                child.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        _stop_group(child, grace)
        for stream in (child.stdout, child.stderr):
            stream.close()
    stopped = timed_out or cancelled
    return RunResult(None if stopped else child.returncode, timed_out, bytes(stdout), overflow,
                     stderr.decode("utf-8", "replace"), started, time.time(), cancelled)


def _stop_group(child, grace):
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait()


class Runner:
    def __init__(self, runner_config, state_dir, cache_dir):
        self.version = runner_config["ansible_core"]
        self.collections = runner_config["collections"]
        self.root = Path(state_dir) / "ansible"
        self.cache = Path(cache_dir)
        self.home = self.root / "home"
        self.collections_dir = self.root / "collections"
        self.plugins = self.root / "callback_plugins"
        self.config_file = self.root / "ansible.cfg"
        self.tmp = self.cache / "tmp"
        self.runs = self.cache / "runs"

    def command(self, tool, *arguments):
        return [uvx_path(), "--from", f"ansible-core=={self.version}", tool, *arguments]

    def environment(self, *, events=None, operator=False):
        env = {key: os.environ[key] for key in PASSTHROUGH if key in os.environ}
        env.update(self.ansible_environment(operator=operator))
        env["TMPDIR"] = str(self.tmp)
        if events:
            env["SWITCHYARD_ANSIBLE_EVENTS"] = str(events)
        return env

    def ansible_environment(self, *, operator=False):
        """Fixed settings that replace the repo's ansible.cfg (never loaded) and any inherited ANSIBLE_*."""
        env = {
            "ANSIBLE_CONFIG": str(self.config_file),
            "ANSIBLE_HOME": str(self.home),
            "ANSIBLE_LOCAL_TEMP": str(self.tmp),
            "ANSIBLE_COLLECTIONS_PATH": str(self.collections_dir),
            "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "False",
            "ANSIBLE_CALLBACK_PLUGINS": str(self.plugins),
            "ANSIBLE_CALLBACKS_ENABLED": CALLBACK,
            "ANSIBLE_LOAD_CALLBACK_PLUGINS": "True",
            "ANSIBLE_CACHE_PLUGIN": "memory",
            "ANSIBLE_FORKS": "1",
            "ANSIBLE_HOST_KEY_CHECKING": "True",
            "ANSIBLE_SSH_RETRIES": "0",
            "ANSIBLE_TIMEOUT": "10",
            "ANSIBLE_RETRY_FILES_ENABLED": "False",
            "ANSIBLE_NOCOLOR": "1",
        }
        if not operator:
            env["ANSIBLE_BECOME_ASK_PASS"] = "False"
            env["ANSIBLE_ASK_PASS"] = "False"
        return env

    def prepare(self):
        """Private directories, callback plugin and config; pinned collections. Local only."""
        for path in (self.root, self.home, self.collections_dir, self.plugins):
            private_dir(path)
        self.cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        for path in (self.cache, self.tmp, self.runs):
            private_dir(path)
        source = Path(__file__).with_name("ansible_callback.py").read_bytes()
        target = self.plugins / (CALLBACK + ".py")
        if not target.exists() or target.read_bytes() != source:
            write_private(target, source)
        config = "[defaults]\ninterpreter_python = auto_silent\nretry_files_enabled = False\n"
        if not self.config_file.exists() or self.config_file.read_text() != config:
            write_private(self.config_file, config)
        for collection in self.collections:
            if self.installed_collection(collection["name"]) != collection["version"]:
                result = run_process(self.command("ansible-galaxy", "collection", "install", "--force",
                                                  "-p", str(self.collections_dir),
                                                  f"{collection['name']}:=={collection['version']}"),
                                     cwd=str(self.root), env=self.environment(), timeout=600)
                if result.exit_code != 0 or self.installed_collection(collection["name"]) != collection["version"]:
                    raise ValueError(f"Could not install pinned collection {collection['name']} {collection['version']}")

    def installed_collection(self, name):
        namespace, collection = name.split(".")
        manifest = self.collections_dir / "ansible_collections" / namespace / collection / "MANIFEST.json"
        try:
            return json.loads(manifest.read_text())["collection_info"]["version"]
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def check_version(self):
        """First use downloads ansible-core into uv's cache (outside any device lease)."""
        result = run_process(self.command("ansible-playbook", "--version"), cwd=str(self.root),
                             env=self.environment(), timeout=600, stdout_limit=65536)
        match = re.search(r"\[core ([0-9][0-9.]*)\]", result.stdout.decode("utf-8", "replace"))
        if result.exit_code != 0 or not match:
            raise ValueError("Pinned ansible-core runner is unavailable: " + _last_line(result.stderr_tail))
        if match[1] != self.version:
            raise ValueError(f"Runner reports ansible-core {match[1]}, expected pinned {self.version}")
        return match[1]

    def run_dir(self):
        return Path(tempfile.mkdtemp(prefix="run-", dir=private_dir(self.runs)))


def _last_line(text):
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1][:300] if lines else "no output"


class EventStream:
    """The callback's events, kept off disk. The callback writes JSON lines to a FIFO in the private run
    directory (`SWITCHYARD_ANSIBLE_EVENTS`); a reader thread parses each line and passes it through `scrub`
    before keeping it in memory, so a secret Ansible echoes (a templated task name, a failure message) is
    never written anywhere. Switchyard holds a write end itself until `close`, so the reader sees end of
    file only after the runner and Switchyard are both done."""

    LIMIT = 16 * 1024 * 1024

    def __init__(self, directory, scrub=lambda value: value):
        self.path = Path(directory) / "events.fifo"
        os.mkfifo(self.path, 0o600)
        self._read = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        self._hold = os.open(self.path, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        self._scrub = scrub
        self._records, self._size, self._lock = [], 0, threading.Lock()
        self._thread = threading.Thread(target=self._pump, name="ansible-events", daemon=True)
        self._thread.start()

    def _keep(self, line):
        self._size += len(line)
        if self._size > self.LIMIT:
            return  # Bounded like the callback itself; the reader keeps draining so the runner never blocks.
        try:
            value = json.loads(line)
        except ValueError:
            return
        if isinstance(value, dict) and isinstance(value.get("event"), str):
            value = self._scrub(value)
            with self._lock:
                self._records.append(value)

    def _pump(self):
        pending = b""
        try:
            while True:
                if not select.select([self._read], [], [], 0.2)[0]:
                    continue
                part = os.read(self._read, 65536)
                if not part:
                    break
                pending += part
                *lines, pending = pending.split(b"\n")
                for line in lines:
                    self._keep(line)
                if len(pending) > 1048576:
                    pending = b""
        except OSError:
            pass
        if pending:
            self._keep(pending)

    def records(self):
        with self._lock:
            return list(self._records)

    def close(self):
        """Idempotent: release Switchyard's write end, drain to end of file, remove the FIFO."""
        if self._hold is None:
            return
        os.close(self._hold)
        self._hold = None
        self._thread.join(10)
        os.close(self._read)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def parse_events(path):
    """Read the last run recorded in an events file (an operator's own terminal run) into bounded task results."""
    try:
        with open(path, "rb") as stream:
            lines = stream.read(16 * 1024 * 1024).splitlines()
    except FileNotFoundError:
        lines = []
    records = []
    for line in lines:
        try:
            records.append(json.loads(line))
        except ValueError:
            continue
    return parse_records(records)


def parse_records(records):
    """Bounded task results from the events of the last run in `records`."""
    events = []
    for value in records:
        if isinstance(value, dict) and isinstance(value.get("event"), str):
            if value["event"] == "start":
                events = []
            events.append(value)
    tasks, truncated = [], False
    summary = {"started": None, "ended": None, "check_mode": None, "stats": None, "no_hosts_matched": False,
               "current_task": None, "current_play": None}
    for value in events:
        kind = value["event"]
        if kind == "start":
            summary["started"] = value.get("at")
            summary["check_mode"] = bool(value.get("check_mode"))
        elif kind == "play":
            summary["current_play"] = str(value.get("name") or "")[:256]
        elif kind == "task":
            summary["current_task"] = str(value.get("name") or "")[:256]
        elif kind == "result":
            if len(tasks) >= MAX_TASKS:
                truncated = True
                continue
            task = {key: value[key] for key in ("task", "host", "status", "action", "handler", "no_log", "diff_bytes",
                                                "not_predicted", "forced_run", "ignored", "msg") if key in value}
            tasks.append(task)
        elif kind == "stats":
            summary["stats"] = value.get("hosts")
        elif kind == "end":
            summary["ended"] = value.get("at")
            summary["current_task"] = None
        elif kind == "truncated":
            truncated = True
        elif kind == "no_hosts_matched":
            summary["no_hosts_matched"] = True
    names = lambda status: [task["task"] for task in tasks if task.get("status") == status]
    summary.update(tasks=tasks, truncated=truncated, changed_tasks=names("changed"),
                   failed_tasks=[task["task"] for task in tasks if task.get("status") == "failed" and not task.get("ignored")],
                   unreachable_tasks=names("unreachable"),
                   not_predicted=[task["task"] for task in tasks if task.get("not_predicted")],
                   forced_run=[task["task"] for task in tasks if task.get("forced_run")])
    return summary
