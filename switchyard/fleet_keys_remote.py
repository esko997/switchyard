"""Fixed stdlib-only remote key actions; never returns or reads private key bytes."""
import base64
from contextlib import contextmanager
import fcntl
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import re
import shutil
import stat
import resource
import subprocess
import tempfile

BEGIN = b"# BEGIN SWITCHYARD FLEET KEYS v1\n"
END = b"# END SWITCHYARD FLEET KEYS v1\n"
GENERATION = re.compile(r"[0-9a-f]{32}\Z")
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
LIMIT = 131072


class Conflict(ValueError):
    pass


def public_key(value):
    if not isinstance(value, str) or len(value) > 512:
        raise Conflict("Invalid Ed25519 public key")
    fields = value.strip().split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise Conflict("Only Ed25519 keys are supported")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except ValueError as error:
        raise Conflict("Invalid public key encoding") from error
    if len(blob) != 51 or blob[:19] != b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20":
        raise Conflict("Invalid Ed25519 key structure")
    return "ssh-ed25519 " + fields[1]


def fingerprint(value):
    blob = base64.b64decode(public_key(value).split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def managed(original, content):
    """Replace exactly our byte-delimited block; manual bytes are never decoded."""
    if original.count(BEGIN) != original.count(END) or original.count(BEGIN) > 1:
        raise Conflict("Malformed or duplicate managed section")
    if (b"# BEGIN SWITCHYARD" in original.replace(BEGIN, b"")
            or b"# END SWITCHYARD" in original.replace(END, b"")):
        raise Conflict("Unrecognized managed section")
    block = BEGIN + content + END if content else b""
    if BEGIN not in original:
        return block + original
    start = original.index(BEGIN)
    finish = original.index(END) + len(END)
    if finish <= start or (start and original[start - 1:start] != b"\n"):
        raise Conflict("Invalid managed section boundary")
    return original[:start] + block + original[finish:]


def unmanaged(original):
    return managed(original, b"")


def client_supported():
    if not shutil.which("ssh") or not shutil.which("ssh-keygen"):
        return False
    try:
        # -G only evaluates our fixed configuration; it never opens a connection.
        result = subprocess.run(["ssh", "-G", "-F", "/dev/null", "-o", "IdentityAgent=none",
                                 "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "KbdInteractiveAuthentication=no",
                                 "--", "switchyard-capability-check"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class Files:
    def __init__(self, home=None):
        self.home = Path(home) if home is not None else Path.home()
        self.ssh = self.home / ".ssh"
        self.root = self.ssh / "switchyard"
        self.paths = {"authorized_keys": self.ssh / "authorized_keys",
                      "config": self.root / "config", "known_hosts": self.root / "known_hosts"}

    def safe(self, path, *, directory=False, private=False):
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if (info.st_uid != os.getuid() or info.st_mode & 0o022
                or (directory and not stat.S_ISDIR(info.st_mode))
                or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))
                or (private and info.st_mode & 0o077)):
            raise Conflict("Unsafe ownership, permissions, link or file type: " + path.name)
        return info

    def directories(self, create=False):
        self.safe(self.home, directory=True)
        for path in (self.ssh, self.root):
            if self.safe(path, directory=True) is None and create:
                path.mkdir(mode=0o700)
                self.safe(path, directory=True)

    def read(self, path):
        if self.safe(path) is None:
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o022:
                raise Conflict("File changed while opening")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                value = stream.read(LIMIT + 1)
            if len(value) > LIMIT:
                raise Conflict("SSH file exceeds inspection bound")
            return value
        finally:
            os.close(fd)

    def identity(self, generation):
        if not isinstance(generation, str) or not GENERATION.fullmatch(generation):
            raise Conflict("Invalid identity generation")
        return self.root / ("id_ed25519-" + generation)

    def inspect(self):
        self.directories()
        files = {}
        for name, path in self.paths.items():
            raw = self.read(path)
            if raw is not None:
                manual = unmanaged(raw)
                if name != "authorized_keys" and manual:
                    raise Conflict("Dedicated client files contain unmanaged settings")
            files[name] = raw
        keys = {}
        identities = {}
        if self.root.exists():
            entries = list(islice(self.root.iterdir(), 257))
            if len(entries) > 256:
                raise Conflict("Too many dedicated SSH files")
            for path in entries:
                if path.name.startswith("id_ed25519-") and not path.name.endswith(".pub"):
                    generation = path.name[11:]
                    private = self.identity(generation)
                    info = self.safe(private, private=True)
                    if info is None or not 0 < info.st_size <= 16384:
                        raise Conflict("Private identity changed or exceeds the supported file-size bound")
                    identities[generation] = [info.st_ino, info.st_size, info.st_mtime_ns, stat.S_IMODE(info.st_mode)]
                if path.name.startswith("id_ed25519-") and path.name.endswith(".pub"):
                    generation = path.name[11:-4]
                    private = self.identity(generation)
                    if self.safe(private, private=True) is None:
                        raise Conflict("Public identity has no safe local private key")
                    raw = self.read(path)
                    keys[generation] = public_key(raw.decode("ascii"))
        server = Path("/etc/ssh/ssh_host_ed25519_key.pub")
        server_key = None
        try:
            info = server.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022:
                with server.open("rb") as stream:
                    raw = stream.read(513)
                server_key = public_key(raw.decode("ascii"))
        except (OSError, UnicodeError, Conflict):
            pass
        supported = bool(server_key and client_supported())
        # Include all inspected managed/manual bytes and public identities, never private bytes.
        revision = hashlib.sha256(json.dumps({"files": {k: None if v is None else hashlib.sha256(v).hexdigest()
                                                        for k, v in files.items()},
                                               "keys": keys, "identities": identities, "server_key": server_key}, sort_keys=True).encode()).hexdigest()
        return {"supported": supported, "revision": revision, "keys": keys, "server_key": server_key,
                "detail": ("Ed25519 client and server identity available; peer listener/authentication not yet proven"
                           if supported else "Requires a modern OpenSSH client with strict Ed25519/IdentityAgent support, ssh-keygen and a readable root-owned Ed25519 server public key; no installation or crypto downgrade performed")}

    @contextmanager
    def locked(self):
        self.directories(create=True)
        lock = self.root / "lock"
        self.safe(lock, private=True)
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            self.safe(lock, private=True)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise Conflict("Remote managed-file lock is busy") from error
            yield
        finally:
            os.close(fd)

    def atomic(self, path, content, previous):
        # Recoverable previous versions are local to this host and contain public data only.
        backup = path.with_name(path.name + ".switchyard-prior")
        if previous is not None:
            self._replace(backup, previous, self.read(backup))
        self._replace(path, content, previous)

    def _replace(self, path, content, previous):
        self.safe(path)
        fd, temporary = tempfile.mkstemp(prefix=".switchyard-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            if self.read(path) != previous:
                raise Conflict("SSH file changed concurrently; inspect and plan again")
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def apply(self, request):
        with self.locked():
            before = self.inspect()
            if before["revision"] != request["expected_revision"]:
                raise Conflict("Inspected SSH files changed; inspect and plan again")
            if not before["supported"]:
                return before
            generation = request.get("generation")
            if request["action"] == "identity":
                private = self.identity(generation)
                if self.safe(private, private=True) is None:
                    if self.read(private.with_name(private.name + ".pub")) is not None:
                        raise Conflict("Identity path already contains a public key")
                    # ssh-keygen writes private material directly on its owner host only.
                    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "switchyard-managed",
                                    "-f", str(private)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=12, check=True)
                else:
                    self.safe(private, private=True)
                    public_path = private.with_name(private.name + ".pub")
                    if self.read(public_path) is None:
                        # Recover a completed private-key creation whose public-file write was interrupted.
                        result = subprocess.run(["ssh-keygen", "-y", "-f", str(private)], stdin=subprocess.DEVNULL,
                                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12, check=True)
                        public = public_key(result.stdout.decode("ascii"))
                        self.atomic(public_path, (public + " switchyard-managed\n").encode(), None)
                return self.inspect()
            if request["action"] != "configure":
                raise Conflict("Unknown remote key action")
            grants = [public_key(key) for key in request["grants"]]
            peers = request["peers"]
            config, pins = [], []
            if peers:
                self.safe(self.identity(generation), private=True)
                if generation not in before["keys"]:
                    raise Conflict("Selected local identity is unavailable")
            for peer in peers:
                host_id = peer["host_id"]
                if not HOST.fullmatch(host_id):
                    raise Conflict("Invalid peer alias")
                # These values are broker-validated configuration, not user-authored SSH fragments.
                user, address = peer["target"].split("@")
                if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user) or not re.fullmatch(r"[A-Za-z0-9:.\-]+", address):
                    raise Conflict("Invalid peer endpoint")
                alias = "switchyard-" + host_id
                config.extend(["Host " + alias, "  HostName " + address, "  User " + user, "  Port 22",
                               '  IdentityFile "' + str(self.identity(generation)).replace('\\', '\\\\').replace('"', '\\"') + '"',
                               "  IdentitiesOnly yes", "  IdentityAgent none", "  BatchMode yes",
                               "  PreferredAuthentications publickey", "  PasswordAuthentication no",
                               "  KbdInteractiveAuthentication no", "  PubkeyAuthentication yes",
                               "  StrictHostKeyChecking yes", "  HostKeyAlias " + alias,
                               '  UserKnownHostsFile "' + str(self.paths["known_hosts"]).replace('\\', '\\\\').replace('"', '\\"') + '"',
                               "  GlobalKnownHostsFile /dev/null", "  HostKeyAlgorithms ssh-ed25519",
                               "  ForwardAgent no", "  ClearAllForwardings yes", "  ProxyCommand none",
                               "  ProxyJump none", "  ControlMaster no", "  ControlPath none", "  ConnectTimeout 5", ""])
                pins.append(alias + " " + public_key(peer["server_key"]))
            contents = {"authorized_keys": ("".join(key + " switchyard-managed\n" for key in sorted(set(grants)))).encode(),
                        "config": ("\n".join(config) + "\n").encode() if config else b"",
                        "known_hosts": ("\n".join(pins) + "\n").encode() if pins else b""}
            residual = []
            original = self.read(self.paths["authorized_keys"]) or b""
            manual = unmanaged(original)
            for key in request.get("revoked_keys", []):
                key = public_key(key)
                if key.split()[1].encode() in re.findall(rb"ssh-ed25519[ \t]+([A-Za-z0-9+/=]+)", manual):
                    residual.append(fingerprint(key))
            for name, content in contents.items():
                path = self.paths[name]
                previous = self.read(path)
                replacement = managed(previous or b"", content)
                if replacement != (previous or b""):
                    self.atomic(path, replacement, previous)
            return {**self.inspect(), "residual_access": residual}

    def verify(self, request):
        self.directories()
        identity = self.identity(request["generation"])
        if self.safe(identity, private=True) is None:
            raise Conflict("Verification identity unavailable")
        peer = request["peer"]
        user, address = peer["target"].split("@")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user) or not re.fullmatch(r"[A-Za-z0-9:.\-]+", address):
            raise Conflict("Invalid verification endpoint")
        # Ephemeral public-only pin isolates verification from manual client config/agents.
        fd, name = tempfile.mkstemp(prefix=".verify-", dir=self.root)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write("switchyard-peer " + public_key(peer["server_key"]) + "\n")
            command = ["ssh", "-F", "/dev/null", "-T", "-p", "22", "-i", str(identity),
                       "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                       "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
                       "-o", "KbdInteractiveAuthentication=no", "-o", "PubkeyAuthentication=yes",
                       "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias=switchyard-peer",
                       "-o", "UserKnownHostsFile=" + name, "-o", "GlobalKnownHostsFile=/dev/null",
                       "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ForwardAgent=no",
                       "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=4", "-o", "ConnectionAttempts=1",
                       "-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=1",
                       "--", user + "@" + address, "printf switchyard-fleet-key-ok"]
            # Limit SSH's regular-file output in the child as well as bounded reads in this process.
            def bound_output():
                resource.setrlimit(resource.RLIMIT_FSIZE, (16384, 16384))
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                                           start_new_session=True, preexec_fn=bound_output)
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    import signal
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    return {"status": "pending", "detail": "Peer connection deadline; listener/reachability/authentication unproven"}
                output.seek(0)
                errors.seek(0)
                out, err = output.read(1025), errors.read(4097)
                if process.returncode == 0 and out == b"switchyard-fleet-key-ok":
                    return {"status": "verified", "detail": "Dedicated identity authenticated with pinned Ed25519 host key"}
                if process.returncode == 255 and b"Permission denied (publickey" in err:
                    return {"status": "revoked", "detail": "Pinned listener explicitly rejected this dedicated public key"}
                return {"status": "pending", "detail": "Peer SSH failed: check listener, account/key authentication, routing and pinned server identity; no settings changed"}
        finally:
            os.unlink(name)


def main(request):
    try:
        files = Files()
        if request["action"] == "inspect":
            result = files.inspect()
        elif request["action"] == "verify":
            result = files.verify(request)
        else:
            result = files.apply(request)
        print(json.dumps({"ok": True, **result}))
    except Conflict as error:
        print(json.dumps({"ok": False, "status": "conflict", "detail": str(error)}))
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        print(json.dumps({"ok": False, "status": "pending", "detail": "Remote key action failed; inspect local SSH files before reconciling; no automatic retry"}))
