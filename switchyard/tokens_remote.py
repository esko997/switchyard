"""Fixed remote program for start tokens of adopted (registered) applications.

Executed through `switchyard.remote.run_remote` while the caller holds the host's
canonical lease; the controller appends `print(json.dumps(main(PAYLOAD)))`.
Stdlib only. It writes exactly one file per (application, component) below
`~/.local/state/switchyard/tokens/` (plus a `.nobackup` marker and a `README` in
that directory, create-only) and nothing else. Never follows a symlink.

Line 1 of a token file is the only thing a gate compares:
  switchyard-generation-token/v1 application=<app> component=<c> host=<host> generation=<N>
revoked:
  switchyard-generation-token/v1 revoked application=<app> component=<c> host=<host> generation=<N>
Later lines are metadata (issued_at=, revoked_at=, operation=) and ignored by gates.
"""
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import uuid
from datetime import datetime, timezone

FORMAT = "switchyard-generation-token/v1"
ROOT = (".local", "state", "switchyard", "tokens")
ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
LINE = re.compile(FORMAT + r"( revoked)? application=([a-z0-9][a-z0-9-]{0,63}) component=([a-z0-9][a-z0-9-]{0,63})"
                  r" host=([a-z0-9][a-z0-9-]{0,63}) generation=([1-9][0-9]{0,17})\Z")
LIMIT = 4096
README = (
    "Switchyard start tokens (one file per application component).\n"
    "Line 1 of each file is compared by start gates; later lines are metadata.\n"
    "EXCLUDE THIS DIRECTORY FROM BACKUPS AND RESTORES: restoring an old token file\n"
    "re-opens a start path that Switchyard revoked. Tokens are issued and revoked only\n"
    "by `switchyard token issue|revoke`; never copy them between hosts.\n")


class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def home():
    return pwd.getpwuid(os.getuid()).pw_dir


def token_line(payload, revoked=False):
    return (FORMAT + (" revoked" if revoked else "") + " application=" + payload["application"] + " component="
            + payload["component"] + " host=" + payload["host_id"] + " generation=" + str(payload["generation"]))


def parse(line):
    match = LINE.fullmatch(line)
    if match is None:
        return None
    return {"revoked": bool(match.group(1)), "application": match.group(2), "component": match.group(3),
            "host_id": match.group(4), "generation": int(match.group(5))}


def tokens_dir(*, create):
    """Every component below $HOME must be a real directory owned by this user; the last one is 0700."""
    current = Path(home())
    for part in ROOT:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            require(create, "Token directory does not exist")
            os.mkdir(current, 0o700)
            info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(),
                "Symlink or foreign directory in the token path: " + str(current))
    if create:
        os.chmod(current, 0o700)
    return current


def app_dir(application, *, create):
    root = tokens_dir(create=create)
    path = root / application
    try:
        info = path.lstat()
    except FileNotFoundError:
        require(create, "Application token directory does not exist")
        os.mkdir(path, 0o700)
        info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), "Symlink or foreign directory: " + str(path))
    if create:
        os.chmod(path, 0o700)
    return root, path


def read_token(path):
    """None if absent; refuses symlinks, foreign owners and non-regular files."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise Refusal("Token path is not a readable regular file (symlink?): " + type(error).__name__)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_size <= LIMIT,
                "Token path is not a bounded regular file owned by this user")
        data = os.read(fd, LIMIT + 1)
    finally:
        os.close(fd)
    return {"bytes": data, "mode": oct(stat.S_IMODE(info.st_mode)), "sha256": hashlib.sha256(data).hexdigest()}


def _sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_only(path, data, mode):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except FileExistsError:
        return False
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return True


def describe(path):
    """Read-only state of one token file."""
    current = read_token(path)
    if current is None:
        return {"exists": False}
    text = current["bytes"].decode("utf-8", "replace")
    lines = text.split("\n")
    first = lines[0]
    extra = [index + 1 for index, line in enumerate(lines[1:], start=1)
             if (parsed := parse(line)) is not None and not parsed["revoked"]]
    return {"exists": True, "line1": first[:512], "parsed": parse(first), "extra_valid_lines": extra,
            "mode": current["mode"], "sha256": current["sha256"]}


def write(payload):
    """Write line 1 (valid or revoked) atomically, read it back. Touches only the tokens directory."""
    for key in ("application", "component", "host_id"):
        require(isinstance(payload.get(key), str) and ID.fullmatch(payload[key]), "Invalid " + key)
    require(type(payload.get("generation")) is int and payload["generation"] > 0, "Invalid generation")
    revoked = payload["mode"] == "revoked"
    require(payload["mode"] in ("valid", "revoked"), "Invalid token mode")
    mutated = False
    try:
        root, directory = app_dir(payload["application"], create=True)
        markers = []
        if create_only(root / ".nobackup", b"", 0o600):
            markers.append(".nobackup")
        if create_only(root / "README", README.encode(), 0o600):
            markers.append("README")
        path = directory / (payload["component"] + ".token")
        before = describe(path)  # refuses a symlink or foreign file before replacing it
        at = stamp()
        line = token_line(payload, revoked)
        meta = [("revoked_at=" if revoked else "issued_at=") + at, "operation=" + payload["operation_id"]]
        if revoked and payload.get("issued_at"):
            meta.insert(0, "issued_at=" + payload["issued_at"])
        data = ("\n".join([line, *meta]) + "\n").encode()
        temp = directory / ("." + path.name + ".switchyard-" + uuid.uuid4().hex)
        mutated = True
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp, path)
        _sync(directory)
        after = describe(path)
        require(after.get("exists") and after["line1"] == line and after["mode"] == "0o600",
                "Token read-back did not match the written line")
        return {"status": "succeeded", "path": str(path), "line": line, "at": at, "before": before, "after": after,
                "markers_created": markers}
    except Exception as error:
        message = str(error) if isinstance(error, Refusal) else "Token write failed (" + type(error).__name__ + ")"
        return {"status": "needs-inspection" if mutated else "failed", "error": message}


def read(payload):
    """Read-only: line-1 state of the requested tokens; never creates the directory."""
    results = []
    for item in payload["items"]:
        try:
            try:
                _, directory = app_dir(item["application"], create=False)
            except Refusal as error:
                if "does not exist" not in str(error):
                    raise
                results.append({**item, "path": None, "state": {"exists": False}})
                continue
            path = directory / (item["component"] + ".token")
            results.append({**item, "path": str(path), "state": describe(path)})
        except Exception as error:
            results.append({**item, "error": str(error) if isinstance(error, Refusal) else type(error).__name__})
    return {"status": "succeeded", "home": home(), "results": results}


ACTIONS = {"write": write, "read": read}


def main(payload):
    try:
        require(isinstance(payload, dict) and payload.get("action") in ACTIONS, "Unsupported token action")
        require(os.getuid() != 0, "Rootful execution is forbidden")
        return ACTIONS[payload["action"]](payload)
    except Refusal as error:
        return {"status": "failed", "error": str(error)}
    except Exception as error:
        return {"status": "failed", "error": "Remote token step failed (" + type(error).__name__ + ")"}
