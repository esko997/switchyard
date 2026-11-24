"""Host-ID-scoped OpenSSH pins; bootstrap is local and never establishes trust."""
import base64
import binascii
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile

_HOST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_KEY_TYPE = re.compile(r"(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp(?:256|384|521))\Z")


def _key(key_line):
    if not isinstance(key_line, str) or len(key_line) > 16384:
        raise ValueError("Invalid SSH public key")
    fields = key_line.split()
    if len(fields) != 2 or not _KEY_TYPE.fullmatch(fields[0]):
        raise ValueError("Invalid SSH public key")
    try:
        blob = base64.b64decode(fields[1], validate=True)
        size = struct.unpack(">I", blob[:4])[0]
        if blob[4:4 + size] != fields[0].encode() or len(blob) <= 4 + size:
            raise ValueError("Invalid SSH public key")
    except (binascii.Error, struct.error) as error:
        raise ValueError("Invalid SSH public key") from error
    return fields[0] + " " + base64.b64encode(blob).decode(), blob


def fingerprint(key_line):
    _, blob = _key(key_line)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def parse_keys(output):
    """Read ssh-keygen/-keyscan host-prefixed output, never retaining comments."""
    keys = set()
    for line in output.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        # Marked entries (notably revoked keys) must not become trusted pins.
        if len(fields) >= 3 and not fields[0].startswith("@"):
            keys.add(_key(" ".join(fields[1:3]))[0])
    return sorted(keys)


def bootstrap(address, port=22, known_hosts=Path.home() / ".ssh/known_hosts"):
    if not isinstance(address, str) or not address or address.startswith("-") or any(c.isspace() for c in address):
        raise ValueError("Invalid SSH address")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid SSH port")
    path = Path(known_hosts)
    if not path.exists():
        return []
    lookup = address if port == 22 else f"[{address}]:{port}"
    result = subprocess.run(["ssh-keygen", "-F", lookup, "-f", str(path)],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False)
    if result.returncode == 1:
        return []
    if result.returncode != 0 or len(result.stdout) > 1048576:
        raise ValueError("Cannot read existing SSH pins")
    return parse_keys(result.stdout.decode("utf-8"))


def write_pins(path, pins):
    path = Path(path)
    parent = path.parent
    if not path.is_absolute() or parent.resolve(strict=True) != parent:
        raise ValueError("Pins require a canonical absolute directory")
    info = parent.stat()
    if info.st_uid != os.getuid() or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        raise ValueError("Pins directory must be owned and not writable by others")
    if path.is_symlink():
        raise ValueError("Pins file cannot be a symlink")
    if path.exists():
        info = path.stat()
        if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("Pins file must be private and owned")
    lines = []
    for host_id, keys in sorted(pins.items()):
        if not isinstance(host_id, str) or not _HOST_ID.fullmatch(host_id) or not isinstance(keys, list):
            raise ValueError("Invalid host pins")
        for key in sorted({_key(value)[0] for value in keys}):
            lines.append("switchyard-" + host_id + " " + key + "\n")
    fd, temporary = tempfile.mkstemp(prefix=".known-hosts-", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write("".join(lines))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
