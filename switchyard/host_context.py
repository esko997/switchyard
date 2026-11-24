"""Explicit integrated-container execution of fixed Python payloads on the host.

This is packaging, not isolation. The user bus and host network namespace are
operator grants. A private Unix socket transfers the caller's actual flock open
file descriptions to the host payload before it may execute anything. Killing
the container therefore cannot unlock a ledger underneath a surviving host job.
"""
from array import array
from contextlib import contextmanager
import math
import os
import socket
import struct
import subprocess
import sys
import threading
import uuid

from .leases import held_ledgers


_HOST_PREAMBLE = '''import array,os,socket,sys
_switchyard_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
_switchyard_socket.settimeout(10)
_switchyard_socket.connect({address!r})
_switchyard_data, _switchyard_rights, _switchyard_flags, _ = _switchyard_socket.recvmsg(1, socket.CMSG_SPACE(256 * array.array('i').itemsize))
_switchyard_fds = array.array('i')
for _level, _kind, _data in _switchyard_rights:
    if _level == socket.SOL_SOCKET and _kind == socket.SCM_RIGHTS:
        _switchyard_fds.frombytes(_data[:len(_data) - len(_data) % _switchyard_fds.itemsize])
if _switchyard_data != b'1' or _switchyard_flags & socket.MSG_CTRUNC or len(_switchyard_fds) != {count}:
    sys.exit(78)
for _fd in _switchyard_fds:
    os.set_inheritable(_fd, False)
_switchyard_socket.sendall(b'1')
_switchyard_socket.close()
'''


def enabled():
    value = os.environ.get("SWITCHYARD_CONTAINER_HOST", "0")
    if value not in {"0", "1"}:
        raise ValueError("SWITCHYARD_CONTAINER_HOST must be 0 or 1")
    return value == "1"


def _cancel(unit):
    """A successful synchronous stop proves the whole cgroup is gone."""
    try:
        result = subprocess.run(["systemctl", "--user", "stop", unit], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
        if result.returncode == 0:
            return True
        result = subprocess.run(["systemctl", "--user", "show", unit, "--property=LoadState", "--value"],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False)
        return result.returncode == 0 and result.stdout.strip() == b"not-found"
    except (OSError, subprocess.SubprocessError):
        return False


@contextmanager
def execution(source, *, timeout):
    """Yield (argv, source) for existing bounded transports, preserving native mode.

    Always confirm host-unit exit, even after normal transport return. If the bus is
    unavailable, leave its borrowed flock descriptors locked and omit the local
    RELEASE; RuntimeMaxSec still bounds the host job independently of this client.
    """
    if not isinstance(source, bytes):
        raise ValueError("Fixed host payload source must be bytes")
    if not enabled():
        yield [sys.executable, "-I", "-S", "-"], source
        return
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 270:
        raise ValueError("Invalid host payload deadline")
    entries = held_ledgers()
    if len(entries) > 253:
        raise ValueError("Too many held host ledgers")
    unit = "switchyard-host-" + uuid.uuid4().hex + ".service"
    # Linux abstract sockets share the explicitly granted host network namespace;
    # no container temporary pathname is ever interpreted on the host.
    address = "\0" + unit
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stopped = threading.Event()
    listener.bind(address)
    listener.listen(1)
    listener.settimeout(0.1)

    def transfer():
        while not stopped.is_set():
            try:
                peer, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with peer:
                _, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != os.getuid():
                    continue
                # Mark before sendmsg: even an interrupted/partial send must not
                # permit an explicit unlock of a description the host received.
                for entry in entries:
                    entry["exported"] = True
                    entry["host_pending"].add(unit)
                rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [entry["fd"] for entry in entries]))] if entries else []
                try:
                    peer.settimeout(5)
                    peer.sendmsg([b"1"], rights)
                    if peer.recv(1) != b"1":
                        return
                except OSError:
                    pass
                return
    thread = threading.Thread(target=transfer, name="switchyard-host-ledgers", daemon=True)
    command = ["systemd-run", "--user", "--pipe", "--wait", "--collect", "--quiet", f"--unit={unit}",
               f"--property=RuntimeMaxSec={math.ceil(timeout)}", "--property=TimeoutStopSec=5",
               "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
               "--", "/usr/bin/python3", "-I", "-S", "-"]
    wrapped = (_HOST_PREAMBLE.format(address=address, count=len(entries))
               + "exec(compile(" + repr(source) + ", '<switchyard-host-payload>', 'exec'))\n").encode()
    thread.start()
    try:
        yield command, wrapped
    finally:
        stopped.set()
        thread.join()
        listener.close()
        if _cancel(unit):
            for entry in entries:
                entry["host_pending"].discard(unit)
