"""Execute fixed Python payloads in the host context of an integrated container."""
from contextlib import contextmanager
import math
import os
import subprocess
import sys
import uuid

from .leases import mark_uncertain


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

    Confirm the host unit stopped before releasing its durable lease. If the
    user manager cannot prove it, leave the lease suspect.
    """
    if not isinstance(source, bytes):
        raise ValueError("Fixed host payload source must be bytes")
    if not enabled():
        yield [sys.executable, "-I", "-S", "-"], source
        return
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 270:
        raise ValueError("Invalid host payload deadline")
    unit = "switchyard-host-" + uuid.uuid4().hex + ".service"
    command = ["systemd-run", "--user", "--pipe", "--wait", "--collect", "--quiet", f"--unit={unit}",
               f"--property=RuntimeMaxSec={math.ceil(timeout)}", "--property=TimeoutStopSec=5",
               "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
               # systemd-run resolves argv[0] inside the image before handing
               # the command off. The host interpreter need not exist there.
               "--", "/usr/bin/env", "--", "/usr/bin/python3", "-I", "-S", "-"]
    try:
        yield command, source
    finally:
        if not _cancel(unit):
            mark_uncertain("host unit termination unconfirmed")
