"""Local-host compatibility bridge for existing append-only device ledgers.

Not a distributed lease service. All contenders must use this same host/inode.
No API accepts ledger paths from an AI or a browser. A lease is coordination,
not authorization.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import stat
import time
from typing import Iterator
import uuid


class LeaseBusy(RuntimeError):
    pass


class LedgerBroker:
    def __init__(self, resources: dict[str, Path]):
        # Trusted operator mapping; require canonical paths, never create ledgers.
        self.resources = dict(resources)
        for path in self.resources.values():
            if not path.is_absolute() or path != path.resolve(strict=True):
                raise ValueError("Ledger paths must be absolute, existing and canonical (no symlinks)")

    @contextmanager
    def hold(self, resource: str, *, owner: str, scope: str, worktree: str,
             lease_id: str | None = None, metadata: dict | None = None, wait: float = 0) -> Iterator[dict]:
        """wait: bounded seconds to poll for a busy lock before LeaseBusy (nothing has executed yet,
        so this is not a retry); 0 fails immediately."""
        if not isinstance(wait, (int, float)) or isinstance(wait, bool) or not 0 <= wait <= 600:
            raise ValueError("Lease wait must be 0-600 seconds")
        if resource not in self.resources:
            raise ValueError("Unknown lease resource")
        for value in (owner, scope, worktree):
            if not isinstance(value, str) or not value.strip() or len(value) > 512:
                raise ValueError("Lease metadata must be bounded nonempty text")
        metadata = dict(metadata or {})
        if set(metadata) - {"pid", "expires_at", "via"}:
            raise ValueError("Unsupported lease metadata")
        path = self.resources[resource]
        fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
        acquired = False
        claimed = False
        outcome = "failed"
        token = lease_id or uuid.uuid4().hex
        release = {}

        def append(event: str, **extra):
            data = (json.dumps({"at": datetime.now(timezone.utc).isoformat(), "event": event,
                               "lease_id": token, "resource": resource, "owner": owner,
                               "scope": scope, "worktree": worktree, **metadata, **extra}) + "\n").encode()
            # Keep appending to the held inode even if a non-cooperating writer breaks protocol.
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("Could not append lease event")
                view = view[written:]
            os.fsync(fd)

        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("Ledger must be a regular file")
            deadline = time.monotonic() + wait
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as error:
                    if time.monotonic() >= deadline:
                        raise LeaseBusy(f"Resource is busy: {resource}") from error
                    time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
            acquired = True
            opened = os.fstat(fd)
            current = os.stat(path, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise RuntimeError("Ledger inode changed during acquisition")
            baseline = os.pread(fd, 8192, max(0, opened.st_size - 8192)).decode("utf-8", errors="replace")
            append("CLAIM")
            claimed = True
            # `fd` is the locked descriptor (close-on-exec); callers may hand it to one
            # explicitly opted-in child, which then shares this same lock.
            yield {"resource": resource, "lease_id": token, "baseline": baseline, "release": release, "fd": fd}
            outcome = "completed"
        finally:
            try:
                if claimed:
                    append("RELEASE", outcome=outcome, **release,
                           caveat="Coordination only; consult operation evidence for device state.")
            finally:
                if acquired:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
