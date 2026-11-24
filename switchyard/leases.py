"""Context-managed access to the shared durable SQLite lease authority."""
from contextlib import contextmanager
from contextvars import ContextVar
import math
import os
from pathlib import Path
import time
from typing import Iterator
import uuid

from .lease_db import LeaseBusy, LeaseStore, boot_id, process_started, resource_label


_HELD = ContextVar("switchyard_held_leases", default=())


def held_leases():
    """Live entries for this execution context; no descriptor or transaction is held."""
    return _HELD.get()


def mark_uncertain(cause, resource=None):
    """Persist uncertainty before a translated/swallowed remote failure can look successful.

    A resource selects its broker name or canonical device label. Without one,
    every enclosing lease is conservatively quarantined.
    """
    if not isinstance(cause, str) or not cause.strip():
        raise ValueError("Uncertainty requires a cause")
    for held in _HELD.get():
        if not held["uncertainty"] and (resource is None or resource in (held["resource"], held["device"])):
            held["store"].suspect(held["lease_id"], cause)
            held["uncertainty"] = cause


class LedgerBroker:
    def __init__(self, resources: dict[str, Path], *, state_dir):
        self.resources = {resource: Path(path) for resource, path in resources.items()}
        self.keys = {resource: resource_label(resource, path) for resource, path in self.resources.items()}
        self.store = LeaseStore(Path(state_dir) / "leases",
                                legacy_dir={path.parent for path in self.resources.values()},
                                legacy_paths=self.resources.values())

    @contextmanager
    def hold(self, resource: str, *, owner: str, scope: str, worktree: str,
             lease_id: str | None = None, metadata: dict | None = None, wait: float = 0) -> Iterator[dict]:
        """Wait only for acquisition; a missing completion never expires a reservation."""
        if not isinstance(wait, (int, float)) or isinstance(wait, bool) or not math.isfinite(wait) or not 0 <= wait <= 600:
            raise ValueError("Lease wait must be 0-600 seconds")
        if resource not in self.resources:
            raise ValueError("Unknown lease resource")
        for value in (owner, scope, worktree):
            if not isinstance(value, str) or not value.strip() or len(value) > 512:
                raise ValueError("Lease metadata must be bounded nonempty text")
        metadata = dict(metadata or {})
        if set(metadata) - {"pid", "expires_at", "via"}:
            raise ValueError("Unsupported lease metadata")
        token = lease_id or uuid.uuid4().hex
        label = self.keys[resource]
        pid = metadata.get("pid", os.getpid())
        state = {**metadata, "lease_id": token, "device": label, "resource": resource,
                 "ledger": str(self.resources[resource]), "owner": owner, "scope": scope,
                 "worktree": worktree, "pid": pid, "pid_started": process_started(pid),
                 "boot_id": boot_id(), "expires_at": metadata.get("expires_at")}
        deadline = time.monotonic() + wait
        while True:
            try:
                self.store.claim(state)
                break
            except LeaseBusy:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
        release = {}
        held = {"store": self.store, "lease_id": token, "resource": resource, "device": label, "uncertainty": None}
        context = _HELD.set((*_HELD.get(), held))
        failed = None
        try:
            yield {"resource": resource, "lease_id": token, "release": release}
        except BaseException as error:
            failed = error
            raise
        finally:
            try:
                if not held["uncertainty"]:
                    if failed is not None and "outcome" not in release:
                        self.store.suspect(token, f"{type(failed).__name__}: lease context exited without confirmed completion")
                    else:
                        self.store.finish(token, reason=release.get("reason", "completed"),
                                          outcome=release.get("outcome", "completed"), details=release or None)
            finally:
                _HELD.reset(context)
