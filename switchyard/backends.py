"""Trusted, in-process observation plugins. No command execution contract."""
from datetime import datetime, timezone
import platform
from typing import Any, Protocol


class ObservationBackend(Protocol):
    id: str
    name: str
    capabilities: tuple[str, ...]

    def observe(self) -> dict[str, Any]: ...


class StoreBackend:
    """The workload store: the one authority for which workloads exist (observed, registered, deployed)."""
    id = "workload-store"
    name = "Workload store"
    capabilities = ("read-declarations",)

    def __init__(self, store):
        self.store = store

    def observe(self) -> dict[str, Any]:
        with self.store.transaction() as db:
            records = self.store.records(db)
            revision = self.store.revision(db)
        return {"backend": self.id, "revision": revision,
                "workloads": [{"id": record["id"], "relation": record["relation"], "revision": record["revision"]} for record in records]}


class LocalHostBackend:
    id = "local-host"
    name = "Control-plane host"
    capabilities = ("observe-local-host",)

    def observe(self) -> dict[str, Any]:
        return {
            "backend": self.id,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "scope": "control-plane host only",
            "facts": {
                "hostname": platform.node(),
                "os": platform.system(),
                "architecture": platform.machine(),
                "python": platform.python_version(),
            },
        }


class BackendRegistry:
    """Explicit registration by application code, not executable config imports."""

    def __init__(self, *backends: ObservationBackend):
        self._backends: dict[str, ObservationBackend] = {}
        for backend in backends:
            if backend.id in self._backends:
                raise ValueError(f"Duplicate backend: {backend.id}")
            self._backends[backend.id] = backend

    def describe(self) -> list[dict[str, Any]]:
        return [
            {"id": b.id, "name": b.name, "status": "available",
             "capabilities": list(b.capabilities)}
            for b in self._backends.values()
        ]

    def observe(self, backend_id: str) -> dict[str, Any]:
        try:
            backend = self._backends[backend_id]
        except KeyError as error:
            raise ValueError(f"Unknown observation backend: {backend_id}") from error
        return backend.observe()
