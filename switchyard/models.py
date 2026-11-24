"""Normalized observation contract. Unknown readings are null, not zero."""
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

Count = Annotated[int, Field(strict=True, ge=0)]
Percent = Annotated[float, Field(ge=0, le=100, allow_inf_nan=False)]
Text = Annotated[str, Field(min_length=1, max_length=4096)]


def timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Observation timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HostFacts(Record):
    hostname: Text
    os: Text
    distribution: Text | None
    architecture: Text


class CPUCounters(Record):
    total_ticks: Count
    idle_ticks: Count
    uptime_seconds: Annotated[float, Field(ge=0, allow_inf_nan=False)]
    boot_id: Annotated[str, Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]

    @model_validator(mode="after")
    def valid_ticks(self):
        if self.idle_ticks > self.total_ticks:
            raise ValueError("Idle CPU ticks exceed total ticks")
        return self


class CPU(Record):
    model: Text | None
    logical_count: Count | None
    utilization_percent: Percent | None
    sample_seconds: Annotated[float, Field(gt=0, allow_inf_nan=False)] | None
    load_1m: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None
    counters: CPUCounters | None = None

    @model_validator(mode="after")
    def sample_required(self):
        if self.utilization_percent is not None and self.sample_seconds is None:
            raise ValueError("CPU utilization requires a measured sample duration")
        return self


class Memory(Record):
    total_bytes: Count | None
    available_bytes: Count | None
    swap_total_bytes: Count | None
    swap_free_bytes: Count | None


class GPU(Record):
    id: Text
    name: Text
    driver: Text | None
    memory_kind: Literal["unknown", "shared", "dedicated"]
    busy_percent: Percent | None
    vram_total_bytes: Count | None
    vram_used_bytes: Count | None


class Disk(Record):
    id: Text
    name: Text
    model: Text | None
    transport: Text | None
    rotational: bool | None
    size_bytes: Count | None


class Filesystem(Record):
    id: Text
    source: Text
    type: Text
    mounts: list[Text] = Field(max_length=256)
    total_bytes: Count | None
    available_bytes: Count | None
    used_bytes: Count | None
    read_only: bool | None
    kind: Literal["persistent", "volatile", "image", "unknown"]
    backing_device_ids: list[Text] = Field(max_length=256)


class Storage(Record):
    devices: list[Disk] = Field(max_length=256)
    filesystems: list[Filesystem] = Field(max_length=512)

    @model_validator(mode="after")
    def backing_references(self):
        ids = {disk.id for disk in self.devices}
        if len(ids) != len(self.devices) or len({fs.id for fs in self.filesystems}) != len(self.filesystems):
            raise ValueError("Duplicate storage identity")
        if any(not set(fs.backing_device_ids) <= ids for fs in self.filesystems):
            raise ValueError("Unknown backing storage device")
        return self


class Workload(Record):
    id: Text
    host_id: Text
    backend: Text
    scope: Text
    native_id: Text
    name: Text
    kind: Literal["service", "scheduled-job", "interactive-session", "environment", "batch-job", "device-job", "application"]
    lifecycle: Literal["running", "idle", "stopped", "starting", "stopping", "completed", "failed", "unknown"]
    health: Literal["unknown"]
    management: Literal["discovered"]
    observed_at: Text
    extensions: dict[str, dict[str, Any]]

    @field_validator("observed_at")
    @classmethod
    def valid_time(cls, value):
        timestamp(value)
        return value

    @field_validator("extensions")
    @classmethod
    def namespaced(cls, value):
        if any("." not in key for key in value):
            raise ValueError("Backend extensions need a versioned namespace")
        return value


class Artifact(Record):
    id: Text
    host_id: Text
    backend: Text
    scope: Text
    native_id: Text
    name: Text
    kind: Literal["package", "image"]
    observed_at: Text
    extensions: dict[str, dict[str, Any]]

    @field_validator("observed_at")
    @classmethod
    def valid_time(cls, value):
        timestamp(value)
        return value

    @field_validator("extensions")
    @classmethod
    def namespaced(cls, value):
        if any("." not in key for key in value):
            raise ValueError("Backend extensions need a versioned namespace")
        return value


class Coverage(Record):
    scope: Text
    status: Literal["complete", "partial", "unavailable"]
    message: str = Field(max_length=4096)
    observed_at: Text | None = None

    @field_validator("observed_at")
    @classmethod
    def valid_time(cls, value):
        if value is not None:
            timestamp(value)
        return value


def _paseo_text(value):
    if any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
        raise ValueError("Control character in Paseo metadata")
    return value


PaseoText = Annotated[str, Field(strict=True, min_length=1, max_length=256), AfterValidator(_paseo_text)]
PaseoPath = Annotated[str, Field(strict=True, min_length=1, max_length=1024), AfterValidator(_paseo_text)]


class PaseoProvider(Record):
    provider: PaseoText
    available: Annotated[bool, Field(strict=True)]


class PaseoDaemon(Record):
    version: PaseoText | None
    server_id: PaseoText | None
    hostname: PaseoText | None
    listen: PaseoText | None
    state: Literal["running", "stopped", "unknown"]
    started_at: PaseoText | None
    providers: list[PaseoProvider] = Field(max_length=64)
    relay_enabled: Annotated[bool, Field(strict=True)] | None


class PaseoAgent(Record):
    id: PaseoText
    short_id: PaseoText | None
    name: PaseoText | None
    provider: PaseoText | None
    status: PaseoText
    cwd: PaseoPath | None
    created_at: PaseoText | None

    @field_validator("status")
    @classmethod
    def non_archived(cls, value):
        if value == "archived":
            raise ValueError("Archived agent")
        return value


class Paseo(Record):
    configured: Annotated[bool, Field(strict=True)] = True
    daemon: PaseoDaemon | None
    agents: list[PaseoAgent] | None = Field(max_length=128)
    cli_candidates: list[PaseoPath] = Field(default_factory=list, max_length=11)

    @model_validator(mode="after")
    def unique_agents(self):
        if self.agents is not None and len({a.id for a in self.agents}) != len(self.agents):
            raise ValueError("Duplicate Paseo agent")
        if len(set(self.cli_candidates)) != len(self.cli_candidates) or any(not p.startswith("/") for p in self.cli_candidates):
            raise ValueError("Invalid Paseo CLI candidates")
        if self.configured and (self.daemon is None or self.cli_candidates):
            raise ValueError("Invalid configured Paseo metadata")
        if not self.configured and (self.agents is not None or self.daemon is not None and
                                    (self.daemon.providers or self.daemon.started_at is not None
                                     or self.daemon.relay_enabled is not None)):
            raise ValueError("Unconfigured Paseo has CLI metadata")
        return self


class Snapshot(Record):
    schema_version: Literal[1]
    host_id: Text
    observed_at: Text
    collector: Literal["linux-v1", "android-v1"]
    host: HostFacts
    cpu: CPU
    memory: Memory
    gpus: list[GPU] = Field(max_length=64)
    storage: Storage
    workloads: list[Workload] = Field(max_length=512)
    coverage: list[Coverage] = Field(max_length=64)
    warnings: list[Text] = Field(max_length=64)
    resource_observed_at: dict[Literal["host", "cpu", "memory", "gpus", "storage", "paseo"], Text] = Field(default_factory=dict)
    artifacts: list[Artifact] = Field(default_factory=list, max_length=512)
    paseo: Paseo | None = None

    @field_validator("resource_observed_at")
    @classmethod
    def valid_resource_times(cls, value):
        for at in value.values():
            timestamp(at)
        return value

    @field_validator("observed_at")
    @classmethod
    def valid_time(cls, value):
        timestamp(value)
        return value

    @model_validator(mode="after")
    def consistent_identity(self):
        if any(w.host_id != self.host_id for w in self.workloads):
            raise ValueError("Workload belongs to a different host")
        if len({w.id for w in self.workloads}) != len(self.workloads):
            raise ValueError("Duplicate workload identity")
        if len({c.scope for c in self.coverage}) != len(self.coverage):
            raise ValueError("Duplicate coverage scope")
        if any(a.host_id != self.host_id for a in self.artifacts):
            raise ValueError("Artifact belongs to a different host")
        if len({a.id for a in self.artifacts}) != len(self.artifacts):
            raise ValueError("Duplicate artifact identity")
        return self
