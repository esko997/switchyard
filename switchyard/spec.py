"""Versioned workload declarations; validation only, not an execution adapter."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from datetime import datetime
from ipaddress import ip_address
import re
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, model_validator

# The legacy static-web cold-migration declaration (planning.py) carried by observed workloads; its own strict models.
from .planning import Recipe as StaticWebRecipe

API_VERSION = "switchyard/v1alpha3"
PREVIOUS_VERSION = "switchyard/v1alpha2"
ApiVersion = Literal["switchyard/v1alpha3"]


def _absolute_path(value):
    if not value.startswith("PLACEHOLDER") and value != "/":
        if any(part in {"", ".", ".."} for part in value[1:].split("/")):
            raise ValueError("host/container paths must be canonical absolute paths")
    return value


def _timestamp(value):
    if not value.startswith("PLACEHOLDER"):
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


def _bind_address(value):
    if not value.startswith("PLACEHOLDER") and str(ip_address(value)) != value:
        raise ValueError("bind address must be a canonical IPv4 or IPv6 address")
    return value


Text = Annotated[str, StringConstraints(min_length=1, max_length=8192, pattern=r"^[^\x00]+$")]
Id = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
Placeholder = Annotated[str, StringConstraints(pattern=r"^PLACEHOLDER(?:[-:].+)?$")]
Digest = Annotated[str, StringConstraints(pattern=r"^(?:[a-f0-9]{64}|PLACEHOLDER(?:[-:].+)?)$")]
AbsolutePath = Annotated[str, StringConstraints(pattern=r"^(?:/[^\x00]*|PLACEHOLDER(?:[-:].+)?)$"), AfterValidator(_absolute_path)]
RelativePath = Annotated[str, StringConstraints(pattern=r"^[^/\x00][^\x00]*$")]
Positive = Annotated[int, Field(gt=0)]
Port = Annotated[int, Field(ge=1, le=65535)]
Timestamp = Annotated[str, StringConstraints(pattern=r"^(?:\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)|PLACEHOLDER(?:[-:].+)?)$"), AfterValidator(_timestamp)]
DnsName = Annotated[str, StringConstraints(max_length=253, pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")]
FileName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]
ConfigText = Annotated[str, StringConstraints(min_length=1, max_length=65536, pattern=r"^[^\x00]+$")]
ParameterValue = Annotated[str, StringConstraints(min_length=1, max_length=1024, pattern=r"^[^\x00-\x1f\x7f{}]+$")]
CONFIG_FILE_LIMIT = 16
CONFIG_BYTES_LIMIT = 65536
# The one substitution syntax in configuration content, DNS checks and (since the GPU round) container args, env
# values and volume subPath: `{{parameter-id}}`, nothing else.
PARAMETER_REFERENCE = re.compile(r"\{\{([a-z0-9][a-z0-9-]{0,63})\}\}")
PATH_SEGMENT = r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}"
ARGUMENT_TOKEN = r"[A-Za-z0-9._:/=,+@%-]{1,256}"
ARGUMENT_LIST_LIMIT = 32


def parameter_references(text):
    """Parameter IDs referenced by `{{id}}` in one text; any other `{{`/`}}` is an error (no template language)."""
    rest = PARAMETER_REFERENCE.sub("", text)
    if re.search(r"\{\{\s*secrets?\b", text):
        raise ValueError("secret references are not allowed in configuration content")
    if "{{" in rest or "}}" in rest:
        raise ValueError("malformed placeholder: only {{parameter-id}} is substituted (no expressions, no literal {{ or }})")
    return PARAMETER_REFERENCE.findall(text)


def check_parameter_value(kind, value):
    """Validate one parameter value against its declared format; returns the value."""
    if kind == "dns-name":
        if len(value) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", value):
            raise ValueError("expected a lowercase DNS name of LDH labels without a trailing dot")
    elif kind in ("ip-address", "ip-address-list"):
        parts = value.split(" ")
        if kind == "ip-address" and len(parts) != 1 or not 1 <= len(parts) <= 8 or len(set(parts)) != len(parts):
            raise ValueError("expected " + ("one address" if kind == "ip-address" else "1-8 distinct addresses separated by single spaces"))
        for part in parts:
            try:
                if str(ip_address(part)) != part:
                    raise ValueError
            except ValueError:
                raise ValueError("expected canonical IPv4/IPv6 addresses") from None
    elif kind == "integer":
        if not re.fullmatch(r"0|[1-9][0-9]{0,17}", value):
            raise ValueError("expected a non-negative decimal integer without leading zeros")
    elif kind == "relative-path":
        if len(value) > 512 or not re.fullmatch(PATH_SEGMENT + "(?:/" + PATH_SEGMENT + ")*", value):
            raise ValueError("expected a relative path of segments [A-Za-z0-9._+-] that start with a letter or digit "
                             "(no leading /, no . or .. segments, no empty segments)")
    elif kind == "argument-list":
        parts = value.split(" ")
        if not 1 <= len(parts) <= ARGUMENT_LIST_LIMIT or not all(re.fullmatch(ARGUMENT_TOKEN, part) for part in parts):
            raise ValueError("expected 1-" + str(ARGUMENT_LIST_LIMIT) + " arguments separated by single spaces, each of "
                             "[A-Za-z0-9._:/=,+@%-] (no quotes, no shell syntax)")
    return value


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def manifest_parameter_texts(manifest):
    """`(texts, args)` of one Pod that may hold `{{parameter}}`: env values and volume subPaths, and the container
    args elements. A `{{` or `}}` anywhere else in the manifest is an error (it would never be substituted)."""
    texts, args = [], []
    data = manifest.model_dump(mode="json")
    for container, dumped in zip(manifest.spec.containers, data["spec"]["containers"]):
        args += container.args
        texts += [env.value for env in container.env if env.value is not None]
        texts += [mount.subPath for mount in container.volumeMounts if mount.subPath is not None]
        dumped.pop("args", None)
        for env in dumped.get("env") or []:
            env.pop("value", None)
        for mount in dumped.get("volumeMounts") or []:
            mount.pop("subPath", None)
    if any("{{" in text or "}}" in text for text in _strings(data)):
        raise ValueError("{{parameter}} is substituted in a Pod manifest only in container args, env values and "
                         "volume subPath; nowhere else")
    return texts, args


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _unique(values, label):
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {label}")


def _refs(values, known, label):
    if not set(values) <= set(known):
        raise ValueError(f"unknown {label}: {sorted(set(values) - set(known))}")


def _relative(path):
    if any(part in {"", ".", ".."} for part in path.split("/")):
        raise ValueError("relative paths must not traverse or contain empty segments")


class TemplateRef(Model):
    id: Id
    revision: Positive


class SourcePin(Model):
    id: Id
    sha256: Digest


class LauncherRef(Model):
    id: Id
    command_ref: Id


class ComposeNative(Model):
    kind: Literal["compose"]
    provider: Literal["podman-compose"] = "podman-compose"
    project_name: Text
    files: list[Id] = Field(min_length=1)
    services: list[Text] = Field(min_length=1)


class QuadletNative(Model):
    kind: Literal["quadlet"]
    source: Id
    unit: Text


class SystemdNative(Model):
    kind: Literal["systemd"]
    unit: Text
    unit_type: Literal["service", "timer", "instance", "transient"] = "service"
    related_units: list[Text] = Field(default_factory=list)
    source: Id | None = None
    launcher: LauncherRef | None = None

    @model_validator(mode="after")
    def transient_launcher(self):
        if (self.unit_type == "transient") != (self.launcher is not None):
            raise ValueError("only transient units require a launcher reference")
        return self


class PodMetadata(Model):
    name: Text
    labels: dict[Text, Text] = Field(default_factory=dict)


class KeyRef(Model):
    name: Id
    key: Text


class ValueFrom(Model):
    secretKeyRef: KeyRef


class Env(Model):
    name: Text
    value: Text | None = None
    valueFrom: ValueFrom | None = None

    @model_validator(mode="after")
    def one_value(self):
        if (self.value is None) == (self.valueFrom is None):
            raise ValueError("env requires exactly one value or valueFrom")
        return self


class ContainerPort(Model):
    name: Text | None = None
    containerPort: Port
    protocol: Literal["TCP", "UDP"] = "TCP"


class VolumeMount(Model):
    name: Id
    mountPath: AbsolutePath
    readOnly: bool = False
    # Kubernetes `subPath`: a relative path inside the volume (dataset volumes only); may hold `{{parameter}}`.
    # Rendered by Switchyard into the bound host path (never passed to Podman). Left out of the document while unset.
    subPath: Annotated[str, StringConstraints(min_length=1, max_length=1024, pattern=r"^[^/\x00][^\x00]*$")] | None = Field(
        default=None, exclude_if=lambda value: value is None)

    @model_validator(mode="after")
    def relative_sub_path(self):
        if self.subPath is not None:
            _relative(self.subPath)
        return self


class HostPath(Model):
    path: Annotated[str, StringConstraints(pattern=r"^(?:dataset|reviewed|config)://[a-z0-9][a-z0-9-]{0,63}$")]
    type: Literal["Directory", "File"]


class ConfigMapVolume(Model):
    name: Id


class Volume(Model):
    name: Id
    hostPath: HostPath | None = None
    emptyDir: dict[str, str] | None = Field(default=None, max_length=0)
    configMap: ConfigMapVolume | None = None

    @model_validator(mode="after")
    def one_source(self):
        if sum(value is not None for value in (self.hostPath, self.emptyDir, self.configMap)) != 1:
            raise ValueError("volume requires exactly one source")
        return self


class Capabilities(Model):
    add: list[Text] = Field(default_factory=list)
    drop: list[Text] = Field(default_factory=list)


class ContainerSecurity(Model):
    runAsUser: Annotated[int, Field(ge=0)] | None = None
    runAsGroup: Annotated[int, Field(ge=0)] | None = None
    readOnlyRootFilesystem: bool | None = None
    allowPrivilegeEscalation: bool | None = None
    capabilities: Capabilities | None = None
    privileged: bool | None = None


class PodSecurity(Model):
    runAsUser: Annotated[int, Field(ge=0)] | None = None
    runAsGroup: Annotated[int, Field(ge=0)] | None = None


class ResourceAmounts(Model):
    cpu: Text | None = None
    memory: Text | None = None


class Resources(Model):
    requests: ResourceAmounts | None = None
    limits: ResourceAmounts | None = None


class HTTPGet(Model):
    path: Text
    port: Port
    scheme: Literal["HTTP", "HTTPS"] = "HTTP"


class TCPSocket(Model):
    port: Port


class LivenessProbe(Model):
    httpGet: HTTPGet | None = None
    tcpSocket: TCPSocket | None = None
    initialDelaySeconds: Annotated[int, Field(ge=0)] = 0
    periodSeconds: Positive = 10
    timeoutSeconds: Positive = 1
    successThreshold: Literal[1] = 1
    failureThreshold: Positive = 3

    @model_validator(mode="after")
    def one_probe(self):
        if (self.httpGet is None) == (self.tcpSocket is None):
            raise ValueError("liveness requires exactly one httpGet or tcpSocket")
        return self


class Container(Model):
    name: Id
    image: Annotated[str, StringConstraints(pattern=r"^.+@sha256:(?:[a-f0-9]{64}|PLACEHOLDER(?:[-:].+)?)$")]
    imagePullPolicy: Literal["Always", "IfNotPresent", "Never"] = "IfNotPresent"
    command: list[Text] = Field(default_factory=list)
    args: list[Text] = Field(default_factory=list)
    workingDir: AbsolutePath | None = None
    env: list[Env] = Field(default_factory=list)
    ports: list[ContainerPort] = Field(default_factory=list)
    volumeMounts: list[VolumeMount] = Field(default_factory=list)
    resources: Resources | None = None
    securityContext: ContainerSecurity | None = None
    livenessProbe: LivenessProbe | None = None


class PodSpec(Model):
    containers: list[Container] = Field(min_length=1)
    volumes: list[Volume] = Field(default_factory=list)
    restartPolicy: Literal["Always", "OnFailure", "Never"] = "Always"
    terminationGracePeriodSeconds: Annotated[int, Field(ge=0)] = 30
    securityContext: PodSecurity | None = None
    hostNetwork: bool = False

    @model_validator(mode="after")
    def local_references(self):
        _unique([c.name for c in self.containers], "container names")
        _unique([v.name for v in self.volumes], "volume names")
        volumes = {v.name for v in self.volumes}
        for container in self.containers:
            _unique([e.name for e in container.env], "environment names")
            _unique([m.name for m in container.volumeMounts], "mount names")
            _refs([m.name for m in container.volumeMounts], volumes, "volume")
        return self


class Pod(Model):
    apiVersion: Literal["v1"] = "v1"
    kind: Literal["Pod"] = "Pod"
    metadata: PodMetadata
    spec: PodSpec


class KubeNative(Model):
    kind: Literal["kube"]
    subset: Literal["podman-pod-v2"] = "podman-pod-v2"
    mode: Literal["kube-play", "quadlet-kube"] = "quadlet-kube"
    manifest: Pod
    compatibility_gates: list[Literal["configmap-volume-unverified"]] = Field(default_factory=list)
    reviews: list[Literal["host-network", "privileged-access"]] = Field(default_factory=list)

    @model_validator(mode="after")
    def reviewed_features(self):
        spec = self.manifest.spec
        if any(v.configMap for v in spec.volumes) and "configmap-volume-unverified" not in self.compatibility_gates:
            raise ValueError("configMap volumes require the unverified compatibility gate")
        if spec.hostNetwork and "host-network" not in self.reviews:
            raise ValueError("hostNetwork requires explicit review")
        for container in spec.containers:
            security = container.securityContext
            if security and (security.privileged or security.allowPrivilegeEscalation or
                             (security.capabilities and security.capabilities.add)):
                if "privileged-access" not in self.reviews:
                    raise ValueError("privileged access requires explicit review")
        return self


class QuadletRuntime(Model):
    """The primary systemd unit is generated by Quadlet (unit and scope: the primary native identity)."""
    kind: Literal["quadlet"]


ComposeProject = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")]
ComposeService = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")]


class ComposeRuntime(Model):
    """An existing Compose project on the placement host: its exact provider, manifests and complete service set."""
    kind: Literal["compose"]
    provider: Literal["docker-compose-v2", "podman-compose"]
    project_name: ComposeProject
    project_directory: AbsolutePath
    files: list[AbsolutePath] = Field(min_length=1, max_length=16)
    services: list[ComposeService] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def unique_entries(self):
        _unique(self.files, "compose files")
        _unique(self.services, "compose services")
        return self


class StaticWebRuntime(Model):
    """The disposable rootless static page (Foobar): the primary identity names its container; `site_file` is
    the page on the control host that Switchyard publishes."""
    kind: Literal["static-web"]
    image: Text
    port: Port
    site_file: AbsolutePath


# How the native runtime starts and stops an observed component: description only. Lifecycle authority over it
# comes solely from the operations policy, which names the workload ID, its actions and hosts.
Runtime = Annotated[QuadletRuntime | ComposeRuntime | StaticWebRuntime, Field(discriminator="kind")]
RUNTIME_BACKENDS = {"quadlet": {"systemd"}, "static-web": {"podman"}}
COMPOSE_ENGINES = {"podman-compose": "podman", "docker-compose-v2": "docker"}


class ObservedNative(Model):
    """A component Switchyard only watches: its native definition is not described, only the resources that
    show it (bound on the Placement by `NativeIdentity`). Never deployed, gated, fenced or source-pinned.
    `runtime` optionally describes how its native runtime starts and stops it (a plain systemd unit needs none);
    it is left out of the document while unset, so records stored before it keep their bytes and hashes."""
    kind: Literal["observed"]
    backend: Text
    resource_kind: Literal["service", "scheduled-job"] = "service"
    runtime: Runtime | None = Field(default=None, exclude_if=lambda value: value is None)

    @model_validator(mode="after")
    def runtime_backend(self):
        if self.runtime is None:
            return self
        if self.resource_kind != "service":
            raise ValueError("a runtime description is for services, not scheduled jobs")
        kind = self.runtime.kind
        allowed = {COMPOSE_ENGINES[self.runtime.provider]} if kind == "compose" else RUNTIME_BACKENDS[kind]
        if self.backend not in allowed:
            raise ValueError(f"a {kind} runtime belongs to a {' or '.join(sorted(allowed))} component, not {self.backend}")
        return self


Native = Annotated[ComposeNative | QuadletNative | SystemdNative | KubeNative | ObservedNative, Field(discriminator="kind")]


class Gate(Model):
    """One enforcement point that refuses to start the component without its generation token."""
    id: Id
    kind: Literal["exec-start-pre", "launcher", "script"]
    target: Text
    covers: Text
    misses: Text | None = None


class Component(Model):
    id: Id
    native: Native
    sources: list[SourcePin] = Field(default_factory=list)
    depends_on: list[Id] = Field(default_factory=list)
    gates: list[Gate] = Field(default_factory=list)

    @model_validator(mode="after")
    def gate_shapes(self):
        _unique([g.id for g in self.gates], "gate IDs")
        native = self.native
        if isinstance(native, SystemdNative) and native.unit_type == "transient" and self.gates:
            if not any(g.kind == "launcher" for g in self.gates):
                raise ValueError("gated transient components require a launcher gate")
            if any(g.kind == "exec-start-pre" and g.target == native.unit for g in self.gates):
                raise ValueError("a transient unit cannot carry an ExecStartPre gate; gate its related units")
        if isinstance(native, ObservedNative) and (self.gates or self.sources):
            raise ValueError("an observed component has no gates or source pins: Switchyard only watches it")
        return self


class Identity(Model):
    """An exclusive external identity (for example a Minecraft username or a Codex thread), or an exclusive host
    resource (`scope: host`, for example a GPU render node): its key is then `<placement host>:<kind>/<name>`, so
    several instances on one host contend for it while the same name on another host is a different resource.
    `scope` is left out of the document while unset."""
    id: Id
    kind: Text
    name: Text
    holders: list[Id] = Field(min_length=1)
    description: Text
    scope: Literal["host"] | None = Field(default=None, exclude_if=lambda value: value is None)


DevicePath = Annotated[str, StringConstraints(max_length=255, pattern=r"^/dev/[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$"),
                       AfterValidator(_absolute_path)]


class Device(Model):
    """A host device node one container of a kube component needs (for example a GPU render node). This declares
    the need only: which devices may be passed on which host is operations-policy authority (`deploy_devices`)."""
    id: Id
    component: Id
    container: Id
    host_path: DevicePath
    container_path: AbsolutePath | None = None
    access: Literal["read-write", "read"] = "read-write"
    description: Text

    def target(self):
        return self.container_path or self.host_path


class ExternalActor(Model):
    id: Id
    description: Text
    access: Literal["read", "write"]
    quiesce_check: Id | None = None


class HealthFile(Model):
    id: Id
    path: RelativePath
    stale_on_restore: Literal[True]

    @model_validator(mode="after")
    def safe_path(self):
        _relative(self.path)
        return self


class Dataset(Model):
    id: Id
    snapshot: Literal["sqlite-backup", "files-quiesced", "btrfs-snapshot", "podman-volume-export"]
    verify: Literal["sha256-manifest", "sqlite-integrity", "manifest-and-sqlite"]
    writers: list[Id] = Field(min_length=1)
    readers: list[Id] = Field(default_factory=list)
    external_actors: list[ExternalActor] = Field(default_factory=list)
    include: list[Text] = Field(default_factory=lambda: ["**"])
    exclude: list[Text] = Field(default_factory=list)
    health_files: list[HealthFile] = Field(default_factory=list)


class SecretLocation(Model):
    """One place a secret lives: its usable value, a verifier hash, or a copy embedded elsewhere."""
    id: Id
    form: Literal["value", "hash", "embedded"]
    role: Literal["holder", "verifier", "copy"]
    component: Id | None = None
    external_dependency: Id | None = None
    dataset: Id | None = None

    @model_validator(mode="after")
    def one_user(self):
        if (self.component is None) == (self.external_dependency is None):
            raise ValueError("secret location names exactly one component or external dependency")
        if self.external_dependency is not None and self.dataset is not None:
            raise ValueError("external secret locations are outside this application's datasets")
        if self.role in {"holder", "copy"} and self.form == "hash":
            raise ValueError("holder/copy locations keep a usable value, not a hash")
        return self


class Secret(Model):
    id: Id
    kind: Literal["file", "environment-file", "podman-secret", "credential"]
    consumers: list[Id] = Field(min_length=1)
    transfer: Literal["copy", "reissue", "operator-provides"]
    rotates_on_use: bool | Literal["unknown"]
    locations: list[SecretLocation] = Field(min_length=1)

    @model_validator(mode="after")
    def location_rules(self):
        _unique([item.id for item in self.locations], "secret location IDs")
        if not any(item.role == "holder" for item in self.locations):
            raise ValueError("secret requires at least one holder location")
        if self.transfer == "copy" and any(item.form == "value" and item.dataset for item in self.locations):
            if any(item.form == "value" and item.dataset is None for item in self.locations):
                raise ValueError("a copy-policy secret whose value lives in a dataset travels only with that dataset")
        return self


class Endpoint(Model):
    id: Id
    component: Id
    protocol: Literal["tcp", "udp"]
    target_port: Port
    consumers: list[Text] = Field(default_factory=list)
    scheme: Literal["http", "https"] | None = Field(default=None, exclude_if=lambda value: value is None)

    @model_validator(mode="after")
    def web_transport(self):
        if self.scheme is not None and self.protocol != "tcp":
            raise ValueError("HTTP/HTTPS endpoint requires TCP")
        return self


class Capacity(Model):
    memory_mib: Positive | None = None
    disk_gib: Annotated[float, Field(gt=0, allow_inf_nan=False)] | None = None
    gpu: Text | None = None


class Requirement(Model):
    name: Text
    components: list[Id] = Field(default_factory=list)
    capacity: Capacity | None = None
    probe_ref: Text | None = None


class ExternalDependency(Model):
    id: Id
    description: Text
    probe_ref: Text | None = None
    secret_ref: Id | None = None


class CheckBase(Model):
    id: Id
    component: Id
    timeout_seconds: Positive = 5


class HTTPCheck(CheckBase):
    type: Literal["http"]
    endpoint: Id
    scheme: Literal["http", "https"] = "http"
    path: Text = "/"
    status: Annotated[int, Field(ge=100, le=599)] = 200
    redirects: bool = False
    body_sha256: Digest | None = None
    predicate_ref: Text | None = None
    credential_ref: Id | None = None
    # A bounded readiness window: the check is retried for up to this many seconds after the unit started (a model
    # server answers 503 while it loads). Left out of the document while unset.
    ready_within_seconds: Annotated[int, Field(ge=1, le=600)] | None = Field(default=None, exclude_if=lambda value: value is None)


class TCPCheck(CheckBase):
    type: Literal["tcp"]
    endpoint: Id


class FileCheck(CheckBase):
    type: Literal["file-freshness"]
    dataset: Id
    health_file: Id
    max_age_seconds: Positive


class PredicateCheck(CheckBase):
    type: Literal["process", "unit-state", "predicate"]
    predicate_ref: Text


class DNSCheck(CheckBase):
    """One DNS query to the claimed bind over the endpoint's protocol; `name`/`expect` may hold `{{parameter}}`."""
    type: Literal["dns"]
    endpoint: Id
    name: Text
    record_type: Literal["A", "AAAA", "PTR", "CNAME", "NS", "SOA", "TXT", "MX", "SRV"] = "A"
    expect: list[Text] = Field(default_factory=list, max_length=16)


HealthCheck = Annotated[HTTPCheck | TCPCheck | FileCheck | PredicateCheck | DNSCheck, Field(discriminator="type")]


class Target(Model):
    kind: Literal["component", "dataset"]
    id: Id


class ScriptRef(Model):
    id: Id
    sha256: Digest


class RecipeStep(Model):
    id: Id
    action: Literal["stop", "start", "restart", "quiesce-check", "snapshot", "transfer", "verify", "fence", "unfence", "activate-gate", "publish", "script"]
    target: Target
    script: ScriptRef | None = None
    idempotent: bool
    checks: list[Id] = Field(default_factory=list)
    checkpoint: Literal["none", "downtime", "writer-switch", "destructive"] = "none"

    @model_validator(mode="after")
    def script_and_resume(self):
        if (self.action == "script") != (self.script is not None):
            raise ValueError("script action requires exactly one stored script reference")
        if self.idempotent and not self.checks:
            raise ValueError("resumable idempotent steps require verification checks")
        return self


class Recipe(Model):
    id: Id
    revision: Positive
    steps: list[RecipeStep] = Field(min_length=1)


class ConsistencyGroup(Model):
    id: Id
    datasets: list[Id] = Field(min_length=1)


class Provenance(Model):
    submitted_by: Text
    source: Text
    evidence: list[Text] = Field(default_factory=list)


class Parameter(Model):
    """A named per-instance value substituted as `{{id}}` into configuration content, DNS checks, container args,
    env values and volume subPath. Templates declare `default` only; an instance records the operator's `value`.
    An `argument-list` parameter expands to several container args and stands alone in one args element."""
    id: Id
    description: Text
    format: Literal["text", "dns-name", "ip-address", "ip-address-list", "integer", "relative-path", "argument-list"] = "text"
    default: ParameterValue | None = None
    value: ParameterValue | None = None

    @model_validator(mode="after")
    def formatted(self):
        for value in (self.default, self.value):
            if value is not None:
                check_parameter_value(self.format, value)
        return self


def _host_address(value):
    if "%" in value or str(ip_address(value)) != value:
        raise ValueError("record address must be a canonical IPv4 or IPv6 address")
    return value


class HostRecord(Model):
    """An operator record kept by the instance: `name` is relative to the generator's zone."""
    name: DnsName
    address: Annotated[str, StringConstraints(min_length=2, max_length=45), AfterValidator(_host_address)]


class ConfigGenerator(Model):
    """Named generator. `registry-hosts`: one hosts-format line per registry host with a known LAN address,
    plus `records`, all inside `zone`."""
    kind: Literal["registry-hosts"]
    zone: Text
    records: list[HostRecord] = Field(default_factory=list, max_length=256)

    @model_validator(mode="after")
    def unique_records(self):
        _unique([r.name for r in self.records], "record names")
        return self


class ConfigFile(Model):
    """A file whose content Switchyard decides: literal `content` or a `generator`, rendered at plan time and
    mounted read-only through a `config://<component>` directory volume."""
    id: Id
    component: Id
    path: FileName
    content: ConfigText | None = None
    generator: ConfigGenerator | None = None
    on_change: Literal["restart", "none"] = "restart"

    @model_validator(mode="after")
    def one_source(self):
        if (self.content is None) == (self.generator is None):
            raise ValueError("a configuration file has exactly one of content or generator")
        return self

    def texts(self):
        """Every text that may hold `{{parameter}}` references."""
        return [self.content] if self.content is not None else [self.generator.zone]


class Notes(Model):
    """Operator prose that is not yet reviewed into typed checks, datasets or dependencies. Descriptive only:
    never parsed into commands, probes or ordering."""
    text: Text | None = None
    health: Text | None = None
    data_locations: list[Text] = Field(default_factory=list, max_length=128)
    workload_dependencies: list[Id] = Field(default_factory=list, max_length=128)

    @model_validator(mode="after")
    def unique_entries(self):
        _unique(self.data_locations, "data locations")
        _unique(self.workload_dependencies, "workload dependencies")
        return self


# Fields added to v1alpha3 after its first release (2026-11-23: configuration files; then notes for observed
# workloads). They are left out of `content_sha256` while empty, so records stored before them keep the hash
# they were recorded with. Later additions (devices, identity scope, readiness windows, subPath) are left out of
# the serialized document itself while unset (`exclude_if`), which keeps both bytes and hashes.
HASH_NEUTRAL_WHEN_EMPTY = ("parameters", "config_files", "notes")


class Application(Model):
    apiVersion: ApiVersion = API_VERSION
    kind: Literal["Application"] = "Application"
    id: Id
    revision: Positive
    name: Text
    purpose: Text
    role: Literal["template", "instance"] = "instance"
    template_ref: TemplateRef | None = None
    components: list[Component] = Field(min_length=1)
    datasets: list[Dataset] = Field(default_factory=list)
    secrets: list[Secret] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    requires: list[Requirement] = Field(default_factory=list)
    external_dependencies: list[ExternalDependency] = Field(default_factory=list)
    health_checks: list[HealthCheck] = Field(default_factory=list)
    consistency_groups: list[ConsistencyGroup] = Field(default_factory=list)
    recipes: list[Recipe] = Field(default_factory=list)
    identities: list[Identity] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list, max_length=32)
    config_files: list[ConfigFile] = Field(default_factory=list, max_length=CONFIG_FILE_LIMIT)
    devices: list[Device] = Field(default_factory=list, max_length=16, exclude_if=lambda value: not value)
    notes: Notes | None = None
    provenance: Provenance

    def content_sha256(self) -> str:
        """Hash the complete normalized declaration, including defaults, not placements (empty
        `HASH_NEUTRAL_WHEN_EMPTY` fields excepted)."""
        value = self.model_dump(mode="json")
        for key in HASH_NEUTRAL_WHEN_EMPTY:
            if value[key] in ([], None):
                del value[key]
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @model_validator(mode="after")
    def references(self):
        collections = ("components", "datasets", "secrets", "endpoints", "external_dependencies", "health_checks",
                       "consistency_groups", "recipes", "identities", "parameters", "config_files")
        for name in collections:
            _unique([item.id for item in getattr(self, name)], name)
        components = {c.id: c for c in self.components}
        datasets = {d.id: d for d in self.datasets}
        secrets = {s.id: s for s in self.secrets}
        endpoints = {e.id: e for e in self.endpoints}
        checks = {c.id: c for c in self.health_checks}
        if self.role == "template" and self.template_ref is not None:
            raise ValueError("templates cannot themselves reference a template")
        if self.template_ref and self.template_ref.id == self.id:
            raise ValueError("instance must have its own ID")
        dependencies = {d.id for d in self.external_dependencies}
        for component in self.components:
            _unique([s.id for s in component.sources], "source IDs")
            _refs(component.depends_on, components, "component dependency")
            if component.id in component.depends_on:
                raise ValueError("component cannot depend on itself")
            native = component.native
            if isinstance(native, KubeNative):
                for volume in native.manifest.spec.volumes:
                    if volume.hostPath and volume.hostPath.path.startswith("dataset://"):
                        _refs([volume.hostPath.path.removeprefix("dataset://")], datasets, "hostPath dataset")
                    if volume.hostPath and volume.hostPath.path.startswith("config://"):
                        if volume.hostPath.path != "config://" + component.id or volume.hostPath.type != "Directory":
                            raise ValueError("a config:// volume is the Directory of its own component's configuration files")
                        if not any(f.component == component.id for f in self.config_files):
                            raise ValueError("config:// volume of a component without configuration files")
                for container in native.manifest.spec.containers:
                    for port in container.ports:
                        if not any(e.component == component.id and e.target_port == port.containerPort
                                   and e.protocol == port.protocol.lower() for e in self.endpoints):
                            raise ValueError("container ports require matching logical endpoints")
                    for env in container.env:
                        if env.valueFrom:
                            secret = env.valueFrom.secretKeyRef.name
                            _refs([secret], secrets, "kube secret")
                            if component.id not in secrets[secret].consumers:
                                raise ValueError("kube secret must declare the consuming component")
                    for mount in container.volumeMounts:
                        volume = next(v for v in native.manifest.spec.volumes if v.name == mount.name)
                        if volume.hostPath and volume.hostPath.path.startswith("dataset://"):
                            dataset = datasets[volume.hostPath.path.removeprefix("dataset://")]
                            if component.id not in (dataset.readers if mount.readOnly else dataset.writers):
                                raise ValueError("dataset mount access must be declared")
                        elif mount.subPath is not None:
                            raise ValueError("subPath is supported on dataset volumes only")
                        if volume.hostPath and volume.hostPath.path.startswith("config://") and not mount.readOnly:
                            raise ValueError("configuration files are mounted read-only")
                if native.manifest.spec.hostNetwork:
                    if not any(e.component == component.id for e in self.endpoints):
                        raise ValueError("hostNetwork requires endpoint declarations")
        for dataset in self.datasets:
            for values, label in ((dataset.writers, "writers"), (dataset.readers, "readers")):
                _unique(values, label)
                _refs(values, components, label)
            _unique([f.id for f in dataset.health_files], "health files")
            _unique([a.id for a in dataset.external_actors], "external actors")
            for actor in dataset.external_actors:
                if actor.access == "write" and actor.quiesce_check is None:
                    raise ValueError("external writers require a quiesce check")
                if actor.quiesce_check:
                    _refs([actor.quiesce_check], checks, "external actor check")
        for secret in self.secrets:
            _unique(secret.consumers, "secret consumers")
            _refs(secret.consumers, components, "secret consumer")
            for location in secret.locations:
                if location.component is not None:
                    _refs([location.component], components, "secret location component")
                    if location.role == "holder" and location.component not in secret.consumers:
                        raise ValueError("a holder location belongs to a declared consumer of the secret")
                else:
                    _refs([location.external_dependency], dependencies, "secret location external dependency")
                if location.dataset is not None:
                    _refs([location.dataset], datasets, "secret location dataset")
                    dataset = datasets[location.dataset]
                    if location.component not in dataset.writers + dataset.readers:
                        raise ValueError("a dataset secret location belongs to a component that accesses that dataset")
        exclusive = [(i.kind, i.name) for i in self.identities if not i.name.startswith("PLACEHOLDER")]
        _unique(exclusive, "identity kind/name pairs")
        _unique([d.id for d in self.devices], "device IDs")
        for device in self.devices:
            _refs([device.component], components, "device component")
            native = components[device.component].native
            if not isinstance(native, KubeNative):
                raise ValueError("devices are passed to kube containers only")
            container = next((c for c in native.manifest.spec.containers if c.name == device.container), None)
            if container is None:
                raise ValueError("unknown device container: " + device.container)
            if any(m.mountPath == device.target() for m in container.volumeMounts):
                raise ValueError("device path " + device.target() + " collides with a volume mount")
        _unique([(d.component, d.container, d.target()) for d in self.devices], "device container paths")
        for identity in self.identities:
            _unique(identity.holders, "identity holders")
            _refs(identity.holders, components, "identity holder")
        for endpoint in self.endpoints:
            _refs([endpoint.component], components, "endpoint component")
        for requirement in self.requires:
            _refs(requirement.components, components, "requirement component")
        for dependency in self.external_dependencies:
            if dependency.secret_ref:
                _refs([dependency.secret_ref], secrets, "external dependency secret")
        for check in self.health_checks:
            _refs([check.component], components, "check component")
            if isinstance(check, (HTTPCheck, TCPCheck)):
                _refs([check.endpoint], endpoints, "check endpoint")
                if endpoints[check.endpoint].component != check.component:
                    raise ValueError("check endpoint belongs to a different component")
                if endpoints[check.endpoint].protocol != "tcp":
                    raise ValueError("HTTP/TCP checks require a TCP endpoint")
                if isinstance(check, HTTPCheck) and endpoints[check.endpoint].scheme not in (None, check.scheme):
                    raise ValueError("HTTP check scheme does not match its endpoint")
            if isinstance(check, DNSCheck):
                _refs([check.endpoint], endpoints, "check endpoint")
                if endpoints[check.endpoint].component != check.component:
                    raise ValueError("check endpoint belongs to a different component")
            if isinstance(check, HTTPCheck) and check.credential_ref:
                _refs([check.credential_ref], secrets, "check credential")
            if isinstance(check, FileCheck):
                _refs([check.dataset], datasets, "health dataset")
                _refs([check.health_file], [f.id for f in datasets[check.dataset].health_files], "health file")
        parameters = {p.id: p for p in self.parameters}
        if self.role == "template" and any(p.value is not None for p in self.parameters):
            raise ValueError("templates declare parameter defaults only; values belong to instances")
        texts = [text for f in self.config_files for text in f.texts()]
        texts += [text for c in self.health_checks if isinstance(c, DNSCheck) for text in [c.name, *c.expect]]
        arguments = []
        for component in self.components:
            if isinstance(component.native, KubeNative):
                manifest_texts, manifest_args = manifest_parameter_texts(component.native.manifest)
                texts += manifest_texts
                arguments += manifest_args
        for text in texts + arguments:
            names = parameter_references(text)
            if set(names) & set(secrets):
                raise ValueError("secret references are not allowed in configuration content")
            _refs(names, parameters, "parameter")
        lists = {p.id for p in self.parameters if p.format == "argument-list"}
        for text in texts:
            if set(parameter_references(text)) & lists:
                raise ValueError("an argument-list parameter expands only as a whole container args element")
        for text in arguments:
            names = parameter_references(text)
            if set(names) & lists and text != "{{" + names[0] + "}}":
                raise ValueError("an argument-list parameter stands alone in one args element: " + text)
        _unique([(f.component, f.path) for f in self.config_files], "configuration file paths")
        for item in self.config_files:
            _refs([item.component], components, "configuration file component")
        for group in self.consistency_groups:
            _unique(group.datasets, "consistency datasets")
            _refs(group.datasets, datasets, "consistency dataset")
        for recipe in self.recipes:
            _unique([s.id for s in recipe.steps], "recipe step IDs")
            for step in recipe.steps:
                _refs([step.target.id], components if step.target.kind == "component" else datasets, "recipe target")
                _refs(step.checks, checks, "recipe check")
        return self


ContainerName = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$")]


class NativeIdentity(Model):
    """One native resource of a placed component: its exact native ID, or (containers only) its exact name.
    `backend` names the native manager when it is not the component's own (default: derived from the native
    kind); `role` marks the resource whose state is the component's state (`primary`) or a `supporting` one."""
    native_id: Text | None = None
    scope: Text
    name: ContainerName | None = None
    backend: Text | None = None
    role: Literal["primary", "supporting"] | None = None

    @model_validator(mode="after")
    def one_selector(self):
        if (self.native_id is None) == (self.name is None):
            raise ValueError("a native identity has exactly one of native_id or name")
        if self.name is not None and self.backend not in {"podman", "docker"}:
            raise ValueError("name identities select a Podman or Docker container (backend podman or docker)")
        return self


class ComponentPlacement(Model):
    component: Id
    native_identities: list[NativeIdentity] = Field(min_length=1)
    source_paths: dict[Id, AbsolutePath] = Field(default_factory=dict)
    project_directory: AbsolutePath | None = None
    launcher_path: AbsolutePath | None = None
    ungated_reason: Text | None = None


class DatasetBinding(Model):
    dataset: Id
    path: AbsolutePath
    access: Literal["read", "write"]
    ownership: Literal["native", "idmapped", "remap-required", "unknown"] = "unknown"
    ownership_check: Text | None = None


class SecretBinding(Model):
    """Binds one declared secret location on this placement: a host path, or a path inside its dataset."""
    secret: Id
    location: Id
    path: AbsolutePath | None = None
    relative_path: RelativePath | None = None
    mode: Annotated[str, StringConstraints(pattern=r"^0[0-7]{3}$")] = "0600"
    conversion: Literal["podman-kube-secret"] | None = None

    @model_validator(mode="after")
    def one_path(self):
        if (self.path is None) == (self.relative_path is None):
            raise ValueError("secret binding requires exactly one of path or relative_path")
        if self.relative_path:
            _relative(self.relative_path)
        return self


class EndpointClaim(Model):
    endpoint: Id
    address: Annotated[Text, AfterValidator(_bind_address)]
    host_port: Port


class ReviewedPath(Model):
    id: Id
    path: AbsolutePath
    access: Literal["read", "write"]
    review_ref: Text


class TakeoverAttestation(Model):
    who: Text
    why: Text
    evidence: list[Text] = Field(min_length=1)
    attested_at: Timestamp
    source_generation: Positive
    snapshot_ref: Text
    credential_reissue_evidence: list[Text] = Field(default_factory=list)


class GateEvidence(Model):
    """Evidence that one declared gate checks this token."""
    gate: Id
    evidence: Text


class FenceToken(Model):
    application_id: Id
    component: Id
    generation: Positive
    issued_at: Timestamp
    token_path: AbsolutePath
    gates: list[GateEvidence] = Field(default_factory=list)
    state: Literal["valid", "revoked"]
    revoked_at: Timestamp | None = None

    @model_validator(mode="after")
    def revocation_time(self):
        if (self.state == "revoked") != (self.revoked_at is not None):
            raise ValueError("revoked token requires revoked_at; valid token cannot have it")
        _unique([g.gate for g in self.gates], "gate evidence")
        return self


class FenceRecord(Model):
    journal_generation: Positive
    host_generation: Positive
    tokens: list[FenceToken] = Field(min_length=1)
    masked: bool = False
    activators: list[Text] = Field(min_length=1)
    previous_policy: Text
    stopped_native_ids: list[Text] = Field(default_factory=list)
    evidence: list[Text] = Field(min_length=1)
    verified_at: Timestamp
    release_requires: Literal["explicit-recovery-other-generation-inactive"] = "explicit-recovery-other-generation-inactive"
    takeover: TakeoverAttestation | None = None


class Placement(Model):
    apiVersion: ApiVersion = API_VERSION
    kind: Literal["Placement"] = "Placement"
    id: Id
    application_id: Id
    revision: Positive
    host_id: Id
    generation: Positive
    state: Literal["declared", "staged", "active", "fenced", "retired"]
    ownership: Literal["adopted", "deployed"]
    ownership_id: Text | None = None
    components: list[ComponentPlacement] = Field(min_length=1)
    datasets: list[DatasetBinding] = Field(default_factory=list)
    secrets: list[SecretBinding] = Field(default_factory=list)
    endpoints: list[EndpointClaim] = Field(default_factory=list)
    reviewed_paths: list[ReviewedPath] = Field(default_factory=list)
    fence: FenceRecord | None = None
    migration_recipe: StaticWebRecipe | None = None

    @model_validator(mode="after")
    def generation_gate(self):
        _unique([c.component for c in self.components], "placed components")
        _unique([d.dataset for d in self.datasets], "dataset bindings")
        _unique([(s.secret, s.location) for s in self.secrets], "secret location bindings")
        _unique([e.endpoint for e in self.endpoints], "endpoint claims")
        _unique([p.id for p in self.reviewed_paths], "reviewed paths")
        if (self.ownership == "deployed") != (self.ownership_id is not None):
            raise ValueError("deployed placement requires ownership_id; adoption cannot claim one")
        if self.migration_recipe is not None:
            source, destination = self.migration_recipe.source, self.migration_recipe.destination
            if (source.definition_id, source.device_id) != (self.application_id, self.host_id) or destination.device_id == self.host_id:
                raise ValueError("a migration recipe moves this placement's application from its host to a different host")
        if self.state in {"active", "fenced"} and self.fence is None:
            raise ValueError("active/fenced placement requires verified fence record")
        if self.fence:
            if self.fence.journal_generation != self.generation or self.fence.host_generation != self.generation:
                raise ValueError("generation mismatch requires explicit operator reconciliation")
            _unique([t.component for t in self.fence.tokens], "component tokens")
            if {t.component for t in self.fence.tokens} != {c.component for c in self.components}:
                raise ValueError("fence must cover every placed component")
            for token in self.fence.tokens:
                if token.application_id != self.application_id or token.generation != self.generation:
                    raise ValueError("token identity/generation mismatch")
                if self.state == "active" and token.state != "valid":
                    raise ValueError("active placement requires valid tokens")
                if self.state in {"staged", "fenced", "retired"} and token.state != "revoked":
                    raise ValueError("inactive placement cannot hold valid tokens")
            if self.fence.takeover and self.generation <= self.fence.takeover.source_generation:
                raise ValueError("takeover must bump generation")
        return self


class ActivationParameters(Model):
    component: Id
    deadline_epoch: Positive | Placeholder
    resume_thread: Text | None = None
    model: Text | None = None


class ActivationInput(Model):
    apiVersion: ApiVersion = API_VERSION
    kind: Literal["ActivationInput"] = "ActivationInput"
    application_id: Id
    revision: Positive
    placement_ids: list[Id] = Field(min_length=1)
    runs: list[ActivationParameters] = Field(min_length=1)


class SpecBundle(Model):
    apiVersion: ApiVersion = API_VERSION
    kind: Literal["Bundle"] = "Bundle"
    applications: list[Application] = Field(min_length=1)
    placements: list[Placement] = Field(default_factory=list)
    activation_inputs: list[ActivationInput] = Field(default_factory=list)

    @model_validator(mode="after")
    def cross_record_invariants(self):
        _unique([(a.id, a.revision) for a in self.applications], "application revisions")
        _unique([p.id for p in self.placements], "placement IDs")
        apps = {(a.id, a.revision): a for a in self.applications}
        placements = {p.id: p for p in self.placements}
        active_components, active_writers, claims = set(), set(), []
        identity_holders = {}
        for app in self.applications:
            if app.template_ref:
                key = (app.template_ref.id, app.template_ref.revision)
                if key not in apps or apps[key].role != "template":
                    raise ValueError("template_ref must resolve to a template revision in the bundle")
        for placement in self.placements:
            key = (placement.application_id, placement.revision)
            if key not in apps or apps[key].role != "instance":
                raise ValueError("placement must reference an instance revision")
            app = apps[key]
            check_placement(app, placement)
            endpoints = {e.id: e for e in app.endpoints}
            if placement.state == "active":
                for item in placement.components:
                    identity = (app.id, item.component)
                    if identity in active_components:
                        raise ValueError("single-active component invariant violated")
                    active_components.add(identity)
                    for exclusive in app.identities:
                        if item.component in exclusive.holders:
                            name = (exclusive.kind, exclusive.name) if not exclusive.name.startswith("PLACEHOLDER") \
                                else (app.id, exclusive.id)
                            if exclusive.scope == "host":
                                name = (placement.host_id + ":" + name[0], name[1])
                            identity_holders.setdefault(name, []).append((placement.id, item.component))
                for binding in placement.datasets:
                    if binding.access == "write":
                        identity = (app.id, binding.dataset)
                        if identity in active_writers:
                            raise ValueError("dataset has more than one active writer placement")
                        active_writers.add(identity)
            for claim in placement.endpoints:
                endpoint = endpoints[claim.endpoint]
                if placement.state not in {"retired", "fenced"}:
                    for host, address, protocol, port in claims:
                        if (host, protocol, port) == (placement.host_id, endpoint.protocol, claim.host_port):
                            if address == claim.address or address in {"0.0.0.0", "::"} or claim.address in {"0.0.0.0", "::"}:
                                raise ValueError("overlapping placement endpoint claims")
                    claims.append((placement.host_id, claim.address, endpoint.protocol, claim.host_port))
        for name, holders in identity_holders.items():
            if len(holders) > 1:
                raise ValueError("exclusive identity " + "/".join(name) + " is active in more than one holder: "
                                 + ", ".join(p + ":" + c for p, c in holders))
        for activation in self.activation_inputs:
            key = (activation.application_id, activation.revision)
            if key not in apps or apps[key].role != "instance":
                raise ValueError("activation must reference an instance revision")
            _unique(activation.placement_ids, "activation placements")
            _unique([r.component for r in activation.runs], "activation components")
            _refs(activation.placement_ids, placements, "activation placement")
            selected = set()
            for identity in activation.placement_ids:
                placement = placements[identity]
                if (placement.application_id, placement.revision) != key:
                    raise ValueError("activation placement belongs to another application revision")
                selected.update(c.component for c in placement.components)
            _refs([r.component for r in activation.runs], selected, "activation component")
        return self

    def secret_locations(self, application_id, secret_id, revision=None):
        """Every declared location of one secret and where each placement binds it (reissue inventory)."""
        candidates = [a for a in self.applications if a.id == application_id and (revision is None or a.revision == revision)]
        if not candidates:
            raise ValueError("unknown application revision")
        app = max(candidates, key=lambda a: a.revision)
        secret = next((s for s in app.secrets if s.id == secret_id), None)
        if secret is None:
            raise ValueError("unknown secret")
        result = []
        for location in secret.locations:
            bound = []
            for placement in self.placements:
                if (placement.application_id, placement.revision) != (app.id, app.revision):
                    continue
                for binding in placement.secrets:
                    if (binding.secret, binding.location) == (secret.id, location.id):
                        dataset = next((d for d in placement.datasets if d.dataset == location.dataset), None)
                        bound.append({"placement_id": placement.id, "host_id": placement.host_id, "state": placement.state,
                                      "path": binding.path, "dataset_path": dataset.path if dataset else None,
                                      "relative_path": binding.relative_path})
            result.append({**location.model_dump(mode="json"), "bindings": bound})
        return {"application_id": app.id, "revision": app.revision, "secret": secret.id, "transfer": secret.transfer,
                "rotates_on_use": secret.rotates_on_use, "locations": result}


def check_placement(app: Application, placement: Placement):
    """Checks one placement against its application revision (also used outside bundles)."""
    if (placement.application_id, placement.revision) != (app.id, app.revision):
        raise ValueError("placement belongs to another application revision")
    components = {c.id: c for c in app.components}
    datasets = {d.id: d for d in app.datasets}
    secrets = {s.id: s for s in app.secrets}
    endpoints = {e.id: e for e in app.endpoints}
    selected = {c.component for c in placement.components}
    _refs(selected, components, "placed component")
    tokens = {t.component: t for t in placement.fence.tokens} if placement.fence else {}
    for item in placement.components:
        component = components[item.component]
        native = component.native
        if isinstance(native, ObservedNative) and (placement.ownership != "adopted" or placement.state not in {"declared", "retired"}):
            raise ValueError("an observed component is only watched: adopted ownership, declared (or retired) state")
        if sum(identity.role == "primary" for identity in item.native_identities) > 1:
            raise ValueError("a placed component has at most one primary native identity")
        source_ids = native.files if isinstance(native, ComposeNative) else ([native.source] if isinstance(native, (QuadletNative, SystemdNative)) and native.source else [])
        if set(item.source_paths) != set(source_ids):
            raise ValueError("native source paths must bind the complete source reference set")
        if isinstance(native, ComposeNative) != (item.project_directory is not None):
            raise ValueError("only Compose requires project_directory")
        transient = isinstance(native, SystemdNative) and native.unit_type == "transient"
        if transient != (item.launcher_path is not None):
            raise ValueError("transient unit requires launcher_path only")
        pins = {s.id for s in component.sources}
        if placement.ownership == "adopted" and pins:
            raise ValueError("adopted sources are hashed at PLAN time, not in Application")
        if placement.ownership == "deployed" and set(source_ids) != pins:
            raise ValueError("deployed native sources require exact source hash pins")
        declared = {g.id for g in component.gates}
        if declared and item.ungated_reason:
            raise ValueError("ungated_reason contradicts declared gates")
        token = tokens.get(item.component)
        if token:
            _refs([g.gate for g in token.gates], declared, "gate evidence")
        if placement.state == "active":
            if not declared:
                if placement.ownership == "deployed":
                    raise ValueError("an active deployed component requires declared gates")
                if not item.ungated_reason:
                    raise ValueError("an active component without declared gates requires an explicit ungated_reason")
            elif {g.gate for g in token.gates} != declared:
                raise ValueError("an active component requires token evidence for every declared gate")
    for binding in placement.datasets:
        _refs([binding.dataset], datasets, "bound dataset")
        dataset = datasets[binding.dataset]
        allowed = dataset.writers if binding.access == "write" else dataset.readers
        if not selected.intersection(allowed):
            raise ValueError("dataset access has no local declared consumer")
    bound_datasets = {d.dataset for d in placement.datasets}
    for binding in placement.secrets:
        _refs([binding.secret], secrets, "bound secret")
        location = next((item for item in secrets[binding.secret].locations if item.id == binding.location), None)
        if location is None:
            raise ValueError("unknown secret location: " + binding.secret + "/" + binding.location)
        if location.component not in selected:
            raise ValueError("secret location belongs to a component that is not on this placement")
        if location.dataset is not None:
            if binding.relative_path is None:
                raise ValueError("a secret location inside a dataset binds relative_path, never a second copy path")
            _refs([location.dataset], bound_datasets, "secret dataset binding")
        elif binding.path is None:
            raise ValueError("a secret location outside datasets binds an absolute path")
    for item in placement.components:
        native = components[item.component].native
        if isinstance(native, KubeNative):
            for volume in native.manifest.spec.volumes:
                if volume.hostPath and not volume.hostPath.path.startswith("config://"):  # config: Switchyard-owned, unbound
                    scheme, ref = volume.hostPath.path.split("://")
                    _refs([ref], bound_datasets if scheme == "dataset" else [p.id for p in placement.reviewed_paths], "hostPath binding")
                    if scheme == "reviewed":
                        reviewed = next(p for p in placement.reviewed_paths if p.id == ref)
                        mounts = [m for c in native.manifest.spec.containers for m in c.volumeMounts if m.name == volume.name]
                        if reviewed.access == "read" and any(not m.readOnly for m in mounts):
                            raise ValueError("read-only reviewed path cannot have a writable mount")
            for container in native.manifest.spec.containers:
                for env in container.env:
                    if env.valueFrom:
                        secret = env.valueFrom.secretKeyRef.name
                        bindings = [s for s in placement.secrets if s.secret == secret]
                        if not bindings or any(b.conversion != "podman-kube-secret" for b in bindings):
                            raise ValueError("kube secret requires private whole-secret conversion")
    for claim in placement.endpoints:
        _refs([claim.endpoint], endpoints, "claimed endpoint")
        if endpoints[claim.endpoint].component not in selected:
            raise ValueError("endpoint component is not on placement")
    if placement.state in {"staged", "active"}:
        _refs([e.id for e in app.endpoints if e.component in selected], [e.endpoint for e in placement.endpoints], "required endpoint claim")
        for dataset in app.datasets:
            if selected.intersection(dataset.writers):
                if not any(d.dataset == dataset.id and d.access == "write" for d in placement.datasets):
                    raise ValueError("writer component requires dataset binding")
        bound = {(s.secret, s.location) for s in placement.secrets}
        for secret in app.secrets:
            for location in secret.locations:
                if location.component in selected and (secret.id, location.id) not in bound:
                    raise ValueError("required secret location binding: " + secret.id + "/" + location.id)


# --------------------------------------------------------------- v1alpha2 → v1alpha3 (in memory)

LEGACY_GATE_COVERS = "Upgraded from a v1alpha2 single-gate token; review the complete gate closure."


def upgrade(document, *, gate_ids=None):
    """Return `(document, upgraded_from)`. A v1alpha2 record is converted in memory to v1alpha3:

    - `Dataset.contains_secrets` becomes one `value`/`holder` location per secret in that dataset;
      other secrets get one `file` location held by their first consumer;
    - secret bindings name that location (`within_dataset` → `location`);
    - a token's single `gate`/`gate_ref` becomes gate evidence for gate `gate_ids[kind]`
      (default `legacy-<kind>`); inside a bundle the component also declares that gate.

    Stored revisions keep their original bytes and content hash; the result hashes differently,
    so persisting it is a new revision. v1alpha3 input is returned unchanged (a copy)."""
    document = deepcopy(document)
    if not isinstance(document, dict) or document.get("apiVersion") != PREVIOUS_VERSION:
        return document, None
    kind = document.get("kind")
    if kind == "Application":
        return _upgrade_application(document), PREVIOUS_VERSION
    if kind == "Placement":
        return _upgrade_placement(document, gate_ids), PREVIOUS_VERSION
    if kind == "ActivationInput":
        document["apiVersion"] = API_VERSION
        return document, PREVIOUS_VERSION
    if kind != "Bundle":
        return document, None
    document["apiVersion"] = API_VERSION
    apps = [_upgrade_application(app) if isinstance(app, dict) else app for app in document.get("applications", [])]
    document["applications"] = apps
    placements = []
    for placement in document.get("placements", []):
        legacy = [(t.get("component"), t["gate"]) for t in (placement.get("fence") or {}).get("tokens", []) if "gate" in t]
        placements.append(_upgrade_placement(placement, gate_ids))
        app = next((a for a in apps if (a.get("id"), a.get("revision")) == (placement.get("application_id"), placement.get("revision"))), None)
        for component_id, kind_ in legacy:
            component = next((c for c in (app or {}).get("components", []) if c.get("id") == component_id), None)
            if component is None:
                continue
            gate_id = (gate_ids or {}).get(kind_, "legacy-" + kind_)
            gates = component.setdefault("gates", [])
            if not any(g.get("id") == gate_id for g in gates):
                native = component.get("native", {})
                target = (native.get("launcher") or {}).get("id") if kind_ == "launcher" else native.get("unit")
                gates.append({"id": gate_id, "kind": kind_, "target": target or "PLACEHOLDER-review-gate-target",
                              "covers": LEGACY_GATE_COVERS})
    document["placements"] = placements
    for activation in document.get("activation_inputs", []):
        if isinstance(activation, dict):
            activation["apiVersion"] = API_VERSION
    return document, PREVIOUS_VERSION


def _upgrade_application(app):
    if app.get("apiVersion") != PREVIOUS_VERSION:
        return app
    app["apiVersion"] = API_VERSION
    datasets = {d.get("id"): d for d in app.get("datasets", []) if isinstance(d, dict)}
    contained = {}
    for dataset in datasets.values():
        for secret_id in dataset.pop("contains_secrets", []):
            contained[secret_id] = dataset
    for secret in app.get("secrets", []):
        if not isinstance(secret, dict) or "locations" in secret:
            continue
        consumers = secret.get("consumers") or [None]
        dataset = contained.get(secret.get("id"))
        if dataset is not None:
            access = list(dataset.get("writers", [])) + list(dataset.get("readers", []))
            holder = next((c for c in consumers if c in access), consumers[0])
            secret["locations"] = [{"id": dataset["id"], "form": "value", "role": "holder", "component": holder,
                                    "dataset": dataset["id"]}]
        else:
            secret["locations"] = [{"id": "file", "form": "value", "role": "holder", "component": consumers[0]}]
    return app


def _upgrade_placement(placement, gate_ids):
    if placement.get("apiVersion") != PREVIOUS_VERSION:
        return placement
    placement["apiVersion"] = API_VERSION
    for binding in placement.get("secrets", []):
        if isinstance(binding, dict) and "location" not in binding:
            binding["location"] = binding.pop("within_dataset", None) or "file"
    for token in (placement.get("fence") or {}).get("tokens", []):
        if isinstance(token, dict) and "gate" in token:
            kind = token.pop("gate")
            evidence = token.pop("gate_ref", None) or "upgraded from v1alpha2"
            token["gates"] = [{"gate": (gate_ids or {}).get(kind, "legacy-" + kind), "evidence": evidence}]
    return placement
