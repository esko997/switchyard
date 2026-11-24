"""Bounded static-web declarations and evidence-only assessment. No executor."""
import json
import math
import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .models import timestamp
from .observations import TTL_SECONDS


Text = Annotated[str, Field(strict=True, min_length=1, max_length=2048)]
Reference = Annotated[str, Field(strict=True, min_length=1, max_length=256,
                                 pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]*$")]
Identifier = Annotated[str, Field(strict=True, pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
Bytes = Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
Digest = Annotated[str, Field(strict=True, pattern=r"^sha256:[0-9a-f]{64}$")]


class Declaration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Binding(Declaration):
    definition_id: Identifier
    device_id: Identifier
    backend: Literal["docker"]
    scope: Literal["system"]
    selector: Annotated[dict[str, Reference], Field(min_length=1, max_length=1)]

    @model_validator(mode="after")
    def exact_selector(self):
        if set(self.selector) not in ({"native_id"}, {"name"}):
            raise ValueError("Expected one exact native ID or name selector")
        if "native_id" in self.selector and not re.fullmatch(r"[0-9a-f]{64}", self.selector["native_id"]):
            raise ValueError("Expected a full Docker container ID")
        return self


class Destination(Binding):
    filesystem_id: Reference
    data_root: Text


class Artifact(Declaration):
    kind: Literal["image"]
    reference: Reference
    digest: Digest | None
    architectures: Annotated[list[Reference], Field(min_length=1, max_length=16)]
    reference_status: Literal["unverified"]


class Site(Declaration):
    source_path: Text
    destination_path: Text
    container_path: Literal["/usr/share/nginx/html/index.html"]
    content_sha256: Digest | None
    upper_bound_bytes: Bytes | None
    read_only: Literal[True]


class Resources(Declaration):
    cpu_count: Annotated[int, Field(strict=True, ge=1, le=4096)]
    memory_bytes: Bytes
    storage_reserve_bytes: Bytes


class Network(Declaration):
    bind_address: Literal["127.0.0.1"]
    host_port: Literal[18080]
    container_port: Annotated[int, Field(strict=True, ge=1, le=65535)]
    protocol: Literal["tcp"]


class Verification(Declaration):
    method: Literal["http-body-sha256"]
    path: Literal["/"]
    expected_status: Literal[200]
    follow_redirects: Literal[False]
    baseline: Literal["unobserved"]


class Recovery(Declaration):
    strategy: Literal["restart-unchanged-source-before-cutover"]
    require_destination_stopped: Literal[True]
    require_source_unchanged: Literal[True]
    retain_source_content: Literal[True]
    automatic_restart: Literal[False]


class Recipe(Declaration):
    schema_version: Literal[1]
    kind: Literal["static-web"]
    stop: Text
    transfer: Text
    start: Text
    verify: Text
    recovery: Text
    source: Binding
    destination: Destination
    artifact: Artifact
    site: Site
    resources: Resources
    network: Network
    restart_policy: Literal["no"]
    verification: Verification
    recovery_conditions: Recovery

    @model_validator(mode="after")
    def consistent_declarations(self):
        if self.source.definition_id != self.destination.definition_id:
            raise ValueError("Source and destination must bind the same definition")
        if len(self.artifact.architectures) != len(set(self.artifact.architectures)):
            raise ValueError("Duplicate architecture")
        # A versioned tag is a design reference, never an immutable content pin.
        image, separator, tag = self.artifact.reference.rpartition(":")
        if not separator or "nginx" not in image.split("/")[-1] or tag == "latest" or not re.search(r"\d", tag):
            raise ValueError("Expected an explicit versioned nginx image reference")
        paths = (self.destination.data_root, self.site.source_path, self.site.destination_path)
        for path in paths:
            if (not path.startswith("/") or path == "/" or path.endswith("/")
                    or any(part in ("", ".", "..") for part in path.split("/")[1:])
                    or any(char.isspace() for char in path)):
                raise ValueError("Expected normalized absolute content path")
        if not self.site.destination_path.startswith(self.destination.data_root + "/"):
            raise ValueError("Site destination must be within its declared root")
        return self


def validate_recipe(recipe) -> dict:
    """Return a detached declaration, never an observation or operation."""
    try:
        if not isinstance(recipe, dict) or type(recipe.get("schema_version")) is not int:
            raise ValueError("Recipe schema_version must be integer 1")
        result = Recipe.model_validate(recipe).model_dump()

        def literal_types(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in ("read_only", "follow_redirects", "require_destination_stopped",
                               "require_source_unchanged", "retain_source_content", "automatic_restart") and type(item) is not bool:
                        raise ValueError("Recipe condition must be a boolean")
                    if key in ("host_port", "expected_status") and type(item) is not int:
                        raise ValueError("Recipe number must be an integer")
                    literal_types(item)
            elif isinstance(value, list):
                for item in value:
                    literal_types(item)
        literal_types(recipe)
        encoded = json.dumps(result, allow_nan=False)
        if len(encoded) > 32768:
            raise ValueError("Recipe exceeds 32768 characters")
        if re.search(r"-----BEGIN|(?:password|passwd|token|api[_-]?key|secret)\s*[:=]|\bBearer\s+|://[^/\s]+@",
                     encoded, re.IGNORECASE):
            raise ValueError("Recipe must not contain credentials")
    except (ValidationError, TypeError, OverflowError, RecursionError):
        raise ValueError("Invalid migration recipe structure") from None

    def clean(value):
        if isinstance(value, str) and (not value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError("Invalid migration recipe text")
        if isinstance(value, dict):
            for item in value.values():
                clean(item)
        elif isinstance(value, list):
            for item in value:
                clean(item)
    clean(result)
    return result


def assess_recipe(recipe, workload, target, observations) -> dict:
    """Assess only cached evidence; unrelated samples cannot freshen old facts."""
    recipe = validate_recipe(recipe)
    checks, blockers = [], []

    def check(identity, supported, detail, declaration=None, evidence=None):
        checks.append({"id": identity, "status": "supported" if supported else "blocked",
                       "detail": detail, "declaration": declaration, "evidence": evidence})
        if not supported:
            blockers.append(detail)

    source, destination = recipe["source"], recipe["destination"]
    source_id, target_id = workload.get("device_id"), target["id"]

    def snapshot(host_id):
        value = observations.get(host_id, {}).get("snapshot")
        return value if isinstance(value, dict) and value.get("host_id") == host_id else {}

    def fresh(host_id, at):
        wrapper = observations.get(host_id, {})
        seconds, snap = wrapper.get("age_seconds"), snapshot(host_id)
        if (wrapper.get("freshness") != "fresh" or not snap or not at
                or isinstance(seconds, bool) or not isinstance(seconds, (int, float))
                or not math.isfinite(seconds) or not 0 <= seconds < TTL_SECONDS):
            return False
        try:
            delta = (timestamp(snap["observed_at"]) - timestamp(at)).total_seconds()
            return 0 <= delta and seconds + delta < TTL_SECONDS
        except (ValueError, TypeError, KeyError):
            return False

    def scope_fresh(host_id, scope, *, allow_partial=False):
        matches = [entry for entry in snapshot(host_id).get("coverage", []) if entry.get("scope") == scope]
        statuses = ("complete", "partial") if allow_partial else ("complete",)
        return (len(matches) == 1 and matches[0].get("status") in statuses
                and fresh(host_id, matches[0].get("observed_at")))

    def resource_fresh(host_id, resource):
        snap = snapshot(host_id)
        return (fresh(host_id, snap.get("resource_observed_at", {}).get(resource))
                and (resource == "host" or scope_fresh(host_id, resource, allow_partial=True)))

    def matches(host_id, binding):
        key, value = next(iter(binding["selector"].items()))
        return [entry for entry in snapshot(host_id).get("workloads", [])
                if (entry.get("host_id"), entry.get("backend"), entry.get("scope"), entry.get(key))
                == (host_id, binding["backend"], binding["scope"], value)]

    source_matches = matches(source_id, source)
    record = source_matches[0] if len(source_matches) == 1 else None
    primary = [binding for binding in workload.get("bindings", []) if binding.get("role") == "primary"]
    declared_primary = {key: source[key] for key in ("backend", "scope", "selector")}
    declaration_bound = (
        workload.get("management") == "defined" and workload.get("id") == source["definition_id"]
        and source["device_id"] == source_id and workload.get("backend") == source["backend"]
        and len(primary) == 1
        and {key: primary[0].get(key) for key in declared_primary} == declared_primary)
    source_scope = source["backend"] + ":" + source["scope"]
    runtime_scope = destination["backend"] + ":" + destination["scope"]
    source_fresh = (bool(record) and fresh(source_id, record.get("observed_at"))
                    and scope_fresh(source_id, source_scope)
                    and bool(re.fullmatch(r"[0-9a-f]{64}", record.get("native_id", ""))))
    check("execution-authority", False, "Execution is disabled; definitions and recipes grant no lifecycle permission.")
    check("source-binding", declaration_bound and source_fresh and source_id != target_id,
          "Source must match the defined primary binding and exactly one fresh full native ID; names do not pin an incarnation.",
          source, source_matches)
    check("destination-binding", destination["definition_id"] == workload.get("id")
          and destination["device_id"] == target_id and source_id != target_id,
          "Destination must explicitly bind this definition to the selected different host.", destination)
    for role, host_id in (("source", source_id), ("destination", target_id)):
        snap = snapshot(host_id)
        check(role + "-host-identity", resource_fresh(host_id, "host"),
              role.capitalize() + " host identity must be freshly observed under its exact configured host ID.",
              host_id, snap.get("host"))
        architecture = snap.get("host", {}).get("architecture")
        check("artifact-architecture" if role == "destination" else "source-architecture",
              resource_fresh(host_id, "host") and architecture in recipe["artifact"]["architectures"],
              role.capitalize() + " architecture must be freshly observed and supported by the image.",
              recipe["artifact"]["architectures"], {"architecture": architecture})
        scope = source_scope if role == "source" else runtime_scope
        check(role + "-runtime", scope_fresh(host_id, scope),
              role.capitalize() + " Docker runtime requires fresh complete scope evidence; binary presence alone is insufficient.",
              scope, [entry for entry in snap.get("coverage", []) if entry.get("scope") == scope])
    target_snap = snapshot(target_id)
    artifact = recipe["artifact"]
    images = [image for image in target_snap.get("artifacts", [])
              if (image.get("host_id"), image.get("backend"), image.get("scope"), image.get("kind"))
              == (target_id, destination["backend"], destination["scope"], "image")
              and artifact["digest"] is not None and image.get("native_id") == artifact["digest"]
              and fresh(target_id, image.get("observed_at"))]
    check("artifact-digest", bool(images) and scope_fresh(target_id, runtime_scope),
          "Declared image content digest must match fresh installed destination image evidence; a tag is not a digest pin.",
          artifact, images)
    container = (record or {}).get("extensions", {}).get("container.v1", {})
    check("source-artifact-digest", declaration_bound and source_fresh and artifact["digest"] is not None
          and container.get("image_id") == artifact["digest"] and container.get("image_reference") == artifact["reference"],
          "Fresh selected source must use the declared nginx image reference and content digest.",
          artifact, {"image_id": container.get("image_id"), "image_reference": container.get("image_reference")})
    for resource, field, minimum in (("cpu", "logical_count", recipe["resources"]["cpu_count"]),
                                     ("memory", "available_bytes", recipe["resources"]["memory_bytes"])):
        value = target_snap.get(resource, {}).get(field)
        check("destination-" + resource, resource_fresh(target_id, resource) and type(value) is int and value >= minimum,
              f"Destination {resource} requires fresh known capacity meeting the budget; this is not a reservation.",
              minimum, {field: value, "observed_at": target_snap.get("resource_observed_at", {}).get(resource)})
    site = recipe["site"]
    budget = None if site["upper_bound_bytes"] is None else site["upper_bound_bytes"] + recipe["resources"]["storage_reserve_bytes"]
    pools = [pool for pool in target_snap.get("storage", {}).get("filesystems", [])
             if pool.get("id") == destination["filesystem_id"]]
    pool = pools[0] if len(pools) == 1 else {}
    paths = [destination["data_root"], site["destination_path"]]

    def contains(mount, path):
        return isinstance(mount, str) and mount.startswith("/") and (path == mount or path.startswith(mount.rstrip("/") + "/"))

    mounts = pool.get("mounts", [])
    mapped = bool(pool) and all(any(contains(mount, path) for mount in mounts) and not any(
        other.get("id") != pool.get("id") and contains(child, path)
        and all(len(child.rstrip("/")) > len(mount.rstrip("/")) for mount in mounts if contains(mount, path))
        for other in target_snap.get("storage", {}).get("filesystems", []) for child in other.get("mounts", [])) for path in paths)
    available = pool.get("available_bytes")
    check("destination-storage", resource_fresh(target_id, "storage") and budget is not None and mapped
          and pool.get("kind") == "persistent" and pool.get("read_only") is False
          and type(available) is int and available >= budget,
          "Exact destination filesystem must freshly map site paths and have persistent writable capacity for content plus reserve.",
          {"filesystem_id": destination["filesystem_id"], "paths": paths, "required_bytes": budget}, pool or None)
    check("source-stopped", declaration_bound and source_fresh and record.get("lifecycle") == "stopped",
          "Exact source container must be freshly stopped; unreachable is not stopped.", source, record)
    content_mounts = [mount for mount in container.get("mounts", [])
                      if (mount.get("source"), mount.get("destination"), mount.get("type"), mount.get("read_only"))
                      == (site["source_path"], site["container_path"], "bind", True)]
    check("source-readonly-content", declaration_bound and source_fresh and len(content_mounts) == 1,
          "Fresh source mount must bind the exact declared content file read-only.", site, content_mounts)
    check("destination-name-available", False,
          "Absence from bounded container discovery does not establish that the dedicated destination name is available.",
          destination["selector"], matches(target_id, destination))
    check("dedicated-port", False,
          "Dedicated loopback TCP port 18080 availability and exclusive exposure are not observed by current collectors.", recipe["network"])
    check("restart-inhibited", False,
          "No-restart policy and absence of external restart automation are declared but not observed.", recipe["restart_policy"])
    check("content-digest", False,
          "Deployed source and transferred destination file SHA256 and actual byte bounds are unobserved; an authored asset hash is not deployment evidence.", site)
    check("http-body-verification", False,
          "HTTP 200 with redirects refused and the exact response body SHA256 matching site.content_sha256 must be independently measured on both hosts; no HTTP request is made.",
          recipe["verification"])
    check("recovery-before-cutover", False,
          "Recovery requires independently verified stopped destination and unchanged retained source content before cutover; no automatic restart is authorized.",
          recipe["recovery_conditions"])
    return {"blockers": blockers, "checks": checks}
