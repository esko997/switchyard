"""Deliberate workload definitions and read-only native-resource bindings."""
from copy import deepcopy
import json
import math
import re
import time

from pydantic import ValidationError

from . import spec
from .models import timestamp
from .observations import TTL_SECONDS, age
from .planning import validate_recipe

__all__ = ["validate_definitions", "resolve_definitions"]

_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_CONTAINER_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}\Z")
_FIELDS = {
    "id", "name", "purpose", "device_id", "backend", "management", "kind",
    "bindings", "requirements", "architectures", "recipe", "notes", "health_check",
    "data_locations", "dependencies", "supported_operations",
}
# Optional on input (catalog seeds and definitions written before it), always present on output: how the native
# runtime starts and stops the workload (`spec.Runtime`), description only.
_OPTIONAL = {"runtime"}
_OPERATIONS = ["observe", "plan-migration"]


def _runtime(value, backend, kind):
    if value is None:
        return None
    try:
        native = spec.ObservedNative.model_validate({"kind": "observed", "backend": backend, "resource_kind": kind,
                                                     "runtime": value})
    except ValidationError as error:
        details = "; ".join(".".join(str(p) for p in e["loc"]) + ": " + e["msg"] for e in error.errors()[:5])
        raise ValueError("Invalid workload runtime: " + details) from None
    return native.model_dump(mode="json")["runtime"]


def _text(value, label, limit=4096):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
        raise ValueError(f"{label} must be nonempty text (at most {limit} characters)")
    return value


def _identifier(value, label):
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"Invalid {label}")
    return value


def _strings(value, label, limit=128):
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"{label} must be a bounded list")
    result = [_text(item, label) for item in value]
    if len(set(result)) != len(result):
        raise ValueError(f"Duplicate {label}")
    return result


def _binding(value):
    if not isinstance(value, dict) or set(value) != {"backend", "scope", "selector", "role"}:
        raise ValueError("Invalid binding fields")
    backend = _text(value["backend"], "binding backend", 128)
    scope = _text(value["scope"], "binding scope", 256)
    if any(text != text.strip() or any(ord(char) < 32 for char in text) for text in (backend, scope)):
        raise ValueError("Binding backend and scope must be exact")
    selector = value["selector"]
    if not isinstance(selector, dict) or set(selector) not in ({"native_id"}, {"name"}):
        raise ValueError("Binding selector must contain exactly native_id or name")
    key = next(iter(selector))
    selected = _text(selector[key], "binding selector")
    if selected != selected.strip() or any(ord(char) < 32 or char in "*?[]" for char in selected):
        raise ValueError("Binding selector must be an exact identifier, not a pattern")
    if key == "name" and (backend not in {"docker", "podman"} or not _CONTAINER_NAME.fullmatch(selected)):
        raise ValueError("Name selectors require an exact Docker or Podman container name")
    if value["role"] not in ("primary", "supporting"):
        raise ValueError("Invalid binding role")
    return {"backend": backend, "scope": scope, "selector": {key: selected}, "role": value["role"]}


def _binding_key(binding):
    key, value = next(iter(binding["selector"].items()))
    return binding["backend"], binding["scope"], key, value


ARCHITECTURE_PREFIX = "architecture:"  # architectures are stored as `requires` entries of this form


def validate_definitions(records, host_ids) -> list[dict]:
    """Validate the editor's form of observed workloads: bounded declarations, exact bindings, and migration
    recipes that bind the definition's primary resource and a different registry host."""
    if not isinstance(records, list) or len(records) > 128:
        raise ValueError("workloads must be a bounded list of definitions")
    result, identities, primaries = [], set(), set()
    for record in records:
        if not isinstance(record, dict) or not _FIELDS <= set(record) <= _FIELDS | _OPTIONAL:
            raise ValueError("Invalid workload definition fields")
        identity = _identifier(record["id"], "workload definition ID")
        if identity in identities:
            raise ValueError("Duplicate workload definition ID")
        identities.add(identity)
        host = _identifier(record["device_id"], "workload source device")
        if host not in host_ids:
            raise ValueError("Workload definition references unknown source device")
        if record["management"] != "observed" or record["kind"] not in ("service", "scheduled-job"):
            raise ValueError("Invalid workload definition management or kind")
        bindings = record["bindings"]
        if not isinstance(bindings, list) or not 1 <= len(bindings) <= 128:
            raise ValueError("bindings must be a nonempty bounded list")
        bindings = [_binding(binding) for binding in bindings]
        keys = [_binding_key(binding) for binding in bindings]
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate workload binding")
        primary = [binding for binding in bindings if binding["role"] == "primary"]
        if len(primary) != 1:
            raise ValueError("Exactly one primary binding is required")
        backend = _text(record["backend"], "workload backend", 128)
        if primary[0]["backend"] != backend:
            raise ValueError("Workload backend must match its primary binding")
        primary_key = (host, *_binding_key(primary[0]))
        if primary_key in primaries:
            raise ValueError("Duplicate primary binding across workload definitions")
        primaries.add(primary_key)
        operations = _strings(record["supported_operations"], "supported_operations", 2)
        if set(operations) != set(_OPERATIONS):
            raise ValueError("Definitions support observation and migration proposals only")
        recipe = record["recipe"]
        if recipe is not None:
            if not isinstance(recipe, dict):
                raise ValueError("recipe must be an object or null")
            try:
                encoded = json.dumps(recipe, allow_nan=False)
            except (TypeError, ValueError, RecursionError) as exc:
                raise ValueError("recipe must be bounded JSON") from exc
            if len(encoded) > 65536:
                raise ValueError("recipe must be bounded JSON")
            recipe = validate_recipe(recipe)
            source, destination = recipe["source"], recipe["destination"]
            if (source["definition_id"] != identity or source["device_id"] != host
                    or any(source[key] != primary[0][key] for key in ("backend", "scope", "selector"))
                    or destination["definition_id"] != identity or destination["device_id"] not in host_ids
                    or destination["device_id"] == host):
                raise ValueError("Migration recipe must bind this definition's primary resource and a different registry host")
        requirements = _strings(record["requirements"], "requirements")
        if any(item.startswith(ARCHITECTURE_PREFIX) for item in requirements):
            raise ValueError("Declare architectures in architectures, not as requirements")
        dependencies = _strings(record["dependencies"], "dependencies")
        for dependency in dependencies:
            _identifier(dependency, "dependency ID")
        health_check = record["health_check"]
        result.append({
            "id": identity, "name": _text(record["name"], "workload name"),
            "purpose": _text(record["purpose"], "workload purpose", 8192),
            "device_id": host, "backend": backend, "management": "observed", "kind": record["kind"],
            "bindings": bindings, "requirements": requirements,
            "architectures": _strings(record["architectures"], "architectures", 64),
            "recipe": recipe, "notes": _text(record["notes"], "workload notes", 8192),
            "health_check": None if health_check is None else _text(health_check, "health_check", 8192),
            "data_locations": _strings(record["data_locations"], "data_locations"),
            "dependencies": dependencies, "supported_operations": list(_OPERATIONS),
            "runtime": _runtime(record.get("runtime"), backend, record["kind"]),
        })
    graph = {record["id"]: record["dependencies"] for record in result}
    if any(dependency not in graph for dependencies in graph.values() for dependency in dependencies):
        raise ValueError("Workload definition references unknown dependency")
    visited, active = set(), set()

    def visit(identity):
        if identity in active:
            raise ValueError("Workload dependency cycle")
        if identity in visited:
            return
        active.add(identity)
        for dependency in graph[identity]:
            visit(dependency)
        active.remove(identity)
        visited.add(identity)

    for identity in graph:
        visit(identity)
    return result


def _timing(resource, now):
    at = resource.get("observed_at")
    if not isinstance(at, str):
        return None, "never", None
    try:
        timestamp(at)
        seconds = age(at, now)
    except (ValueError, TypeError, OverflowError):
        return None, "never", None
    # Core supplies timed resources. Retain their exact sample age and freshness,
    # rather than substituting a helper's timestamp or the definition read time.
    supplied_age = resource.get("age_seconds")
    if isinstance(supplied_age, (int, float)) and not isinstance(supplied_age, bool) and math.isfinite(supplied_age) and supplied_age >= 0:
        seconds = supplied_age
    ttl = resource.get("freshness_ttl_seconds", TTL_SECONDS)
    freshness = resource.get("freshness")
    if freshness not in ("fresh", "stale", "never"):
        freshness = "fresh" if seconds < ttl else "stale"
    if freshness == "never":
        return None, "never", None
    if seconds >= ttl:
        freshness = "stale"
    return at, freshness, seconds


def resolve_definitions(definitions, resources) -> list[dict]:
    """Join exact host/backend/scope selectors without granting lifecycle authority."""
    index = {}
    for resource in resources:
        scope = resource["host_id"], resource["backend"], resource["scope"]
        for selector in ("native_id", "name"):
            index.setdefault((*scope, selector, resource[selector]), []).append(resource)
    result, now = [], time.time()
    for definition in definitions:
        evidence, selected, primary = [], [], None
        for binding in definition["bindings"]:
            key = (definition["device_id"], *_binding_key(binding))
            matches = index.get(key, [])
            status = "missing" if not matches else "matched" if len(matches) == 1 else "ambiguous"
            if status == "matched" and binding["role"] == "primary":
                candidate = matches[0]
                environment = candidate.get("extensions", {}).get("container.v1", {}).get("environment")
                if candidate["kind"] == "environment" or environment == "distrobox":
                    status = "mismatch"
            evidence.append({"binding": deepcopy(binding), "matches": [resource["id"] for resource in matches], "status": status})
            if status == "matched":
                selected.append(matches[0]["id"])
                if binding["role"] == "primary":
                    primary = matches[0]
        at, freshness, seconds = _timing(primary, now) if primary is not None else (None, "never", None)
        result.append({
            **deepcopy(definition), "resource_ids": list(dict.fromkeys(selected)),
            "bindings_evidence": evidence,
            "lifecycle": primary["lifecycle"] if primary is not None and freshness == "fresh" else "unknown",
            "health": "unknown", "observed_at": at, "freshness": freshness, "age_seconds": seconds,
            "freshness_ttl_seconds": primary.get("freshness_ttl_seconds", TTL_SECONDS) if primary is not None else TTL_SECONDS,
            "authority": {"execute": False, "approval": "not-granted"},
        })
    return result
