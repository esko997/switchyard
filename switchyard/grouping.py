"""Read-only application associations. Groups never confer lifecycle authority."""
import hashlib
import json
import re


def load_groups(catalog: dict, host_ids: set[str]) -> list[dict]:
    groups = catalog.get("application_groups", [])
    if not isinstance(groups, list) or len(groups) > 128:
        raise ValueError("application_groups must be a bounded list")
    fields = {"id", "name", "host_id", "backend", "scope", "native_ids", "provenance"}
    identities, members, result = set(), set(), []
    for group in groups:
        if not isinstance(group, dict) or set(group) != fields:
            raise ValueError("Invalid application group fields")
        if any(not isinstance(group[k], str) or not group[k].strip() or len(group[k]) > 4096 for k in fields - {"native_ids"}):
            raise ValueError("Invalid application group metadata")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", group["id"]) or group["id"] in identities:
            raise ValueError("Invalid or duplicate application group ID")
        if group["host_id"] not in host_ids:
            raise ValueError("Application group references unknown host")
        native_ids = group["native_ids"]
        if not isinstance(native_ids, list) or not 1 <= len(native_ids) <= 128 or any(not isinstance(i, str) or not i or len(i) > 4096 for i in native_ids):
            raise ValueError("Invalid application group members")
        for native_id in native_ids:
            key = (group["host_id"], group["backend"], group["scope"], native_id)
            if key in members:
                raise ValueError("Native resource belongs to multiple declared groups")
            members.add(key)
        identities.add(group["id"])
        result.append({**group, "native_ids": list(native_ids)})
    return result


def build_groups(declarations: list[dict], workloads: list[dict]) -> list[dict]:
    native = {(w["host_id"], w["backend"], w["scope"], w["native_id"]): w["id"] for w in workloads}
    result, claimed = [], set()
    for group in declarations:
        scope = (group["host_id"], group["backend"], group["scope"])
        selected = [native[(*scope, name)] for name in group["native_ids"] if (*scope, name) in native]
        claimed.update(selected)
        result.append({"id": "group-" + group["id"], "name": group["name"],
                       "host_id": group["host_id"], "backend": group["backend"], "scope": group["scope"],
                       "member_ids": selected,
                       "missing_native_ids": [name for name in group["native_ids"] if (*scope, name) not in native],
                       "provenance": group["provenance"], "management": "discovered", "atomic": False})
    projects = {}
    for work in workloads:
        if work["id"] in claimed or work["backend"] not in {"podman", "docker"}:
            continue
        project = work["extensions"].get("container.v1", {}).get("project")
        if not isinstance(project, str) or not project:
            continue
        key = (work["host_id"], work["backend"], work["scope"], project)
        projects.setdefault(key, []).append(work["id"])
    for key, member_ids in projects.items():
        digest = hashlib.sha256(json.dumps(key).encode()).hexdigest()[:24]
        result.append({"id": "group-project-" + digest, "name": key[3], "host_id": key[0],
                       "backend": key[1], "scope": key[2], "member_ids": member_ids,
                       "missing_native_ids": [], "management": "discovered", "atomic": False,
                       "provenance": "Container project label; data/dependency boundary and atomic operations are unverified."})
    return result
