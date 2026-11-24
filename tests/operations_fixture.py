"""Operations policy fixtures: schema-2 grants plus the workload store records that describe them.

Tests keep writing descriptions in the broker's internal form (`backend`, `host_id`, `unit`, ... or the static-web
recipe); these helpers put that description into an observed store record and grant it in the policy file."""
import json
from pathlib import Path

from switchyard.operations_policy import MANAGED_ACTIONS, SCOPED_ACTIONS
from switchyard.workload_store import WorkloadStore
from switchyard.workloads import observed_record

COMPOSE = ("provider", "project_name", "project_directory", "files", "services")


def definition(workload_id, description):
    """The observed definition (editor form) whose resolution is exactly `description`."""
    backend = description.get("backend")
    if backend is None:  # the static-web recipe
        host, store_backend, kind = description["initial_host"], "podman", "service"
        bindings = [{"backend": "podman", "scope": "user:1000", "selector": {"name": description["container_name"]}, "role": "primary"}]
        runtime = {"kind": "static-web", **{key: description[key] for key in ("image", "port", "site_file")}}
    elif backend == "compose":
        host, kind = description["host_id"], "service"
        store_backend = "podman" if description["provider"] == "podman-compose" else "docker"
        bindings = [{"backend": store_backend, "scope": "user:1000", "selector": {"name": description["project_name"] + "-" + service},
                     "role": "primary" if index == 0 else "supporting"} for index, service in enumerate(description["services"])]
        runtime = {"kind": "compose", **{key: description[key] for key in COMPOSE}}
    else:
        host, store_backend, kind = description["host_id"], "systemd", "service"
        bindings = [{"backend": "systemd", "scope": "user:1000" if description["scope"] == "user" else description["scope"],
                     "selector": {"native_id": description["unit"]}, "role": "primary"}]
        runtime = {"kind": "quadlet"} if backend == "quadlet" else None
    return {"id": workload_id, "name": description["name"], "purpose": "Fixture workload", "device_id": host,
            "backend": store_backend, "management": "observed", "kind": kind, "bindings": bindings,
            "requirements": [], "architectures": [], "recipe": None, "notes": "Fixture", "health_check": None,
            "data_locations": [], "dependencies": [], "supported_operations": ["observe", "plan-migration"], "runtime": runtime}


def put_definition(directory, value):
    store = WorkloadStore(directory)
    with store.transaction() as db:
        current = store.record(db, value["id"])
        revision = current["revision"] + 1 if current else 1
        bundle, digest = observed_record(value, revision=revision, provenance={"submitted_by": "test", "source": "fixture"})
        store.put_record(db, workload_id=value["id"], relation="observed", expected_revision=revision - 1, revision=revision,
                         content_sha256=digest, data=bundle, meta={"origin": "test"})


def describe(directory, workload_id, description):
    """Write (or revise) the store record of `workload_id` so that it describes `description`."""
    put_definition(directory, definition(workload_id, description))


def grant(description):
    if description.get("backend") is None:
        return {"actions": list(MANAGED_ACTIONS), "hosts": list(description["allowed_hosts"])}
    return {"actions": list(SCOPED_ACTIONS), "hosts": [description["host_id"]]}


def write_policy(path, config, directory=None):
    """Write `config` (descriptions under `workloads`) as a schema-2 policy; with `directory`, also describe every
    workload in the store there."""
    for workload_id, description in config.get("workloads", {}).items():
        if directory is not None:
            describe(directory, workload_id, description)
    policy = {**{key: value for key, value in config.items() if key != "schema_version"}, "schema_version": 2,
              "workloads": {key: grant(value) for key, value in config.get("workloads", {}).items()}}
    Path(path).write_text(json.dumps(policy))
