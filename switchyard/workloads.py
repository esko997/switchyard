"""Workload records in the spec format, the views every interface reads, and the store's seed, export and import.

The workload store (`workload_store.py`) is the one authority for which workloads exist. This module converts
between its records and the forms the interfaces use:

- an observed workload is a spec Bundle (one Application whose single `observed` component names the backend,
  one declared adopted Placement whose native identities are the definition's bindings); the definition editor
  edits it in the older definition form, converted losslessly both ways;
- a registered application's bindings are declared by its placements' native identities;
- a deployed instance's bindings are derived from its deploy journal placement (see `deploy.DeployManager`).
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3

from pydantic import ValidationError

from . import spec
from .definitions import ARCHITECTURE_PREFIX, resolve_definitions, validate_definitions
from .grouping import load_groups
from .operation_store import encode, now

COMPONENT = "main"  # the single component of an observed workload
EXPORT_SCHEMA = "switchyard/store-export/v1"
# Native manager of a registered component's resources when its identity names none.
NATIVE_BACKEND = {"systemd": "systemd", "quadlet": "systemd", "compose": "podman", "kube": "podman"}


def _errors(error):
    return "; ".join(".".join(str(p) for p in e["loc"]) + ": " + e["msg"] for e in error.errors()[:20])


def document_sha256(document):
    return hashlib.sha256(encode(document).encode()).hexdigest()


# ------------------------------------------------------------------------- observed: definition <-> record

def definition_bundle(definition, *, revision, provenance):
    """A validated definition as the normalized Bundle document stored for an observed workload."""
    identities = [{"scope": b["scope"], "backend": b["backend"], "role": b["role"], **b["selector"]} for b in definition["bindings"]]
    document = {
        "apiVersion": spec.API_VERSION, "kind": "Bundle",
        "applications": [{
            "apiVersion": spec.API_VERSION, "kind": "Application", "id": definition["id"], "revision": revision,
            "name": definition["name"], "purpose": definition["purpose"],
            "components": [{"id": COMPONENT, "native": {"kind": "observed", "backend": definition["backend"],
                                                         "resource_kind": definition["kind"],
                                                         "runtime": deepcopy(definition["runtime"])}}],
            "requires": [{"name": item} for item in definition["requirements"]]
                        + [{"name": ARCHITECTURE_PREFIX + item} for item in definition["architectures"]],
            "notes": {"text": definition["notes"], "health": definition["health_check"],
                      "data_locations": list(definition["data_locations"]),
                      "workload_dependencies": list(definition["dependencies"])},
            "provenance": provenance,
        }],
        "placements": [{
            "apiVersion": spec.API_VERSION, "kind": "Placement", "id": definition["id"], "application_id": definition["id"],
            "revision": revision, "host_id": definition["device_id"], "generation": 1, "state": "declared",
            "ownership": "adopted", "components": [{"component": COMPONENT, "native_identities": identities}],
            "migration_recipe": deepcopy(definition["recipe"]),
        }],
    }
    try:
        return spec.SpecBundle.model_validate(document).model_dump(mode="json")
    except ValidationError as error:
        raise ValueError("Invalid observed workload record: " + _errors(error)) from None


def bundle_definition(bundle):
    """The definition form of an observed record (validated by `definitions.validate_definitions`)."""
    application, placement = bundle["applications"][0], bundle["placements"][0]
    native = application["components"][0]["native"]
    notes = application.get("notes") or {}
    requires = [item["name"] for item in application.get("requires", [])]
    bindings = []
    for identity in placement["components"][0]["native_identities"]:
        selector = {"name": identity["name"]} if identity.get("name") is not None else {"native_id": identity["native_id"]}
        bindings.append({"backend": identity["backend"], "scope": identity["scope"], "selector": selector, "role": identity["role"]})
    return {
        "id": application["id"], "name": application["name"], "purpose": application["purpose"],
        "device_id": placement["host_id"], "backend": native["backend"], "management": "observed",
        "kind": native["resource_kind"], "bindings": bindings,
        "requirements": [item for item in requires if not item.startswith(ARCHITECTURE_PREFIX)],
        "architectures": [item[len(ARCHITECTURE_PREFIX):] for item in requires if item.startswith(ARCHITECTURE_PREFIX)],
        "recipe": deepcopy(placement.get("migration_recipe")), "notes": notes.get("text"),
        "health_check": notes.get("health"), "data_locations": list(notes.get("data_locations", [])),
        "dependencies": list(notes.get("workload_dependencies", [])),
        "supported_operations": ["observe", "plan-migration"], "runtime": deepcopy(native.get("runtime")),
    }


def observed_record(definition, *, revision, provenance):
    """(bundle, content hash) for an observed definition at a record revision."""
    bundle = definition_bundle(definition, revision=revision, provenance=provenance)
    return bundle, document_sha256(bundle)


# ------------------------------------------------------------------------- registered applications

def _latest_application(bundle):
    return max(bundle["applications"], key=lambda app: app["revision"])


def placement_bindings(bundle, placement):
    """Declared bindings of one placement: one entry per native identity, with its component."""
    application = next(app for app in bundle["applications"]
                       if (app["id"], app["revision"]) == (placement["application_id"], placement["revision"]))
    natives = {component["id"]: component["native"] for component in application["components"]}
    result = []
    for item in placement["components"]:
        native = natives[item["component"]]
        default = native["backend"] if native["kind"] == "observed" else NATIVE_BACKEND[native["kind"]]
        for index, identity in enumerate(item["native_identities"]):
            selector = {"name": identity["name"]} if identity.get("name") is not None else {"native_id": identity["native_id"]}
            result.append({"component": item["component"], "native": native, "binding": {
                "backend": identity.get("backend") or default, "scope": identity["scope"], "selector": selector,
                "role": identity.get("role") or ("primary" if index == 0 else "supporting")}})
    return result


def _current_placements(bundle):
    return [placement for placement in bundle["placements"] if placement["state"] != "retired"]


def registered_declaration(record):
    """Inventory form of a registered application: its identity, placements and declared bindings."""
    bundle = record["data"]
    application = _latest_application(bundle)
    placements = _current_placements(bundle)
    bindings = [{**item["binding"], "host_id": placement["host_id"], "component": item["component"]}
                for placement in placements for item in placement_bindings(bundle, placement)]
    backends = sorted({binding["backend"] for binding in bindings})
    return {
        "id": record["id"], "name": application["name"], "purpose": application["purpose"],
        "device_id": placements[0]["host_id"] if placements else None,
        "backend": backends[0] if len(backends) == 1 else "mixed", "management": "registered", "kind": "application",
        "bindings": bindings, "components": [component["id"] for component in application["components"]],
        "placements": [{key: placement[key] for key in ("id", "host_id", "state", "ownership", "revision")} for placement in placements],
        "requirements": [item["name"] for item in application.get("requires", [])], "architectures": [],
        "recipe": None, "notes": None, "health_check": None, "data_locations": [], "dependencies": [],
        "supported_operations": ["observe"],
        "registration": {"revision": record["revision"], "registered_at": record["updated_at"],
                         "submitted_by": record["meta"].get("submitted_by"), "source": record["meta"].get("source"),
                         "applications": record["meta"].get("applications", []), "warnings": record["meta"].get("warnings", [])},
    }


def _binding_key(host_id, binding):
    selector, value = next(iter(binding["selector"].items()))
    return host_id, binding["backend"], binding["scope"], selector, value


def links(definitions, registered):
    """Observed workloads whose primary unit or container is a component of a registered application on the same
    host: `{workload_id: {application_id, component, placement_id, host_id}}`, matched on exactly what both declare
    (host, backend, scope and native ID or container name). Also every partial overlap that is not a link."""
    components = {}
    for record in registered:
        for placement in _current_placements(record["data"]):
            for item in placement_bindings(record["data"], placement):
                components.setdefault(_binding_key(placement["host_id"], item["binding"]), []).append(
                    {"application_id": record["id"], "component": item["component"],
                     "placement_id": placement["id"], "host_id": placement["host_id"]})
    linked, overlaps = {}, []
    for definition in definitions:
        primary = next(binding for binding in definition["bindings"] if binding["role"] == "primary")
        matches = components.get(_binding_key(definition["device_id"], primary), [])
        if len(matches) == 1:
            linked[definition["id"]] = dict(matches[0])
        elif matches:
            overlaps.append({"workload_id": definition["id"], "reason": "primary matches several registered components",
                             "components": matches})
        for binding in definition["bindings"]:
            if binding["role"] == "supporting":
                for match in components.get(_binding_key(definition["device_id"], binding), []):
                    overlaps.append({"workload_id": definition["id"], "reason": "a supporting binding (not the primary) "
                                     "is a registered component", "binding": deepcopy(binding), "components": [match]})
    return linked, overlaps


def _aggregate(states):
    known = sorted(set(states))
    return known[0] if len(known) == 1 else "unknown"


def registered_rows(registered, resources, *, linked, tokens):
    """Fleet rows for registered applications: each component joined with host observations the way observed
    workloads are joined, the application summarizing its components."""
    rows = []
    linked_by_component = {}
    for workload_id, link in linked.items():
        linked_by_component.setdefault((link["application_id"], link["placement_id"], link["component"]), []).append(workload_id)
    for record in registered:
        declaration = registered_declaration(record)
        bundle = record["data"]
        components, evidence, resource_ids = [], [], []
        for placement in _current_placements(bundle):
            entries = placement_bindings(bundle, placement)
            for component in dict.fromkeys(item["component"] for item in entries):
                bindings = [item["binding"] for item in entries if item["component"] == component]
                native = next(item["native"] for item in entries if item["component"] == component)
                resolved = resolve_definitions([{"id": component, "device_id": placement["host_id"], "bindings": bindings}], resources)[0]
                for item in resolved["bindings_evidence"]:
                    item.update(host_id=placement["host_id"], component=component)
                evidence.extend(resolved["bindings_evidence"])
                resource_ids.extend(resolved["resource_ids"])
                components.append({
                    "component": component, "placement_id": placement["id"], "host_id": placement["host_id"],
                    "placement_state": placement["state"], "native": deepcopy(native),
                    "lifecycle": resolved["lifecycle"], "observed_at": resolved["observed_at"],
                    "freshness": resolved["freshness"], "age_seconds": resolved["age_seconds"],
                    "freshness_ttl_seconds": resolved["freshness_ttl_seconds"],
                    "resource_ids": resolved["resource_ids"], "bindings_evidence": resolved["bindings_evidence"],
                    "linked_workloads": sorted(linked_by_component.get((record["id"], placement["id"], component), [])),
                    "tokens": [token for token in tokens.get(record["id"], [])
                               if token["component"] == component and token["host_id"] == placement["host_id"]],
                })
        observed = [item for item in components if item["observed_at"]]
        oldest = min(observed, key=lambda item: item["observed_at"]) if observed else None
        freshness = "never" if not observed else "stale" if any(item["freshness"] != "fresh" for item in components) else "fresh"
        lifecycles = [item["lifecycle"] for item in components]
        counts = {state: lifecycles.count(state) for state in dict.fromkeys(lifecycles)}
        rows.append({
            **declaration, "resource_ids": list(dict.fromkeys(resource_ids)), "bindings_evidence": evidence,
            "lifecycle": _aggregate(lifecycles) if components else "unknown",
            "lifecycle_summary": ", ".join(f"{count} {state}" for state, count in counts.items()),
            "health": "unknown", "observed_at": oldest["observed_at"] if oldest else None, "freshness": freshness,
            "age_seconds": oldest["age_seconds"] if oldest else None,
            "freshness_ttl_seconds": oldest["freshness_ttl_seconds"] if oldest else None,
            "declared_device_id": declaration["device_id"], "registered_components": components,
            "authority": {"execute": False, "approval": "not-granted",
                          "note": "Registered by its owner: metadata only, no lifecycle authority; start tokens are separate."},
        })
    return rows


# ------------------------------------------------------------------------- seeding

def read_catalog(path):
    """The operator catalog: hosts seed the registry once, workloads and groups seed the store once."""
    with Path(path).open("rb") as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError("Catalog exceeds 1 MiB")
    try:
        catalog = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise ValueError("Catalog is not valid UTF-8 JSON") from error
    if not isinstance(catalog, dict):
        raise ValueError("Catalog must be an object")
    return catalog, hashlib.sha256(raw).hexdigest()


def catalog_workloads(catalog, host_ids):
    records = catalog.get("workloads", [])
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError("Catalog workloads must be a list of objects")
    # Catalogs written before the store say `defined`; the store's relation word for them is `observed`.
    records = [{**record, "management": "observed"} if record.get("management") == "defined" else record for record in records]
    return validate_definitions(records, host_ids)


def seed_plan(db, store, *, catalog, catalog_sha256, catalog_path, host_ids):
    """Exactly what a seed would create, from one consistent read of the catalog and the legacy tables."""
    definitions = catalog_workloads(catalog, host_ids)
    groups = load_groups(catalog, set(host_ids))
    legacy = store.legacy_summary(db)
    existing = {record["id"]: record["relation"] for record in store.records(db)}
    conflicts = []
    owners = {}
    for item in legacy["deployed"]:
        owners.setdefault(item["id"], []).append("deployed instance")
    for item in legacy["registered"]:
        owners.setdefault(item["id"], []).append("registration")
    for definition in definitions:
        owners.setdefault(definition["id"], []).append("catalog workload")
    for identity, sources in owners.items():
        if len(sources) > 1:
            conflicts.append(f"ID {identity} is used by: " + ", ".join(sources))
    for item in legacy["deployed"] + legacy["registered"]:
        relation = existing.get(item["id"])
        if relation is not None and relation != item["relation"]:
            conflicts.append(f"ID {item['id']} is already a {relation} record")
    for definition in definitions:
        if definition["id"] in existing:
            conflicts.append(f"Catalog workload {definition['id']} is already a {existing[definition['id']]} record")
    provenance = catalog.get("definition_provenance") if isinstance(catalog.get("definition_provenance"), dict) else {}
    return {
        "catalog": {"path": str(Path(catalog_path).resolve()), "sha256": catalog_sha256,
                    "workloads_sha256": document_sha256(definitions)},
        "observed": [{"id": definition["id"], "host_id": definition["device_id"], "backend": definition["backend"],
                      "kind": definition["kind"], "bindings": len(definition["bindings"]),
                      "recipe": definition["recipe"] is not None, "provenance": bool(provenance.get(definition["id"]))}
                     for definition in definitions],
        "deployed": legacy["deployed"], "registered": legacy["registered"],
        "groups": [group["id"] for group in groups], "legacy_tables": legacy["tables"],
        "carried_over_beside_records": legacy["journal"], "conflicts": conflicts,
        "_definitions": definitions, "_groups": groups, "_provenance": provenance,
    }


def public_plan(plan):
    return {key: value for key, value in plan.items() if not key.startswith("_")}


def seed(store, *, catalog, catalog_sha256, catalog_path, host_ids):
    """Seed the store once, in one transaction: catalog workloads become observed records, the legacy instance and
    registration tables are copied byte for byte with their revisions, catalog groups become store groups.
    Idempotent (a seeded store is left alone); the legacy tables stay untouched and a backup is taken first."""
    with store.transaction() as db:
        current = store.meta(db, "seed")
        if current is not None:
            return {"seeded": False, "already_seeded": current}
        plan = seed_plan(db, store, catalog=catalog, catalog_sha256=catalog_sha256, catalog_path=catalog_path, host_ids=host_ids)
        if plan["conflicts"]:
            raise ValueError("Workload store seed refused (nothing written): " + "; ".join(plan["conflicts"]))
        # The store took a copy of the pre-change file before adding its tables (`pre_store_backup`).
        backup = store.meta(db, "pre_store_backup")
        if backup is None and plan["legacy_tables"]:
            backup = str(store.backup("pre-store-seed"))
        stamp = now()
        copied = store.copy_legacy(db)
        for definition in plan["_definitions"]:
            bundle, digest = observed_record(definition, revision=1, provenance={
                "submitted_by": "operator catalog", "source": plan["catalog"]["path"]})
            store.put_record(db, workload_id=definition["id"], relation="observed", expected_revision=0, revision=1,
                             content_sha256=digest, data=bundle, stamp=stamp,
                             meta={"origin": "catalog-seed", "catalog_sha256": catalog_sha256,
                                   "definition_provenance": plan["_provenance"].get(definition["id"])})
        store.replace_groups(db, plan["_groups"])
        # Loud, not best effort: anything that did not carry over exactly aborts the whole seed (rolled back).
        problems = store.verify_legacy_copy(db)
        stored = [bundle_definition(record["data"]) for record in store.records(db, "observed")]
        converted = {item["id"]: item for item in validate_definitions(stored, host_ids)} if stored else {}
        for definition in plan["_definitions"]:
            if converted.get(definition["id"]) != definition:
                problems.append(f"observed workload {definition['id']}: record does not convert back to its catalog definition")
        if store.groups(db) != plan["_groups"]:
            problems.append("application groups did not carry over")
        if problems:
            raise ValueError("Workload store seed aborted, nothing written: " + "; ".join(problems))
        report = {**public_plan(plan), "seeded_at": stamp, "backup": str(backup) if backup else None, "copied": copied,
                  "verified": "every legacy instance and registration revision byte for byte; every catalog workload "
                              "converts back to its definition; groups equal"}
        store.set_meta(db, "seed", report)
    return {"seeded": True, **report}


def dry_run(store_path, *, catalog, catalog_sha256, catalog_path, host_ids):
    """The seed plan read through a read-only connection; never creates or changes a file."""
    from .workload_store import WorkloadStore
    path = Path(store_path)
    if not path.exists():
        db = sqlite3.connect(":memory:")
    else:
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=3)
    db.row_factory = sqlite3.Row
    try:
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "store_meta" in names:
            row = db.execute("SELECT value FROM store_meta WHERE key='seed'").fetchone()
            if row:
                return {"seeded": True, "seed": json.loads(row[0])}
        view = WorkloadStore.reader(names)
        plan = seed_plan(db, view, catalog=catalog, catalog_sha256=catalog_sha256, catalog_path=catalog_path, host_ids=host_ids)
        return {"seeded": False, "store": str(path), "would_create": public_plan(plan),
                "backup": "a timestamped copy of the store beside it" if plan["legacy_tables"] else None}
    finally:
        db.close()


# ------------------------------------------------------------------------- export and import

def export_document(store, hosts):
    """Hosts, workloads (all three relations), templates and groups as one deterministic, secret-free document.
    Deploy journal state (placements, claims, tokens, verifications) stays in the store: it is not description."""
    with store.transaction() as db:
        records = store.records(db)
        templates = [dict(row) for row in db.execute("SELECT id, revision, content_sha256, data FROM templates ORDER BY id, revision")]
        groups = store.groups(db)
    workloads = []
    for record in records:
        item = {"id": record["id"], "relation": record["relation"], "revision": record["revision"],
                "content_sha256": record["content_sha256"], "document": record["data"]}
        if record["relation"] == "deployed":
            item["template_ref"] = record["template_ref"]
        else:
            item["provenance"] = {key: value for key, value in record["meta"].items()}
        workloads.append(item)
    return {"schema": EXPORT_SCHEMA, "hosts": hosts, "workloads": workloads,
            "templates": [{"id": row["id"], "revision": row["revision"], "content_sha256": row["content_sha256"],
                           "document": json.loads(row["data"])} for row in templates],
            "groups": groups}


def export_bytes(document):
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _check_document(document):
    if not isinstance(document, dict) or document.get("schema") != EXPORT_SCHEMA \
            or set(document) != {"schema", "hosts", "workloads", "templates", "groups"} \
            or any(not isinstance(document[key], list) for key in ("hosts", "workloads", "templates", "groups")):
        raise ValueError("Not a " + EXPORT_SCHEMA + " document")


def import_plan(db, store, document, *, registry_hosts, validate_observed):
    """Compare an export with the store. Creates only what is absent; anything that differs is a conflict.
    `validate_observed(definitions)`: the desk's definition validation for the union of observed workloads."""
    _check_document(document)
    blockers, warnings, actions = [], [], []
    registry = {host["id"]: host for host in registry_hosts}
    for host in document["hosts"]:
        if not isinstance(host, dict) or host.get("id") not in registry:
            blockers.append(f"Host {host.get('id') if isinstance(host, dict) else host} is not in the host registry; "
                            "add it there first (the registry is the host authority)")
        elif any(host.get(key) != registry[host["id"]].get(key) for key in host):
            warnings.append(f"Host {host['id']} differs from the registry; the registry is kept unchanged")
    existing = {record["id"]: record for record in store.records(db)}
    observed = {identity: record for identity, record in existing.items() if record["relation"] == "observed"}
    incoming_observed = []
    seen = set()
    for item in document["workloads"]:
        if not isinstance(item, dict) or not {"id", "relation", "revision", "content_sha256", "document"} <= set(item):
            blockers.append("Malformed workload entry")
            continue
        identity, relation = item["id"], item["relation"]
        if identity in seen:
            blockers.append(f"Duplicate workload {identity}")
            continue
        seen.add(identity)
        current = existing.get(identity)
        if current is not None:
            same = (current["relation"], current["revision"], current["content_sha256"], current["data"]) == \
                   (relation, item["revision"], item["content_sha256"], item["document"])
            if same:
                actions.append({"workload": identity, "relation": relation, "action": "unchanged"})
            else:
                blockers.append(f"Workload {identity} differs from the store ({current['relation']} revision {current['revision']}); "
                                "import never overwrites")
            continue
        if relation == "deployed":
            blockers.append(f"Deployed instance {identity} is absent: deployed records belong to the deploy journal "
                            "(placements, generations, ownership) and cannot be created by import")
            continue
        if relation not in ("observed", "registered") or type(item["revision"]) is not int or item["revision"] < 1:
            blockers.append(f"Workload {identity}: invalid relation or revision")
            continue
        # The document is kept as exported (stored bytes are never rewritten); its hash must match.
        if not isinstance(item["document"], dict) or document_sha256(item["document"]) != item["content_sha256"]:
            blockers.append(f"Workload {identity}: document hash does not match its content_sha256")
            continue
        try:
            bundle = spec.SpecBundle.model_validate(spec.upgrade(item["document"])[0]).model_dump(mode="json")
        except ValidationError as error:
            blockers.append(f"Workload {identity}: invalid Bundle: {_errors(error)}")
            continue
        if {app["id"] for app in bundle["applications"]} != {identity}:
            blockers.append(f"Workload {identity}: the Bundle holds another application ID")
            continue
        if relation == "registered" and any(p["ownership"] != "adopted" or p.get("ownership_id") for p in bundle["placements"]):
            blockers.append(f"Registered application {identity}: placements must be adopted without ownership IDs")
            continue
        if relation == "observed":
            try:
                definition = bundle_definition(bundle)
            except (KeyError, IndexError, TypeError):
                blockers.append(f"Observed workload {identity}: not an observed-workload record")
                continue
            incoming_observed.append(definition)
        actions.append({"workload": identity, "relation": relation, "action": "create", "revision": item["revision"],
                        "_entry": item})
    if incoming_observed:
        try:
            validate_observed([bundle_definition(record["data"]) for record in observed.values()] + incoming_observed)
        except ValueError as error:
            blockers.append("Observed workloads do not validate together with the store's: " + str(error))
    stored_templates = {(row["id"], row["revision"]): row["content_sha256"]
                        for row in db.execute("SELECT id, revision, content_sha256 FROM templates")}
    for item in document["templates"]:
        if not isinstance(item, dict) or not {"id", "revision", "content_sha256", "document"} <= set(item):
            blockers.append("Malformed template entry")
            continue
        key = (item["id"], item["revision"])
        if key in stored_templates:
            if stored_templates[key] != item["content_sha256"]:
                blockers.append(f"Template {item['id']}@{item['revision']} differs from the store")
            else:
                actions.append({"template": f"{item['id']}@{item['revision']}", "action": "unchanged"})
            continue
        document_, _ = spec.upgrade(item["document"])
        try:
            application = spec.Application.model_validate(document_)
        except ValidationError as error:
            blockers.append(f"Template {item['id']}@{item['revision']}: {_errors(error)}")
            continue
        if application.role != "template" or (application.id, application.revision) != key \
                or (item["document"].get("apiVersion") == spec.API_VERSION and application.content_sha256() != item["content_sha256"]):
            blockers.append(f"Template {item['id']}@{item['revision']}: identity or hash mismatch")
            continue
        actions.append({"template": f"{item['id']}@{item['revision']}", "action": "create", "_entry": item})
    groups = store.groups(db)
    if document["groups"] != groups:
        if groups:
            blockers.append("Application groups differ from the store; import never overwrites them")
        else:
            try:
                load_groups({"application_groups": document["groups"]}, set(registry))
                actions.append({"groups": [group["id"] for group in document["groups"]], "action": "create",
                                "_groups": document["groups"]})
            except ValueError as error:
                blockers.append("Invalid groups: " + str(error))
    return {"revision": store.revision(db), "blockers": blockers, "warnings": warnings, "actions": actions}


def public_import(plan):
    return {**plan, "actions": [{key: value for key, value in action.items() if not key.startswith("_")} for action in plan["actions"]]}


def apply_import(db, store, plan, *, source_sha256):
    stamp = now()
    for action in plan["actions"]:
        if action["action"] != "create":
            continue
        entry = action.get("_entry")
        if "workload" in action:
            meta = {**(entry.get("provenance") or {}), "origin": "import", "import_sha256": source_sha256}
            store.put_record(db, workload_id=entry["id"], relation=entry["relation"], expected_revision=0,
                             revision=entry["revision"], content_sha256=entry["content_sha256"], data=entry["document"],
                             meta=meta, stamp=stamp)
        elif "template" in action:
            db.execute("INSERT INTO templates VALUES(?,?,?,?,?)", (entry["id"], entry["revision"], entry["content_sha256"],
                                                                     encode(entry["document"]), stamp))
        else:
            store.replace_groups(db, action["_groups"])
