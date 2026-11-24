"""The workload store: seeding a state directory created before it, the single read path, the residents link,
export/import and undo. Temporary state only; no host is contacted."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from switchyard import spec
from switchyard.core import Service, namespace, seed_dry_run
from switchyard.workload_store import WorkloadStore
from switchyard.workloads import export_bytes

ROOT = Path(__file__).resolve().parents[1]

# The deploy journal schema before the workload store (commit 93edf8e, deploy_store.py).
LEGACY_SCHEMA = """
CREATE TABLE templates(id TEXT NOT NULL, revision INTEGER NOT NULL, content_sha256 TEXT NOT NULL, data TEXT NOT NULL,
    saved_at TEXT NOT NULL, PRIMARY KEY(id, revision));
CREATE TABLE instances(id TEXT PRIMARY KEY, revision INTEGER NOT NULL, template_id TEXT NOT NULL,
    template_revision INTEGER NOT NULL, content_sha256 TEXT NOT NULL, data TEXT NOT NULL, meta TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE placements(instance_id TEXT NOT NULL, generation INTEGER NOT NULL, host_id TEXT NOT NULL, state TEXT NOT NULL,
    data TEXT NOT NULL, meta TEXT NOT NULL, revision INTEGER NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(instance_id, generation));
CREATE TABLE claims(host_id TEXT NOT NULL, family INTEGER NOT NULL, address TEXT NOT NULL, protocol TEXT NOT NULL,
    port INTEGER NOT NULL, owner_kind TEXT NOT NULL CHECK(owner_kind IN ('plan','placement')), owner_id TEXT NOT NULL,
    endpoint TEXT NOT NULL, generation INTEGER NOT NULL, expires_at TEXT,
    PRIMARY KEY(host_id, address, protocol, port, owner_kind, owner_id));
CREATE TABLE inspections(operation_id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE registrations(id TEXT NOT NULL, revision INTEGER NOT NULL, data TEXT NOT NULL, meta TEXT NOT NULL,
    registered_at TEXT NOT NULL, PRIMARY KEY(id, revision));
CREATE TABLE instance_revisions(id TEXT NOT NULL, revision INTEGER NOT NULL, content_sha256 TEXT NOT NULL, data TEXT NOT NULL,
    created_at TEXT NOT NULL, PRIMARY KEY(id, revision));
CREATE TABLE verifications(instance_id TEXT NOT NULL, generation INTEGER NOT NULL, operation_id TEXT NOT NULL,
    data TEXT NOT NULL, verified_at TEXT NOT NULL, PRIMARY KEY(instance_id, generation));
CREATE TABLE tokens(application TEXT NOT NULL, component TEXT NOT NULL, host_id TEXT NOT NULL, generation INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('valid','revoked','unknown')), data TEXT NOT NULL, revision INTEGER NOT NULL,
    updated_at TEXT NOT NULL, verification TEXT, PRIMARY KEY(application, component, host_id));
"""


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def device(identity):
    return {"id": identity, "name": identity.title(), "platform": "linux", "architecture": "x86_64",
            "capabilities": ["linux"], "access": "declared-only", "observed_at": None, "provenance": "Test",
            "notes": "Test host"}


def definition(identity, host, backend, selector, *, kind="service"):
    return {"id": identity, "name": identity.title(), "purpose": "Test workload", "device_id": host, "backend": backend,
            "management": "defined", "kind": kind,
            "bindings": [{"backend": backend, "scope": "user:1000", "selector": selector, "role": "primary"}],
            "requirements": ["linux"], "architectures": ["x86_64"], "recipe": None, "notes": "Observed only",
            "health_check": None, "data_locations": ["/srv/" + identity], "dependencies": [],
            "supported_operations": ["observe", "plan-migration"]}


def table_dump(path, tables):
    db = sqlite3.connect(path)
    try:
        return {table: db.execute(f"SELECT * FROM {table} ORDER BY 1, 2").fetchall() for table in tables}
    finally:
        db.close()


class WorkloadStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.catalog_path = self.root / "catalog.json"
        self.catalog = {
            "schema_version": 1, "provenance": "Test catalog",
            "devices": [device("host-c"), device("host-a"), device("host-b")],
            "workloads": [definition("test-hub", "host-c", "systemd", {"native_id": "test-hub.service"}),
                          definition("usenet", "host-b", "podman", {"name": "sabnzbd"})],
            "application_groups": [{"id": "pop-tools", "name": "Tools", "host_id": "host-b", "backend": "systemd",
                                    "scope": "user:1000", "native_ids": ["tool.service"], "provenance": "Test"}],
            "definition_provenance": {"test-hub": {"method": "cached-discovery", "updated_at": "2026-11-22T00:00:00+00:00"}},
        }
        self.write_catalog()
        self.state = self.root / "state"

    def write_catalog(self):
        self.catalog_path.write_text(json.dumps(self.catalog))

    def service(self, state=None):
        return Service(self.catalog_path, state_dir=state or self.state)

    def store_path(self, state=None):
        return (state or self.state) / "operations" / namespace(self.catalog_path) / "deploy.sqlite3"

    def legacy_state(self):
        """A state directory as the deploy journal left it before the workload store existed."""
        path = self.store_path()
        path.parent.mkdir(parents=True, mode=0o700)
        self.state.chmod(0o700)
        example = json.loads((ROOT / "docs/spec/examples/02-static-web.json").read_text())
        template = example["applications"][0]
        instance = {**deepcopy(example["applications"][1]), "id": "garden"}
        placement = {**deepcopy(example["placements"][0]), "id": "garden-1", "application_id": "garden"}
        second = {**deepcopy(instance), "revision": 2, "purpose": "Second revision"}
        placement["revision"] = 2
        residents = json.loads((ROOT / "tests/fixtures/residents.json").read_text())
        db = sqlite3.connect(path)
        with db:
            db.executescript(LEGACY_SCHEMA)
            db.execute("INSERT INTO templates VALUES(?,?,?,?,?)", (template["id"], 1, spec.Application.model_validate(template).content_sha256(),
                                                                     encode(template), "2026-11-20T00:00:00+00:00"))
            # Revision 2 is current; revision 1 only in the revision table; the current row predates that table.
            db.execute("INSERT INTO instances VALUES(?,?,?,?,?,?,?,?)", ("garden", 2, template["id"], 1, "2" * 64, encode(second),
                       encode({"content_sha256": "2" * 64, "history": []}), "2026-11-21T00:00:00+00:00"))
            db.execute("INSERT INTO instance_revisions VALUES(?,?,?,?,?)", ("garden", 1, "1" * 64, encode(instance), "2026-11-20T00:00:00+00:00"))
            db.execute("INSERT INTO placements VALUES(?,?,?,?,?,?,?,?)", ("garden", 1, "host-a", "staged", encode(placement), encode({
                "native": {"names": {"service": "garden.service", "containers": ["garden-web"]}, "claims": [
                    {"protocol": "tcp", "address": "127.0.0.1", "port": 18081, "endpoint": "web"}]},
                "uid": 1000, "token": {"state": "revoked"}, "uncertain": False, "ownership_id": "owned-1"}), 4,
                "2026-11-21T00:00:00+00:00"))
            db.execute("INSERT INTO claims VALUES(?,?,?,?,?,?,?,?,?,NULL)", ("host-a", 4, "127.0.0.1", "tcp", 18081, "placement", "garden", "web", 1))
            db.execute("INSERT INTO verifications VALUES(?,?,?,?,?)", ("garden", 1, "op-1", encode({"verified_at": "2026-11-21T01:00:00+00:00",
                       "consistent": True, "findings": []}), "2026-11-21T01:00:00+00:00"))
            for revision in (1, 2):
                document = deepcopy(residents)
                document["applications"][0]["purpose"] += f" (registration {revision})"
                meta = {"submitted_by": "residents agent", "source": "residents.json", "source_sha256": "c" * 64,
                        "document_sha256": hashlib.sha256(encode(document).encode()).hexdigest(), "upgraded_from": None,
                        "applications": [], "warnings": [], "authority": "none: metadata only"}
                db.execute("INSERT INTO registrations VALUES(?,?,?,?,?)", ("test-agent-cluster", revision, encode(document),
                           encode(meta), f"2026-11-2{revision}T00:00:00+00:00"))
            db.execute("INSERT INTO tokens VALUES(?,?,?,?,?,?,?,?,NULL)", ("test-agent-cluster", "hub", "host-c", 2, "valid",
                       encode({"token_path": "/run/hub.token"}), 3, "2026-11-22T00:00:00+00:00"))
        db.close()
        path.chmod(0o600)
        return path

    def test_seeding_a_pre_store_state_directory_loses_nothing_and_can_be_undone(self):
        path = self.legacy_state()
        legacy = ("instances", "instance_revisions", "registrations")
        journal = ("templates", "placements", "claims", "verifications", "tokens")
        before = table_dump(path, legacy + journal)
        before_bytes = path.read_bytes()
        plan = seed_dry_run(self.catalog_path, state_dir=self.state)
        self.assertEqual(path.read_bytes(), before_bytes)  # the dry run changes nothing
        self.assertFalse(plan["seeded"])
        self.assertEqual([item["id"] for item in plan["would_create"]["observed"]], ["test-hub", "usenet"])
        self.assertEqual([(item["id"], item["revisions"]) for item in plan["would_create"]["deployed"]], [("garden", [1, 2])])
        self.assertEqual([(item["id"], item["revisions"]) for item in plan["would_create"]["registered"]], [("test-agent-cluster", [1, 2])])

        service = self.service()
        self.assertEqual(table_dump(path, legacy + journal), before)  # old tables and journal untouched
        with service._store.transaction() as db:
            records = {record["id"]: record for record in service._store.records(db)}
            seed = service._store.meta(db, "seed")
            raw = {row[0]: row[1] for row in db.execute("SELECT id || '@' || revision, data FROM workload_revisions")}
        self.assertEqual({key: value["relation"] for key, value in records.items()},
                         {"test-hub": "observed", "usenet": "observed", "garden": "deployed", "test-agent-cluster": "registered"})
        self.assertEqual(raw["garden@1"], before["instance_revisions"][0][3])  # stored bytes verbatim
        self.assertEqual(raw["garden@2"], before["instances"][0][5])
        self.assertEqual([raw["test-agent-cluster@1"], raw["test-agent-cluster@2"]], [row[2] for row in before["registrations"]])
        self.assertEqual(records["garden"]["revision"], 2)
        self.assertEqual(records["test-agent-cluster"]["meta"]["submitted_by"], "residents agent")
        self.assertEqual(records["test-hub"]["meta"]["definition_provenance"]["method"], "cached-discovery")
        # The deploy journal and tokens keep working on the carried-over records.
        manager = service.deployments()
        self.assertEqual(manager.instance_revision("garden@1")["stored_application"]["revision"], 1)
        self.assertEqual(manager.list()[0]["claims"], ["tcp/127.0.0.1:18081"])
        self.assertEqual(manager.registered_application("test-agent-cluster@1")["meta"]["source"], "residents.json")
        self.assertEqual(service.store_status()["registered_components"][0]["application_id"], "test-agent-cluster")
        self.assertEqual(service.store_status()["groups"], ["pop-tools"])

        # Idempotent: a second start (even with a changed catalog) never seeds again.
        self.catalog["workloads"].append(definition("late", "host-b", "systemd", {"native_id": "late.service"}))
        self.write_catalog()
        again = self.service()
        self.assertEqual(again.store_status()["seed"]["seeded_at"], seed["seeded_at"])
        self.assertNotIn("late", [item["id"] for item in again.fleet()["workloads"]])
        self.assertIn({"id": "late", "difference": "only in the catalog file (ignored)"},
                      again.store_status()["catalog"]["workload_differences"])

        # Undo: the backup is the file as it was before the store added its tables; the old tables hold the same.
        backup = Path(seed["backup"])
        self.assertEqual(table_dump(backup, legacy + journal), before)
        names = sqlite3.connect(backup)
        self.addCleanup(names.close)
        self.assertNotIn("workloads", {row[0] for row in names.execute("SELECT name FROM sqlite_master WHERE type='table'")})

    def test_conflicting_ids_refuse_the_seed_and_write_nothing(self):
        self.legacy_state()
        self.catalog["workloads"].append(definition("garden", "host-b", "systemd", {"native_id": "garden.service"}))
        self.write_catalog()
        with self.assertRaisesRegex(ValueError, "seed refused.*garden"):
            self.service()
        self.assertTrue(seed_dry_run(self.catalog_path, state_dir=self.state)["would_create"]["conflicts"])
        with WorkloadStore(self.store_path().parent).transaction() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM workloads").fetchone()[0], 0)
            self.assertIsNone(db.execute("SELECT value FROM store_meta WHERE key='seed'").fetchone())

    def test_a_copy_that_does_not_verify_aborts_the_seed(self):
        self.legacy_state()
        with patch.object(WorkloadStore, "verify_legacy_copy", return_value=["deployed garden@1: revision missing"]):
            with self.assertRaisesRegex(ValueError, "seed aborted.*garden@1"):
                self.service()
        self.assertFalse(WorkloadStore(self.store_path().parent).seeded())

    def test_fleet_reads_workloads_only_from_the_store(self):
        service = self.service()
        self.assertEqual(sorted(item["id"] for item in service.fleet()["workloads"]), ["test-hub", "usenet"])
        # Catalog workloads after seeding never reach any view.
        self.catalog["workloads"] = [definition("other", "host-b", "systemd", {"native_id": "other.service"})]
        self.write_catalog()
        fresh = self.service()
        self.assertEqual(sorted(item["id"] for item in fresh.fleet()["workloads"]), ["test-hub", "usenet"])
        self.assertEqual(sorted(item["id"] for item in fresh.inventory()["workloads"]), ["test-hub", "usenet"])
        # A record written to the store reaches every view, with its relation as `management`.
        residents = json.loads((ROOT / "tests/fixtures/residents.json").read_text())
        fresh.deployments().register_application(residents, expected_revision=0)
        fleet = fresh.fleet()
        self.assertEqual({item["id"]: item["management"] for item in fleet["workloads"]},
                         {"test-hub": "observed", "usenet": "observed", "test-agent-cluster": "registered"})
        self.assertEqual(fleet["store"]["relations"], {"observed": 2, "registered": 1, "deployed": 0})
        self.assertIn("test-agent-cluster", [item["id"] for item in fresh.inventory()["workloads"]])

    def test_registration_changes_the_revision_an_open_editor_draft_holds(self):
        service = self.service()
        draft = service.definition_inventory()
        residents = json.loads((ROOT / "tests/fixtures/residents.json").read_text())
        service.deployments().register_application(residents, expected_revision=0)
        edited = deepcopy(draft["workloads"][0])
        edited["name"] = "Edited"
        with self.assertRaisesRegex(ValueError, "revision changed"):
            service.update_workload_definition(edited["id"], edited, expected_revision=draft["revision"])
        current = service.definition_inventory()["revision"]
        saved = service.update_workload_definition(edited["id"], edited, expected_revision=current)
        with service._store.transaction() as db:
            self.assertEqual(service._store.record(db, edited["id"])["revision"], 2)
        self.assertNotEqual(saved["revision"], current)
        # IDs are unique across relations.
        clash = deepcopy(draft["workloads"][1])
        clash["id"] = "test-agent-cluster"
        with self.assertRaisesRegex(ValueError, "already belongs to a registered"):
            service.save_workload_definition(clash, expected_revision=saved["revision"])

    def test_residents_appear_once_linked_by_their_declared_bindings(self):
        service = self.service()
        residents = json.loads((ROOT / "tests/fixtures/residents.json").read_text())
        service.deployments().register_application(residents, expected_revision=0)
        workloads = {item["id"]: item for item in service.fleet()["workloads"]}
        self.assertEqual(workloads["test-hub"]["part_of"],
                         {"application_id": "test-agent-cluster", "component": "hub", "placement_id": "test-cluster-hub",
                          "host_id": "host-c"})
        self.assertNotIn("part_of", workloads["usenet"])
        application = workloads["test-agent-cluster"]
        components = {(item["host_id"], item["component"]): item for item in application["registered_components"]}
        self.assertEqual(components[("host-c", "hub")]["linked_workloads"], ["test-hub"])
        # The station's test-hub.service is on another host: not the observed Host C workload.
        self.assertEqual(components[("host-a", "station")]["linked_workloads"], [])
        self.assertEqual(application["authority"]["execute"], False)
        hub = next(item for item in application["bindings_evidence"] if item["component"] == "hub")
        self.assertEqual(hub["binding"], {"backend": "systemd", "scope": "user:1000",
                                          "selector": {"native_id": "test-hub.service"}, "role": "primary"})

    def test_export_is_deterministic_and_imports_into_an_empty_or_matching_store(self):
        self.legacy_state()
        service = self.service()
        document = service.export_store()
        self.assertEqual(export_bytes(document), export_bytes(service.export_store()))
        self.assertEqual({item["relation"] for item in document["workloads"]}, {"observed", "registered", "deployed"})
        self.assertNotIn("verified_revision", document["hosts"][0])
        # Matching store: everything unchanged, nothing to apply.
        plan = service.import_store(document, source_sha256="x")
        self.assertEqual(plan["blockers"], [])
        self.assertEqual({action["action"] for action in plan["actions"]}, {"unchanged"})
        # Empty store: the catalog seeds no workloads or groups there.
        self.catalog["workloads"], self.catalog["application_groups"] = [], []
        self.write_catalog()
        empty = Service(self.catalog_path, state_dir=self.root / "empty-state")
        blocked = empty.import_store(document, source_sha256="x")
        self.assertEqual(blocked["blockers"], ["Deployed instance garden is absent: deployed records belong to the deploy "
                                               "journal (placements, generations, ownership) and cannot be created by import"])
        portable = {**document, "workloads": [item for item in document["workloads"] if item["relation"] != "deployed"]}
        plan = empty.import_store(portable, source_sha256="x")
        self.assertEqual(plan["blockers"], [])
        with self.assertRaisesRegex(ValueError, "revision changed"):
            empty.import_store(portable, source_sha256="x", expected_revision="stale")
        applied = empty.import_store(portable, source_sha256="x", expected_revision=plan["revision"])
        self.assertTrue(applied["applied"])
        result = empty.export_store()
        strip = lambda items: [{k: v for k, v in item.items() if k != "provenance"} for item in items]
        self.assertEqual(strip(result["workloads"]), strip(portable["workloads"]))
        self.assertEqual((result["templates"], result["groups"]), (document["templates"], document["groups"]))
        self.assertEqual(empty.definition_inventory()["workloads"], service.definition_inventory()["workloads"])
        # Never overwritten: a differing record is a blocker.
        changed = deepcopy(portable)
        changed["workloads"][0]["document"]["applications"][0]["purpose"] = "Changed"
        self.assertTrue(any("differs" in blocker for blocker in empty.import_store(changed, source_sha256="x")["blockers"]))


if __name__ == "__main__":
    unittest.main()
