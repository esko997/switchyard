"""Schema-2 operations policy (authority only), managed placements in the workload store, and the one-time migration.

Fixture hosts and state only; nothing contacts a device."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from switchyard.broker import Broker
from switchyard.operation_store import encode
from switchyard.operations_policy import migrate
from switchyard.workload_store import WorkloadStore
from operations_fixture import definition, describe, put_definition

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "docker.io/nginxinc/nginx-unprivileged:1.28.0-alpine"


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.site = self.root / "index.html"
        self.site.write_text("<h1>fixture</h1>")
        self.hosts = {}
        for name in ("alpha", "beta"):
            ledger = self.root / (name + ".ledger")
            ledger.write_text("fixture baseline\n")
            self.hosts[name] = {"host_id": name, "transport": "ssh", "target": pwd.getpwuid(os.getuid()).pw_name + "@fixture.invalid",
                                "expected_hostname": platform.node(), "ledger": str(ledger), "user_units": [], "system_units": []}
        # The descriptions an old (schema 1) policy carried inline, one per supported kind.
        self.descriptions = {
            "foobar": {"name": "Foobar", "allowed_hosts": ["alpha", "beta"], "initial_host": "alpha",
                       "container_name": "switchyard-foobar", "image": IMAGE, "site_file": str(self.site), "port": 18080},
            "unit": {"backend": "systemd", "name": "Unit", "host_id": "alpha", "scope": "user", "unit": "unit.service"},
            "quad": {"backend": "quadlet", "name": "Quadlet", "host_id": "alpha", "scope": "system", "unit": "quad.service"},
            "project": {"backend": "compose", "name": "Project", "host_id": "beta", "provider": "podman-compose",
                        "project_name": "project", "project_directory": "/srv/project",
                        "files": ["/srv/project/compose.yaml"], "services": ["web", "db"]},
        }
        self.policy_path = self.root / "operations.json"

    def write(self, workloads, **extra):
        self.policy_path.write_text(json.dumps({"schema_version": 2, "shell_hosts": [], "workloads": workloads, **extra}))
        return self.policy_path

    def broker(self, path=None):
        return Broker(path or self.policy_path, hosts=self.hosts, state_dir=self.state)

    def full_grants(self):
        return {"foobar": {"actions": ["deploy", "start", "stop", "migrate", "recover"], "hosts": ["alpha", "beta"]},
                "unit": {"actions": ["start", "stop", "restart"], "hosts": ["alpha"]},
                "quad": {"actions": ["start", "stop", "restart"], "hosts": ["alpha"]},
                "project": {"actions": ["start", "stop", "restart"], "hosts": ["beta"]}}


class PolicyFormatTests(Fixture):
    def test_descriptions_come_only_from_store_records(self):
        for key, value in self.descriptions.items():
            describe(self.state, key, value)
        broker = self.broker(self.write(self.full_grants()))
        config = broker._configuration()
        self.assertEqual(config["workloads"], self.descriptions)
        entries = {entry["id"]: entry for entry in broker.policy()["workloads"]}
        self.assertEqual(entries["foobar"], {"id": "foobar", "name": "Foobar", "allowed_hosts": ["alpha", "beta"],
                                             "actions": ["deploy", "start", "stop", "migrate", "recover"],
                                             "backend": "podman", "container_name": "switchyard-foobar"})
        self.assertEqual(entries["quad"], {"id": "quad", **self.descriptions["quad"], "allowed_hosts": ["alpha"],
                                           "actions": ["start", "stop", "restart"], "inspection_required": True})
        # Editing the record is what changes the description; the policy file stays the same.
        describe(self.state, "unit", {**self.descriptions["unit"], "unit": "renamed.service"})
        self.assertEqual(broker._configuration()["workloads"]["unit"]["unit"], "renamed.service")

    def test_old_format_is_refused_with_the_converting_command(self):
        self.policy_path.write_text(json.dumps({"schema_version": 1, "shell_hosts": [], "workloads": {"unit": self.descriptions["unit"]}}))
        with self.assertRaisesRegex(ValueError, r"old format.*migrate-operations .*operations\.json --output"):
            self.broker()

    def test_grants_the_store_cannot_support_are_refused_at_load(self):
        for key in ("foobar", "unit", "project"):
            describe(self.state, key, self.descriptions[key])
        container = definition("container", self.descriptions["unit"])
        container.update(backend="podman", bindings=[{"backend": "podman", "scope": "user:1000",
                                                      "selector": {"name": "personal"}, "role": "primary"}])
        put_definition(self.state, container)
        timer = definition("timer", {**self.descriptions["unit"], "unit": "timer.service"})
        timer.update(kind="scheduled-job")
        put_definition(self.state, timer)
        other_web = definition("other-web", self.descriptions["foobar"])
        other_web["bindings"][0]["selector"] = {"name": "other-web"}
        put_definition(self.state, other_web)
        scoped = ["start", "stop", "restart"]
        cases = [
            ("missing", {"absent": {"actions": scoped, "hosts": ["alpha"]}}, "absent, which is not in the workload store"),
            ("descriptive field", {"unit": {"actions": scoped, "hosts": ["alpha"], "unit": "unit.service"}}, "exactly `actions` and `hosts`"),
            ("no supported backend", {"container": {"actions": scoped, "hosts": ["alpha"]}}, "no primary binding of a supported backend"),
            ("scheduled job", {"timer": {"actions": scoped, "hosts": ["alpha"]}}, "lifecycle actions need a service"),
            ("unsupported action", {"unit": {"actions": ["start", "migrate"], "hosts": ["alpha"]}}, "migrate, which its systemd backend"),
            ("other host", {"unit": {"actions": scoped, "hosts": ["beta"]}}, r"hosts must be \[\"alpha\"\]"),
            ("two hosts", {"project": {"actions": scoped, "hosts": ["alpha", "beta"]}}, "acts only where its store record places it"),
            ("initial host not granted", {"foobar": {"actions": ["start"], "hosts": ["beta"]}}, "does not include alpha"),
            ("recipe on another workload", {"other-web": {"actions": ["start"], "hosts": ["alpha"]}}, "only for the disposable foobar"),
            ("duplicate action", {"unit": {"actions": ["start", "start"], "hosts": ["alpha"]}}, "distinct names"),
        ]
        for label, workloads, message in cases:
            with self.subTest(case=label), self.assertRaisesRegex(ValueError, message):
                self.broker(self.write(workloads))

    def test_registered_and_deployed_records_are_not_lifecycle_grants(self):
        store = WorkloadStore(self.state)
        with store.transaction() as db:
            store.put_record(db, workload_id="registered-app", relation="registered", expected_revision=0, revision=1,
                             content_sha256="0" * 64, data={}, meta={})
        with self.assertRaisesRegex(ValueError, "a registered workload; lifecycle grants cover observed workloads only"):
            self.broker(self.write({"registered-app": {"actions": ["start"], "hosts": ["alpha"]}}))

    def test_narrow_grants_refuse_other_actions_at_plan_and_execute(self):
        describe(self.state, "foobar", self.descriptions["foobar"])
        broker = self.broker(self.write({"foobar": {"actions": ["recover", "deploy"], "hosts": ["alpha"]}}))
        self.assertEqual(broker.policy()["workloads"][0]["actions"], ["deploy", "recover"])
        plan = broker.plan("deploy", "foobar")
        with self.assertRaisesRegex(ValueError, "does not grant start on foobar"):
            broker.plan("start", "foobar")
        self.write({"foobar": {"actions": ["recover"], "hosts": ["alpha"]}})
        with self.assertRaisesRegex(ValueError, "does not grant deploy on foobar"):
            broker.execute(plan["id"], approved=True, request_id="revoked")
        self.assertEqual(broker.receipts(), [])


class PlacementTests(Fixture):
    """Foobar's placement lives in the workload store; its receipt in the journal. They never disagree."""
    PLACEMENT = {"workload_id": "foobar", "host_id": "beta", "native_id": "b" * 64, "lifecycle": "running", "uncertain": False}

    def setUp(self):
        super().setUp()
        describe(self.state, "foobar", self.descriptions["foobar"])
        self.write({"foobar": {"actions": ["deploy", "start", "stop", "migrate", "recover"], "hosts": ["alpha", "beta"]}})

    def stored(self):
        with closing(sqlite3.connect(self.state / "deploy.sqlite3")) as db:
            row = db.execute("SELECT ownership_id, placement, sequence FROM managed_placements WHERE workload_id='foobar'").fetchone()
        return row and (row[0], json.loads(row[1]) if row[1] else None, row[2])

    def intents(self):
        with closing(sqlite3.connect(self.state / "operations.sqlite3")) as db:
            return db.execute("SELECT count(*) FROM placement_intents").fetchone()[0]

    def test_receipt_and_placement_are_written_together_and_applied_to_the_store(self):
        broker = self.broker()
        plan = broker.plan("deploy", "foobar")
        owner = self.stored()[0]
        self.assertEqual(self.stored(), (owner, None, 0))
        with broker.store.transaction() as db:
            receipt = broker._begin(db, request_id="deploy-1", intent={"plan_id": plan["id"], "action": "deploy", "target_id": "beta"},
                                    kind="managed", host_ids=["beta"], workload_id="foobar")["receipt"]
        broker.store.event(receipt["id"], "deployment-intent", {"workload_id": "foobar", "host_id": "beta"})
        self.assertEqual(self.stored()[1], {"workload_id": "foobar", "host_id": "beta", "lifecycle": "unknown", "uncertain": True})
        with broker.store.transaction() as db:
            broker.store.finish(db, receipt["id"], {"status": "succeeded", "placement": {**self.PLACEMENT, "ownership_id": owner}})
        self.assertEqual(self.stored(), (owner, {**self.PLACEMENT, "ownership_id": owner}, 2))
        self.assertEqual(self.intents(), 0)
        self.assertEqual(broker.placements(), {"foobar": {**self.PLACEMENT, "ownership_id": owner}})
        with self.assertRaisesRegex(ValueError, "already has recorded placement"):
            broker.plan("deploy", "foobar")

    def test_crash_between_the_receipt_and_the_store_never_shows_a_disagreeing_placement(self):
        broker = self.broker()
        broker.plan("deploy", "foobar")
        with broker.store.transaction() as db:
            receipt = broker._begin(db, request_id="crash", intent={"action": "deploy"}, kind="managed",
                                    host_ids=["beta"], workload_id="foobar")["receipt"]
        # A separate process finishes the receipt and dies after the journal commit, before the store write.
        program = ("import os, sys; from pathlib import Path; from switchyard.operation_store import Store; "
                   "from switchyard.workload_store import WorkloadStore; "
                   "WorkloadStore.apply_placement_intents = lambda self, intents: os._exit(9); "
                   "store = Store(Path(sys.argv[1])); import json\n"
                   "with store.transaction() as db: store.finish(db, sys.argv[2], {'status': 'succeeded', 'placement': json.loads(sys.argv[3])})")
        child = subprocess.run([sys.executable, "-c", program, str(self.state), receipt["id"], json.dumps(self.PLACEMENT)],
                               cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(child.returncode, 9, child.stderr)
        # The crash window: the receipt says succeeded and the intent is durable; the store row is still empty.
        with closing(sqlite3.connect(self.state / "operations.sqlite3")) as db:
            status = json.loads(db.execute("SELECT receipt FROM operations WHERE id=?", (receipt["id"],)).fetchone()[0])["status"]
        self.assertEqual(status, "succeeded")
        self.assertEqual(self.intents(), 1)
        self.assertIsNone(self.stored()[1])
        # Any reader inside a journal transaction already sees the receipt's placement ...
        with broker.store._transaction() as db:
            self.assertEqual(broker.store.placement(db, "foobar")["placement"], self.PLACEMENT)
        # ... and the next process that opens the journal applies it, once.
        reopened = Broker(None, hosts={}, state_dir=self.state)
        self.assertEqual(self.stored()[1], self.PLACEMENT)
        self.assertEqual(self.intents(), 0)
        self.assertEqual(reopened.placements(), {"foobar": self.PLACEMENT})
        reopened.store.drain()
        self.assertEqual(self.stored()[2], 1)

    def test_an_older_intent_never_overwrites_a_newer_placement(self):
        broker = self.broker()
        broker.plan("deploy", "foobar")
        owner = self.stored()[0]
        broker.store.workloads.apply_placement_intents([(5, "foobar", owner, encode(self.PLACEMENT))])
        broker.store.workloads.apply_placement_intents([(4, "foobar", owner, encode({**self.PLACEMENT, "host_id": "alpha"}))])
        broker.store.workloads.apply_placement_intents([(5, "foobar", owner, encode({**self.PLACEMENT, "host_id": "alpha"}))])
        self.assertEqual(self.stored(), (owner, self.PLACEMENT, 5))


class MigrationTests(Fixture):
    LEGACY = {"workload_id": "foobar", "host_id": "beta", "native_id": "c" * 64, "lifecycle": "stopped",
              "ownership_id": "11111111-1111-4111-8111-111111111111", "uncertain": False}

    def setUp(self):
        super().setUp()
        # A state directory as the previous release left it: observed records without runtimes, the journal's
        # own placement table, and a schema-1 policy holding every description.
        for key, value in self.descriptions.items():
            plain = definition(key, value)
            plain["runtime"] = None
            put_definition(self.state, plain)
        with closing(sqlite3.connect(self.state / "operations.sqlite3")) as db, db:
            db.execute("CREATE TABLE workloads(id TEXT PRIMARY KEY, ownership_id TEXT NOT NULL, placement TEXT)")
            db.execute("INSERT INTO workloads VALUES('foobar', ?, ?)", (self.LEGACY["ownership_id"], encode(self.LEGACY)))
        self.old = {"schema_version": 1, "shell_hosts": ["alpha"], "deploy_hosts": ["beta"], "workloads": self.descriptions}
        self.old_path = self.root / "operations.v1.json"
        self.old_path.write_text(json.dumps(self.old))
        self.new_path = self.root / "operations.v2.json"

    def digests(self):
        return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(self.root.rglob("*")) if path.is_file()}

    def revisions(self):
        with closing(sqlite3.connect(self.state / "deploy.sqlite3")) as db:
            return dict(db.execute("SELECT id, revision FROM workloads"))

    def test_unmigrated_journal_refuses_placement_reads_naming_the_command(self):
        with self.assertRaisesRegex(ValueError, "still in the operation journal.*migrate-operations"):
            Broker(None, hosts={}, state_dir=self.state).placements()

    def test_dry_run_writes_nothing_and_reports_the_file_and_what_moves(self):
        before = self.digests()
        plan = migrate(self.old_path, self.new_path, self.state)
        self.assertEqual(self.digests(), before)
        self.assertFalse(plan["applied"])
        self.assertEqual(plan["policy"], {"schema_version": 2, "shell_hosts": ["alpha"], "deploy_hosts": ["beta"],
                                          "workloads": self.full_grants()})
        self.assertEqual({row["id"]: row["adds"]["runtime"]["kind"] for row in plan["store"]["records"]},
                         {"foobar": "static-web", "quad": "quadlet", "project": "compose"})
        self.assertEqual(plan["store"]["unchanged_records"], ["unit"])
        self.assertEqual(plan["store"]["placements"], [{"workload_id": "foobar", "ownership_id": self.LEGACY["ownership_id"],
                                                        "placement": self.LEGACY, "state": "moves into the store"}])

    def test_apply_moves_everything_once_and_the_result_matches_the_old_policy(self):
        old_records = self.revisions()
        result = migrate(self.old_path, self.new_path, self.state, apply=True)
        self.assertTrue(result["applied"])
        self.assertEqual(json.loads(self.new_path.read_text()), result["policy"])
        self.assertEqual(self.revisions(), {**old_records, "foobar": 2, "quad": 2, "project": 2})
        broker = self.broker(self.new_path)
        # Every description resolves to exactly what the old file said: same authority fingerprints, same plans.
        self.assertEqual(broker._configuration()["workloads"], self.descriptions)
        self.assertEqual(broker.placements(), {"foobar": self.LEGACY})
        with broker.store._transaction() as db:
            self.assertEqual(broker.store.ownership(db, "foobar")["ownership_id"], self.LEGACY["ownership_id"])
        for backup in result["backups"]:
            self.assertTrue(Path(backup).exists())
        # Idempotent: a second run changes nothing and takes no new backups.
        before = self.digests()
        again = migrate(self.old_path, self.new_path, self.state, apply=True)
        self.assertEqual(self.digests(), before)
        self.assertNotIn("backups", again)
        self.assertEqual(again["store"]["placements"][0]["state"], "already in the store")
        self.assertEqual(again["policy_file"], "identical, already written")

    def test_undo_restores_the_backups_byte_for_byte_state(self):
        with closing(sqlite3.connect(self.state / "deploy.sqlite3")) as db:
            records = list(db.execute("SELECT id, revision, data FROM workloads ORDER BY id"))
        result = migrate(self.old_path, self.new_path, self.state, apply=True)
        store_backup, journal_backup = (Path(item) for item in result["backups"])
        (self.state / "deploy.sqlite3").write_bytes(store_backup.read_bytes())
        (self.state / "operations.sqlite3").write_bytes(journal_backup.read_bytes())
        with closing(sqlite3.connect(self.state / "deploy.sqlite3")) as db:
            self.assertEqual(list(db.execute("SELECT id, revision, data FROM workloads ORDER BY id")), records)
            self.assertEqual(db.execute("SELECT count(*) FROM managed_placements").fetchone()[0], 0)
        # Back to the unmigrated state: the guard names the command again, and the migration can be rerun.
        with self.assertRaisesRegex(ValueError, "still in the operation journal"):
            Broker(None, hosts={}, state_dir=self.state).placements()

    def test_disagreement_and_a_different_target_are_refused_before_writing(self):
        before = self.digests()
        changed = {**self.old, "workloads": {**self.descriptions, "unit": {**self.descriptions["unit"], "name": "Renamed"}}}
        self.old_path.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, r"unit: the old policy and the workload store disagree on name \(policy 'Renamed', store 'Unit'\)"):
            migrate(self.old_path, self.new_path, self.state, apply=True)
        self.old_path.write_text(json.dumps(self.old))
        self.new_path.write_text("{}")
        with self.assertRaisesRegex(ValueError, "already exists and differs"):
            migrate(self.old_path, self.new_path, self.state, apply=True)
        self.assertEqual({key: value for key, value in self.digests().items() if key != self.new_path.name},
                         {key: value for key, value in before.items()})

    def test_old_code_acting_after_migration_is_detected(self):
        migrate(self.old_path, self.new_path, self.state, apply=True)
        with closing(sqlite3.connect(self.state / "operations.sqlite3")) as db, db:
            db.execute("UPDATE workloads SET placement=? WHERE id='foobar'", (encode({**self.LEGACY, "host_id": "alpha"}),))
        with self.assertRaisesRegex(ValueError, "changed after it was moved"):
            Broker(None, hosts={}, state_dir=self.state).placements()

    def test_cli_dry_run_and_apply(self):
        catalog = self.root / "catalog.json"
        catalog.write_text((ROOT / "catalogs" / "example.json").read_text())
        from switchyard.core import namespace
        directory = self.root / "cli-state" / "operations" / namespace(catalog)
        directory.parent.mkdir(parents=True)
        self.state.rename(directory)
        command = [sys.executable, "-c", "from switchyard.cli import main; main()", "--catalog", str(catalog),
                   "--state-dir", str(self.root / "cli-state"), "--operations", str(self.old_path),
                   "migrate-operations", str(self.old_path), "--output", str(self.new_path)]
        preview = subprocess.run([*command, "--dry-run"], cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertFalse(json.loads(preview.stdout)["applied"])
        self.assertFalse(self.new_path.exists())
        applied = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(json.loads(self.new_path.read_text())["schema_version"], 2)


class ExampleTests(unittest.TestCase):
    """The tracked examples are fictional, load together and are what a new fleet copies."""

    def test_examples_load_together(self):
        from switchyard import ansible_ops
        from switchyard.core import Service
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog = root / "home-lab.json"
            catalog.write_text((ROOT / "catalogs/example.json").read_text())
            collectors = json.loads((ROOT / "catalogs/collectors.example.json").read_text())
            for host in collectors["hosts"]:  # ledgers must exist; the example's paths are placeholders to edit
                ledger = root / Path(host["ledger"]).name
                ledger.write_text("example ledger\n")
                host["ledger"] = str(ledger)
            (root / "home-lab.collectors.json").write_text(json.dumps(collectors))
            (root / "home-lab.operations.json").write_text((ROOT / "catalogs/operations.example.json").read_text())
            service = Service(catalog, state_dir=root / "state", collectors_path=root / "home-lab.collectors.json",
                              operations_path=root / "home-lab.operations.json")
            policy = service.operation_policy()
            self.assertEqual([(entry["id"], entry["backend"], entry["unit"]) for entry in policy["workloads"]],
                             [("notes-sync", "systemd", "notes-sync.service")])
            self.assertEqual(policy["shell_hosts"], ["source"])
            ansible_ops.load_config(ROOT / "catalogs/ansible.example.json")

    def test_examples_use_documentation_or_public_addresses_only(self):
        import ipaddress
        import re
        documentation = ipaddress.ip_network("192.0.2.0/24")
        for path in sorted((ROOT / "catalogs").rglob("*.json")):
            if path.name.startswith("home-lab"):
                continue  # your own, untracked configuration
            for literal in re.findall(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", path.read_text()):
                address = ipaddress.ip_address(literal)
                with self.subTest(path=path.name, address=literal):
                    # No private network of a real fleet; public resolvers (the DNS template's default) are fine.
                    self.assertTrue(address in documentation or address.is_loopback or address.is_unspecified or address.is_global)


if __name__ == "__main__":
    unittest.main()
