"""Start tokens for registered (adopted) applications, against a fixture host only.

The real fixed remote program (`tokens_remote.main`) runs in-process against a temporary
$HOME while the worker holds a durable SQLite lease. No real host is touched.
"""
import argparse
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import platform
import pwd
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from switchyard import operation_worker, tokens, tokens_remote
from switchyard.broker import Broker
from switchyard.deploy import DeployManager
from switchyard.leases import LedgerBroker, mark_uncertain
from switchyard.lease_db import resource_label
from switchyard.operation_store import encode
from switchyard.remote import RemoteError

APP = "tiny"


def bundle():
    def placement(host, component, unit):
        return {"apiVersion": "switchyard/v1alpha3", "kind": "Placement", "id": APP + "-" + host, "application_id": APP,
                "revision": 1, "host_id": host, "generation": 1, "state": "declared", "ownership": "adopted",
                "components": [{"component": component, "native_identities": [{"native_id": unit, "scope": "user:1000"}]}]}
    return {"apiVersion": "switchyard/v1alpha3", "kind": "Bundle",
            "applications": [{"apiVersion": "switchyard/v1alpha3", "kind": "Application", "id": APP, "revision": 1,
                              "name": "Tiny", "purpose": "Token fixture",
                              "components": [{"id": "web", "native": {"kind": "systemd", "unit": "tiny.service"}},
                                             {"id": "worker", "native": {"kind": "systemd", "unit": "tiny-worker.service"}}],
                              "provenance": {"submitted_by": "test", "source": "fixture"}}],
            "placements": [placement("alpha", "web", "tiny.service"), placement("beta", "worker", "tiny-worker.service")]}


def run_check(script):
    return subprocess.run(["/bin/sh", "-c", script], stdin=subprocess.DEVNULL, capture_output=True).returncode == 0


class TokenTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.hosts = {}
        for name in ("alpha", "beta"):
            ledger = self.root / ("DEVICE_ACCESS_" + name.upper() + ".md")
            self.hosts[name] = {"host_id": name, "transport": "ssh", "target": pwd.getpwuid(os.getuid()).pw_name + "@fixture.invalid",
                                "expected_hostname": platform.node(), "ledger": str(ledger), "user_units": [], "system_units": []}
        self.config = {"schema_version": 2, "shell_hosts": [], "workloads": {}, "token_hosts": ["alpha"]}
        self.config_path = self.root / "operations.json"
        self.write_config()
        self.broker = Broker(self.config_path, hosts=self.hosts, state_dir=self.root / "state")
        self.leases = LedgerBroker({name: Path(host["ledger"]) for name, host in self.hosts.items()},
                                  state_dir=self.broker.lease_state_dir)
        self.manager = tokens.TokenManager(self.broker)
        DeployManager(self.broker).register_application(bundle(), expected_revision=0)
        self.home = self.root / "home" / "user"
        self.home.mkdir(parents=True)
        (self.home / "keep.txt").write_text("unrelated user file")
        self.remote_actions = []
        patch.object(self.broker, "_dispatch", side_effect=self.dispatch).start()
        patch.object(tokens, "run_remote", side_effect=self.fake_remote).start()
        patch.object(tokens_remote, "home", lambda: str(self.home)).start()
        for signum in (operation_worker.signal.SIGTERM, operation_worker.signal.SIGINT):
            self.addCleanup(operation_worker.signal.signal, signum, operation_worker.signal.getsignal(signum))
        self.addCleanup(patch.stopall)

    def write_config(self):
        self.config_path.write_text(json.dumps(self.config))

    def fake_remote(self, host, source, payload, *, timeout, local=False):
        lease = self.leases.store.current(resource_label(host["host_id"], host["ledger"]))
        self.assertIsNotNone(lease)  # durable authority covers the whole remote step
        self.assertEqual((lease["resource"], lease["owner"], lease["status"]), (host["host_id"], "switchyard", "claimed"))
        self.assertFalse(Path(host["ledger"]).exists())
        self.assertIn("def main(payload)", source)
        self.remote_actions.append(payload["action"])
        return json.loads(json.dumps(tokens_remote.main(json.loads(json.dumps(payload)))))

    def dispatch(self, receipt, payload):
        payload = {**payload, "operation_id": receipt["id"], "state_dir": str(self.broker.store.directory),
                   "lease_state_dir": str(self.broker.lease_state_dir),
                   "hosts": {key: self.hosts[key] for key in receipt["host_ids"]}}
        payload.pop("operation_hosts", None)
        with patch.object(operation_worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(encode(payload).encode()))), \
                patch.object(operation_worker.signal, "signal"), redirect_stdout(io.StringIO()):
            operation_worker.main()
        return {"receipt": self.broker.receipt(receipt["id"])}

    # helpers -------------------------------------------------------------------
    def token_path(self, component="web"):
        return self.home / ".local/state/switchyard/tokens" / APP / (component + ".token")

    def issue(self, request_id, component="web", host="alpha"):
        return self.manager.issue(APP, component, host, approved=True, request_id=request_id)

    def revoke(self, request_id, component="web", host="alpha"):
        return self.manager.revoke(APP, component, host, approved=True, request_id=request_id)

    def line(self, generation, revoked=False, host="alpha"):
        return tokens.token_line(APP, "web", host, generation, revoked)

    def outside_tokens(self):
        root = self.home / ".local/state/switchyard/tokens"
        return {str(p): p.read_bytes() for p in self.home.rglob("*") if p.is_file() and root not in p.parents}

    def verify(self, **kwargs):
        result = self.manager.verify(APP, "web", "alpha", **kwargs)
        return result, result["hosts"][0]["verifications"][0]

    @staticmethod
    def codes(verification):
        return sorted(f["code"] for f in verification["findings"])

    # issue / revoke ------------------------------------------------------------
    def test_preview_issue_reissue_and_replay(self):
        preview = self.manager.issue(APP, "web", "alpha")["preview"]
        self.assertEqual((preview["line"], preview["generation"], preview["change"][:5]), (self.line(1), 1, "first"))
        self.assertEqual(self.remote_actions, [])
        outside = self.outside_tokens()
        result = self.issue("issue-1")
        receipt = result["receipt"]
        self.assertEqual((receipt["status"], receipt["kind"], receipt["action"], receipt["application_id"], receipt["component"]),
                         ("succeeded", "token", "issue", APP, "web"))
        path = self.token_path()
        lines = path.read_text().splitlines()
        self.assertEqual(lines[0], self.line(1))
        self.assertTrue(lines[1].startswith("issued_at=") and lines[2] == "operation=" + receipt["id"])
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(path.parent.stat().st_mode & 0o777), "0o700")
        self.assertEqual(oct(path.parent.parent.stat().st_mode & 0o777), "0o700")
        self.assertTrue((path.parent.parent / ".nobackup").exists())
        self.assertIn("EXCLUDE THIS DIRECTORY FROM BACKUPS", (path.parent.parent / "README").read_text())
        self.assertEqual([p.name for p in path.parent.iterdir()], ["web.token"])  # no temp file left
        self.assertEqual(self.outside_tokens(), outside)  # nothing outside the tokens directory
        token = result["token"]
        self.assertEqual((token["generation"], token["state"], token["path"], token["evidence"]["line1"]),
                         (1, "valid", str(path), self.line(1)))
        actions = list(self.remote_actions)
        self.assertEqual(self.issue("issue-1")["receipt"]["id"], receipt["id"])  # replay: same receipt, no host contact
        self.assertEqual(self.remote_actions, actions)
        again = self.issue("issue-2")
        self.assertEqual((again["token"]["generation"], again["token"]["state"]), (1, "valid"))  # verified no-op
        self.assertEqual(path.read_text().splitlines()[0], self.line(1))
        with self.assertRaisesRegex(ValueError, "different intent"):
            self.revoke("issue-1")

    def test_revoke_then_issue_bumps_generation(self):
        with self.assertRaisesRegex(ValueError, "ever issued"):
            self.manager.revoke(APP, "web", "alpha")
        self.issue("issue-1")
        preview = self.manager.revoke(APP, "web", "alpha")["preview"]
        self.assertIn("stops nothing that is running", preview["warning"])
        result = self.revoke("revoke-1")
        self.assertEqual((result["receipt"]["status"], result["token"]["state"]), ("succeeded", "revoked"))
        self.assertIn("stops nothing that is running", result["warning"])
        self.assertEqual(self.token_path().read_text().splitlines()[0], self.line(1, revoked=True))
        self.assertEqual(self.manager.issue(APP, "web", "alpha")["preview"]["generation"], 2)
        result = self.issue("issue-2")
        self.assertEqual((result["token"]["generation"], result["token"]["state"]), (2, "valid"))
        self.assertEqual(self.token_path().read_text().splitlines()[0], self.line(2))
        self.assertEqual([op["generation"] for op in result["token"]["operations"]], [1, 1, 2])

    def test_refusals_before_any_host_contact(self):
        with self.assertRaisesRegex(ValueError, "not registered"):
            self.manager.issue("unknown-app", "web", "alpha", approved=True, request_id="r1")
        with self.assertRaisesRegex(ValueError, "Component worker is not placed on alpha"):
            self.manager.issue(APP, "worker", "alpha", approved=True, request_id="r2")
        with self.assertRaisesRegex(ValueError, "not listed in the operations policy token_hosts"):
            self.manager.issue(APP, "worker", "beta", approved=True, request_id="r3")
        self.config["token_hosts"] = []
        self.write_config()
        with self.assertRaisesRegex(ValueError, "token_hosts"):
            self.manager.issue(APP, "web", "alpha")
        self.config["token_hosts"] = ["nowhere"]
        self.write_config()
        with self.assertRaisesRegex(ValueError, "Token hosts require"):
            self.manager.policy()
        self.assertEqual(self.remote_actions, [])
        with self.assertRaisesRegex(ValueError, "require --request-id"):
            self.config["token_hosts"] = ["alpha"]
            self.write_config()
            self.manager.issue(APP, "web", "alpha", approved=True)

    def test_authority_or_registration_change_after_dispatch_executes_nothing(self):
        original = self.dispatch

        def unregister(receipt, payload):
            DeployManager(self.broker).unregister_application(APP, expected_revision=1)
            return original(receipt, payload)

        with patch.object(self.broker, "_dispatch", side_effect=unregister):
            result = self.issue("issue-1")
        self.assertEqual(result["receipt"]["status"], "failed")
        self.assertEqual((self.remote_actions, result["token"]), ([], None))

    def test_busy_lease_and_device_block(self):
        with patch.dict(os.environ, {"SWITCHYARD_OPERATION_LEASE_WAIT": "0"}), \
                self.leases.hold("alpha", owner="fixture", scope="busy token issue", worktree=str(self.root)):
            result = self.issue("issue-busy")
        self.assertEqual((result["receipt"]["status"], result["token"]), ("busy", None))
        self.leases.store.break_device("ALPHA", reason="lease broken", operator="op")
        result = self.issue("issue-blocked")
        self.assertEqual(result["receipt"]["status"], "busy")
        self.assertIn("blocked", result["receipt"]["error"])
        self.assertEqual((self.remote_actions, result["token"]), ([], None))
        self.assertFalse(self.token_path().exists())

    def test_symlinked_token_path_or_directory_is_refused(self):
        target = self.root / "elsewhere.txt"
        target.write_text("not a token")
        directory = self.token_path().parent
        directory.mkdir(parents=True, mode=0o700)
        self.token_path().symlink_to(target)
        result = self.issue("issue-symlink")
        self.assertEqual(result["receipt"]["status"], "failed")
        self.assertIn("symlink", result["receipt"]["error"])
        self.assertEqual((target.read_text(), result["token"]), ("not a token", None))  # intent withdrawn
        self.assertTrue(self.token_path().is_symlink())
        self.token_path().unlink()
        directory.rmdir()
        elsewhere = self.root / "elsewhere-dir"
        elsewhere.mkdir()
        directory.symlink_to(elsewhere)
        result = self.issue("issue-symlink-dir")
        self.assertEqual(result["receipt"]["status"], "failed")
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_transport_loss_leaves_unknown_and_next_issue_bumps(self):
        def lost(host, source, payload, *, timeout, local=False):
            self.fake_remote(host, source, payload, timeout=timeout, local=local)  # the write happened…
            raise RemoteError("transport lost")  # …but its result never arrived

        with patch.object(tokens, "run_remote", side_effect=lost):
            result = self.issue("issue-lost")
        self.assertEqual(result["receipt"]["status"], "needs-inspection")
        self.assertEqual((result["token"]["state"], result["token"]["generation"], result["token"]["uncertain"]), ("unknown", 1, True))
        lease = self.leases.store.current("ALPHA")
        self.assertEqual(lease["status"], "suspect")
        self.leases.store.break_device("ALPHA", reason="fixture recovery", operator="test",
                                       attest_stopped="The in-process token write returned; no transport or worker remains",
                                       expected_id=lease["lease_id"])
        _, verification = self.verify()
        self.assertEqual(self.codes(verification), ["token-journal-uncertain"])
        result = self.issue("issue-after-loss")
        self.assertEqual((result["token"]["state"], result["token"]["generation"]), ("valid", 2))

    # gate ----------------------------------------------------------------------
    def test_gate_compares_line_one_only(self):
        with self.assertRaisesRegex(ValueError, "issue one first"):
            self.manager.gate(APP, "web", "alpha")
        self.issue("issue-1")
        gate = self.manager.gate(APP, "web", "alpha")
        path = str(self.token_path())
        self.assertEqual(gate["shell"], '[ "$(head -n 1 -- "' + path + '")" = "' + self.line(1) + '" ]')
        self.assertEqual(gate["systemd"], "ExecStartPre=/bin/sh -c '" + gate["shell"].replace("$", "$$") + "'")
        systemd_script = gate["systemd"][len("ExecStartPre=/bin/sh -c '"):-1].replace("$$", "$")
        self.assertTrue(run_check(gate["shell"]) and run_check(systemd_script))
        self.revoke("revoke-1")
        self.assertFalse(run_check(gate["shell"]))
        with self.token_path().open("a") as stream:  # simulate an appended valid token line
            stream.write(self.line(1) + "\n")
        self.assertFalse(run_check(gate["shell"]))
        self.assertTrue(run_check('grep -qxF -- "' + self.line(1) + '" "' + path + '"'))  # the old whole-file check passes
        self.assertIn("refuses", self.manager.gate(APP, "web", "alpha")["warning"])
        self.token_path().write_text(self.line(1).replace("host=alpha", "host=beta") + "\n")  # copied from another host
        self.assertFalse(run_check(gate["shell"]))
        self.token_path().unlink()
        self.assertFalse(run_check(gate["shell"]))

    # verify --------------------------------------------------------------------
    def test_verify_findings_and_never_mutates(self):
        self.issue("issue-1")
        before_file, before_row = self.token_path().read_bytes(), self.manager.show(APP)["tokens"][0]
        result, verification = self.verify()
        self.assertEqual((result["consistent"], verification["findings"]), (True, []))
        self.assertEqual(result["hosts"][0]["receipt"]["action"], "verify")
        self.assertEqual(self.token_path().read_bytes(), before_file)
        after_row = self.manager.show(APP)["tokens"][0]
        self.assertEqual({k: v for k, v in after_row.items() if k != "last_verification"},
                         {k: v for k, v in before_row.items() if k != "last_verification"})
        self.assertTrue(after_row["last_verification"]["consistent"])
        path = self.token_path()
        cases = [
            (lambda: path.write_text(self.line(1, revoked=True) + "\n"), ["token-revoked-while-valid"]),
            (lambda: path.write_text(self.line(3) + "\n"), ["token-generation-mismatch"]),
            (lambda: path.write_text(self.line(1, host="beta") + "\n"), ["token-foreign-host"]),
            (lambda: path.write_text("garbage\n"), ["token-malformed"]),
            (lambda: path.write_text(tokens.token_line("other", "web", "alpha", 1) + "\n"), ["token-malformed"]),
            (lambda: path.unlink(), ["token-missing"]),
            (lambda: path.write_text(self.line(1) + "\nissued_at=x\n" + self.line(1) + "\n"), ["extra-valid-line"]),
        ]
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                mutate()
                _, verification = self.verify()
                self.assertEqual(self.codes(verification), expected)
                self.assertEqual(verification["consistent"], expected == ["extra-valid-line"])
        path.write_text(self.line(1) + "\n")
        saved = path.read_bytes()
        self.revoke("revoke-1")
        path.write_bytes(saved)  # a home restore brings back the valid token
        _, verification = self.verify()
        self.assertEqual(self.codes(verification), ["token-valid-while-revoked"])

    def test_verify_unreachable_busy_and_no_records(self):
        with self.assertRaisesRegex(ValueError, "No token records"):
            self.manager.verify(APP)
        self.issue("issue-1")

        def lost(host, source, payload, *, timeout, local=False):
            mark_uncertain("fixture verification transport lost", resource=host["host_id"])
            raise RemoteError("transport lost")

        with patch.object(tokens, "run_remote", side_effect=lost):
            result, verification = self.verify()
        self.assertEqual((result["hosts"][0]["receipt"]["status"], self.codes(verification), result["consistent"]),
                         ("needs-inspection", ["unreachable"], False))
        lease = self.leases.store.current("ALPHA")
        self.assertEqual(lease["status"], "suspect")
        self.leases.store.break_device("ALPHA", reason="fixture recovery", operator="test",
                                       attest_stopped="The injected read transport failed before the remote call ran",
                                       expected_id=lease["lease_id"])
        with patch.dict(os.environ, {"SWITCHYARD_OPERATION_LEASE_WAIT": "0"}), \
                self.leases.hold("alpha", owner="fixture", scope="busy token verification", worktree=str(self.root)):
            result, verification = self.verify()
        self.assertEqual((result["hosts"][0]["receipt"]["status"], self.codes(verification)), ("busy", ["unreachable"]))

    def test_cli(self):
        parser = argparse.ArgumentParser()
        commands = parser.add_subparsers(dest="command", required=True)
        tokens.register_cli(commands)
        service = SimpleNamespace(tokens=lambda: self.manager)

        def cli(*argv):
            return tokens.handle_cli(parser.parse_args(list(argv)), service)

        self.assertIn("preview", cli("token", "issue", APP, "web", "--host", "alpha"))
        self.assertEqual(cli("token", "issue", APP, "web", "--host", "alpha", "--approve", "--request-id", "c1")["token"]["generation"], 1)
        self.assertEqual(cli("token", "show", APP)["tokens"][0]["state"], "valid")
        self.assertTrue(cli("token", "verify", APP, "web", "--host", "alpha")["consistent"])
        self.assertEqual(cli("token", "gate", APP, "web", "--host", "alpha")["line"], self.line(1))
        self.assertEqual(cli("token", "revoke", APP, "web", "--host", "alpha", "--approve", "--request-id", "c2")["token"]["state"], "revoked")
        self.assertIsNone(tokens.handle_cli(SimpleNamespace(command="deploy"), service))


if __name__ == "__main__":
    unittest.main()
