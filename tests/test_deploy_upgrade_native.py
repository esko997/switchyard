"""Same-ID upgrade native safety against the in-process fake host; no host/network access."""
import copy
import json
from pathlib import Path
from unittest.mock import patch

from switchyard import deploy_remote
from test_deploy import DeployFixture


class UpgradeNativeTests(DeployFixture):
    def setUp(self):
        super().setUp()
        self.save_template()
        _, result = self.deploy()
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        self.previous = copy.deepcopy(next(p for p in reversed(self.remote_payloads) if p["action"] == "start"))
        self.previous.update(state="active", expected_token="valid")
        self.preparation = copy.deepcopy(next(p for p in self.remote_payloads if p["action"] == "prepare"))
        self.payload = {"action": "upgrade-check", "names": copy.deepcopy(self.previous["names"]),
                        "paths": copy.deepcopy(self.previous["paths"]), "previous": self.previous}

    def check(self):
        return deploy_remote.main(self.payload)

    def assert_refused(self, text):
        result = self.check()
        self.assertEqual(result["status"], "failed", result)
        self.assertIn(text, result["error"])

    def stopped(self, *, state="fenced", token="revoked", failed=False):
        deploy_remote.stop_and_verify(self.previous)
        if token == "revoked":
            deploy_remote.revoke_token(self.previous)
        self.previous.update(state=state, expected_token=token)
        if failed:
            self.host.units[self.previous["names"]["service"]]["active"] = "failed"

    def test_active_proof_is_read_only(self):
        files = {str(p): p.read_bytes() for p in self.host.home.rglob("*") if p.is_file()}
        before = len(self.host.calls)
        result = self.check()
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(result["previous"]["generation"], self.previous["generation"])
        self.assertEqual(result["previous"]["token"]["state"], "valid")
        self.assertEqual(files, {str(p): p.read_bytes() for p in self.host.home.rglob("*") if p.is_file()})
        self.assertFalse(any(any(arg in ("start", "stop", "daemon-reload", "reset-failed") for arg in call)
                             for call in self.host.calls[before:]))

    def test_foreign_owner_refused_without_mutation(self):
        owner = Path(self.previous["paths"]["owner"])
        value = json.loads(owner.read_text())
        value["ownership_id"] = "foreign"
        owner.write_text(json.dumps(value))
        with patch.object(deploy_remote, "revoke_token") as revoke, patch.object(deploy_remote, "stop_and_verify") as stop:
            self.assert_refused("owner.json belongs")
        revoke.assert_not_called()
        stop.assert_not_called()

    def test_missing_or_changed_old_native_file_refused(self):
        path = Path(self.previous["paths"]["yaml"])
        path.write_text(path.read_text() + "# drift\n")
        self.assert_refused("file differs")
        path.unlink()
        self.assert_refused("files are incomplete")

    def test_high_water_generation_drift_refused(self):
        (Path(self.previous["paths"]["app_dir"]) / "generation").write_text("99\n")
        self.assert_refused("host generation differs")

    def test_fenced_failed_unit_is_allowed_but_token_drift_is_not(self):
        self.stopped(failed=True)
        self.assertEqual(self.check()["status"], "succeeded")
        deploy_remote.issue_token(self.previous)
        self.assert_refused("token differs")

    def test_fenced_running_unit_or_pod_is_refused(self):
        self.stopped()
        self.host.units[self.previous["names"]["service"]]["active"] = "active"
        self.assert_refused("stopped placement has running")

    def test_staged_valid_and_revoked_tokens_are_distinct(self):
        self.stopped(state="staged", token="valid")
        self.assertEqual(self.check()["status"], "succeeded")
        self.previous["expected_token"] = "revoked"
        self.assert_refused("token differs")
        deploy_remote.revoke_token(self.previous)
        self.assertEqual(self.check()["status"], "succeeded")

    def test_new_container_name_collision_is_not_waived(self):
        name = self.previous["names"]["pod"] + "-new-worker"
        self.payload["names"]["containers"].append(name)
        self.host.foreign_containers.add(name)
        self.assert_refused("container exists: " + name)

    def test_old_container_name_collision_when_fenced_is_not_waived(self):
        self.stopped()
        name = self.previous["names"]["containers"][0]
        self.host.foreign_containers.add(name)
        self.assert_refused("container exists: " + name)

    def test_foreign_pod_and_competing_unit_are_refused(self):
        pod = self.host.pods[self.previous["names"]["pod"]]
        original = pod["Labels"]["io.switchyard/generation"]
        pod["Labels"]["io.switchyard/generation"] = "99"
        self.assert_refused("ownership labels")
        pod["Labels"]["io.switchyard/generation"] = original
        self.host.units[self.previous["names"]["service"]]["source"] = "/foreign/unit.kube"
        self.assert_refused("competing or stale")

    def test_foreign_quadlet_is_not_waived(self):
        path = Path(self.previous["paths"]["unit"]).with_suffix(".container")
        path.write_text("[Container]\nImage=foreign\n")
        self.assert_refused("Upgrade collision")

    def test_config_hash_extra_files_and_app_entries_refused(self):
        directory = Path(self.previous["paths"]["config_dir"])
        directory.mkdir(parents=True)
        text = b"known configuration\n"
        config = directory / "settings.conf"
        config.write_bytes(text)
        self.previous["config"] = [{"name": config.name, "sha256": deploy_remote.sha256(text)}]
        self.assertEqual(self.check()["status"], "succeeded")
        config.write_bytes(b"changed")
        self.assert_refused("configuration differs")
        config.write_bytes(text)
        extra = directory / "unrecorded.conf"
        extra.write_text("foreign")
        self.assert_refused("configuration differs")
        extra.unlink()
        (directory.parent / "foreign-component").mkdir()
        self.assert_refused("configuration root")
        (directory.parent / "foreign-component").rmdir()
        (Path(self.previous["paths"]["app_dir"]) / "unknown").write_text("foreign")
        self.assert_refused("application directory")

    def inspect_payload(self):
        original = next(p for p in self.remote_payloads if p["action"] == "inspect")
        return {**copy.deepcopy(original), "previous": self.previous}

    def test_inspect_filters_only_exact_active_claim_tuples(self):
        claim = self.previous["claims"][0]
        exact = {key: claim[key] for key in ("protocol", "address", "port")}
        other = [dict(exact, address="0.0.0.0"), dict(exact, address="::"),
                 dict(exact, address="192.168.50.121"), dict(exact, protocol="udp"),
                 dict(exact, port=claim["port"] + 1)]
        self.host.listeners = [exact, *other]
        result = deploy_remote.inspect(self.inspect_payload())
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["inspection"]["listeners"], other)
        self.assertEqual(result["inspection"]["collisions"], [])
        self.assertTrue(deploy_remote.port_conflicts([claim], other))

    def test_inspect_does_not_filter_listeners_for_fenced_placement(self):
        self.stopped()
        listener = dict(self.previous["claims"][0])
        self.host.listeners = [listener]
        result = deploy_remote.inspect(self.inspect_payload())
        self.assertEqual(result["inspection"]["listeners"], [listener])

    def test_inspect_refuses_drift_before_facts_or_registry_calls(self):
        Path(self.previous["paths"]["yaml"]).write_text("foreign")
        with patch.object(deploy_remote, "facts") as facts, patch.object(deploy_remote, "resolve_image") as registry:
            result = deploy_remote.main(self.inspect_payload())
        self.assertEqual(result["status"], "failed")
        facts.assert_not_called()
        registry.assert_not_called()

    def test_apply_check_rechecks_addresses_and_non_owned_listeners(self):
        self.payload["claims"] = copy.deepcopy(self.previous["claims"])
        self.assertEqual(self.check()["status"], "succeeded")
        self.host.listeners.append(dict(self.previous["claims"][0], address="0.0.0.0"))
        self.assert_refused("another listener")
        self.host.listeners = []
        self.payload["claims"][0]["address"] = "192.168.50.121"
        self.assert_refused("no longer assigned")

    def test_apply_check_rechecks_dataset_binding_and_subpaths(self):
        self.payload["claims"] = copy.deepcopy(self.previous["claims"])
        self.payload["datasets"] = copy.deepcopy(self.previous["datasets"])
        self.assertEqual(self.check()["status"], "succeeded")
        self.assertTrue(self.payload["datasets"])
        self.payload["datasets"][0]["path"] += "-changed"
        self.assert_refused("dataset bindings differ")
        self.payload["datasets"] = copy.deepcopy(self.previous["datasets"])
        self.payload["datasets"][0]["sub_paths"] = ["missing-child"]
        self.assert_refused("sub-path is no longer readable")

    def test_apply_check_rechecks_native_and_review_device_numbers(self):
        self.payload["claims"] = copy.deepcopy(self.previous["claims"])
        path = "/dev/dri/renderD128"
        self.payload["devices"] = [{"host": path, "major": 226, "minor": 128}]
        self.assertEqual(self.check()["status"], "succeeded")
        self.payload["devices"] = [{"host_path": path, "major_minor": "226:128"}]
        self.assertEqual(self.check()["status"], "succeeded")
        self.host.devices[path]["minor"] = 129
        self.assert_refused("device changed")

    def test_wildcard_is_never_exempted_even_if_journaled(self):
        wildcard = dict(self.previous["claims"][0], address="0.0.0.0")
        self.previous["claims"].append(wildcard)
        self.host.listeners = [wildcard]
        self.assertEqual(deploy_remote.upgrade_listeners(self.previous), [wildcard])

    def test_staged_revoked_prepare_revokes_before_unit_creation(self):
        result = deploy_remote.undeploy({**self.previous, "revoke_first": True})
        self.assertEqual(result["status"], "succeeded", result)
        payload = {**self.preparation, "install": "staged-revoked", "retained_entries": ["data", "generation"],
                   "expected_host_generation": self.previous["generation"]}
        create_file = deploy_remote.create_file
        seen = []

        def create(path, data, mode):
            if str(path) == payload["paths"]["unit"]:
                seen.append(deploy_remote.token_state(payload)["state"])
            return create_file(path, data, mode)

        with patch.object(deploy_remote, "create_file", side_effect=create):
            result = deploy_remote.prepare(payload)
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(seen, ["revoked"])
        self.assertEqual(deploy_remote.token_state(payload)["state"], "revoked")
        self.assertFalse(self.host.started(payload["names"]["service"]))

    def test_undeploy_revoke_first_precedes_stop_and_happens_once(self):
        stop = deploy_remote.stop_and_verify
        revoke = deploy_remote.revoke_token

        def stop_after_revocation(payload):
            self.assertEqual(deploy_remote.token_state(payload)["state"], "revoked")
            return stop(payload)

        with patch.object(deploy_remote, "stop_and_verify", side_effect=stop_after_revocation), \
                patch.object(deploy_remote, "revoke_token", wraps=revoke) as revocations:
            result = deploy_remote.undeploy({**self.previous, "revoke_first": True})
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(revocations.call_count, 1)

    def test_normal_undeploy_keeps_valid_token_until_after_stop(self):
        stop = deploy_remote.stop_and_verify

        def stop_before_revocation(payload):
            self.assertEqual(deploy_remote.token_state(payload)["state"], "valid")
            return stop(payload)

        with patch.object(deploy_remote, "stop_and_verify", side_effect=stop_before_revocation):
            result = deploy_remote.undeploy(self.previous)
        self.assertEqual(result["status"], "succeeded", result)
