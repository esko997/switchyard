"""Synthetic remote outcomes only: never SSH or start a real container."""
import base64
import copy
import hashlib
import unittest
from unittest.mock import patch

from switchyard.podman_ops import execute_managed
from switchyard.podman_remote import IMAGE, NAME


OWNER = "22222222-2222-4222-8222-222222222222"
BODY = b"<h1>foobar</h1>\n"
HASH = hashlib.sha256(BODY).hexdigest()
IMAGE_ID = "sha256:" + "a" * 64
IMAGE_DIGEST = "docker.io/nginxinc/nginx-unprivileged@sha256:" + "b" * 64
NATIVE = "c" * 64
DEST_NATIVE = "d" * 64
HOSTS = {name: {"transport": "ssh", "target": "operator@" + name}
         for name in ("source", "destination")}


def placement():
    return {"workload_id": "foobar", "host_id": "source", "native_id": NATIVE,
            "image_id": IMAGE_ID, "image_digest": IMAGE_DIGEST,
            "content_sha256": HASH, "lifecycle": "running", "ownership_id": OWNER,
            "verified_at": "2026-11-22T00:00:00+00:00", "uncertain": False, "scope": "user:1000"}


def request(action="migrate"):
    return {"action": action, "workload_id": "foobar", "source_id": "source",
            "target_id": "destination" if action == "migrate" else None,
            "config": {"container_name": NAME, "image": IMAGE, "port": 18080,
                       "ownership_id": OWNER, "allowed_hosts": list(HOSTS)},
            "placement": placement(), "site_content": BODY.decode(), "site_sha256": HASH,
            "operation_id": "operation-1"}


def okay(**extra):
    return {"status": "succeeded", "scope": "user:1000", **extra}


def source_running(**extra):
    return okay(native_id=NATIVE, running=True, architecture="amd64",
                content_b64=base64.b64encode(BODY).decode(), **extra)


class ManagedOperationTests(unittest.TestCase):
    def setUp(self):
        self.calls, self.events = [], []

    def run_operation(self, value, outcomes):
        remaining = list(outcomes)

        def remote(host, source, payload, *, timeout):
            pair = (host["target"].split("@")[1], payload["action"])
            self.calls.append((pair, copy.deepcopy(payload)))
            expected, result = remaining.pop(0)
            self.assertEqual(pair, expected)
            self.assertIn("PAYLOAD", source)
            if isinstance(result, Exception):
                raise result
            return result

        with patch("switchyard.podman_ops.run_remote", side_effect=remote):
            result = execute_managed(value, HOSTS, lambda event, data:
                                     self.events.append((event, copy.deepcopy(data))))
        self.assertEqual(remaining, [])
        return result

    def migration_prefix(self):
        return [(("destination", "preflight"), okay(architecture="amd64")),
                (("source", "inspect-running"), source_running()),
                (("destination", "prestage"), okay(image_id=IMAGE_ID, image_digest=IMAGE_DIGEST)),
                (("source", "stop"), okay(native_id=NATIVE, running=False))]

    def test_destination_collision_does_not_stop_source(self):
        result = self.run_operation(request(), [(("destination", "preflight"),
            {"status": "failed", "error": "Container name collision"})])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["placement"]["lifecycle"], "running")
        self.assertFalse(result["placement"]["uncertain"])

    def test_destination_prestage_failure_does_not_stop_source(self):
        result = self.run_operation(request(), self.migration_prefix()[:2] + [
            (("destination", "prestage"), {"status": "failed", "error": "architecture mismatch"})])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["placement"]["host_id"], "source")
        self.assertNotIn(("source", "stop"), [pair for pair, _ in self.calls])

    def test_source_content_mismatch_never_stops(self):
        result = self.run_operation(request(), [self.migration_prefix()[0],
            (("source", "inspect-running"), okay(architecture="amd64", running=True,
             content_b64=base64.b64encode(b"changed").decode()))])
        self.assertEqual(result["status"], "failed")
        self.assertNotIn(("source", "stop"), [pair for pair, _ in self.calls])

    def test_uncertain_target_start_never_automatically_restarts_source(self):
        result = self.run_operation(request(), self.migration_prefix() + [
            (("destination", "deploy"), TimeoutError("lost transport"))])
        self.assertEqual(result["status"], "needs-inspection")
        self.assertEqual(result["placement"]["lifecycle"], "unknown")
        self.assertTrue(result["placement"]["uncertain"])
        self.assertEqual(result["placement"]["recovery"]["source"]["native_id"], NATIVE)
        self.assertNotIn(("source", "start"), [pair for pair, _ in self.calls])
        self.assertIn("recovery-intent", [event for event, _ in self.events])

    def test_confirmed_target_refusal_preserves_stopped_source(self):
        result = self.run_operation(request(), self.migration_prefix() + [
            (("destination", "deploy"), {"status": "failed", "error": "owned directory changed"})])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["placement"]["lifecycle"], "stopped")
        self.assertIn("recovery", result["placement"])
        self.assertNotIn(("source", "start"), [pair for pair, _ in self.calls])

    def test_verified_cutover_transfers_verified_source_bytes_and_pins_image(self):
        value = request()
        value["site_content"] = "new operator edit not deployed"
        value["site_sha256"] = hashlib.sha256(value["site_content"].encode()).hexdigest()
        result = self.run_operation(value, self.migration_prefix() + [
            (("destination", "deploy"), okay(native_id=DEST_NATIVE, running=True)),
            (("source", "inspect"), okay(native_id=NATIVE, running=False))])
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["placement"]["host_id"], "destination")
        self.assertFalse(result["placement"]["uncertain"])
        target_payload = next(payload for pair, payload in self.calls if pair == ("destination", "deploy"))
        self.assertEqual(base64.b64decode(target_payload["content_b64"]), BODY)
        self.assertEqual(target_payload["image_id"], IMAGE_ID)
        self.assertEqual(target_payload["image_digest"], IMAGE_DIGEST)
        self.assertEqual(target_payload["content_sha256"], HASH)

    def recovery_request(self, known_target=False):
        value = request("recover")
        value["target_id"] = "source"
        value["placement"]["lifecycle"] = "unknown"
        value["placement"]["uncertain"] = True
        value["placement"]["recovery"] = {"source": placement(), "target_id": "destination"}
        if known_target:
            value["placement"]["recovery"]["target_native_id"] = DEST_NATIVE
        return value

    def test_recovery_refuses_unverified_destination_and_never_starts_source(self):
        result = self.run_operation(self.recovery_request(), [
            (("destination", "inspect-target"), {"status": "failed", "error": "different owner"})])
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["placement"]["uncertain"])
        self.assertNotIn(("source", "start"), [pair for pair, _ in self.calls])

    def test_recovery_inspects_then_stops_owned_target_before_source_restart(self):
        result = self.run_operation(self.recovery_request(), [
            (("destination", "inspect-target"), okay(native_id=DEST_NATIVE, running=True)),
            (("destination", "stop"), okay(native_id=DEST_NATIVE, running=False)),
            (("destination", "absent-or-stopped"), okay(native_id=DEST_NATIVE, running=False)),
            (("source", "inspect"), okay(native_id=NATIVE, running=False)),
            (("source", "start"), okay(native_id=NATIVE, running=True))])
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["placement"]["host_id"], "source")
        self.assertFalse(result["placement"]["uncertain"])
        self.assertEqual(self.calls[1][1]["native_id"], DEST_NATIVE)
        self.assertNotIn("recovery", result["placement"])

    def test_unknown_target_stop_prevents_source_restart(self):
        result = self.run_operation(self.recovery_request(True), [
            (("destination", "inspect-target"), okay(native_id=DEST_NATIVE, running=True)),
            (("destination", "stop"), {"status": "needs-inspection", "error": "deadline"})])
        self.assertEqual(result["status"], "needs-inspection")
        self.assertNotIn(("source", "start"), [pair for pair, _ in self.calls])

    def test_initial_deploy_records_intent_before_uncertain_run(self):
        value = request("deploy")
        value.update(placement=None, source_id=None, target_id="source")
        result = self.run_operation(value, [
            (("source", "preflight"), okay(architecture="amd64")),
            (("source", "prestage"), okay(image_id=IMAGE_ID, image_digest=IMAGE_DIGEST)),
            (("source", "deploy"), {"status": "needs-inspection", "error": "HTTP hash mismatch"})])
        self.assertEqual(result["status"], "needs-inspection")
        self.assertEqual(result["placement"]["image_digest"], IMAGE_DIGEST)
        self.assertTrue(result["placement"]["uncertain"])
        self.assertEqual([event for event, _ in self.events].count("deployment-intent"), 1)

    def test_stop_uncertain_source_does_not_clear_unresolved_target(self):
        value = self.recovery_request()
        value.update(action="stop", target_id=None)
        result = self.run_operation(value, [(("source", "stop"), okay(native_id=NATIVE, running=False))])
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["placement"]["lifecycle"], "stopped")
        self.assertTrue(result["placement"]["uncertain"])

    def test_different_placement_owner_is_refused_without_remote_calls(self):
        value = request()
        value["placement"]["ownership_id"] = "33333333-3333-4333-8333-333333333333"
        result = self.run_operation(value, [])
        self.assertEqual(result["status"], "failed")

    def test_malformed_read_is_uncertain_not_confirmed_failure(self):
        result = self.run_operation(request(), [(("destination", "preflight"), {})])
        self.assertEqual(result["status"], "needs-inspection")

    def test_partial_initial_deployment_recovery_reconciles_owned_container(self):
        value = request("recover")
        value["target_id"] = "source"
        value["placement"].update(native_id=None, lifecycle="unknown", uncertain=True)
        result = self.run_operation(value, [
            (("source", "inspect-target"), okay(native_id=NATIVE, running=True)),
            (("source", "inspect-running"), source_running())])
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["placement"]["native_id"], NATIVE)
        self.assertFalse(result["placement"]["uncertain"])

    def test_retained_owned_destination_can_be_reused_without_name_adoption(self):
        value = request()
        value["placement"]["retained_target"] = {"host_id": "destination",
            "native_id": DEST_NATIVE, "ownership_id": OWNER}
        prefix = self.migration_prefix()
        prefix[0] = (("destination", "preflight"), okay(architecture="amd64", native_id=DEST_NATIVE))
        result = self.run_operation(value, prefix + [
            (("destination", "deploy"), okay(native_id=DEST_NATIVE, running=True)),
            (("source", "inspect"), okay(native_id=NATIVE, running=False))])
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(self.calls[0][1]["allow_owned"])
        self.assertEqual(self.calls[0][1]["native_id"], DEST_NATIVE)
        self.assertEqual(self.calls[4][1]["native_id"], DEST_NATIVE)


if __name__ == "__main__":
    unittest.main()
