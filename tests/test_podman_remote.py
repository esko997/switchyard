"""Offline safety boundaries of the fixed Podman program; no runtime calls."""
import copy
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from switchyard import podman_remote as remote


OWNER = "22222222-2222-4222-8222-222222222222"
BODY = b"<h1>foobar</h1>\n"
HASH = hashlib.sha256(BODY).hexdigest()
IMAGE_ID = "sha256:" + "a" * 64
IMAGE_DIGEST = "docker.io/nginxinc/nginx-unprivileged@sha256:" + "b" * 64
NATIVE = "c" * 64


class RemoteSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        home_patch = patch.object(remote.Path, "home", return_value=self.home)
        home_patch.start()
        self.addCleanup(home_patch.stop)
        self.site = remote.provision_content(OWNER, BODY, HASH)
        self.payload = {"action": "inspect", "workload_id": "foobar", "container_name": remote.NAME,
                        "image": remote.IMAGE, "port": 18080, "ownership_id": OWNER,
                        "image_id": IMAGE_ID, "image_digest": IMAGE_DIGEST,
                        "content_sha256": HASH, "native_id": NATIVE, "expected_user": "operator"}
        self.record = {
            "Id": NATIVE, "Name": remote.NAME, "Image": IMAGE_ID,
            "EffectiveCaps": [], "BoundingCaps": [], "State": {"Running": True},
            "Config": {"User": "101:101", "Labels": {remote.LABEL: OWNER, remote.WORKLOAD_LABEL: "foobar"}},
            "HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "CapDrop": ["CAP_CHOWN"],
                           "CapAdd": [], "SecurityOpt": ["no-new-privileges"],
                           "RestartPolicy": {"Name": "no"}, "Memory": 64 * 1024 * 1024,
                           "MemorySwap": 64 * 1024 * 1024, "CpuPeriod": 100000, "CpuQuota": 50000,
                           "PidsLimit": 32, "NetworkMode": "slirp4netns",
                           "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]},
                           "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777,rprivate,tmpcopyup"},
                           "LogConfig": {"Type": "k8s-file", "Config": None, "Size": "1.049MB"}},
            "Mounts": [{"Type": "bind", "Source": str(self.site),
                        "Destination": remote.CONTENT_PATH, "RW": False}]}

    def test_actual_podman_expanded_capdrop_and_log_size_are_supported(self):
        native, content = remote.validate_container(self.record, self.payload)
        self.assertEqual((native, content), (NATIVE, BODY))

    def test_missing_or_different_container_owner_is_rejected(self):
        for value in (None, "another-owner"):
            with self.subTest(value=value):
                record = copy.deepcopy(self.record)
                record["Config"]["Labels"][remote.LABEL] = value
                with self.assertRaisesRegex(remote.Refusal, "ownership"):
                    remote.validate_container(record, self.payload)

    def test_changed_native_incarnation_rejected(self):
        self.record["Id"] = "d" * 64
        with self.assertRaisesRegex(remote.Refusal, "incarnation"):
            remote.validate_container(self.record, self.payload)

    def test_lan_bind_extra_mount_capability_and_unbounded_logs_rejected(self):
        records = []
        record = copy.deepcopy(self.record)
        record["HostConfig"]["PortBindings"]["8080/tcp"][0]["HostIp"] = "0.0.0.0"
        records.append(record)
        record = copy.deepcopy(self.record)
        record["Mounts"].append({"Type": "bind", "Source": "/home/personal", "RW": True})
        records.append(record)
        record = copy.deepcopy(self.record)
        record["EffectiveCaps"] = ["CAP_NET_ADMIN"]
        records.append(record)
        record = copy.deepcopy(self.record)
        record["HostConfig"]["LogConfig"]["Size"] = "-1B"
        records.append(record)
        record = copy.deepcopy(self.record)
        record["HostConfig"]["Tmpfs"]["/tmp"] += ",size=1g"
        # A contradictory tmpfs size must not be accepted just because one
        # expected-size token appears in the inspect output.
        records.append(record)
        for record in records:
            with self.subTest(record=record), self.assertRaises(remote.Refusal):
                remote.validate_container(record, self.payload)

    def test_hash_mismatch_rejected(self):
        self.site.write_bytes(b"changed")
        with self.assertRaisesRegex(remote.Refusal, "hash mismatch"):
            remote.validate_container(self.record, self.payload)

    def test_ownership_directory_is_never_adopted_or_overwritten(self):
        (self.site.parent / "owner.json").unlink()
        before = self.site.read_bytes()
        with self.assertRaisesRegex(remote.Refusal, "unowned"):
            remote.provision_content(OWNER, b"replacement", hashlib.sha256(b"replacement").hexdigest())
        self.assertEqual(self.site.read_bytes(), before)

    def test_existing_content_is_not_overwritten(self):
        with self.assertRaisesRegex(remote.Refusal, "overwrite"):
            remote.provision_content(OWNER, b"replacement", hashlib.sha256(b"replacement").hexdigest())
        self.assertEqual(self.site.read_bytes(), BODY)

    def test_symlink_and_unexpected_file_are_refused(self):
        self.site.unlink()
        self.site.symlink_to(self.home / "personal")
        with self.assertRaises(OSError):
            remote.provision_content(OWNER, BODY, HASH)
        self.site.unlink()
        self.site.write_bytes(BODY)
        (self.site.parent / "personal").write_text("do not touch")
        with self.assertRaisesRegex(remote.Refusal, "Unexpected files"):
            remote.paths(OWNER)

    def test_site_mode_is_readable_with_private_operator_umask(self):
        second = self.home / "another-home"
        second.mkdir()
        old = os.umask(0o077)
        try:
            with patch.object(remote.Path, "home", return_value=second):
                site = remote.provision_content(OWNER, BODY, HASH)
        finally:
            os.umask(old)
        self.assertEqual(site.stat().st_mode & 0o777, 0o644)

    def test_http_redirect_is_not_followed(self):
        connection = MagicMock()
        connection.getresponse.return_value = SimpleNamespace(status=302, read=lambda bound: BODY)
        with patch.object(remote.http.client, "HTTPConnection", return_value=connection) as factory:
            with self.assertRaisesRegex(remote.Refusal, "redirects forbidden"):
                remote.verify_http(HASH)
        factory.assert_called_once_with("127.0.0.1", 18080, timeout=2)
        connection.request.assert_called_once()

    def test_http_wrong_body_is_not_health(self):
        connection = MagicMock()
        connection.getresponse.return_value = SimpleNamespace(status=200, read=lambda bound: b"wrong")
        with patch.object(remote.http.client, "HTTPConnection", return_value=connection):
            with self.assertRaisesRegex(remote.Refusal, "body hash mismatch"):
                remote.verify_http(HASH)

    def test_endpoint_environment_is_removed_and_remote_mode_disabled(self):
        stream = tempfile.TemporaryFile()
        self.addCleanup(stream.close)
        stream.write(b"ok")
        stream.seek(0)
        errors = tempfile.TemporaryFile()
        self.addCleanup(errors.close)
        process = SimpleNamespace(stdout=stream, stderr=errors, poll=lambda: 0, wait=lambda timeout: 0)
        with patch.dict(os.environ, {"CONTAINER_HOST": "ssh://elsewhere", "DOCKER_HOST": "tcp://elsewhere",
                                    "CONTAINER_CONNECTION": "rootful", "DOCKER_CONTEXT": "other"}):
            with patch.object(remote.subprocess, "Popen", return_value=process) as run:
                self.assertEqual(remote.podman("info"), "ok")
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/usr/bin/podman", "--remote=false", "info"])
        self.assertNotIn("CONTAINER_HOST", kwargs["env"])
        self.assertNotIn("CONTAINER_CONNECTION", kwargs["env"])
        self.assertNotIn("DOCKER_HOST", kwargs["env"])
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)

    def test_name_collision_refuses_before_any_podman_mutation(self):
        payload = {**self.payload, "action": "preflight"}
        with patch.object(remote, "runtime", return_value="amd64"), \
                patch.object(remote, "container_record", return_value=self.record), \
                patch.object(remote, "podman") as podman:
            result = remote.execute(payload)
        self.assertEqual(result["status"], "failed")
        self.assertIn("collision", result["error"])
        podman.assert_not_called()

    def test_mutating_timeout_is_uncertain_not_confirmed_failure(self):
        payload = {**self.payload, "action": "stop"}
        with patch.object(remote, "runtime", return_value="amd64"), \
                patch.object(remote, "container_record", return_value=self.record), \
                patch.object(remote, "podman", side_effect=subprocess.TimeoutExpired("podman", 20)):
            result = remote.execute(payload)
        self.assertEqual(result["status"], "needs-inspection")

    def test_absent_destination_is_positive_recovery_evidence(self):
        payload = {**self.payload, "action": "absent-or-stopped"}
        with patch.object(remote, "runtime", return_value="amd64"), \
                patch.object(remote, "container_record", return_value=None):
            result = remote.execute(payload)
        self.assertEqual(result, {"status": "succeeded", "absent": True, "running": False})

    def test_root_and_different_login_user_are_refused(self):
        with patch.object(remote.os, "getuid", return_value=0):
            with self.assertRaisesRegex(remote.Refusal, "Rootful"):
                remote.runtime(self.payload)
        with patch.object(remote.os, "getuid", return_value=1000), \
                patch.object(remote.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="other")):
            with self.assertRaisesRegex(remote.Refusal, "user identity"):
                remote.runtime(self.payload)

    def test_actual_image_id_and_repo_digest_are_not_fabricated_from_tag(self):
        record = {"Id": "a" * 64, "RepoDigests": [IMAGE_DIGEST], "Architecture": "amd64"}
        with patch.object(remote, "json_command", return_value=[record]):
            image = remote.image_record(remote.IMAGE)
        self.assertEqual(image["image_id"], IMAGE_ID)
        self.assertEqual(image["image_digest"], IMAGE_DIGEST)
        record["RepoDigests"] = []
        with patch.object(remote, "json_command", return_value=[record]):
            with self.assertRaisesRegex(remote.Refusal, "RepoDigest"):
                remote.image_record(remote.IMAGE)

    def test_deploy_passes_security_options_and_immutable_id_without_shell(self):
        import base64
        payload = {**self.payload, "action": "deploy", "content_b64": base64.b64encode(BODY).decode()}
        with patch.object(remote, "runtime", return_value="amd64"), \
                patch.object(remote, "container_record", side_effect=[None, self.record]), \
                patch.object(remote, "port_free"), patch.object(remote, "verify_http"), \
                patch.object(remote, "image_record", return_value={
                    "image_id": IMAGE_ID, "image_digest": IMAGE_DIGEST, "repo_digests": [IMAGE_DIGEST]}), \
                patch.object(remote, "podman") as podman:
            result = remote.execute(payload)
        self.assertEqual(result["status"], "succeeded")
        argv = podman.call_args.args
        self.assertEqual(argv[-1], IMAGE_ID)
        for flag in ("--pull=never", "--read-only", "--read-only-tmpfs=false", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", "--memory=64m", "--memory-swap=64m",
                     "--pids-limit=32", "--restart=no"):
            self.assertIn(flag, argv)
        self.assertIn("127.0.0.1:18080:8080/tcp", argv)
        self.assertNotIn("--privileged", argv)

    def test_podman_output_is_bounded_while_reading(self):
        stream = tempfile.TemporaryFile()
        self.addCleanup(stream.close)
        stream.write(b"x" * (2 * 1024 * 1024 + 1))
        stream.seek(0)
        errors = tempfile.TemporaryFile()
        self.addCleanup(errors.close)
        process = SimpleNamespace(stdout=stream, stderr=errors, poll=lambda: 0, wait=lambda timeout: 0)
        with patch.object(remote.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(remote.Refusal, "response exceeds bound"):
                remote.podman("ps")

    def test_failed_command_diagnostics_are_bounded_and_separate_from_receipt_error(self):
        import sys
        popen = subprocess.Popen
        def child(command, **kwargs):
            return popen([sys.executable, "-c",
                          "import sys; sys.stderr.write('private-detail:' + 'x' * 70000); sys.exit(125)"],
                         **kwargs)
        with patch.object(remote.subprocess, "Popen", side_effect=child):
            with self.assertRaises(remote.CommandFailure) as error:
                remote.podman("run", timeout=3)
        self.assertEqual(len(error.exception.diagnostics.encode()), 16384)
        self.assertTrue(error.exception.diagnostics.startswith("private-detail:"))
        self.assertNotIn("private-detail", str(error.exception))


if __name__ == "__main__":
    unittest.main()
