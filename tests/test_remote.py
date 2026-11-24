"""Real local processes exercise the fixed harness; no SSH/network access."""
import json
import os
from pathlib import Path
import platform
import pwd
import sys
import tempfile
import unittest
from unittest.mock import patch

from switchyard import collector, remote


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.host = {"transport": "ssh", "target": pwd.getpwuid(os.getuid()).pw_name + "@fixture.invalid",
                     "expected_hostname": platform.node()}
        self.transport = patch.object(remote, "_ssh_command", return_value=[sys.executable, "-I", "-S", "-"])
        self.ssh_command = self.transport.start()
        self.addCleanup(self.transport.stop)

    def test_identity_is_checked_before_action(self):
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / "forbidden"
            host = {**self.host, "expected_hostname": "definitely-not-this-fixture-host"}
            source = "from pathlib import Path\nPath(PAYLOAD['path']).touch()\nprint('{}')"
            with self.assertRaises(remote.RemoteError) as caught:
                remote.run_remote(host, source, {"path": str(marker)})
            self.assertTrue(caught.exception.uncertain)
            self.assertFalse(marker.exists())

    def test_payload_is_data_not_interpolated_command(self):
        value = "'\\\"; $(touch /must-not-exist)\n\u2603"
        result = remote.run_remote(self.host, "print(json.dumps({'value': PAYLOAD['value']}))", {"value": value})
        self.assertEqual(result, {"value": value})
        self.assertEqual(self.ssh_command.call_count, 1)

    def test_local_mode_runs_fixed_source_without_ssh_and_still_checks_identity(self):
        result = remote.run_remote(self.host, "print(json.dumps({'value': PAYLOAD['value']}))", {"value": 1}, local=True)
        self.assertEqual(result, {"value": 1})
        self.ssh_command.assert_not_called()
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / "forbidden"
            other = {**self.host, "target": "not-this-account@fixture.invalid"}
            with self.assertRaises(remote.RemoteError):
                remote.run_remote(other, "from pathlib import Path\nPath(PAYLOAD['path']).touch()\nprint('{}')", {"path": str(marker)}, local=True)
            self.assertFalse(marker.exists())

    def test_non_json_duplicate_keys_nonzero_and_output_overflow_are_uncertain(self):
        sources = ("print('not json')", "print('{\"x\":1,\"x\":2}')", "raise SystemExit(1)",
                   "print('x' * 300000)")
        for source in sources:
            with self.subTest(source=source), self.assertRaises(remote.RemoteError):
                remote.run_remote(self.host, source, {}, timeout=2)

    def test_shell_pipeline_redirection_and_nonzero_are_real(self):
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / "file"
            script = "printf 'abc' | tr a-z A-Z > '" + str(marker) + "'; cat '" + str(marker) + "'; printf 'err' >&2; exit 7"
            result = remote.run_remote(self.host, remote.SHELL_SOURCE, {"script": script, "timeout_seconds": 2}, timeout=3)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["exit_code"], 7)
            self.assertEqual(result["stdout"], "ABC")
            self.assertEqual(result["stderr"], "err")
            self.assertEqual(marker.read_text(), "ABC")

    def test_shell_timeout_and_output_limit_are_not_confirmed_failures(self):
        for script in ("sleep 10", "yes output"):
            with self.subTest(script=script):
                result = remote.run_remote(self.host, remote.SHELL_SOURCE, {"script": script, "timeout_seconds": 1}, timeout=3)
                self.assertEqual(result["status"], "needs-inspection")
                self.assertLessEqual(len(result["stdout"].encode()), 16384)
                self.assertIsNone(result["exit_code"])

    def test_transport_deadline_reaps_owned_group(self):
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / "pid"
            source = "import os,time; open(" + repr(str(marker)) + ",'w').write(str(os.getpid())); time.sleep(10)"
            with self.assertRaises(remote.RemoteError):
                remote.run_bounded([sys.executable, "-I", "-S", "-c", source], b"", timeout=0.5)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(marker.read_text()), 0)


if __name__ == "__main__":
    unittest.main()
