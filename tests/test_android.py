"""Isolated Android adapter fixtures; never use the SDK, a device or host telemetry."""
import fcntl
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from switchyard import android
from switchyard.collector import CollectionError
from switchyard.leases import LeaseBusy

SERIAL = "TESTUSB0001"
SORTIE = "org.example.launcher"
SYNC = "org.example.sync"
TRACKER = "org.example.tracker"


def config(ledger):
    return {"host_id": "test-handheld", "transport": "adb", "expected_hostname": SERIAL, "serial": SERIAL,
            "ledger": str(ledger), "user_id": 0, "packages": [SORTIE, SYNC, TRACKER]}


def response():
    return ("switchyard-android-v1\nidentity\t" + SERIAL + "\n"
            "property\tro.product.model\tExample Handheld\n"
            "property\tro.build.version.release\t13\n"
            "property\tro.product.cpu.abi\tarm64-v8a\n"
            "property\tro.soc.model\tQTI SG8275\n"
            "cpu\t8\nmemory\tMemTotal\t16000000\nmemory\tMemAvailable\t9000000\n"
            "memory\tSwapTotal\t4000000\nmemory\tSwapFree\t2000000\n"
            "mount\t/dev/block/dm-17\tf2fs\trw\n"
            "capacity\t/dev/block/dm-17\t476303180\t429299324\t47003856\n"
            "package\t" + SORTIE + "\tpresent\t10123\t102\nversion\t" + SORTIE + "\t1.2.0\n"
            "package\t" + SYNC + "\tpresent\t10124\t205\nversion\t" + SYNC + "\t2.0.5\n"
            "package\t" + TRACKER + "\tpresent\t10125\t17\n"
            "process\t10123\t" + SORTIE + "\nprocess\t10123\t" + SORTIE + ":renderer\n"
            "process_status\tcomplete\nend\n").encode()


def scopes(snapshot):
    return {entry["scope"]: entry for entry in snapshot["coverage"]}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = self.root / "DEVICE_ACCESS_TESTHANDHELD.md"
        self.ledger.write_text("isolated fixture ledger\n")
        self.mapping = patch.object(android.locks, "DEFAULT_LEDGER_DIR", self.root)
        self.mapping.start()
        self.addCleanup(self.mapping.stop)
        self.adb = self.root / "platform-tools/adb"
        self.adb.parent.mkdir()
        self.adb.write_text("#!/bin/sh\nexit 1\n")
        self.adb.chmod(0o755)
        self.sdk = patch.object(android, "SDK_ADB", self.adb)
        self.sdk.start()
        self.addCleanup(self.sdk.stop)
        self.config = config(self.ledger)

    def collect(self, output=None):
        with patch.object(android, "_existing_server"), patch.object(android, "_run", return_value=(0, response() if output is None else output)):
            return android.collect_host(self.config)


class ConfigurationTests(Fixture):
    def test_exact_config_is_offline_and_copied(self):
        with patch.object(android.subprocess, "Popen", side_effect=AssertionError("No transport")), \
             patch.object(android.socket, "create_connection", side_effect=AssertionError("No server inspection")):
            result = android.validate_config(self.config)
        self.assertEqual(result, self.config)
        self.assertIsNot(result["packages"], self.config["packages"])

    def test_unknown_fields_serials_profiles_and_identity_denied(self):
        for changes in ({"adb_path": "/usr/bin/adb"}, {"serial": "192.168.50.48:5555"},
                        {"serial": "$(id)"}, {"expected_hostname": "friendly-name"},
                        {"transport": "ssh"}, {"user_id": 10}, {"user_id": True},
                        {"ledger": str(self.root / "private-ledger")}, {"shell": "id"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                android.validate_config({**self.config, **changes})
        with self.assertRaises(ValueError):
            android.validate_config({key: value for key, value in self.config.items() if key != "packages"})

    def test_configured_serial_is_not_a_built_in_device_allowlist(self):
        changed = {**self.config, "serial": "ANOTHER_USB_002", "expected_hostname": "ANOTHER_USB_002"}
        self.assertEqual(android.validate_config(changed), changed)
        for serial in ("", "-s", "emulator:5555", "usb serial", "USB\nOTHER", "USB;id", "$(id)", "x" * 129):
            with self.subTest(serial=serial), self.assertRaises(ValueError):
                android.validate_config({**self.config, "serial": serial, "expected_hostname": serial})

    def test_sdk_must_be_existing_executable_not_an_alias(self):
        self.adb.chmod(0o644)
        with self.assertRaises(ValueError):
            android._command(self.config)
        self.adb.chmod(0o755)
        link = self.root / "adb-link"
        link.symlink_to(self.adb)
        with patch.object(android, "SDK_ADB", link), self.assertRaises(ValueError):
            android._command(self.config)

    def test_another_hosts_canonical_ledger_cannot_be_substituted(self):
        other = self.root / "DEVICE_ACCESS_OTHER.md"
        other.touch()
        with self.assertRaises(ValueError):
            android.validate_config({**self.config, "ledger": str(other)})

    def test_package_allowlist_rejects_injection_duplicates_and_overflow(self):
        for packages in ([SORTIE, SORTIE], ["org.example;id"], ["org.example\nsecret"], ["-a"],
                         ["*"], ["org.example:child"], ["$(id)"], [None], "org.example",
                         ["org.app" + str(i) for i in range(17)]):
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                android.validate_config({**self.config, "packages": packages})
        self.assertEqual(android.validate_config({**self.config, "packages": []})["packages"], [])

    def test_canonical_inode_not_alias_or_private_copy(self):
        link = self.root / "link"
        link.symlink_to(self.ledger)
        with self.assertRaises(ValueError):
            android.validate_config({**self.config, "ledger": str(link)})
        with self.assertRaises(ValueError):
            android.validate_config({**self.config, "ledger": str(self.root / "." / "elsewhere")})

    def test_command_is_sdk_explicit_serial_fixed_remote_server_read_only(self):
        args = android._command(self.config)
        self.assertEqual(args[:8], [str(android.SDK_ADB), "-s", SERIAL, "-H", "127.0.0.1", "-P", "5037", "shell"])
        self.assertEqual(args[8:12], ["-T", "-n", "sh", "-c"])
        script = shlex.split(args[-1])[0]
        self.assertIn('cmd package list packages --user 0 -U --show-versioncode "$p"', script)
        self.assertIn("ps -A -n -o UID,NAME", script)
        self.assertLess(script.index('[ "$identity" = '), script.index("dumpsys package"))
        for forbidden in ("start-server", "kill-server", " connect ", "sudo", "install ", "am start", "input ", "logcat", " /data/data"):
            self.assertNotIn(forbidden, script)


class EvidenceTests(Fixture):
    def test_installed_artifacts_are_distinct_from_sampled_running_applications(self):
        result = self.collect()
        self.assertEqual(result["collector"], "android-v1")
        self.assertEqual(result["host"], {"hostname": SERIAL, "os": "Android", "distribution": "Example Handheld Android 13", "architecture": "arm64-v8a"})
        self.assertEqual({a["native_id"] for a in result["artifacts"]}, {SORTIE, SYNC, TRACKER})
        self.assertEqual([w["native_id"] for w in result["workloads"]], [SORTIE])
        work = result["workloads"][0]
        self.assertEqual((work["kind"], work["lifecycle"], work["health"], work["management"]), ("application", "running", "unknown", "discovered"))
        evidence = work["extensions"]["android.v1"]
        self.assertEqual(evidence["process_names"], [SORTIE, SORTIE + ":renderer"])
        self.assertEqual(evidence["process_uids"], [10123])
        self.assertEqual(set(evidence), {"package", "user_id", "package_uid", "version_name", "version_code", "process_names", "process_uids", "limitations"})
        self.assertEqual(scopes(result)["android-package:user:0"]["status"], "complete")
        self.assertEqual(scopes(result)["android:user:0"]["status"], "partial")
        self.assertTrue(all(len(item["id"]) <= 128 for item in result["artifacts"] + result["workloads"]))
        self.assertNotEqual(work["id"], next(a["id"] for a in result["artifacts"] if a["native_id"] == SORTIE))

    def test_profile_and_package_uid_must_both_match(self):
        for uid in ("110123", "10124", "99001"):
            with self.subTest(uid=uid):
                value = response().replace(b"process\t10123\t", ("process\t" + uid + "\t").encode())
                result = android._snapshot(value, self.config)
                self.assertEqual(result["workloads"], [])
                self.assertEqual(len(result["artifacts"]), 3)

    def test_resources_do_not_double_count_emulated_storage_or_invent_gpu_cpu_load(self):
        result = self.collect()
        self.assertEqual(result["cpu"]["logical_count"], 8)
        for key in ("utilization_percent", "load_1m", "sample_seconds"):
            self.assertIsNone(result["cpu"][key])
        self.assertEqual(result["memory"]["available_bytes"], 9000000 * 1024)
        self.assertEqual(len(result["storage"]["filesystems"]), 1)
        self.assertEqual(result["storage"]["filesystems"][0]["mounts"], ["/data"])
        self.assertEqual(result["storage"]["devices"], [])
        self.assertEqual(result["gpus"], [])
        self.assertEqual(scopes(result)["gpus"]["status"], "unavailable")
        self.assertNotIn("gpus", result["resource_observed_at"])

    def test_missing_resource_evidence_has_unavailable_scope_and_no_new_timestamp(self):
        value = response().replace(b"cpu\t8", b"cpu\tunavailable")
        value = b"\n".join(line for line in value.split(b"\n") if not line.startswith((b"memory\t", b"mount\t", b"capacity\t")))
        result = android._snapshot(value, self.config)
        for scope in ("cpu", "memory", "storage"):
            self.assertEqual(scopes(result)[scope]["status"], "unavailable")
            self.assertNotIn(scope, result["resource_observed_at"])
        self.assertIsNone(result["memory"]["available_bytes"])

    def test_failed_package_or_process_discovery_does_not_claim_complete_absence(self):
        value = response().replace(("package\t" + SYNC + "\tpresent\t10124\t205").encode(), ("package\t" + SYNC + "\tunavailable").encode())
        value = value.replace(("version\t" + SYNC + "\t2.0.5\n").encode(), b"")
        value = value.replace(b"process_status\tcomplete", b"process_status\tunavailable")
        result = android._snapshot(value, self.config)
        self.assertEqual(scopes(result)["android-package:user:0"]["status"], "partial")
        self.assertEqual(scopes(result)["android:user:0"]["status"], "unavailable")
        self.assertEqual(result["workloads"], [])
        self.assertEqual({a["native_id"] for a in result["artifacts"]}, {SORTIE, TRACKER})

    def test_confirmed_uninstalled_package_is_not_artifact_or_running(self):
        value = response().replace(("package\t" + SORTIE + "\tpresent\t10123\t102").encode(), ("package\t" + SORTIE + "\tabsent").encode())
        value = value.replace(("version\t" + SORTIE + "\t1.2.0\n").encode(), b"")
        result = android._snapshot(value, self.config)
        self.assertEqual(result["workloads"], [])
        self.assertNotIn(SORTIE, {a["native_id"] for a in result["artifacts"]})

    def test_unknown_raw_truncated_duplicate_identity_and_bad_counters_are_rejected(self):
        samples = [response().replace(SERIAL.encode(), b"other-device", 1), response()[:-4],
                   response().replace(b"end\n", b"dump\tprivate-secret\nend\n"),
                   response().replace(b"end\n", ("identity\t" + SERIAL + "\nend\n").encode()),
                   response().replace(b"cpu\t8", b"cpu\t0"),
                   response().replace(b"memory\tMemAvailable\t9000000", b"memory\tMemAvailable\t999999999"),
                   response().replace(b"process\t10123\t", b"process\tbad\t"),
                   response().replace(SORTIE.encode() + b":renderer", b"org.unconfigured:renderer"),
                   response().replace(b"end\n", b"end\nprivate-secret\n"), b"\xff", b"x" * (android.MAX_STDOUT + 1)]
        for value in samples:
            with self.subTest(value=value[:40]), self.assertRaises(CollectionError) as error:
                android._snapshot(value, self.config)
            self.assertNotIn("private-secret", str(error.exception))

    def test_process_and_package_response_caps(self):
        extra = ("process\t10123\t" + SORTIE + "\n").encode() * android.MAX_PROCESSES
        with self.assertRaises(CollectionError):
            android._snapshot(response().replace(b"process_status", extra + b"process_status"), self.config)
        with self.assertRaises(CollectionError):
            android._snapshot(response().replace(b"end\n", b"package\torg.unconfigured\tabsent\nend\n"), self.config)


class ExistingServerTests(unittest.TestCase):
    class Server:
        def __init__(self, data):
            self.data, self.sent = data, []
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, value):
            self.timeout = value
        def sendall(self, data):
            self.sent.append(data)
        def recv(self, size):
            # Fragmented responses also exercise the bounded exact-read path.
            part, self.data = self.data[:1], self.data[1:]
            return part

    def test_read_only_version_preflight_is_fixed_loopback_and_bounded(self):
        server = self.Server(b"OKAY00040029")
        with patch.object(android.socket, "create_connection", return_value=server) as connect:
            android._existing_server(time.monotonic() + 2)
        self.assertEqual(connect.call_args.args, (("127.0.0.1", 5037),))
        self.assertLessEqual(connect.call_args.kwargs["timeout"], 0.5)
        self.assertEqual(server.sent, [b"000chost:version"])

    def test_absent_mismatched_or_malformed_server_is_refused_without_adb(self):
        for data in (b"", b"FAIL0004oops", b"OKAY00040028", b"OKAYffff0029", b"OKAY0004002"):
            with self.subTest(data=data), patch.object(android.socket, "create_connection", return_value=self.Server(data)), \
                 patch.object(android.subprocess, "Popen", side_effect=AssertionError("No adb repair")), self.assertRaises(CollectionError):
                android._existing_server(time.monotonic() + 1)
        with patch.object(android.socket, "create_connection", side_effect=ConnectionRefusedError), self.assertRaises(CollectionError):
            android._existing_server(time.monotonic() + 1)


class LeaseAndTransportTests(Fixture):
    def events(self):
        return [json.loads(line) for line in self.ledger.read_text().splitlines()[1:]]

    def test_busy_canonical_lease_prevents_server_and_adb_calls(self):
        with self.ledger.open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            with patch.object(android, "_existing_server", side_effect=AssertionError("No target access")), \
                 patch.object(android, "_run", side_effect=AssertionError("No adb")), self.assertRaises(LeaseBusy):
                android.collect_host(self.config)
        self.assertEqual(self.events(), [])

    def test_receipt_is_inside_lease_bound_to_claim_and_sanitized_evidence(self):
        original = android._receipt
        def receipt(*args):
            with self.ledger.open("a") as stream:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            original(*args)
        with patch.object(android, "_receipt", side_effect=receipt):
            self.collect()
        events = self.events()
        self.assertEqual([event["event"] for event in events], ["CLAIM", "OBSERVATION", "RELEASE"])
        self.assertEqual(events[0]["lease_id"], events[1]["lease_id"])
        self.assertEqual(events[1]["lease_id"], events[2]["lease_id"])
        self.assertEqual(len(events[1]["outcome"]["snapshot_sha256"]), 64)
        self.assertEqual(events[2]["outcome"], "completed")

    def test_missing_server_transport_failure_and_cancellation_receipt_before_unlock(self):
        for failure in (CollectionError("Existing compatible local ADB server required"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), patch.object(android, "_existing_server", side_effect=failure), \
                 patch.object(android, "_run", side_effect=AssertionError("No adb")), self.assertRaises(type(failure)):
                android.collect_host(self.config)
            self.assertEqual(self.events()[-2]["outcome"], "failed")
            self.assertEqual(self.events()[-1]["event"], "RELEASE")
        with patch.object(android, "_existing_server"), patch.object(android, "_run", return_value=(1, b"raw-private-secret")), self.assertRaises(CollectionError) as error:
            android.collect_host(self.config)
        self.assertNotIn("raw-private-secret", str(error.exception))
        self.assertNotIn("raw-private-secret", self.ledger.read_text())

    def test_real_local_fake_command_bounds_stdout_stderr_and_deadline(self):
        for stream, limit in (("stdout", android.MAX_STDOUT), ("stderr", android.MAX_STDERR)):
            code = "import sys,time; sys." + stream + ".write('x'*" + str(limit + 8192) + "); sys." + stream + ".flush(); time.sleep(10)"
            with self.subTest(stream=stream), self.assertRaisesRegex(CollectionError, "output limit"):
                android._run([sys.executable, "-I", "-S", "-c", code], time.monotonic() + 2)
        with self.assertRaisesRegex(CollectionError, "deadline"):
            android._run([sys.executable, "-I", "-S", "-c", "import time; time.sleep(10)"], time.monotonic() + 0.2)

    def test_real_cancellation_reaps_child_and_uses_devnull_clean_environment(self):
        original = android.subprocess.Popen
        children = []
        def spawn(*args, **kwargs):
            self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
            self.assertTrue(kwargs["start_new_session"])
            self.assertTrue(kwargs["close_fds"])
            self.assertNotIn("ADB_SERVER_SOCKET", kwargs["env"])
            self.assertNotIn("ADB_TRACE", kwargs["env"])
            child = original(*args, **kwargs)
            children.append(child)
            return child
        selector = android.selectors.DefaultSelector()
        with patch.object(android.subprocess, "Popen", side_effect=spawn), \
             patch.object(android.selectors, "DefaultSelector", return_value=selector), \
             patch.object(selector, "select", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            android._run([sys.executable, "-I", "-S", "-c", "import time; time.sleep(10)"], time.monotonic() + 2)
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed)
        self.assertTrue(children[0].stderr.closed)

    def test_real_process_group_is_cleaned_before_receipt_and_release(self):
        child_file = self.root / "children"
        fake = self.root / "fake-adb"
        code = ("import os,subprocess,sys,time,signal\n"
                "child=subprocess.Popen([sys.executable,'-I','-S','-c','import time; time.sleep(10)'])\n"
                "def stop(sig, frame):\n child.wait(timeout=1); sys.exit(0)\n"
                "signal.signal(signal.SIGTERM,stop)\n"
                "open(" + repr(str(child_file)) + ",'w').write(str(os.getpid())+' '+str(child.pid))\n"
                "time.sleep(10)\n")
        fake.write_text("#!" + sys.executable + "\n" + code)
        fake.chmod(0o700)
        original = android._receipt
        def receipt(*args):
            self.assertTrue(child_file.exists())
            for pid in map(int, child_file.read_text().split()):
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
            with self.ledger.open("a") as stream:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            original(*args)
        with patch.object(android, "SDK_ADB", fake), patch.object(android, "_existing_server"), \
             patch.object(android, "DEADLINE_SECONDS", 0.5), patch.object(android, "_receipt", side_effect=receipt), \
             self.assertRaisesRegex(CollectionError, "deadline"):
            android.collect_host(self.config)
        self.assertEqual(self.events()[-1]["event"], "RELEASE")

    def test_on_device_filters_run_against_only_isolated_fake_command_fixtures(self):
        awk = shutil.which("awk")
        if awk is None:
            self.skipTest("awk required for fixed Android filter fixture")
        meminfo = self.root / "meminfo"
        meminfo.write_text("MemTotal: 16000000 kB\nMemAvailable: 9000000 kB\nSwapTotal: 4000000 kB\nSwapFree: 2000000 kB\nSecret: PRIVATE_PAYLOAD\n")
        mounts = self.root / "mounts"
        mounts.write_text("/dev/block/dm-17 /data f2fs rw,seclabel 0 0\n/dev/fuse /storage/emulated fuse rw 0 0\n")
        program = self.root / "fixture-command"
        fixture_source = ("import os,sys\nname=os.path.basename(sys.argv[0]); args=sys.argv[1:]\n"
                          "if name=='getprop':\n print(" + repr({"ro.serialno": SERIAL, "ro.product.model": "Example Handheld", "ro.build.version.release": "13", "ro.product.cpu.abi": "arm64-v8a", "ro.soc.model": "QTI SG8275"}) + ".get(args[0],''))\n"
                          "elif name=='getconf': print('8')\n"
                          "elif name=='df': print('Filesystem 1K-blocks Used Available Use% Mounted on\\n/dev/block/dm-17 1000 600 400 60% /data/obb')\n"
                          "elif name=='cmd':\n p=args[-1]; uid={" + repr(SORTIE) + ":10123," + repr(SYNC) + ":10124," + repr(TRACKER) + ":10125}[p]; print('package:'+p+' versionCode:17 uid:'+str(uid))\n"
                          "elif name=='dumpsys':\n p=args[-1]; print('PRIVATE_PAYLOAD\\n  Package ['+p+'] (fixture):\\n    versionName=1.2.3\\n    extras=PRIVATE_PAYLOAD')\n"
                          "elif name=='ps': print('UID NAME\\n10123 " + SORTIE + "\\n110123 " + SORTIE + "\\n10124 unconfigured.private\\n10123 " + SORTIE + ":renderer')\n"
                          "else: sys.exit(9)\n")
        program.write_text("#!" + sys.executable + "\n" + fixture_source)
        program.chmod(0o700)
        for name in ("getprop", "getconf", "df", "cmd", "dumpsys", "ps"):
            (self.root / name).symlink_to(program)
        # The fake SDK executes the exact fixed filters with fixture-only proc
        # paths, never reading this workstation's counters or process table.
        fake = self.root / "fake-adb"
        fake.write_text("#!" + sys.executable + "\nimport os,shlex,sys\n"
                        "script=shlex.split(sys.argv[-1])[0].replace('/proc/meminfo'," + repr(shlex.quote(str(meminfo))) + ").replace('/proc/mounts'," + repr(shlex.quote(str(mounts))) + ")\n"
                        "os.environ['PATH']=" + repr(str(self.root) + ":" + str(Path(awk).parent) + ":/usr/bin:/bin") + "\n"
                        "os.execv('/bin/sh',['sh','-c',script])\n")
        fake.chmod(0o700)
        with patch.object(android, "SDK_ADB", fake), patch.object(android, "_existing_server"):
            result = android.collect_host(self.config)
        self.assertEqual([w["native_id"] for w in result["workloads"]], [SORTIE])
        self.assertEqual(len(result["artifacts"]), 3)
        self.assertEqual(result["storage"]["filesystems"][0]["available_bytes"], 400 * 1024)
        self.assertNotIn("PRIVATE_PAYLOAD", json.dumps(result))
        self.assertNotIn("PRIVATE_PAYLOAD", self.ledger.read_text())
        self.assertNotIn("unconfigured.private", json.dumps(result))
        self.assertEqual(result["workloads"][0]["extensions"]["android.v1"]["process_uids"], [10123])


if __name__ == "__main__":
    unittest.main()
