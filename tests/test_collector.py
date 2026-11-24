"""Isolated collector regressions: no test contacts a host or collects this machine."""
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from switchyard import collector, locks, probe
from switchyard.leases import LeaseBusy


def config():
    return {"host_id": "test-host", "transport": "local", "expected_hostname": "fixture",
            "user_units": ["example.service", "schedule.timer"], "system_units": ["daemon.service"]}


def snapshot():
    at = "2026-11-22T00:00:00+00:00"
    return {"schema_version": 1, "host_id": "test-host", "observed_at": at, "collector": "linux-v1",
            "host": {"hostname": "fixture", "os": "Linux", "distribution": "Fixture Linux", "architecture": "x86_64"},
            "cpu": {"model": None, "logical_count": 2, "utilization_percent": 20.0, "sample_seconds": 0.1, "load_1m": 0.0},
            "memory": {"total_bytes": 1024, "available_bytes": 512, "swap_total_bytes": 0, "swap_free_bytes": 0},
            "gpus": [], "storage": {"devices": [], "filesystems": []}, "workloads": [],
            "coverage": [{"scope": scope, "status": "partial" if scope.startswith("systemd:") else "complete", "message": "fixture"}
                         for scope in ("cpu", "memory", "gpus", "storage", "systemd:user:1000", "systemd:system")],
            "warnings": []}


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "collectors.json"
        self.ledger = Path(self.temp.name) / "ledger"
        self.ledger.touch()

    def load(self, record):
        self.path.write_text(json.dumps({"schema_version": 1, "hosts": [record]}))
        return collector.load_config(self.path)

    def remote(self):
        return {**config(), "transport": "ssh", "target": "observer@fixture.test", "ledger": str(self.ledger)}

    def test_none_and_offline_loading(self):
        self.assertEqual(collector.load_config(None), {})
        with patch.object(collector.subprocess, "Popen", side_effect=AssertionError("No execution while loading")):
            self.assertEqual(self.load(self.remote())["test-host"], self.remote())

    def test_unit_injection_patterns_and_scope_denied(self):
        for unit in ("--all.service", "*.service", "foo;id.service", "foo\nbar.service", "foo.socket", "foo/service.service", "$(id).service", "foo\\x20.service"):
            record = config()
            record["user_units"] = [unit]
            with self.subTest(unit=unit), self.assertRaises(ValueError):
                self.load(record)
        for extra in ({"command": "id"}, {"uid": 0}, {"target": "observer@fixture"}, {"system_units": ["daemon.service"] * 33}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.load({**config(), **extra})

    def test_target_injection_root_and_duplicate_fields_denied(self):
        for target in ("root@fixture", "observer@fixture;id", "observer@-option", "observer@fixture\nfoo", "observer@999.1.1.1", "observer@fixture $(id)", "-oProxyCommand=x@fixture"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.load({**self.remote(), "target": target})
        self.path.write_text('{"schema_version":1,"schema_version":1,"hosts":[]}')
        with self.assertRaises(ValueError):
            collector.load_config(self.path)

    def test_symlink_ledger_and_missing_ledger_denied(self):
        link = Path(self.temp.name) / "link"
        link.symlink_to(self.ledger)
        for ledger in (link, Path(self.temp.name) / "missing"):
            with self.subTest(ledger=ledger), self.assertRaises(ValueError):
                self.load({**self.remote(), "ledger": str(ledger)})

    def test_explicit_canonical_ledger_does_not_depend_on_endpoint(self):
        record = {**self.remote(), "target": "operator@192.168.50.20"}
        self.assertEqual(self.load(record)["test-host"], record)

    def test_portable_ledger_root_and_explicit_override(self):
        with patch.dict(os.environ, {"XDG_STATE_HOME": str(Path(self.temp.name) / "state")}, clear=True):
            self.assertEqual(locks._default_ledger_dir(), Path(self.temp.name) / "state/switchyard/ledgers")
            with patch.dict(os.environ, {"SWITCHYARD_LEDGER_DIR": str(Path(self.temp.name) / "shared")}):
                self.assertEqual(locks._default_ledger_dir(), Path(self.temp.name) / "shared")
        with patch.dict(os.environ, {}, clear=True), patch.object(Path, "home", return_value=Path(self.temp.name)):
            self.assertEqual(locks._default_ledger_dir(), Path(self.temp.name) / ".local/state/switchyard/ledgers")

    def test_config_byte_limit(self):
        self.path.write_text(" " * 65537)
        with self.assertRaises(ValueError):
            collector.load_config(self.path)

    def test_container_engines_are_explicit_unique_names(self):
        for engines in (None, "podman", ["podman", "podman"], ["containerd"], ["docker", "podman", "docker"], [True]):
            with self.subTest(engines=engines), self.assertRaises(ValueError):
                self.load({**config(), "container_engines": engines})
        record = {**config(), "container_engines": ["podman", "docker"]}
        self.assertEqual(self.load(record)["test-host"], record)
        self.assertNotIn("container_engines", self.load(config())["test-host"])

    def test_adb_validation_and_collection_use_lazy_adapter(self):
        import types
        record = {"host_id": "android", "transport": "adb"}
        adapter = types.ModuleType("switchyard.android")
        with patch.dict(sys.modules, {"switchyard.android": adapter}), \
             patch.object(adapter, "validate_config", create=True, return_value=record) as validate, \
             patch.object(adapter, "collect_host", create=True, return_value={"android": "fixture"}) as collect, \
             patch.object(collector, "_probe_source", side_effect=AssertionError("No Linux batch for ADB")):
            self.assertEqual(self.load(record), {"android": record})
            self.assertEqual(collector.collect_host(record), {"android": "fixture"})
        self.assertEqual(validate.call_count, 2)
        collect.assert_called_once_with(record)

    def test_composed_probe_is_standalone_stdlib_source(self):
        source = collector._probe_source({**config(), "container_engines": ["podman"]}).decode()
        compile(source, "<fixed-probe>", "exec")
        namespace = {"__name__": "__fixed_probe__", "__package__": None}
        exec(source.rsplit("\nmain(json.loads(", 1)[0], namespace)
        self.assertEqual(namespace["container_probe"].validate_engines(["podman"]), ["podman"])
        self.assertIn('"container_engines": ["podman"]', source)

    def test_ssh_is_one_fixed_no_forward_strict_channel(self):
        args = collector._ssh_command(self.remote())
        self.assertEqual(args.count("ssh"), 1)
        for option in ("StrictHostKeyChecking=yes", "BatchMode=yes", "ControlPath=none", "ClearAllForwardings=yes", "ConnectTimeout=5", "ProxyCommand=none"):
            self.assertIn(option, args)
        self.assertEqual(args[-2:], ["observer@fixture.test", "python3 -I -S -"])
        source = collector._probe_source(config()).decode()
        self.assertIn("main(json.loads(", source)
        self.assertNotIn("observer@", source)



class SamplingTests(unittest.TestCase):
    @staticmethod
    def fast_snapshot(total=100, idle=30, uptime=100, boot="11111111-1111-1111-1111-111111111111"):
        value = snapshot()
        value["coverage"] = [entry for entry in value["coverage"] if entry["scope"] not in {"gpus", "storage"}]
        value["cpu"].update(utilization_percent=None, sample_seconds=None,
                            counters={"total_ticks": total, "idle_ticks": idle,
                                      "uptime_seconds": uptime, "boot_id": boot})
        return value

    def test_cpu_delta_uses_remote_uptime_and_first_or_reset_is_unknown(self):
        first = self.fast_snapshot()
        result = collector._apply_cpu_delta(self.fast_snapshot(), None)
        self.assertIsNone(result["cpu"]["utilization_percent"])
        result = collector._apply_cpu_delta(self.fast_snapshot(300, 80, 165), first)
        self.assertEqual(result["cpu"]["utilization_percent"], 75)
        self.assertEqual(result["cpu"]["sample_seconds"], 65)
        resets = (self.fast_snapshot(300, 80, 165, "22222222-2222-2222-2222-222222222222"),
                  self.fast_snapshot(90, 20, 165), self.fast_snapshot(300, 20, 165),
                  self.fast_snapshot(300, 80, 10), self.fast_snapshot(100, 30, 100))
        for current in resets:
            with self.subTest(counters=current["cpu"]["counters"]):
                result = collector._apply_cpu_delta(current, first)
                self.assertIsNone(result["cpu"]["utilization_percent"])
                self.assertIsNone(result["cpu"]["sample_seconds"])

    def test_modes_validate_only_the_scopes_they_own(self):
        fast = self.fast_snapshot()
        self.assertEqual(collector._validate_snapshot(json.dumps(fast), config(), mode="fast")["host_id"], "test-host")
        for change in (lambda s: s["cpu"].update(counters=None),
                       lambda s: s["cpu"]["counters"].update(idle_ticks=101),
                       lambda s: s["cpu"]["counters"].update(boot_id="not-a-boot-id"),
                       lambda s: s["cpu"].update(utilization_percent=25, sample_seconds=10),
                       lambda s: s["coverage"].append({"scope": "storage", "status": "complete", "message": ""})):
            bad = self.fast_snapshot()
            change(bad)
            with self.assertRaises(collector.CollectionError):
                collector._validate_snapshot(json.dumps(bad), config(), mode="fast")
        storage = snapshot()
        storage["coverage"] = [c for c in storage["coverage"] if c["scope"] == "storage"]
        self.assertEqual(collector._validate_snapshot(json.dumps(storage), config(), mode="storage")["coverage"][0]["scope"], "storage")
        with self.assertRaises(collector.CollectionError):
            collector._validate_snapshot(json.dumps(fast), config())

    def test_fast_probe_does_not_scan_storage_gpu_images_or_sleep(self):
        with patch.object(probe.platform, "system", return_value="Linux"), \
             patch.object(probe.platform, "node", return_value="fixture"), \
             patch.object(probe.platform, "machine", return_value="x86_64"), \
             patch.object(probe.os, "geteuid", return_value=1000), patch.object(probe.os, "getuid", return_value=1000), \
             patch.object(probe, "text", side_effect=OSError), \
             patch.object(probe, "cpu_fast", return_value=self.fast_snapshot()["cpu"]), \
             patch.object(probe, "memory", return_value=snapshot()["memory"]), \
             patch.object(probe, "cpu", side_effect=AssertionError("short sampling forbidden")), \
             patch.object(probe, "storage", side_effect=AssertionError("storage scan forbidden")), \
             patch.object(probe, "gpus", side_effect=AssertionError("PCI scan forbidden")), \
             patch.object(probe.time, "sleep", side_effect=AssertionError("sleep forbidden")), \
             patch.object(probe.container_probe, "observe_containers", side_effect=AssertionError("container scan forbidden")), \
             patch.object(probe, "systemctl", return_value=({}, 1)):
            value = probe.observe({**config(), "mode": "fast"})
        self.assertEqual({c["scope"] for c in value["coverage"]},
                         {"cpu", "memory", "systemd:user:1000", "systemd:system"})

    def test_storage_probe_does_not_read_other_scopes(self):
        with patch.object(probe.platform, "system", return_value="Linux"), \
             patch.object(probe.platform, "node", return_value="fixture"), \
             patch.object(probe.platform, "machine", return_value="x86_64"), \
             patch.object(probe.os, "geteuid", return_value=1000), patch.object(probe, "text", side_effect=OSError), \
             patch.object(probe, "storage", return_value=({"devices": [], "filesystems": []}, False)), \
             patch.object(probe, "cpu", side_effect=AssertionError("CPU forbidden")), \
             patch.object(probe, "cpu_fast", side_effect=AssertionError("CPU forbidden")), \
             patch.object(probe, "memory", side_effect=AssertionError("memory forbidden")), \
             patch.object(probe, "gpus", side_effect=AssertionError("GPU forbidden")), \
             patch.object(probe, "systemctl", side_effect=AssertionError("units forbidden")), \
             patch.object(probe.container_probe, "observe_containers", side_effect=AssertionError("containers forbidden")):
            value = probe.observe({**config(), "mode": "storage"})
        self.assertEqual([c["scope"] for c in value["coverage"]], ["storage"])

    def test_fast_counter_reader_never_sleeps(self):
        with patch.object(probe, "cpu_ticks", return_value=(100, 30)), \
             patch.object(probe, "text", side_effect=["100.25 0.0", "11111111-1111-1111-1111-111111111111", "model name : Test CPU"]), \
             patch.object(probe.os, "cpu_count", return_value=4), \
             patch.object(probe.os, "getloadavg", return_value=(0, 0, 0)), \
             patch.object(probe.time, "sleep", side_effect=AssertionError("sleep forbidden")):
            value = probe.cpu_fast()
        self.assertEqual(value["counters"]["uptime_seconds"], 100.25)
        self.assertIsNone(value["utilization_percent"])
        self.assertEqual(value["model"], "Test CPU")

    def test_monitor_intervals_bounded_and_android_cannot_opt_in(self):
        intervals = {"fast_seconds": 10, "storage_seconds": 60, "inventory_seconds": 300}
        self.assertEqual(collector._validate_config({**config(), "monitor": intervals})["monitor"], intervals)
        for key, value in (("fast_seconds", 9), ("storage_seconds", 59), ("inventory_seconds", 299),
                           ("fast_seconds", True), ("fast_seconds", 86401)):
            with self.assertRaises(ValueError):
                collector._validate_config({**config(), "monitor": {**intervals, key: value}})
        with self.assertRaises(ValueError):
            collector._validate_config({"transport": "adb", "monitor": intervals})


class NativeEvidenceTests(unittest.TestCase):
    def test_workload_id_is_stable_bounded_and_scope_distinct(self):
        host = "h" * 64
        unit = "u" * 170 + ".service"
        system = probe.workload(host, "system", unit, {}, "2026-11-22T00:00:00Z")
        user = probe.workload(host, "user:1000", unit, {}, "2026-11-22T00:00:00Z")
        self.assertLessEqual(len(system["id"]), 128)
        self.assertNotEqual(system["id"], user["id"])
        self.assertEqual(system["native_id"], unit)
        self.assertEqual(system["id"], probe.workload(host, "system", unit, {}, "2026-11-23T00:00:00Z")["id"])

    def test_states_are_not_health_checks(self):
        cases = [("loaded", "active", "waiting", "x.timer", "idle"),
                 ("loaded", "active", "exited", "x.service", "completed"),
                 ("loaded", "active", "running", "x.service", "running"),
                 ("not-found", "active", "running", "x.service", "unknown"),
                 ("loaded", "inactive", "dead", "x.service", "stopped"),
                 ("loaded", "failed", "failed", "x.service", "failed"),
                 ("loaded", "active", "mystery", "x.service", "unknown")]
        for load, active, sub, unit, expected in cases:
            properties = {"Id": unit, "LoadState": load, "ActiveState": active, "SubState": sub}
            with self.subTest(properties=properties):
                work = probe.workload("test-host", "system", unit, properties, "2026-11-22T00:00:00Z")
                self.assertEqual(work["lifecycle"], expected)
                self.assertEqual(work["health"], "unknown")

    def test_parser_rejects_aliases_extra_properties_duplicate_and_overflow(self):
        valid = "Id=x.service\nLoadState=loaded\nActiveState=active\nSubState=running\n"
        self.assertEqual(probe.parse_units(valid, ["x.service"])["x.service"]["SubState"], "running")
        for output in (valid + "Environment=secret\n", valid + "Id=x.service\n", valid.replace("x.service", "alias.service"),
                       valid + "\n" + valid, "Id=x.service\nResult=" + "x" * 1025, ""):
            with self.subTest(output=output[:80]), self.assertRaises(ValueError):
                probe.parse_units(output, ["x.service"])

    def test_probe_scope_failure_is_not_empty_complete(self):
        with patch.object(probe.platform, "system", return_value="Linux"), patch.object(probe.platform, "node", return_value="fixture"), \
             patch.object(probe.os, "geteuid", return_value=1000), patch.object(probe.os, "getuid", return_value=1000), \
             patch.object(probe, "text", side_effect=OSError), patch.object(probe, "cpu", side_effect=OSError), \
             patch.object(probe, "memory", side_effect=OSError), patch.object(probe, "gpus", return_value=[]), \
             patch.object(probe, "storage", return_value=({"devices": [], "filesystems": []}, True)), \
             patch.object(probe, "systemctl", side_effect=OSError), patch.object(probe, "paseo_http", side_effect=OSError), \
             patch.object(probe, "paseo_cli_candidates", return_value=[]):
            value = probe.observe(config())
        coverage = {c["scope"]: c["status"] for c in value["coverage"]}
        self.assertEqual(coverage["systemd:user:1000"], "unavailable")
        self.assertEqual(coverage["storage"], "partial")
        self.assertIsNone(value["cpu"]["utilization_percent"])
        self.assertEqual(value["workloads"], [])

    def test_identity_check_precedes_resource_reads_and_denies_root(self):
        with patch.object(probe.platform, "system", return_value="Linux"), patch.object(probe.platform, "node", return_value="wrong"), \
             patch.object(probe.os, "geteuid", return_value=1000), patch.object(probe, "cpu", side_effect=AssertionError("must not collect")):
            with self.assertRaises(ValueError):
                probe.observe(config())
        with patch.object(probe.platform, "system", return_value="Linux"), patch.object(probe.os, "geteuid", return_value=0):
            with self.assertRaises(ValueError):
                probe.observe(config())

    def test_snapshot_strict_identity_scope_and_native_evidence(self):
        self.assertEqual(collector._validate_snapshot(json.dumps(snapshot()), config())["host_id"], "test-host")
        mutations = [lambda s: s["host"].update(hostname="other"), lambda s: s["cpu"].update(sample_seconds=0.3),
                     lambda s: s["memory"].update(total_bytes=True), lambda s: s.update(unexpected=True),
                     lambda s: s["coverage"].append({"scope": "processes", "status": "complete", "message": "no"})]
        for mutate in mutations:
            value = snapshot()
            mutate(value)
            with self.assertRaises(collector.CollectionError):
                collector._validate_snapshot(json.dumps(value), config())
        props = {"Id": "example.service", "LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead"}
        value = snapshot()
        work = probe.workload("test-host", "user:1000", "example.service", props, value["observed_at"])
        value["workloads"] = [work]
        self.assertEqual(collector._validate_snapshot(json.dumps(value), config())["workloads"][0]["lifecycle"], "unknown")
        work["lifecycle"] = "running"
        with self.assertRaises(collector.CollectionError):
            collector._validate_snapshot(json.dumps(value), config())


class ResourceTests(unittest.TestCase):
    def test_short_cpu_sample_rejects_counter_reset_and_late_interval(self):
        with patch.object(probe, "cpu_ticks", side_effect=[(100, 30), (120, 35)]), \
             patch.object(probe.time, "monotonic", side_effect=[0, 0.1]), patch.object(probe.time, "sleep"), \
             patch.object(probe, "text", return_value="model name : Fixture CPU"), \
             patch.object(probe.os, "cpu_count", return_value=4), patch.object(probe.os, "getloadavg", return_value=(1, 2, 3)):
            result = probe.cpu()
        self.assertEqual(result["utilization_percent"], 75)
        self.assertEqual(result["sample_seconds"], 0.1)
        with patch.object(probe, "cpu_ticks", side_effect=[(100, 30), (90, 20)]), \
             patch.object(probe.time, "monotonic", side_effect=[0, 0.3]), patch.object(probe.time, "sleep"), \
             patch.object(probe, "text", return_value=""), patch.object(probe.os, "getloadavg", return_value=(0, 0, 0)):
            result = probe.cpu()
        self.assertIsNone(result["utilization_percent"])
        self.assertIsNone(result["sample_seconds"])

    def test_memory_uses_available_not_free_and_never_invents_values(self):
        with patch.object(probe, "text", return_value="MemTotal: 100 kB\nMemFree: 5 kB\nMemAvailable: 20 kB\nSwapTotal: 0 kB"):
            result = probe.memory()
        self.assertEqual(result["available_bytes"], 20 * 1024)
        self.assertIsNone(result["swap_free_bytes"])

    def test_gpu_does_not_read_telemetry_on_suspended_device(self):
        # Intel also makes discrete GPUs: vendor identity does not prove shared RAM.
        for vendor in ("0x10de", "0x8086"):
            with self.subTest(vendor=vendor), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                device = root / "0000:01:00.0"
                (device / "power").mkdir(parents=True)
                for name, value in (("class", "0x030000"), ("vendor", vendor), ("device", "0x1c20"), ("power/runtime_status", "suspended")):
                    (device / name).write_text(value)
                with patch.object(probe, "Path", return_value=root), patch.object(probe, "integer", side_effect=AssertionError("must not wake GPU")):
                    result = probe.gpus()
                self.assertIsNone(result[0]["busy_percent"])
                self.assertIsNone(result[0]["vram_total_bytes"])
                self.assertEqual(result[0]["memory_kind"], "unknown")

    def test_mount_capacity_dedup_and_unknown_network_not_statted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            blocks = root / "block"
            blocks.mkdir()
            disk = blocks / "sda"
            (disk / "device").mkdir(parents=True)
            (disk / "queue").mkdir()
            for name, value in (("dev", "8:0"), ("size", "200"), ("queue/rotational", "1"), ("device/model", "fixture")):
                (disk / name).write_text(value)
            (root / "btrfs").mkdir()
            mounts = ("1 0 8:0 / /data rw - ext4 /dev/sda rw\n"
                      "2 0 8:0 /sub /view rw - ext4 /dev/sda rw\n"
                      "3 0 0:2 / /ram rw - tmpfs tmpfs rw\n"
                      "4 0 0:3 / /network rw - nfs server:/share rw\n")
            original_text = probe.text
            def metadata(path, limit=probe.READ_LIMIT):
                return mounts if str(path) == "/proc/self/mountinfo" else original_text(path, limit)
            def paths(path):
                return blocks if str(path) == "/sys/class/block" else root / "btrfs"
            stats = type("Stat", (), {"f_blocks": 100, "f_bavail": 60, "f_bfree": 70, "f_frsize": 1024})()
            with patch.object(probe, "Path", side_effect=paths), patch.object(probe, "text", side_effect=metadata), \
                 patch.object(probe.os, "statvfs", return_value=stats) as statvfs:
                result, partial = probe.storage()
            self.assertEqual([call.args[0] for call in statvfs.call_args_list], ["/data", "/ram"])
        self.assertTrue(partial)
        filesystem = next(f for f in result["filesystems"] if f["type"] == "ext4")
        self.assertEqual(filesystem["mounts"], ["/data", "/view"])
        self.assertEqual(filesystem["backing_device_ids"], ["block:sda"])
        self.assertEqual(len(result["devices"]), 1)
        self.assertEqual(next(f for f in result["filesystems"] if f["type"] == "tmpfs")["kind"], "volatile")

    def test_only_allowlisted_block_backed_fuse_capacity_is_read(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            blocks = root / "block"
            blocks.mkdir()
            for name, dev in (("sda", "8:0"), ("sdb", "8:16"), ("sdc", "8:32")):
                disk = blocks / name
                (disk / "device").mkdir(parents=True)
                (disk / "queue").mkdir()
                for key, value in (("dev", dev), ("size", "200"), ("queue/rotational", "1"), ("device/model", "fixture")):
                    (disk / key).write_text(value)
            (root / "btrfs").mkdir()
            mounts = ("1 0 8:0 / /mnt/listed rw - fuseblk /dev/sda rw\n"
                      "2 0 8:16 / /mnt/unlisted rw - fuseblk /dev/sdb rw\n"
                      "3 0 0:40 / /home/user/remote rw - fuse.rclone remote: rw\n")
            original_text = probe.text
            def metadata(path, limit=probe.READ_LIMIT):
                return mounts if str(path) == "/proc/self/mountinfo" else original_text(path, limit)
            def paths(path):
                return blocks if str(path) == "/sys/class/block" else root / "btrfs"
            allowed = probe.validate_mounts(["/mnt/listed", "/home/user/remote", "/mnt/absent"])
            with patch.object(probe, "Path", side_effect=paths), patch.object(probe, "text", side_effect=metadata), \
                 patch.object(probe.os, "statvfs", side_effect=AssertionError("FUSE must not be statted in-process")), \
                 patch.object(probe, "external_statfs", return_value=(1000, 400, 500)) as external:
                result, partial = probe.storage(allowed)
        # Network FUSE stays unread even when listed; the absent listed mount makes coverage partial.
        self.assertEqual([call.args[0] for call in external.call_args_list], ["/mnt/listed"])
        self.assertTrue(partial)
        by_mount = {f["mounts"][0]: f for f in result["filesystems"]}
        self.assertEqual((by_mount["/mnt/listed"]["kind"], by_mount["/mnt/listed"]["available_bytes"]), ("persistent", 400))
        self.assertEqual((by_mount["/mnt/unlisted"]["kind"], by_mount["/mnt/unlisted"]["total_bytes"]), ("unknown", None))
        self.assertIsNone(by_mount["/home/user/remote"]["total_bytes"])

    def test_storage_mount_allowlist_rejects_relative_traversal_and_duplicates(self):
        for mounts in (["relative"], ["/mnt/../etc"], ["/mnt/a", "/mnt/a"], ["/mnt/a\n"], ["/mnt/a/"], "/mnt/a", [f"/m{i}" for i in range(33)]):
            with self.subTest(mounts=mounts), self.assertRaises(ValueError):
                probe.validate_mounts(mounts)
        self.assertEqual(probe.validate_mounts(["/", "/mnt/disk 1"]), frozenset({"/", "/mnt/disk 1"}))


class ProcessAndLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ledger = Path(self.temp.name) / "ledger"
        self.ledger.write_text("fixture ledger\n")
        self.remote = {**config(), "transport": "ssh", "target": "observer@fixture.test", "ledger": str(self.ledger)}

    def run_python(self, code, seconds=2):
        return collector._run([sys.executable, "-I", "-S", "-c", code], b"", time.monotonic() + seconds)

    def test_bounded_stdout_and_stderr_reap_owned_child(self):
        for stream, limit in (("stdout", collector.MAX_STDOUT), ("stderr", collector.MAX_STDERR)):
            with self.subTest(stream=stream), self.assertRaisesRegex(collector.CollectionError, "output limit"):
                self.run_python("import sys,time; sys." + stream + ".write('x'*" + str(limit + 8192) + "); sys." + stream + ".flush(); time.sleep(10)")

    def test_timeout_reaps_process_group(self):
        pid_file = Path(self.temp.name) / "pid"
        code = "import os,time; open(" + repr(str(pid_file)) + ",'w').write(str(os.getpid())); time.sleep(10)"
        with self.assertRaisesRegex(collector.CollectionError, "deadline"):
            self.run_python(code, 0.5)
        pid = int(pid_file.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_interrupt_reaps_real_owned_child(self):
        original_popen = collector.subprocess.Popen
        children = []
        def spawn(*args, **kwargs):
            child = original_popen(*args, **kwargs)
            children.append(child)
            return child
        selector = collector.selectors.DefaultSelector()
        with patch.object(collector.selectors, "DefaultSelector", return_value=selector), \
             patch.object(selector, "select", side_effect=KeyboardInterrupt), patch.object(collector.subprocess, "Popen", side_effect=spawn):
            with self.assertRaises(KeyboardInterrupt):
                self.run_python("import time; time.sleep(10)")
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed)

    def test_cancellation_reaps_before_lease_receipt_and_release(self):
        events = []
        original = collector._receipt
        def receipt(*args):
            events.append("receipt")
            with self.ledger.open("a") as stream:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            original(*args)
        with patch.object(collector, "_run", side_effect=KeyboardInterrupt), patch.object(collector, "_receipt", side_effect=receipt):
            with self.assertRaises(KeyboardInterrupt):
                collector.collect_host(self.remote)
        self.assertEqual(events, ["receipt"])
        self.assertIn('"event": "RELEASE"', self.ledger.read_text())
        self.assertLess(self.ledger.read_text().index('"event": "OBSERVATION"'), self.ledger.read_text().index('"event": "RELEASE"'))

    def test_lease_refusal_does_not_spawn(self):
        with self.ledger.open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            with patch.object(collector, "_run", side_effect=AssertionError("No transport while busy")):
                with self.assertRaises(LeaseBusy):
                    collector.collect_host(self.remote)
        self.assertNotIn('"event": "CLAIM"', self.ledger.read_text())

    def test_failure_preserves_sanitization_and_receipt(self):
        with patch.object(collector, "_run", return_value=(255, b"password and remote errors")):
            with self.assertRaises(collector.CollectionError) as error:
                collector.collect_host(self.remote)
        self.assertNotIn("password", str(error.exception))
        self.assertIn('"outcome": "failed"', self.ledger.read_text())

    def test_success_receipt_includes_evidence_before_release(self):
        output = json.dumps(snapshot()).encode()
        with patch.object(collector, "_run", return_value=(0, output)):
            self.assertEqual(collector.collect_host(self.remote)["host_id"], "test-host")
        self.assertIn("snapshot_sha256", self.ledger.read_text())
        self.assertIn("2026-11-22T00:00:00+00:00", self.ledger.read_text())


if __name__ == "__main__":
    unittest.main()
