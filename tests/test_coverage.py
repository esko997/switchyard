import unittest

from switchyard.coverage import host_integration


class IntegrationCoverageTests(unittest.TestCase):
    def render(self, host, collector=None, **kwargs):
        result = host_integration(host, collector, shell_hosts=kwargs.get("shell_hosts", []),
                                  managed_workloads=kwargs.get("managed_workloads", []), key_state=kwargs.get("key_state", {}))
        return {item["id"]: item for item in result["items"]}

    def host(self):
        return {"id": "test", "platform": "linux", "observation": {"freshness": "fresh", "snapshot": {"host": {"hostname": "test"}}},
                "coverage": [{"scope": scope, "status": "complete", "freshness": "fresh"}
                             for scope in ("cpu", "memory", "gpus", "storage", "systemd:user:1000")]}

    def test_declared_capabilities_do_not_grant_control_or_verify_identity(self):
        result = self.render({"id": "test", "platform": "linux", "capabilities": ["ssh", "podman"]})
        for key in ("identity", "access", "shell", "lifecycle", "migration"):
            self.assertEqual(result[key]["status"], "unconfigured")

    def test_fresh_cpu_cannot_hide_stale_storage(self):
        host = self.host()
        host["coverage"][3]["freshness"] = "stale"
        result = self.render(host, {"transport": "ssh", "user_units": ["example.service"]})
        self.assertEqual(result["identity"]["status"], "verified")
        self.assertEqual(result["resources"]["status"], "stale")
        self.assertEqual(result["discovery"]["status"], "verified")

    def test_empty_allowlists_are_not_complete_workload_discovery(self):
        result = self.render(self.host(), {"transport": "ssh", "user_units": [], "system_units": []})
        self.assertEqual(result["resources"]["status"], "verified")
        self.assertEqual(result["discovery"]["status"], "unconfigured")

    def test_failed_latest_access_does_not_erase_retained_identity(self):
        host = self.host()
        host["observation"]["last_attempt"] = {"status": "busy", "message": "Canonical lease held elsewhere"}
        result = self.render(host, {"transport": "ssh"}, shell_hosts=["test"],
                             managed_workloads=[{"id": "foobar", "allowed_hosts": ["test"], "actions": ["start"]}])
        self.assertEqual(result["access"]["status"], "blocked")
        self.assertEqual(result["identity"]["status"], "verified")
        self.assertEqual(result["shell"]["status"], "configured")
        self.assertEqual(result["lifecycle"]["status"], "configured")
        self.assertEqual(result["migration"]["status"], "unconfigured")

    def test_android_package_inventory_is_not_complete_resource_coverage(self):
        host = self.host()
        host["platform"] = "android"
        host["coverage"] = [{"scope": "android-package:user:0", "status": "complete", "freshness": "fresh"}]
        result = self.render(host, {"transport": "adb", "packages": ["org.example"]})
        self.assertEqual(result["discovery"]["status"], "verified")
        self.assertEqual(result["resources"]["status"], "configured")
        self.assertEqual(result["fleet-keys"]["status"], "unsupported")

    def test_key_conflict_does_not_appear_verified(self):
        result = self.render(self.host(), {"transport": "ssh"}, key_state={"hosts": [{"host_id": "test", "status": "conflict", "detail": "Manual key remains"}]})
        self.assertEqual(result["fleet-keys"]["status"], "blocked")
        self.assertEqual(result["fleet-keys"]["detail"], "Manual key remains")
