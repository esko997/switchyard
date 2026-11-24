"""GPU workloads through deploy: devices, detached pulls, parameters in the pod, subPath datasets, readiness windows,
host-scoped exclusive resources and switching. Fake host only (see test_deploy.FakeHost)."""
import argparse
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from switchyard import deploy, deploy_remote, spec
from switchyard.broker import Broker
from switchyard.remote import RemoteError

from test_deploy import ROOT, DeployFixture

LLAMA = json.loads((ROOT / "catalogs" / "templates" / "llama-server-vulkan.json").read_text())
LLAMA["revision"] = 1  # first saved revision in this isolated journal
MODEL_DIR = "unsloth/Qwen3.8-27B-GGUF"
MODEL_FILE = "Qwen3.8-27B-UD-Q4_K_XL.gguf"
RENDER = "/dev/dri/renderD128"


class GPUDeployTests(DeployFixture):
    def setUp(self):
        super().setUp()
        self.config["deploy_devices"] = {"alpha": [RENDER]}
        self.write_config()
        self.models = self.root / "mnt" / "models"
        (self.models / MODEL_DIR).mkdir(parents=True)
        (self.models / MODEL_DIR / MODEL_FILE).write_bytes(b"GGUF" + b"\0" * 60)
        os.chmod(self.models / MODEL_DIR / MODEL_FILE, 0o644)
        self.manager.save_template(copy.deepcopy(LLAMA), expected_revision=0)

    def llama_plan(self, instance="llm-a", port=18190, fenced=False, **params):
        values = {"model-dir": MODEL_DIR, "model-file": MODEL_FILE, **{key.replace("_", "-"): value for key, value in params.items()}}
        return self.manager.plan(instance_id=instance, host_id="alpha", template="llama-server-vulkan",
                                 ports={"http": port}, addresses={"http": "192.168.50.120"},
                                 datasets={"models": str(self.models)}, params=values, install_fenced=fenced)

    def llama(self, instance="llm-a", port=18190, fenced=False, **params):
        plan = self.llama_plan(instance, port, fenced, **params)
        self.assertTrue(plan["executable"], [p for p in plan["preconditions"] if not p["ok"]])
        result = self.manager.apply(plan["id"], approved=True, request_id="apply-" + instance)
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        return plan, result

    def blocked(self, plan):
        return {p["id"]: p["evidence"] for p in plan["preconditions"] if p["blocking"] and not p["ok"]}

    def service(self, instance):
        return self.state(instance)["meta"]["native"]["names"]["service"]

    # spec ------------------------------------------------------------------------
    def test_spec_additions_validate_and_leave_older_records_unchanged(self):
        template = spec.Application.model_validate(LLAMA)
        self.assertEqual(template.identities[0].scope, "host")
        self.assertEqual(template.devices[0].target(), RENDER)
        stored = json.loads((ROOT / "docs/spec/examples/08-llama-gpu.json").read_text())
        self.assertEqual(spec.SpecBundle.model_validate(stored).model_dump(mode="json"), stored)
        for name in ("02-static-web.json", "03-residents.json", "05-lan-dns.json"):
            for app in spec.SpecBundle.model_validate_json((ROOT / "docs/spec/examples" / name).read_text()).applications:
                text = json.dumps(app.model_dump(mode="json"))
                for key in ("devices", "scope", "ready_within_seconds", "subPath"):
                    self.assertNotIn('"' + key + '"', text, name)  # unset additions stay out of document and hash

        def broken(change):
            value = copy.deepcopy(LLAMA)
            change(value)
            with self.assertRaises(ValidationError):
                spec.Application.model_validate(value)

        container = lambda v: v["components"][0]["native"]["manifest"]["spec"]["containers"][0]
        broken(lambda v: container(v)["args"].append("{{undeclared}}"))
        broken(lambda v: container(v)["args"].append("--x={{extra-args}}"))  # a list stands alone in one element
        broken(lambda v: container(v).setdefault("env", []).append({"name": "A", "value": "{{extra-args}}"}))
        broken(lambda v: container(v).update(workingDir="/{{model-dir}}"))  # never substituted there
        broken(lambda v: container(v)["volumeMounts"][0].update(subPath="../escape"))
        broken(lambda v: v["devices"][0].update(host_path="/etc/passwd"))
        broken(lambda v: v["devices"][0].update(container="missing"))
        broken(lambda v: v["devices"][0].update(container_path="/models"))  # collides with the dataset mount
        broken(lambda v: v["parameters"][2].update(default="64k"))  # integer format
        broken(lambda v: v["parameters"][3].update(default="-ngl 'all'"))  # no quotes in argument lists
        broken(lambda v: v["health_checks"][0].update(ready_within_seconds=601))
        with self.assertRaises(ValueError):
            spec.check_parameter_value("relative-path", "a/../b")

    def test_host_scoped_identity_is_exclusive_per_host_in_bundles(self):
        bundle = json.loads((ROOT / "docs/spec/examples/08-llama-gpu.json").read_text())
        other = copy.deepcopy(bundle["placements"][0])
        other.update(id="llm-b-g1", application_id="llm-b")
        other["endpoints"][0]["host_port"] += 1
        app_b = copy.deepcopy(bundle["applications"][1])
        app_b.update(id="llm-b")
        bundle["applications"].append(app_b)
        bundle["placements"].append(other)
        for token in other["fence"]["tokens"]:
            token["application_id"] = "llm-b"
        with self.assertRaisesRegex(ValidationError, "active in more than one holder"):
            spec.SpecBundle.model_validate(bundle)
        bundle["placements"][1]["host_id"] = "elsewhere"  # the same render node on another host is another GPU
        spec.SpecBundle.model_validate(bundle)

    # plan ------------------------------------------------------------------------
    def test_plan_renders_device_subpath_and_parameters_and_reviews_them(self):
        plan = self.llama_plan(extra_args="-ngl all -fa on")
        self.assertTrue(plan["executable"], self.blocked(plan))
        manifest = deploy.parse_pod(plan["native"]["files"]["yaml"]["text"])
        volumes = {v["name"]: v["hostPath"] for v in manifest["spec"]["volumes"]}
        container = manifest["spec"]["containers"][0]
        mounts = {m["mountPath"]: m for m in container["volumeMounts"]}
        self.assertEqual(volumes[mounts[RENDER]["name"]], {"path": RENDER, "type": "CharDevice"})
        self.assertEqual(volumes[mounts["/models"]["name"]], {"path": str(self.models) + "/" + MODEL_DIR, "type": "Directory"})
        self.assertTrue(mounts["/models"]["readOnly"])
        self.assertNotIn("subPath", mounts["/models"])  # Switchyard binds the resolved directory itself
        self.assertEqual(container["args"], ["--host", "0.0.0.0", "--port", "8080", "--model", "/models/" + MODEL_FILE,
                                             "--ctx-size", "65536", "-ngl", "all", "-fa", "on"])
        device = plan["devices"][0]
        self.assertEqual((device["type"], device["major_minor"], device["mode"]), ("character device", "226:128", "0666"))
        self.assertIn("every local user (mode 0666)", device["who_can_open"])
        self.assertTrue(device["container_can_open"])
        self.assertIn("render node read-write", device["meaning"])
        self.assertIn("Device access: " + RENDER + " in container switchyard-llm-a-server-server (read-write)",
                      plan["approvals"][1]["includes"])
        self.assertIn("No authentication", plan["lan_exposure"][0]["endpoint_notes"][0])
        dataset = next(p for p in plan["preconditions"] if p["id"] == "dataset-models")["evidence"]
        self.assertEqual(dataset["mount"], "read-only")
        self.assertIn("never creates, chowns, relabels or deletes it", dataset["note"])
        self.assertTrue(next(p for p in plan["preconditions"] if p["id"] == "dataset-models-sub-paths")["ok"])
        self.assertIn("readiness window 120 s", " ".join(plan["steps"]))
        self.assertEqual(plan["exclusive"][0]["resource"], "alpha:gpu:/dev/dri/renderD128")
        self.assertEqual(plan["install"], "start")
        self.assertEqual(self.remote_payloads[-1]["devices"], [RENDER])  # inspected on the host under its lease

    def test_device_and_policy_refusals_block_the_plan(self):
        cases = [
            ("device-grant-render", lambda: (self.config.update(deploy_devices={}), self.write_config())),
            ("device-render", lambda: self.host.devices.pop(RENDER)),
            ("device-render", lambda: self.host.devices[RENDER].update(char=False)),
            ("device-render", lambda: self.host.devices[RENDER].update(mode="0660")),
            ("device-render", lambda: self.host.devices[RENDER].update(writable=False)),
            ("podman-device-support", lambda: self.host.__setattr__("podman_version", "4.1.1")),
            # Owned by the deploying account, 0600: container user 1000 maps to a subordinate ID and cannot open it.
            ("device-render", lambda: self.host.devices[RENDER].update(uid=os.getuid(), mode="0600")),
        ]
        original = copy.deepcopy(self.host.devices)
        for index, (blocker, change) in enumerate(cases):
            with self.subTest(blocker=blocker, case=index):
                self.host.devices, self.host.podman_version = copy.deepcopy(original), "5.4.2"
                self.config["deploy_devices"] = {"alpha": [RENDER]}
                self.write_config()
                change()
                plan = self.llama_plan("llm-" + str(index), 18190 + index)
                self.assertFalse(plan["executable"])
                self.assertIn(blocker, self.blocked(plan))
        self.assertEqual(self.host.units, {})

    def test_only_container_root_opens_a_node_owned_by_the_account(self):
        self.host.devices[RENDER].update(uid=os.getuid(), mode="0600")
        plan = self.llama_plan()
        self.assertFalse(plan["devices"][0]["container_can_open"])
        self.assertIn("runAsUser 1000", " ".join(self.blocked(plan)["device-render"]["problems"]))
        root = copy.deepcopy(LLAMA)
        root["revision"] = 2
        root["components"][0]["native"]["manifest"]["spec"]["containers"][0]["securityContext"]["runAsUser"] = 0
        self.manager.save_template(root, expected_revision=1)
        plan = self.llama_plan("llm-root", 18191)  # container root is the deploying account in a rootless pod
        self.assertTrue(plan["devices"][0]["container_can_open"])
        self.assertNotIn("device-render", self.blocked(plan))

    def test_subpath_must_be_an_existing_directory_without_symlinks(self):
        plan = self.llama_plan("llm-x", model_dir="unsloth/missing")
        self.assertIn("dataset-models-sub-paths", self.blocked(plan))
        (self.models / "linked").symlink_to(self.models / "unsloth")
        plan = self.llama_plan("llm-y", model_dir="linked/Qwen3.8-27B-GGUF")
        self.assertIn("reached through a symlink", " ".join(self.blocked(plan)["dataset-models-sub-paths"]["problems"]))
        plan = self.manager.plan(instance_id="llm-z", host_id="alpha", template="llama-server-vulkan", ports={"http": 18192},
                                 params={"model-dir": MODEL_DIR, "model-file": MODEL_FILE})  # no --dataset: an empty one
        self.assertIn("cannot exist", " ".join(self.blocked(plan)["dataset-models-sub-paths"]["problems"]))
        before = len(self.remote_actions)
        with self.assertRaisesRegex(ValueError, "model-dir"):
            self.llama_plan("llm-w", model_dir="../../etc")  # refused before any host is contacted
        with self.assertRaisesRegex(ValueError, "model-file"):
            self.manager.plan(instance_id="llm-v", host_id="alpha", template="llama-server-vulkan",
                              datasets={"models": str(self.models)}, params={"model-dir": MODEL_DIR})
        self.assertEqual(len(self.remote_actions), before)

    # apply, start, verify ------------------------------------------------------------
    def test_apply_proves_devices_and_verify_reports_device_drift(self):
        plan, result = self.llama()
        placement = self.state("llm-a")
        self.assertEqual(placement["state"], "active")
        self.assertEqual(placement["meta"]["native"]["devices"][0]["major"], 226)
        evidence = " ".join(placement["placement"]["fence"]["evidence"])
        self.assertIn('"/dev/dri/renderD128"', evidence)  # read back from the running container's OCI configuration
        start = next(p for p in self.remote_payloads if p["action"] == "start")
        self.assertGreaterEqual(start["timeout"] - deploy_remote.CLEANUP_SECONDS - 60, 120)  # the readiness window fits the step
        self.assertTrue(self.manager.verify("llm-a")["consistent"])
        verify = next(p for p in reversed(self.remote_payloads) if p["action"] == "verify")
        self.assertEqual(verify["health_budget"], 125)
        pod = self.host.pods["switchyard-llm-a-server"]
        Path(pod["Containers"][0]["oci"]).write_text(json.dumps({"mounts": []}))  # the device vanished from the container
        found = self.manager.verify("llm-a")["verifications"][0]
        self.assertIn("devices-changed", [f["code"] for f in found["findings"]])
        self.assertFalse(found["consistent"])

    def test_start_refuses_a_container_without_its_declared_device(self):
        self.host.drop_devices = True
        plan = self.llama_plan()
        result = self.manager.apply(plan["id"], approved=True, request_id="apply-drop")
        self.assertEqual(result["receipt"]["status"], "failed")
        self.assertIn("do not have exactly the declared devices", result["receipt"]["error"])
        self.assertEqual((result["placement"]["state"], result["placement"]["token"]["state"]), ("staged", "revoked"))
        self.assertNotIn("switchyard-llm-a-server", self.host.pods)

    def test_large_image_needs_a_detached_pull_first_and_apply_never_pulls_it(self):
        self.host.image_size = 400 * 1024 * 1024
        plan = self.llama_plan()
        evidence = self.blocked(plan)["image-present"]
        self.assertTrue(evidence["command"].startswith("switchyard deploy pull-start --host alpha --image ghcr.io/ggml-org/llama.cpp@sha256:"),
                        evidence)
        preview = self.manager.pull_start("alpha", template="llama-server-vulkan")
        self.assertTrue(preview["preview"]["approval_required"])
        started = self.manager.pull_start("alpha", template="llama-server-vulkan", approved=True, request_id="pull-1")
        self.assertEqual(started["receipt"]["status"], "succeeded", started)
        self.assertEqual(started["pull"]["state"], "running")
        unit = next(iter(self.host.pull_units))
        argv = self.host.pull_units[unit]["argv"]
        self.assertIn("--property=RuntimeMaxSec=" + str(deploy_remote.PULL_MAX_SECONDS), argv)
        self.assertEqual(argv[-3:-1], [deploy_remote.PODMAN, started["pull"]["reference"]])  # values are arguments, never shell text
        again = self.manager.pull_start("alpha", template="llama-server-vulkan", approved=True, request_id="pull-2")
        self.assertEqual((again["pull"]["state"], again["pull"]["started"]), ("running", False))  # one pull per image
        self.assertEqual(sum(1 for call in self.host.calls if call[0] == deploy_remote.SYSTEMD_RUN), 1)
        self.assertEqual(self.manager.pulls()[0]["state"], "running")  # visible without host access
        self.host.finish_pull(unit)
        status = self.manager.pull_status("alpha", template="llama-server-vulkan")
        self.assertEqual(status["pull"]["state"], "succeeded")
        self.assertEqual(status["pull"]["observed"]["progress"]["blobs_started"], 2)
        plan = self.llama_plan()
        self.assertTrue(plan["executable"], self.blocked(plan))
        calls = len(self.host.calls)
        self.manager.apply(plan["id"], approved=True, request_id="apply-large")
        self.assertFalse(any(call[:2] == [deploy_remote.PODMAN, "pull"] for call in self.host.calls[calls:]))
        self.assertTrue(next(p for p in self.remote_payloads if p["action"] == "pull")["local_only"])
        self.assertEqual(self.manager.list()[0]["image_pull"]["state"], "succeeded")

    def test_detached_pull_disk_check_failure_and_interruption(self):
        self.host.image_size = 400 * 1024 * 1024
        with patch.object(deploy_remote, "storage_space", lambda root: {"graph_root": "/s", "free_bytes": 10 ** 9}):
            refused = self.manager.pull_start("alpha", template="llama-server-vulkan", approved=True, request_id="pull-full")
        self.assertEqual(refused["receipt"]["status"], "failed")
        self.assertIn("Not enough free space", refused["receipt"]["error"])
        self.assertEqual(refused["pull"]["state"], "refused")
        self.assertEqual(self.host.pull_units, {})
        self.manager.pull_start("alpha", template="llama-server-vulkan", approved=True, request_id="pull-a")
        self.host.finish_pull(next(iter(self.host.pull_units)), code=125)
        failed = self.manager.pull_status("alpha", template="llama-server-vulkan")["pull"]
        self.assertEqual((failed["state"], failed["observed"]["exit_code"]), ("failed", "125"))
        resumed = self.manager.pull_start("alpha", template="llama-server-vulkan", approved=True, request_id="pull-b")
        self.assertEqual(resumed["pull"]["state"], "running")  # a failed pull may start again (layers already stored are reused)
        self.host.pull_units.clear()  # the unit vanished (RuntimeMaxSec, reboot) before podman returned
        self.assertEqual(self.manager.pull_status("alpha", template="llama-server-vulkan")["pull"]["state"], "interrupted")

    # one at a time, switching ------------------------------------------------------
    def two_models(self):
        self.llama("llm-a", 18190)
        blocked = self.llama_plan("llm-b", 18191)
        self.assertIn("llm-a (active)", self.blocked(blocked)["exclusive-gpu"]["held_by"])
        self.llama("llm-b", 18191, fenced=True)

    def test_second_holder_is_installed_fenced_and_every_start_path_is_refused(self):
        self.two_models()
        state = self.state("llm-b")
        self.assertEqual((state["state"], state["meta"]["token"]["state"]), ("fenced", "revoked"))
        self.assertNotIn("switchyard-llm-b-server", self.host.pods)
        self.assertEqual(self.host.start(self.service("llm-b")), (1, b""))  # manual systemctl --user start: gate refuses
        with self.assertRaisesRegex(ValueError, "fenced; unfence first"):
            self.manager.act("llm-b", "start", approved=True, request_id="start-b")
        with self.assertRaisesRegex(ValueError, r"Unfence refused: exclusive resource alpha:gpu:/dev/dri/renderD128.* is held by llm-a"):
            self.manager.act("llm-b", "unfence", approved=True, request_id="unfence-b")
        self.manager.act("llm-a", "stop", approved=True, request_id="stop-a")  # staged with a valid token still holds it
        with self.assertRaisesRegex(ValueError, "held by llm-a \\(staged\\)"):
            self.manager.act("llm-b", "unfence", approved=True, request_id="unfence-b2")
        listed = {item["instance_id"]: item for item in self.manager.list()}
        self.assertEqual(listed["llm-b"]["exclusive"][0]["contenders"], [{"instance_id": "llm-a", "state": "staged", "holding": True}])
        fleet = {item["definition"]["id"]: item["deployment"] for item in self.manager.workload_definitions()}
        self.assertEqual(fleet["llm-a"]["devices"][0]["host"], RENDER)

    def test_switch_moves_the_gpu_in_one_operation_and_replays(self):
        self.two_models()
        plan = self.manager.switch_plan("llm-b")
        self.assertTrue(plan["executable"], plan["preconditions"])
        self.assertEqual([p["instance_id"] for p in plan["previous"]], ["llm-a"])
        self.assertFalse(plan["restore_on_failure"])
        result = self.manager.switch_apply(plan["id"], approved=True, request_id="switch-1")
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        self.assertEqual((result["placement"]["state"], result["previous"][0]["state"]), ("active", "fenced"))
        self.assertNotIn("switchyard-llm-a-server", self.host.pods)
        self.assertIn("switchyard-llm-b-server", self.host.pods)
        report = result["switch"]
        self.assertEqual([s["step"] for s in report["steps"]], ["fence", "unfence", "start"])
        used = [int(d["devices"][0]["vram_used"]) for d in report["devices"]]
        self.assertEqual([d["at"] for d in report["devices"]], ["before", "after-fence", "after-start"])
        self.assertTrue(used[0] > used[1] < used[2])  # released, then re-acquired
        self.assertEqual(self.broker.receipt(result["receipt"]["id"])["kind"], "deploy")
        replay = self.manager.switch_apply(plan["id"], approved=True, request_id="switch-1")
        self.assertEqual(replay["receipt"]["id"], result["receipt"]["id"])
        verified = self.manager.verify("llm-b")
        self.assertEqual(sorted(v["instance_id"] for v in verified["verifications"]), ["llm-a", "llm-b"])
        self.assertTrue(verified["consistent"], verified)
        self.assertEqual(self.host.start(self.service("llm-a")), (1, b""))  # the old holder's start paths are closed

    def test_failed_target_ends_fenced_and_restore_is_an_explicit_choice(self):
        self.two_models()
        self.host.unhealthy_ports = {18191}  # llm-b never becomes healthy (a wrong model file)
        result = self.manager.switch_apply(self.manager.switch_plan("llm-b")["id"], approved=True, request_id="switch-bad")
        self.assertEqual(result["receipt"]["status"], "failed")
        self.assertEqual((result["placement"]["state"], result["previous"][0]["state"]), ("fenced", "fenced"))
        self.assertEqual(result["switch"]["outcome"], "target-failed")
        self.assertIn("start failed during a switch", " ".join(self.state("llm-b")["placement"]["fence"]["evidence"]))
        self.assertEqual(self.host.pods, {})
        self.assertTrue(self.manager.verify("llm-a")["consistent"])
        self.manager.act("llm-a", "unfence", approved=True, request_id="unfence-a")
        self.manager.act("llm-a", "start", approved=True, request_id="start-a")
        plan = self.manager.switch_plan("llm-b", restore_on_failure=True)
        result = self.manager.switch_apply(plan["id"], approved=True, request_id="switch-restore")
        self.assertEqual(result["receipt"]["status"], "failed")
        self.assertEqual(result["switch"]["outcome"], "target-failed-restored")
        self.assertEqual((result["placement"]["state"], result["previous"][0]["state"]), ("fenced", "active"))
        self.assertEqual(list(self.host.pods), ["switchyard-llm-a-server"])
        restored = self.manager.verify("llm-a")  # no switch intent is left behind on the restored holder
        self.assertTrue(restored["consistent"], restored["verifications"])

    def test_lost_connection_and_crash_mid_switch_are_explained_by_verify(self):
        self.two_models()

        def lose_start(payload):
            if payload["action"] == "start" and payload["instance_id"] == "llm-b":
                raise RemoteError("Invalid or unavailable SSH operation response; effects need inspection")

        self.remote_hook = lose_start
        result = self.manager.switch_apply(self.manager.switch_plan("llm-b")["id"], approved=True, request_id="switch-lost")
        self.assertEqual(result["receipt"]["status"], "needs-inspection")
        self.assertEqual(result["switch"]["outcome"], "target-unknown")
        self.assertTrue(result["placement"]["uncertain"])
        self.assertEqual(result["previous"][0]["state"], "fenced")
        self.remote_hook = None
        codes = {v["instance_id"]: [f["code"] for f in v["findings"]] for v in self.manager.verify("llm-b")["verifications"]}
        self.assertIn("operation-interrupted", codes["llm-b"])
        with self.assertRaisesRegex(ValueError, "uncertain"):
            self.manager.switch_plan("llm-b")
        self.manager.act("llm-b", "fence", approved=True, request_id="fence-b")  # explicit recovery
        self.assertTrue(self.manager.verify("llm-b")["consistent"])

        def crash(payload):
            if payload["action"] == "unfence" and payload["instance_id"] == "llm-a":
                raise RuntimeError("worker killed")

        self.remote_hook = crash
        result = self.manager.switch_apply(self.manager.switch_plan("llm-a")["id"], approved=True, request_id="switch-crash")
        self.assertEqual(result["receipt"]["status"], "needs-inspection")
        self.remote_hook = None
        lease = self.leases.store.current("ALPHA")
        self.assertTrue(lease["suspect"])
        self.leases.store.break_device("ALPHA", reason="fixture recovery", operator="test",
                                       attest_stopped="The in-process fixture cannot leave a remote process",
                                       expected_id=lease["lease_id"])
        found = {v["instance_id"]: v for v in self.manager.verify("llm-a")["verifications"]}
        interrupted = [f for f in found["llm-a"]["findings"] if f["code"] == "operation-interrupted"]
        self.assertIn(result["receipt"]["id"], interrupted[0]["detail"])
        self.assertIn("receipt needs-inspection", interrupted[0]["detail"])

    def test_verify_reports_two_holders_of_one_gpu(self):
        self.two_models()
        token = Path(self.state("llm-b")["meta"]["native"]["paths"]["token"])
        state = self.state("llm-b")
        line = deploy.identity_line("llm-b", "server", state["generation"], state["meta"]["ownership_id"])
        token.write_text(line + "\nissued_at=restored\n")  # a token restored by hand: llm-b could start
        codes = {v["instance_id"]: [f["code"] for f in v["findings"]] for v in self.manager.verify("llm-a")["verifications"]}
        self.assertIn("exclusive-resource-contended", codes["llm-a"])
        self.assertIn("valid-token-while-fenced", codes["llm-b"])

    def test_device_grant_withdrawn_refuses_start_and_switch_but_not_fence(self):
        self.two_models()
        self.config["deploy_devices"] = {}
        self.write_config()
        with self.assertRaisesRegex(ValueError, "does not grant /dev/dri/renderD128"):
            self.manager.switch_plan("llm-b")
        self.manager.act("llm-a", "fence", approved=True, request_id="fence-a")
        with self.assertRaisesRegex(ValueError, "no longer grants"):
            self.manager.act("llm-a", "unfence", approved=True, request_id="unfence-a")

    def test_undeploy_never_touches_the_operator_dataset(self):
        before = sorted((str(p), p.stat().st_size, p.stat().st_mtime_ns) for p in self.models.rglob("*"))
        self.llama()
        plan = self.manager.undeploy_plan("llm-a", delete_data=True)
        self.assertEqual(plan["datasets"][0]["action"], "keep")
        self.manager.undeploy_apply(plan["id"], approved=True, request_id="undeploy-a")
        self.assertEqual(sorted((str(p), p.stat().st_size, p.stat().st_mtime_ns) for p in self.models.rglob("*")), before)

    def test_policy_validation_and_unchanged_fingerprints(self):
        host = self.broker.operation_hosts(self.broker._enabled())["alpha"]
        plain = {"deploy_hosts": ["alpha"]}
        self.assertEqual(deploy.authority(plain, "alpha", host), deploy.authority({**plain, "deploy_devices": {}}, "alpha", host))
        self.assertNotEqual(deploy.authority(plain, "alpha", host),
                            deploy.authority({**plain, "deploy_devices": {"alpha": [RENDER]}}, "alpha", host))
        for devices in ({"beta": [RENDER]}, {"alpha": ["/etc/passwd"]}, {"alpha": ["/dev/../etc"]}, {"alpha": []}, {"alpha": "x"}):
            with self.subTest(devices=devices):
                self.config["deploy_devices"] = devices
                self.write_config()
                with self.assertRaises(ValueError):
                    Broker(self.config_path, hosts=self.hosts, state_dir=self.root / "state2")

    def test_remote_readiness_window_is_inside_the_step_deadline(self):
        now = time.monotonic()
        self.assertEqual(deploy_remote.ready_deadline({"id": "h"}, now + 50), now + 50)
        self.assertLessEqual(deploy_remote.ready_deadline({"ready_within_seconds": 10}, now + 50), now + 11)
        self.assertEqual(deploy_remote.ready_deadline({"ready_within_seconds": 100}, now + 50), now + 50)

    def test_cli_commands(self):
        parser = argparse.ArgumentParser()
        commands = parser.add_subparsers(dest="command", required=True)
        deploy.register_cli(commands)
        service = SimpleNamespace(deployments=lambda: deploy.DeployManager(self.broker), hosts=lambda: {"hosts": []})
        common = ["--host", "alpha", "--address", "http=192.168.50.120", "--dataset", "models=" + str(self.models),
                  "--param", "model-dir=" + MODEL_DIR, "--param", "model-file=" + MODEL_FILE]
        plan = deploy.handle_cli(parser.parse_args(["deploy", "plan", "--template", "llama-server-vulkan", "--instance", "llm-a",
                                                    "--port", "http=18190", *common]), service)
        deploy.handle_cli(parser.parse_args(["deploy", "apply", plan["id"], "--approve", "--request-id", "cli-a"]), service)
        plan = deploy.handle_cli(parser.parse_args(["deploy", "plan", "--template", "llama-server-vulkan", "--instance", "llm-b",
                                                    "--port", "http=18191", "--fenced", *common]), service)
        self.assertEqual(plan["install"], "fenced")
        deploy.handle_cli(parser.parse_args(["deploy", "apply", plan["id"], "--approve", "--request-id", "cli-b"]), service)
        switch = deploy.handle_cli(parser.parse_args(["deploy", "switch-plan", "llm-b", "--restore-on-failure"]), service)
        self.assertTrue(switch["restore_on_failure"])
        done = deploy.handle_cli(parser.parse_args(["deploy", "switch-apply", switch["id"], "--approve", "--request-id", "cli-s"]), service)
        self.assertEqual(done["receipt"]["status"], "succeeded")
        status = deploy.handle_cli(parser.parse_args(["deploy", "pull-status", "--host", "alpha", "--template", "llama-server-vulkan"]), service)
        self.assertEqual(status["receipt"]["status"], "succeeded")
        self.assertIsInstance(deploy.handle_cli(parser.parse_args(["deploy", "pulls"]), service), list)


if __name__ == "__main__":
    unittest.main()
