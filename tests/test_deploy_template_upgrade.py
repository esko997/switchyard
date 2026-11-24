"""Same-ID template cutovers through the real controller, leased worker and remote program.

Only native commands are emulated by test_deploy.DeployFixture; no devices or
network services are used, and no upgrade implementation is replaced by a fake.
"""
import copy
import json
from pathlib import Path
import unittest

from unittest.mock import patch

from switchyard import deploy, deploy_remote, spec

from test_deploy import DeployFixture, ROOT, TEMPLATE


class TemplateUpgradeTests(DeployFixture):
    def setUp(self):
        super().setUp()
        template = copy.deepcopy(TEMPLATE)
        template["parameters"] = [
            {"id": "mode", "description": "Runtime mode", "default": "template-mode"},
            {"id": "title", "description": "Operator site title", "default": "template-title"},
        ]
        self.container(template)["env"] = [
            {"name": "MODE", "value": "{{mode}}"},
            {"name": "TITLE", "value": "{{title}}"},
        ]
        self.manager.save_template(template, expected_revision=0)

    @staticmethod
    def container(application):
        return application["components"][0]["native"]["manifest"]["spec"]["containers"][0]

    def newer_template(self):
        template = copy.deepcopy(self.manager.template("static-web@1")["application"])
        template["revision"] = 2
        container = self.container(template)
        container.update(name="web-next", command=["/usr/sbin/nginx"], args=["--mode", "{{mode}}"],
                         image="docker.io/library/nginx:1.29-alpine@sha256:PLACEHOLDER-resolve-at-plan")
        # The service address is a placement binding, not the container's target port.
        container["ports"][0]["containerPort"] = 8081
        template["endpoints"][0]["target_port"] = 8081
        template["parameters"][0]["default"] = "new-template-mode"
        template["identities"] = [{"id": "engine", "kind": "engine", "name": "new-runtime",
                                    "scope": "host", "holders": ["web"],
                                    "description": "Exclusive runtime slot"}]
        return template

    def save_newer(self):
        template = self.newer_template()
        self.manager.save_template(template, expected_revision=1)
        return template

    def active(self, instance="garden", **kwargs):
        kwargs.setdefault("params", {"mode": "operator-mode", "title": "operator-title"})
        plan, result = self.deploy(instance, **kwargs)
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        return plan

    def apply_upgrade(self, instance="garden", **kwargs):
        plan = self.manager.upgrade_plan(instance, "static-web@2", **kwargs)
        self.assertTrue(plan["executable"], plan["blockers"])
        result = self.manager.apply(plan["id"], approved=True, request_id="upgrade-" + instance)
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        return plan, result

    def native_bytes(self, instance="garden"):
        return {key: Path(path).read_bytes() for key, path in self.paths(instance).items()
                if key in ("unit", "yaml", "token", "owner")}

    def assert_no_cutover(self):
        self.assertNotIn("undeploy", self.remote_actions)
        self.assertNotIn("prepare", self.remote_actions)
        self.assertNotIn("start", self.remote_actions)

    def test_active_upgrade_keeps_identity_address_data_and_immutable_history(self):
        original = self.active(ports={"http": 18681}, addresses={"http": "192.168.50.120"})
        before = copy.deepcopy(self.manager.show("garden"))
        old_revision = self.manager.instance_revision("garden@1")
        site = Path(self.paths()["data_root"], "site", "index.html")
        site.write_text("operator-owned content survives the swap\n")
        self.save_newer()
        plan = self.manager.upgrade_plan("garden", "static-web@2", params={"mode": "approved-mode"})
        self.assertTrue(plan["executable"], plan["blockers"])
        self.assertEqual((plan["action"], plan["instance_id"], plan["host_id"], plan["generation"]),
                         ("deploy", "garden", "alpha", 2))
        self.assertEqual(plan["native"]["claims"], original["native"]["claims"])
        self.assertEqual(plan["native"]["datasets"], original["native"]["datasets"])
        # Preview must not stop or alter the active generation.
        self.assertEqual(self.state(), before["placement"])
        old_pod_id = self.host.pods[original["native"]["names"]["pod"]]["Id"]
        self.remote_actions.clear()
        result = self.manager.apply(plan["id"], approved=True, request_id="upgrade-garden")
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        after = self.manager.show("garden")
        row = after["placement"]
        self.assertEqual((after["instance"]["id"], after["instance"]["revision"], after["instance"]["template_ref"]),
                         ("garden", 2, {"id": "static-web", "revision": 2}))
        self.assertEqual((row["host_id"], row["generation"], row["state"], row["meta"]["token"]["state"]),
                         ("alpha", 2, "active", "valid"))
        self.assertNotEqual(row["meta"]["ownership_id"], before["placement"]["meta"]["ownership_id"])
        self.assertEqual(row["meta"]["ownership_id"], plan["ownership_id"])
        self.assertEqual(row["placement"]["revision"], 2)
        claim_keys = ("host_id", "address", "protocol", "port", "endpoint", "owner_kind")
        self.assertEqual([{key: claim[key] for key in claim_keys} for claim in after["claims"]],
                         [{key: claim[key] for key in claim_keys} for claim in before["claims"]])
        self.assertEqual([claim["generation"] for claim in after["claims"]], [2])
        self.assertTrue(self.host.started(plan["native"]["names"]["service"]))
        pod = self.host.pods[plan["native"]["names"]["pod"]]
        self.assertNotEqual(pod["Id"], old_pod_id)
        self.assertEqual(pod["Labels"]["io.switchyard/generation"], "2")
        self.assertEqual(pod["Labels"]["io.switchyard/ownership-id"], plan["ownership_id"])
        manifest = deploy.parse_pod(Path(self.paths()["yaml"]).read_text())
        container = manifest["spec"]["containers"][0]
        self.assertEqual((container["name"], container["command"], container["args"]),
                         ("web-next", ["/usr/sbin/nginx"], ["--mode", "approved-mode"]))
        self.assertEqual({entry["name"]: entry["value"] for entry in container["env"]},
                         {"MODE": "approved-mode", "TITLE": "operator-title"})
        self.assertEqual(container["image"], plan["image"]["pull_reference"])
        self.assertTrue(container["image"].startswith("docker.io/library/nginx@sha256:"))
        self.assertEqual(container["ports"][0]["hostPort"], 18681)
        self.assertEqual(container["ports"][0]["hostIP"], "192.168.50.120")
        self.assertEqual(container["ports"][0]["containerPort"], 8081)
        self.assertEqual(site.read_text(), "operator-owned content survives the swap\n")
        health = [event["data"]["health"] for event in result["receipt"]["events"] if event["event"] == "deploy-verified"]
        self.assertTrue(health, result)
        self.assertTrue(all(check["ok"] for check in health[-1]))
        self.assertEqual(self.remote_actions.count("start"), 1)
        self.assertLess(self.remote_actions.index("upgrade-check"), self.remote_actions.index("undeploy"))
        self.assertEqual(self.manager.instance_revision("garden@1"), old_revision)
        self.assertEqual(self.manager.instance_revision("garden@2")["stored_application"], after["application"])
        self.assertEqual([item["revision"] for item in after["revisions"]], [1, 2])
        self.assertEqual([(item["generation"], item["state"], item["application_revision"]) for item in after["generations"]],
                         [(1, "retired", 1), (2, "active", 2)])

    def test_fenced_llama_upgrade_adds_contended_identity_without_ever_starting(self):
        llama = json.loads((ROOT / "catalogs/templates/llama-server-vulkan.json").read_text())
        llama["revision"] = 1
        image_slot = copy.deepcopy(llama["identities"][1])
        llama["identities"] = llama["identities"][:1]
        self.manager.save_template(llama, expected_revision=0)
        self.config["deploy_devices"] = {"alpha": ["/dev/dri/renderD128"]}
        self.write_config()
        models = self.root / "models"
        (models / "model").mkdir(parents=True)
        weights = models / "model/weights.gguf"
        weights.write_bytes(b"GGUF" + b"\0" * 60)
        plan, result = self.deploy("llm", template="llama-server-vulkan@1", ports={"http": 18682},
                                   datasets={"models": str(models)},
                                   params={"model-dir": "model", "model-file": "weights.gguf"})
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        self.assertEqual(self.act("llm", "fence", "fence-llm")["receipt"]["status"], "succeeded")
        old = copy.deepcopy(self.state("llm"))
        old_revision = self.manager.instance_revision("llm@1")
        holder = copy.deepcopy(TEMPLATE)
        holder["id"] = "image-holder"
        holder["identities"] = [{**image_slot, "holders": ["web"]}]
        self.manager.save_template(holder, expected_revision=0)
        other = self.active("alternate-holder", template="image-holder@1", params={})
        holder_pod = copy.deepcopy(self.host.pods[other["native"]["names"]["pod"]])
        llama["revision"] = 2
        llama["identities"].append(image_slot)
        self.manager.save_template(llama, expected_revision=1)
        upgrade = self.manager.upgrade_plan("llm", "llama-server-vulkan@2")
        self.assertTrue(upgrade["executable"], upgrade["blockers"])
        self.assertEqual(upgrade["install"], "fenced")
        self.assertEqual(upgrade["native"]["datasets"], plan["native"]["datasets"])
        self.remote_actions.clear()
        self.host.calls.clear()
        done = self.manager.apply(upgrade["id"], approved=True, request_id="upgrade-fenced-llm")
        self.assertEqual(done["receipt"]["status"], "succeeded", done)
        row = self.state("llm")
        self.assertEqual((row["generation"], row["state"], row["meta"]["token"]["state"]), (2, "fenced", "revoked"))
        self.assertNotEqual(row["meta"]["ownership_id"], old["meta"]["ownership_id"])
        self.assertFalse(deploy.holds(row))
        self.assertNotIn("start", self.remote_actions)
        self.assertFalse(any(call[0] == deploy_remote.SYSTEMCTL and "start" in call for call in self.host.calls))
        self.assertFalse(self.host.started(upgrade["native"]["names"]["service"]))
        self.assertNotIn(upgrade["native"]["names"]["pod"], self.host.pods)
        self.assertEqual(self.host.pods[other["native"]["names"]["pod"]], holder_pod)
        self.assertEqual(self.host.start(upgrade["native"]["names"]["service"])[0], 1)
        self.assertEqual(weights.read_bytes(), b"GGUF" + b"\0" * 60)
        shown = self.manager.show("llm")
        self.assertEqual(shown["instance"]["template_ref"], {"id": "llama-server-vulkan", "revision": 2})
        self.assertEqual(shown["application"]["identities"], llama["identities"])
        self.assertEqual(self.manager.instance_revision("llm@1"), old_revision)

    def test_upgrade_requires_explicit_newer_revision_of_the_same_template(self):
        self.active()
        self.save_newer()
        self.manager.save_template({**copy.deepcopy(TEMPLATE), "id": "unrelated"}, expected_revision=0)
        before = self.native_bytes()
        self.remote_actions.clear()
        for reference in ("static-web", "static-web@1", "unrelated@1"):
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                self.manager.upgrade_plan("garden", reference)
        self.assertEqual(self.remote_actions, [])
        self.assertEqual(self.native_bytes(), before)

    def test_old_template_revision_is_refused_after_a_successful_upgrade(self):
        self.active()
        self.save_newer()
        self.apply_upgrade()
        before = self.native_bytes()
        self.remote_actions.clear()
        for reference in ("static-web@1", "static-web@2"):
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                self.manager.upgrade_plan("garden", reference)
        self.assertEqual(self.remote_actions, [])
        self.assertEqual(self.native_bytes(), before)

    def test_stale_placement_revision_refuses_approval_without_removing_native_files(self):
        original = self.active()
        self.save_newer()
        upgrade = self.manager.upgrade_plan("garden", "static-web@2")
        self.assertEqual(self.act("garden", "stop", "stop-between-plan-and-apply")["receipt"]["status"], "succeeded")
        before = self.native_bytes()
        self.remote_actions.clear()
        with self.assertRaises(ValueError):
            self.manager.apply(upgrade["id"], approved=True, request_id="stale-upgrade")
        self.assertEqual(self.remote_actions, [])
        self.assertEqual(self.native_bytes(), before)
        self.assertIn(original["native"]["names"]["service"], self.host.units)
        self.assertEqual(self.state()["generation"], 1)

    def test_instance_revision_changed_before_lease_refuses_without_native_commands(self):
        original = self.active()
        self.save_newer()
        upgrade = self.manager.upgrade_plan("garden", "static-web@2")
        before = self.native_bytes()
        self.remote_actions.clear()

        def edit_before_lease(receipt, payload):
            with self.manager.store.transaction() as db:
                current = self.manager.store.instance_row(db, "garden")
                application = copy.deepcopy(current["application"])
                application.update(revision=2, purpose="Concurrent operator edit")
                self.manager.store.replace_instance(
                    db, "garden", 1, application,
                    {**current["meta"], "content_sha256": spec.Application.model_validate(application).content_sha256()})
            return self.dispatch(receipt, payload)

        with patch.object(self.broker, "_dispatch", side_effect=edit_before_lease):
            result = self.manager.apply(upgrade["id"], approved=True, request_id="stale-instance-at-lease")
        self.assertEqual(result["receipt"]["status"], "failed", result)
        self.assertEqual(self.remote_actions, [])
        self.assertEqual(self.native_bytes(), before)
        self.assertEqual(self.state()["generation"], 1)
        self.assertTrue(self.host.started(original["native"]["names"]["service"]))
        self.assertEqual(self.manager.show("garden")["application"]["purpose"], "Concurrent operator edit")

    def test_new_template_cannot_silently_drop_an_effective_operator_parameter(self):
        self.active()
        template = self.newer_template()
        template["parameters"] = [entry for entry in template["parameters"] if entry["id"] != "title"]
        self.container(template)["env"] = [entry for entry in self.container(template)["env"] if entry["name"] != "TITLE"]
        self.manager.save_template(template, expected_revision=1)
        before = self.native_bytes()
        self.remote_actions.clear()
        with self.assertRaisesRegex(ValueError, "parameter"):
            self.manager.upgrade_plan("garden", "static-web@2")
        self.assertEqual(self.remote_actions, [])
        self.assertEqual(self.native_bytes(), before)

    def test_foreign_or_drifted_native_resources_refuse_cutover_after_approval(self):
        self.save_newer()
        for index, corruption in enumerate(("unit", "pod-owner")):
            instance = "garden-" + str(index)
            with self.subTest(corruption=corruption):
                original = self.active(instance, template="static-web@1")
                upgrade = self.manager.upgrade_plan(instance, "static-web@2")
                self.assertTrue(upgrade["executable"], upgrade["blockers"])
                if corruption == "unit":
                    unit = Path(self.paths(instance)["unit"])
                    unit.write_text(unit.read_text() + "# operator edit after preview\n")
                else:
                    self.host.pods[original["native"]["names"]["pod"]]["Labels"]["io.switchyard/ownership-id"] = "foreign-owner"
                before = self.native_bytes(instance)
                pod = copy.deepcopy(self.host.pods[original["native"]["names"]["pod"]])
                self.remote_actions.clear()
                result = self.manager.apply(upgrade["id"], approved=True, request_id="refuse-" + instance)
                self.assertEqual(result["receipt"]["status"], "failed", result)
                self.assert_no_cutover()
                self.assertEqual(self.native_bytes(instance), before)
                self.assertEqual(self.host.pods[original["native"]["names"]["pod"]], pod)
                self.assertTrue(self.host.started(original["native"]["names"]["service"]))
                self.assertEqual(self.state(instance)["generation"], 1)
                self.assertEqual(self.manager.show(instance)["instance"]["template_ref"]["revision"], 1)

    def test_image_pull_failure_leaves_original_active_and_history_unchanged(self):
        original = self.active()
        self.save_newer()
        upgrade = self.manager.upgrade_plan("garden", "static-web@2")
        self.assertTrue(upgrade["executable"], upgrade["blockers"])
        before = copy.deepcopy(self.manager.show("garden"))
        native = self.native_bytes()
        pods = copy.deepcopy(self.host.pods)
        self.remote_actions.clear()
        self.host.fail_pull = True
        result = self.manager.apply(upgrade["id"], approved=True, request_id="failed-image-pull")
        self.assertEqual(result["receipt"]["status"], "failed", result)
        self.assertIn("pull", self.remote_actions)
        self.assert_no_cutover()
        self.assertEqual(self.native_bytes(), native)
        self.assertEqual(self.host.pods, pods)
        self.assertTrue(self.host.started(original["native"]["names"]["service"]))
        after = self.manager.show("garden")
        for key in ("instance", "application", "placement", "revisions", "generations"):
            self.assertEqual(after[key], before[key], key)

    def test_retire_then_normal_deploy_with_higher_template_advances_tracked_reference(self):
        self.active()
        old_revision = self.manager.instance_revision("garden@1")
        site = Path(self.paths()["data_root"], "site", "kept.txt")
        site.write_text("keep me")
        retire = self.manager.undeploy_plan("garden")
        done = self.manager.undeploy_apply(retire["id"], approved=True, request_id="retire-garden")
        self.assertEqual(done["receipt"]["status"], "succeeded", done)
        self.save_newer()
        plan = self.manager.plan(instance_id="garden", host_id="alpha", template="static-web@2")
        self.assertTrue(plan["executable"], plan["blockers"])
        result = self.manager.apply(plan["id"], approved=True, request_id="redeploy-garden")
        self.assertEqual(result["receipt"]["status"], "succeeded", result)
        shown = self.manager.show("garden")
        self.assertEqual((shown["instance"]["revision"], shown["instance"]["template_ref"]),
                         (2, {"id": "static-web", "revision": 2}))
        self.assertEqual(shown["application"]["template_ref"], shown["instance"]["template_ref"])
        self.assertEqual((shown["placement"]["generation"], shown["placement"]["state"]), (2, "active"))
        self.assertEqual(site.read_text(), "keep me")
        self.assertEqual(self.manager.instance_revision("garden@1"), old_revision)
        self.assertEqual([item["revision"] for item in shown["revisions"]], [1, 2])


if __name__ == "__main__":
    unittest.main()
