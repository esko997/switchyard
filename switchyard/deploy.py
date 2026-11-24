"""Deployed ownership for the simple container case (workload spec v2, `kube` format).

One application = one component = one Pod on one host, run by a rootless Quadlet
`.kube` unit. Switchyard stores host-free templates (immutable revisions), derives
complete instance applications from them, plans against a leased read-only
inspection of the target, and executes approved plans through the existing broker
and operation worker under the host's canonical lease. Every generated unit carries
a fail-closed generation gate (`ExecStartPre` token check) and ownership labels;
only resources carrying this deployment's ownership ID are ever changed.

Authority: the operations policy key `deploy_hosts`. Adopted workloads are never
touched by this module. There is no reconciliation loop and no automatic retry.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
from ipaddress import ip_address
import json
from pathlib import Path, PurePosixPath
import re
import time
import uuid

from pydantic import ValidationError

from . import deploy_config, deploy_remote, deploy_upgrade, spec
from .collector import _json, _validate_config
from .workload_store import GATE_ID, WILDCARDS, WorkloadStore, overlaps
from .operation_store import digest, encode, now
from .remote import RemoteError, run_remote

PLAN_TTL = timedelta(minutes=10)
PORT_RANGE = range(18100, 19000)
APPS = ".local/share/switchyard/apps"
QUADLET_DIR = ".config/containers/systemd"
NAME_LIMIT = 63  # pod name becomes the pod hostname
LABEL = "io.switchyard/"
HOME = re.compile(r"/[A-Za-z0-9._/-]{1,512}\Z")
PLACEHOLDER = "PLACEHOLDER"
WORKER_SECONDS = 250  # inside the broker's 285 s worker bound, after lease acquisition
DISPATCH_SECONDS = 285  # the broker's default bound on one operation worker (lease wait included)
SWITCH_DISPATCH_SECONDS = 600  # a switch fences, starts a model and may restore the previous holder in one lease
UPGRADE_DISPATCH_SECONDS = 600
DIRECT_ACTIONS = ("fence", "unfence", "start", "stop")
LIFECYCLE_ACTIONS = ("start", "stop", "restart")
LIFECYCLE_DISPATCH_SECONDS = 435  # compound lifecycle operation; HTTP execute allows 450 s
LAN_ROUTE_INSPECT_SECONDS = 110
START_SECONDS = 110  # start step without a declared readiness window (unchanged)
READY_WINDOW_LIMIT = 150  # largest readiness window a start step can hold (run_remote bound 270 s)
LARGE_IMAGE_BYTES = 256 * 1024 * 1024  # compressed; larger images need a detached pull before planning
DEVICE_PODMAN_MINIMUM = (4, 2, 0)  # `hostPath` type CharDevice in `podman kube play` (pkg/specgen/generate/kube)
DERIVED = "switchyard-"  # prefix of volumes Switchyard renders (devices, subPath); reserved in templates


def _ts(value):
    return datetime.fromisoformat(value)


def _expired(value):
    return _ts(value) <= datetime.now(timezone.utc)


# ---------------------------------------------------------------- spec helpers

def validate_document(value):
    """`spec validate`: any v1alpha3 (or upgradable v1alpha2) record or bundle; hashes or a ValueError."""
    if not isinstance(value, dict) or value.get("kind") not in {"Application", "Placement", "ActivationInput", "Bundle"}:
        raise ValueError("Expected a " + spec.API_VERSION + " Application, Placement, ActivationInput or Bundle object")
    value, upgraded_from = spec.upgrade(value)
    record = _validated(value)
    result = {"valid": True, "kind": value["kind"], "apiVersion": spec.API_VERSION,
              "document_sha256": hashlib.sha256(encode(record.model_dump(mode="json")).encode()).hexdigest()}
    if upgraded_from:
        result["upgraded_from"] = upgraded_from
        result["note"] = "Validated after an in-memory upgrade; hashes are of the " + spec.API_VERSION + " form"
    if isinstance(record, spec.Application):
        result.update(id=record.id, revision=record.revision, role=record.role, content_sha256=record.content_sha256())
    elif isinstance(record, spec.SpecBundle):
        result["applications"] = [{"id": app.id, "revision": app.revision, "role": app.role,
                                   "content_sha256": app.content_sha256()} for app in record.applications]
    result["placeholders"] = sorted(set(_placeholders(record.model_dump(mode="json"))))
    return result


def _validated(value):
    model = {"Application": spec.Application, "Placement": spec.Placement,
             "ActivationInput": spec.ActivationInput, "Bundle": spec.SpecBundle}[value["kind"]]
    try:
        return model.model_validate(value)
    except ValidationError as error:
        raise ValueError("Invalid " + value["kind"] + ": " + "; ".join(
            ".".join(str(part) for part in item["loc"]) + ": " + item["msg"] for item in error.errors()[:20])) from None


def _placeholders(value, path="$"):
    if isinstance(value, str) and PLACEHOLDER in value:
        yield path
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _placeholders(item, path + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _placeholders(item, path + "[" + str(index) + "]")


def read_spec_file(path, limit=262144):
    """Raw bytes (for the provenance hash) and the parsed JSON document."""
    if path == "-":
        import sys
        raw = sys.stdin.buffer.read(limit + 1)
    else:
        with Path(path).open("rb") as stream:
            raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Specification file exceeds 256 KiB")
    return raw, _json(raw)


def read_json_file(path, limit=262144):
    return read_spec_file(path, limit)[1]


# ---------------------------------------------------------------- supported subset

def deployable(app):
    """Return the single kube component this round can deploy, or raise with the reason."""
    if not isinstance(app, spec.Application):
        app = spec.Application.model_validate(app)
    if len(app.components) != 1:
        raise ValueError("Deploy supports exactly one component per application in this round")
    component = app.components[0]
    native = component.native
    if not isinstance(native, spec.KubeNative) or native.mode != "quadlet-kube":
        raise ValueError("Deploy supports only kube components in quadlet-kube mode")
    if native.reviews or native.compatibility_gates:
        raise ValueError("Reviewed host-network/privileged access and ConfigMap volumes are not deployable yet")
    pod = native.manifest.spec
    if pod.hostNetwork:
        raise ValueError("hostNetwork is not deployable: listeners must be published from claims")
    if app.secrets or any(env.valueFrom for c in pod.containers for env in c.env):
        raise ValueError("Secrets are not deployable in this round")
    if component.sources:
        raise ValueError("kube components carry their manifest inline; source pins are not expected")
    for volume in pod.volumes:
        if volume.hostPath and volume.hostPath.path.startswith("reviewed://"):
            raise ValueError("reviewed:// host paths are not deployable in this round")
        if volume.hostPath and volume.hostPath.type != "Directory":
            raise ValueError("Only Directory dataset/config host paths are deployable")
        if volume.name.startswith(DERIVED):
            raise ValueError("Volume names starting with " + DERIVED + " are reserved for volumes Switchyard renders")
    for device in app.devices:
        if device.component != component.id:
            raise ValueError("Devices must belong to the deployed component")
        if device.access != "read-write":
            # Rootless Podman bind-mounts a CharDevice hostPath read-write (permissions "rwm"); kube play has no
            # portable way to ask for read-only, so a read-only declaration could not be honoured.
            raise ValueError("Device " + device.id + ": only read-write device access can be rendered for podman kube play")
    for check in checks_of(app, component.id):
        if isinstance(check, spec.HTTPCheck) and (check.ready_within_seconds or 0) > READY_WINDOW_LIMIT:
            raise ValueError("Health check " + check.id + ": ready_within_seconds above " + str(READY_WINDOW_LIMIT)
                             + " does not fit one bounded start step")
    for identity in app.identities:
        if identity.scope == "host" and identity.holders != [component.id]:
            raise ValueError("A host-scoped exclusive resource of a deployed application is held by its component")
    for container in pod.containers:
        if not re.fullmatch(r"[^@\s]+@sha256:(?:[a-f0-9]{64}|PLACEHOLDER(?:[-:].+)?)", container.image):
            raise ValueError("Container images must be name[:tag]@sha256:digest")
    if len(pod.containers) != 1:
        raise ValueError("Deploy supports exactly one container in this round")
    for endpoint in app.endpoints:
        if not any(p.containerPort == endpoint.target_port and p.protocol.lower() == endpoint.protocol
                   for c in pod.containers for p in c.ports):
            raise ValueError("Endpoint " + endpoint.id + " has no matching container port to publish")
    checks = [c for c in app.health_checks if c.component == component.id]
    if not checks or any(not isinstance(c, (spec.HTTPCheck, spec.TCPCheck, spec.DNSCheck)) for c in checks):
        raise ValueError("Deploy requires http/tcp/dns health checks only (at least one)")
    if any(f.component != component.id for f in app.config_files):
        raise ValueError("Configuration files must belong to the deployed component")
    if app.config_files and not any(v.hostPath and v.hostPath.path == "config://" + component.id for v in pod.volumes):
        raise ValueError("Configuration files are declared but no config://" + component.id + " volume mounts them")
    if any(isinstance(c, spec.HTTPCheck) and (c.credential_ref or c.predicate_ref) for c in checks):
        raise ValueError("Credentialed or predicate HTTP checks are not deployable yet")
    labels = native.manifest.metadata.labels
    if any(key.startswith(LABEL) for key in labels):
        raise ValueError("Labels under io.switchyard/ are reserved for ownership")
    if app.role == "template":
        if component.gates:
            raise ValueError("Templates declare no gates: Switchyard generates the instance's generation gate")
    elif [g.model_dump(mode="json", exclude_none=True) for g in component.gates] != [
            generation_gate(native_names(app.id, component)["service"])]:
        raise ValueError("A deployed instance declares exactly Switchyard's generation gate on its generated unit")
    return component


def checks_of(app, component_id):
    return [c for c in app.health_checks if c.component == component_id]


def generation_gate(service):
    """The one gate of a deployed Quadlet .kube component: the generated unit's ExecStartPre token check."""
    return {"id": GATE_ID, "kind": "exec-start-pre", "target": service,
            "covers": "Every systemd start path of the generated Quadlet unit: Switchyard start, manual "
                      "systemctl --user start, default.target at boot and Restart=.",
            "misses": "podman kube play run by hand on the rendered YAML; a filesystem rollback of the token file."}


def with_generation_gate(app):
    """Add Switchyard's gate to an instance application that predates v1alpha3 (no other gate allowed)."""
    app = deepcopy(app)
    component = app["components"][0]
    if not component.get("gates"):
        component["gates"] = [generation_gate(native_names(app["id"], spec.Component.model_validate(component))["service"])]
    return app


def image_parts(image):
    name, _, digest = image.partition("@sha256:")
    repository, tag = name, None
    if ":" in name.rsplit("/", 1)[-1]:
        repository, tag = name.rsplit(":", 1)
    if "." not in repository.split("/", 1)[0] and repository.split("/", 1)[0] != "localhost":
        raise ValueError("Image references must be fully qualified (registry/repository)")
    pinned = re.fullmatch(r"[a-f0-9]{64}", digest) is not None
    if not pinned and tag is None:
        raise ValueError("An unresolved image digest requires a tag to resolve")
    return {"image": image, "repository": repository, "tag": tag, "digest": "sha256:" + digest if pinned else None,
            "reference": repository + (":" + tag if tag else "") if not pinned else repository + "@sha256:" + digest,
            "pull_reference": repository + "@sha256:" + digest if pinned else repository + ":" + tag}


def instance_from_template(template, instance_id, *, pod_name):
    """A complete instance application (not an overlay) derived from a template revision."""
    app = deepcopy(template["application"])
    if app.get("role") != "template":
        raise ValueError("Stored record is not a template")
    app.update(id=instance_id, revision=1, role="instance",
               template_ref={"id": template["id"], "revision": template["revision"]},
               provenance={"submitted_by": "switchyard-deploy", "source": "template " + template["id"] + " revision "
                           + str(template["revision"]), "evidence": ["template content sha256 " + template["content_sha256"]]})
    app["components"][0]["native"]["manifest"]["metadata"]["name"] = pod_name
    return spec.Application.model_validate(with_generation_gate(app)).model_dump(mode="json")


def pin_image(app, digest):
    app = deepcopy(app)
    container = app["components"][0]["native"]["manifest"]["spec"]["containers"][0]
    container["image"] = container["image"].split("@sha256:", 1)[0] + "@" + digest
    return spec.Application.model_validate(app).model_dump(mode="json")


# ---------------------------------------------------------------- rendering

def native_names(instance_id, component):
    base = "switchyard-" + instance_id + "-" + component.id
    if len(base) > NAME_LIMIT:
        raise ValueError("switchyard-<instance>-<component> must be at most 63 characters (pod hostname)")
    containers = [base + "-" + c.name for c in component.native.manifest.spec.containers]
    return {"base": base, "unit_file": base + ".kube", "service": base + ".service", "pod": base, "containers": containers}


def layout(home, instance_id, component_id, names):
    if not HOME.fullmatch(home) or any(part in {"", ".", ".."} for part in home[1:].split("/")):
        raise ValueError("Unsupported account home path for generated units")
    app_dir = home + "/" + APPS + "/" + instance_id
    return {"app_dir": app_dir, "owner": app_dir + "/owner.json", "yaml": app_dir + "/" + component_id + ".yaml",
            "token": app_dir + "/" + component_id + ".token", "unit": home + "/" + QUADLET_DIR + "/" + names["unit_file"],
            "data_root": app_dir + "/data", "config_dir": app_dir + "/config/" + component_id}


def identity_line(instance_id, component_id, generation, ownership_id):
    return (deploy_remote.TOKEN_FORMAT + " application=" + instance_id + " component=" + component_id
            + " generation=" + str(generation) + " ownership-id=" + ownership_id)


def shell_gate(path, line):
    """The canonical start gate: compare line 1 of the token file exactly, nothing else.

    A whole-file `grep -x` passes when a valid line is appended beside a revoked first line."""
    for value in (path, line):
        if not isinstance(value, str) or not value or any(c in value for c in "\"'$`\\\n\r%"):
            raise ValueError("Gate path/line must not contain quotes, $, backquote, backslash, % or newlines")
    return '[ "$(head -n 1 -- "' + path + '")" = "' + line + '" ]'


def systemd_gate(path, line):
    """`ExecStartPre=` value: the shell gate through /bin/sh (systemd needs `$$` for a literal `$`)."""
    return "/bin/sh -c '" + shell_gate(path, line).replace("$", "$$") + "'"


def gate_command(identity, token_path):
    return systemd_gate(token_path, identity)


def render_unit(instance_id, component_id, generation, ownership_id, paths, gate):
    return "\n".join([
        "# Generated by Switchyard; do not edit. Lifecycle actions verify this file's hash.",
        "# instance=" + instance_id + " component=" + component_id + " generation=" + str(generation)
        + " ownership-id=" + ownership_id,
        "[Unit]",
        "Description=Switchyard deployment " + instance_id + "/" + component_id + " (generation " + str(generation) + ")",
        "X-Switchyard-Ownership-Id=" + ownership_id,
        "X-Switchyard-Instance=" + instance_id,
        "X-Switchyard-Generation=" + str(generation),
        "",
        "[Kube]",
        "Yaml=" + paths["yaml"],
        "",
        "[Service]",
        "# Fail-closed generation gate: no valid token, no start (boot, manual or restart).",
        "ExecStartPre=" + gate,
        "TimeoutStartSec=180",
        "",
        "[Install]",
        "WantedBy=default.target",
        ""])


def _prune(value, key=None):
    if isinstance(value, dict):
        result = {k: _prune(v, k) for k, v in value.items() if v is not None}
        return {k: v for k, v in result.items() if not (v == [] or (v == {} and k != "emptyDir"))}
    if isinstance(value, list):
        return [_prune(item) for item in value]
    return value


def render_pod(app, *, generation, ownership_id, pod_name, bindings, claims, image_reference, config_dir=None):
    """Pod manifest bound to a placement: real host paths, claimed host ports, ownership labels, `{{parameter}}`
    values in args/env/subPath, subPath mounts as their own host directories, and declared devices as `CharDevice`
    hostPath volumes. Returns (text, manifest, extras) where `extras` lists the volumes Switchyard added."""
    component = app["components"][0]
    manifest = _prune(spec.Pod.model_validate(component["native"]["manifest"]).model_dump(mode="json"))
    manifest["metadata"]["name"] = pod_name
    manifest["metadata"]["labels"] = {**manifest["metadata"].get("labels", {}),
        LABEL + "ownership-id": ownership_id, LABEL + "instance": app["id"],
        LABEL + "component": component["id"], LABEL + "generation": str(generation)}
    values, formats = deploy_config.parameter_values(app), deploy_config.parameter_formats(app)
    sources = {}
    for volume in manifest["spec"].get("volumes", []):
        if "hostPath" in volume:
            source = sources[volume["name"]] = volume["hostPath"]["path"]
            volume["hostPath"]["path"] = config_dir if source.startswith("config://") else bindings[source.removeprefix("dataset://")]
    extras = {"sub_paths": [], "devices": []}
    for container in manifest["spec"]["containers"]:
        container["image"] = image_reference
        if "args" in container:
            container["args"] = deploy_config.expand_args(container["args"], values, formats)
        for env in container.get("env", []):
            if "value" in env:
                env["value"] = deploy_config.substitute(env["value"], values)
        for mount in container.get("volumeMounts", []):
            if "subPath" in mount:
                # Podman's own subPath handling differs across 4.9/5.x/6.x; Switchyard binds the resolved
                # directory itself (checked on the host: a directory reached without symlinks).
                sub_path = deploy_config.substitute_path(mount.pop("subPath"), values)
                dataset = sources[mount["name"]].removeprefix("dataset://")
                name = DERIVED + "sub-" + str(len(extras["sub_paths"]) + 1)
                extras["sub_paths"].append({"name": name, "volume": mount["name"], "dataset": dataset, "sub_path": sub_path,
                                            "path": bindings[dataset] + "/" + sub_path})
                mount["name"] = name
        for port in container.get("ports", []):
            endpoint = next(e for e in app["endpoints"] if e["component"] == component["id"]
                            and e["target_port"] == port["containerPort"] and e["protocol"] == port["protocol"].lower())
            claim = claims[endpoint["id"]]
            port["hostPort"] = claim["port"]
            if claim["address"] != "0.0.0.0":
                port["hostIP"] = claim["address"]
    for item in extras["sub_paths"]:
        manifest["spec"].setdefault("volumes", []).append({"name": item["name"], "hostPath": {"path": item["path"], "type": "Directory"}})
    for device in app.get("devices") or []:
        if device["component"] != component["id"]:
            continue
        # `hostPath` type CharDevice: kube play adds the node as a device (rootless: a read-write bind mount of
        # the node) at mountPath. Accepted by Podman 4.2 and later (verified in the 4.9.3, 5.4.2 and 6.2.0 sources).
        name = DERIVED + "device-" + str(len(extras["devices"]) + 1)
        target = device.get("container_path") or device["host_path"]
        extras["devices"].append({"name": name, "device": device["id"], "host": device["host_path"], "container": target})
        manifest["spec"].setdefault("volumes", []).append({"name": name, "hostPath": {"path": device["host_path"], "type": "CharDevice"}})
        container = next(c for c in manifest["spec"]["containers"] if c["name"] == device["container"])
        container.setdefault("volumeMounts", []).append({"name": name, "mountPath": target})
    text = ("# Generated by Switchyard; do not edit. JSON is valid YAML 1.2 (podman kube play).\n"
            "# instance=" + app["id"] + " generation=" + str(generation) + " ownership-id=" + ownership_id + "\n"
            + json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return text, manifest, extras


def parse_pod(text):
    return json.loads("\n".join(line for line in text.splitlines() if not line.startswith("#")))


def unpublish(manifest, bindings, declared_images=None, config_dirs=None, extras=None):
    """Inverse of placement binding: the result must validate as a podman-pod-v2 `Pod`.

    `declared_images` restores the declared image when the rendered one is a tag awaiting
    its pull-at-apply digest. `config_dirs` maps `config://<component>` to its host directory.
    `extras` (from `render_pod`) names the subPath and device volumes Switchyard added."""
    manifest = deepcopy(manifest)
    extras = extras or {"sub_paths": [], "devices": []}
    derived = {item["name"]: item for item in extras["sub_paths"]}
    devices = {item["name"] for item in extras["devices"]}
    reverse = {path: "dataset://" + dataset for dataset, path in bindings.items()}
    reverse.update({path: uri for uri, path in (config_dirs or {}).items()})
    if derived or devices:
        manifest["spec"]["volumes"] = [v for v in manifest["spec"].get("volumes", []) if v["name"] not in set(derived) | devices]
    for volume in manifest["spec"].get("volumes", []):
        if "hostPath" in volume:
            volume["hostPath"]["path"] = reverse[volume["hostPath"]["path"]]
    for index, container in enumerate(manifest["spec"]["containers"]):
        if declared_images and "@sha256:" not in container["image"]:
            container["image"] = declared_images[index]
        if derived or devices:
            mounts = []
            for mount in container.get("volumeMounts", []):
                if mount["name"] in devices:
                    continue
                if mount["name"] in derived:
                    mount = {**mount, "name": derived[mount["name"]]["volume"], "subPath": derived[mount["name"]]["sub_path"]}
                mounts.append(mount)
            container["volumeMounts"] = mounts
        for port in container.get("ports", []):
            port.pop("hostPort", None)
            port.pop("hostIP", None)
    return spec.Pod.model_validate(manifest)


def sub_path_mounts(app):
    """`{dataset ID: [subPath after substitution]}` of the deployed component's mounts. Also substitutes every
    container arg and env value once, so a parameter without a value fails before any host is contacted."""
    values, formats = deploy_config.parameter_values(app), deploy_config.parameter_formats(app)
    native = app["components"][0]["native"]["manifest"]["spec"]
    datasets = {v["name"]: v["hostPath"]["path"].removeprefix("dataset://") for v in native.get("volumes") or []
                if (v.get("hostPath") or {}).get("path", "").startswith("dataset://")}
    result = {}
    for container in native["containers"]:
        deploy_config.expand_args(container.get("args") or [], values, formats)
        for env in container.get("env") or []:
            if env.get("value") is not None:
                deploy_config.substitute(env["value"], values)
        for mount in container.get("volumeMounts") or []:
            if mount.get("subPath") is not None and mount["name"] in datasets:
                result.setdefault(datasets[mount["name"]], []).append(deploy_config.substitute_path(mount["subPath"], values))
    return result


def dataset_mount_modes(app):
    """`{dataset ID: "read-only" | "read-write"}` of the deployed component: read-only when every mount is."""
    native = app["components"][0]["native"]["manifest"]["spec"]
    datasets = {v["name"]: v["hostPath"]["path"].removeprefix("dataset://") for v in native.get("volumes") or []
                if (v.get("hostPath") or {}).get("path", "").startswith("dataset://")}
    found = {}
    for container in native["containers"]:
        for mount in container.get("volumeMounts") or []:
            if mount["name"] in datasets:
                found.setdefault(datasets[mount["name"]], []).append(bool(mount.get("readOnly")))
    return {dataset: "read-only" if all(flags) else "read-write" for dataset, flags in found.items()}


def render(app, *, generation, ownership_id, facts, datasets, claims, image_reference, config=()):
    """Every native artifact of one deployment generation, with hashes. Pure function.

    `config`: the instance's configuration files as rendered at plan time (`deploy_config.render_files`)."""
    component = spec.Application.model_validate(app).components[0]
    names = native_names(app["id"], component)
    paths = layout(facts["home"], app["id"], component.id, names)
    identity = identity_line(app["id"], component.id, generation, ownership_id)
    gate = gate_command(identity, paths["token"])
    unit = render_unit(app["id"], component.id, generation, ownership_id, paths, gate)
    bindings = {item["id"]: item["path"] for item in datasets}
    yaml_text, manifest, extras = render_pod(app, generation=generation, ownership_id=ownership_id, pod_name=names["pod"],
                                             bindings=bindings, claims=claims, image_reference=image_reference,
                                             config_dir=paths["config_dir"])
    unpublish(manifest, bindings, [c.image for c in component.native.manifest.spec.containers],  # still podman-pod-v2
              {"config://" + component.id: paths["config_dir"]}, extras)
    devices = [{"id": d["id"], "host": d["host_path"], "container": d.get("container_path") or d["host_path"],
                "access": d.get("access", "read-write"), "container_name": names["base"] + "-" + d["container"]}
               for d in app.get("devices") or [] if d["component"] == component.id]
    return {"component": component.id, "names": names, "paths": paths, "identity": identity, "gate_command": gate,
            "files": {"unit": {"path": paths["unit"], "mode": "0644", "sha256": _sha(unit), "text": unit},
                      "yaml": {"path": paths["yaml"], "mode": "0644", "sha256": _sha(yaml_text), "text": yaml_text}},
            "config": [{**{k: item[k] for k in ("id", "name", "text", "size", "sha256", "mode", "on_change")},
                        "path": paths["config_dir"] + "/" + item["name"]} for item in config],
            "health_checks": render_checks(app, component.id, claims), "devices": devices,
            "sub_paths": [{k: item[k] for k in ("dataset", "sub_path", "path")} for item in extras["sub_paths"]]}


def render_checks(app, component_id, claims):
    """Declared health checks bound to the claimed binds; `{{parameter}}` resolved in DNS names/answers."""
    values = deploy_config.parameter_values(app)
    protocols = {e["id"]: e["protocol"] for e in app["endpoints"]}
    checks = []
    for check in app["health_checks"]:
        if check["component"] != component_id:
            continue
        claim = claims[check["endpoint"]]
        item = {"id": check["id"], "type": check["type"], "address": claim["address"], "port": claim["port"],
                "timeout_seconds": check["timeout_seconds"]}
        if check["type"] == "dns":
            item.update(protocol=protocols[check["endpoint"]], record_type=check.get("record_type", "A"),
                        name=deploy_config.substitute(check["name"], values),
                        expect=[deploy_config.substitute(value, values) for value in check.get("expect", [])])
        else:
            item.update(scheme=check.get("scheme", "http"), path=check.get("path", "/"), status=check.get("status", 200),
                        body_sha256=check.get("body_sha256"))
            if check.get("ready_within_seconds"):
                item["ready_within_seconds"] = check["ready_within_seconds"]
        checks.append(item)
    return checks


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def remote_base(record):
    """Remote payload fields shared by every step of one deployment generation."""
    native = record["native"]
    return {"instance_id": record["instance_id"], "component": native["component"], "generation": record["generation"],
            "ownership_id": record["ownership_id"], "names": native["names"], "paths": native["paths"],
            "gate_command": native["gate_command"], "files": {k: v["sha256"] for k, v in native["files"].items()},
            "datasets": native["datasets"], "claims": [{k: c[k] for k in ("address", "protocol", "port")} for c in native["claims"]],
            "health_checks": native["health_checks"],
            "config": [{"name": item["name"], "sha256": item["sha256"]} for item in native.get("config", [])],
            **({"devices": native["devices"]} if native.get("devices") else {})}


def ready_window(checks):
    """Largest declared readiness window of a deployment's rendered checks (0 without one)."""
    return max([check.get("ready_within_seconds") or 0 for check in checks] or [0])


def start_seconds(checks):
    """Remote start step bound: unchanged without a readiness window; otherwise systemctl start (60 s), the window,
    failure cleanup and a margin."""
    window = ready_window(checks)
    return START_SECONDS if not window else max(START_SECONDS, 60 + window + deploy_remote.CLEANUP_SECONDS + 10)


SYSCTL_DROP_IN = "/etc/sysctl.d/60-unprivileged-ports.conf"


def exposure(claims, facts, host_id, notes=None):
    """LAN-exposure items for non-loopback claims, plus preconditions: the address is assigned on the host,
    and the port is not below the host's `net.ipv4.ip_unprivileged_port_start` (rootless Podman binds host
    ports as the account). `notes`: the endpoints' declared consumer notes (for example "no authentication"),
    repeated on each exposure item. Returns (items, [(id, ok, evidence, blocking)])."""
    items, checks = [], []
    addresses = facts.get("addresses")
    lan = [a for a in addresses or [] if not ip_address(a["address"]).is_loopback]
    for claim in claims:
        label = claim["protocol"] + "/" + claim["address"] + ":" + str(claim["port"])
        if claim["address"] in WILDCARDS:
            networks = sorted({a["network"] + " (" + str(a["ifname"]) + ")" for a in lan})
            items.append({"endpoint": claim["endpoint"], "claim": label, "scope": "all-interfaces", "networks": networks,
                          "note": "Wildcard bind: reachable on every address of " + host_id + "; Switchyard changes no firewall"})
            checks.append(("address-" + claim["endpoint"], True, {"claim": label, "scope": "all interfaces"}, True))
        elif ip_address(claim["address"]).is_loopback:
            checks.append(("address-" + claim["endpoint"], True, {"claim": label, "scope": "loopback only"}, True))
        else:
            match = next((a for a in addresses or [] if a["address"] == claim["address"]), None)
            items.append({"endpoint": claim["endpoint"], "claim": label, "scope": "lan", "address": claim["address"],
                          "interface": match and match["ifname"], "network": match and match["network"],
                          "note": "Reachable from every host on " + (match["network"] if match else "that network")
                                  + "; Switchyard changes no firewall"})
            checks.append(("address-" + claim["endpoint"], match is not None, {
                "claim": label, "assigned": match, "host_addresses": None if addresses is None else sorted(a["address"] for a in addresses),
                "note": "address must be assigned on " + host_id if addresses is not None
                        else "host addresses unknown (`ip -j address show` unavailable); cannot verify"}, True))
    for item in items:
        if (notes or {}).get(item["endpoint"]):
            item["endpoint_notes"] = list(notes[item["endpoint"]])
    start = facts.get("unprivileged_port_start")
    for claim in claims:
        label = claim["protocol"] + "/" + claim["address"] + ":" + str(claim["port"])
        if start is None:
            checks.append(("unprivileged-port-" + claim["endpoint"], False, {
                "claim": label, "note": "net.ipv4.ip_unprivileged_port_start unknown; a port below it fails at start"}, False))
        elif claim["port"] < start:
            lowest = min(c["port"] for c in claims)
            checks.append(("unprivileged-port-" + claim["endpoint"], False, {
                "claim": label, "ip_unprivileged_port_start": start,
                "why": "rootless Podman binds host ports as " + str(facts.get("user")) + ", which may not bind ports below "
                       + str(start) + " on " + host_id,
                "operator_command_persistent": "printf 'net.ipv4.ip_unprivileged_port_start=" + str(lowest) + "\\n' | sudo tee "
                                               + SYSCTL_DROP_IN + " && sudo sysctl --system",
                "operator_command_until_reboot": "sudo sysctl -w net.ipv4.ip_unprivileged_port_start=" + str(lowest),
                "meaning": "every unprivileged process on " + host_id + " may then bind TCP and UDP ports from " + str(lowest)
                           + " upward (IPv4 and IPv6, host network namespace); ports below " + str(lowest) + " stay privileged",
                "note": "Switchyard never runs sudo; run one command on the host, then plan again"}, True))
        else:
            checks.append(("unprivileged-port-" + claim["endpoint"], True,
                           {"claim": label, "ip_unprivileged_port_start": start}, True))
    return items, checks


def config_summary(files, rendered):
    """Plan view of configuration files (texts stay in `native.config`): path, size, hash, generator output."""
    generated = {item["id"]: item.get("generator") for item in rendered}
    return [{"id": f["id"], "path": f["path"], "size": f["size"], "sha256": f["sha256"], "mode": f["mode"],
             "on_change": f["on_change"], **({"generated": generated[f["id"]]} if generated.get(f["id"]) else {})}
            for f in files]


def podman_version(text):
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", str(text or ""))
    return tuple(int(part) for part in match.groups()) if match else None


def device_review(devices, observed, granted, facts, host_id, users=None):
    """Plan view of each declared device (path, type, numbers, owner, mode, who can open it, what the container
    gains) and its preconditions `[(id, ok, evidence, blocking)]`."""
    items, checks = [], []
    if not devices:
        return items, checks
    version = podman_version(facts.get("podman_version"))
    checks.append(("podman-device-support", version is not None and version >= DEVICE_PODMAN_MINIMUM, {
        "podman": facts.get("podman_version"), "requires": ".".join(map(str, DEVICE_PODMAN_MINIMUM)) + " or later",
        "rendering": "hostPath volume of type CharDevice, mounted at the container path: podman kube play adds the node as a "
                     "device (rootless: a read-write bind mount of the node)"}, True))
    for device, state in zip(devices, observed):
        mode = int(state["mode"], 8) if state.get("mode") else 0
        who = []
        if state.get("owner") is not None and mode & 0o600 == 0o600:
            who.append("owner " + state["owner"])
        if state.get("group") is not None and mode & 0o060 == 0o060:
            who.append("group " + state["group"] + (" (" + ", ".join(state["group_members"]) + ")" if state.get("group_members") else ""))
        if mode & 0o006 == 0o006:
            who.append("every local user (mode " + state["mode"] + ")")
        # A rootless container's processes keep none of the account's supplementary groups, and only container root
        # maps to the deploying account; any other container user (or an image default the template does not state)
        # maps to a subordinate ID. So the "other" bits decide, except for a node the account owns that container
        # root opens. `users`: container name -> declared runAsUser (None: not stated).
        run_as = (users or {}).get(device["container_name"])
        container_ok = mode & 0o006 == 0o006 or (run_as == 0 and state.get("uid") == facts.get("uid") and mode & 0o600 == 0o600)
        gpu = state.get("gpu")
        meaning = ("The container can open " + device["host"] + " read-write.")
        if gpu:
            meaning = ("The container can open this GPU's render node read-write: it can submit compute and Vulkan work and "
                       "allocate GPU memory on " + str(gpu.get("vendor")) + ":" + str(gpu.get("device")) + " (driver "
                       + str(gpu.get("driver")) + ", PCI " + str(gpu.get("pci")) + "), shared with every other process on "
                       + host_id + " that uses it; it cannot drive displays (no card node is passed). VRAM in use now: "
                       + str(gpu.get("mem_info_vram_used")) + " of " + str(gpu.get("mem_info_vram_total")) + " bytes.")
        item = {"id": device["id"], "host_path": device["host"], "container_path": device["container"],
                "container": device["container_name"], "access": device["access"], "exists": state.get("exists"),
                "type": "character device" if state.get("char") else "block device" if state.get("block")
                        else "symlink" if state.get("symlink") else "not a device" if state.get("exists") else "missing",
                "major_minor": str(state["major"]) + ":" + str(state["minor"]) if "major" in state else None,
                "owner": state.get("owner"), "group": state.get("group"), "mode": state.get("mode"),
                "who_can_open": who or ["root only"], "deploying_user_can_open": bool(state.get("readable") and state.get("writable")),
                "container_can_open": container_ok, "gpu": gpu, "meaning": meaning}
        items.append(item)
        checks.append(("device-grant-" + device["id"], device["host"] in granted, {
            "device": device["host"], "granted_on_" + host_id: sorted(granted),
            "note": "operations policy deploy_devices must list this device for " + host_id}, True))
        problems = []
        if not state.get("exists"):
            problems.append("missing")
        elif state.get("symlink"):
            problems.append("a symlink (declare the device node itself)")
        elif not state.get("char"):
            problems.append("not a character device")
        else:
            if not item["deploying_user_can_open"]:
                problems.append(str(facts.get("user")) + " cannot open it read-write")
            if not container_ok:
                problems.append("a rootless container cannot open it: it is not world read-write" + (
                    "" if run_as == 0 else ", and the container user (" + ("runAsUser " + str(run_as) if run_as is not None
                    else "image default") + ") maps to a subordinate ID, not to " + str(facts.get("user")))
                    + " (supplementary groups are not kept)")
        checks.append(("device-" + device["id"], not problems, {**{k: item[k] for k in (
            "host_path", "type", "major_minor", "owner", "group", "mode", "who_can_open")}, "problems": problems or None}, True))
    return items, checks


def exclusive_keys(app, host_id):
    """`{host:kind:name: identity}` for an application's host-scoped exclusive resources on `host_id`."""
    return {host_id + ":" + identity["kind"] + ":" + identity["name"]: identity
            for identity in app.get("identities") or [] if identity.get("scope") == "host"}


def holds(row):
    """Whether a placement holds (or may hold) its exclusive resources: active, a valid or unknown token (boot and
    manual starts are open), or uncertain/pending effects. Only fenced (and retired) placements are proven free."""
    if row is None or row["state"] == "retired":
        return False
    meta = row["meta"]
    if meta.get("uncertain") or meta.get("pending") or row["state"] == "active":
        return True
    if row["state"] == "staged":
        return (meta.get("token") or {}).get("state") not in ("revoked", "absent", "removed")
    return False


def contenders(store, instance_id, host_id, app):
    """Other placements on `host_id` that declare one of `app`'s host-scoped exclusive resources."""
    keys = exclusive_keys(app, host_id)
    if not keys:
        return []
    result = []
    for instance, placement in store.instances():
        if instance["id"] == instance_id or placement is None or placement["state"] == "retired" or placement["host_id"] != host_id:
            continue
        shared = sorted(set(keys) & set(exclusive_keys(instance["application"], host_id)))
        if shared:
            meta = placement["meta"]
            result.append({"instance_id": instance["id"], "generation": placement["generation"], "revision": placement["revision"],
                           "state": placement["state"], "token": (meta.get("token") or {}).get("state"),
                           "uncertain": meta.get("uncertain", False), "pending": (meta.get("pending") or {}).get("action"),
                           "holding": holds(placement), "resources": shared})
    return result


def holder_refusal(action, instance_id, holders, *, generic=False):
    resources = sorted({key for holder in holders for key in holder["resources"]})
    return (action + " refused: exclusive resource " + ", ".join(resources) + " is held by " + ", ".join(
        holder["instance_id"] + " (" + holder["state"] + (", uncertain" if holder["uncertain"] else "")
        + (", " + holder["pending"] + " pending" if holder["pending"] else "") + ")" for holder in holders)
        + ("; Stop the workload holding it, then prepare a new plan" if generic
           else "; move it with: switchyard deploy switch-plan " + instance_id))


# ---------------------------------------------------------------- spec records

def build_placement(*, app, host_id, generation, state, ownership_id, native, uid, fence=None):
    component = native["component"]
    value = {"apiVersion": spec.API_VERSION, "kind": "Placement", "id": app["id"] + "-g" + str(generation),
             "application_id": app["id"], "revision": app["revision"], "host_id": host_id, "generation": generation,
             "state": state, "ownership": "deployed", "ownership_id": ownership_id,
             "components": [{"component": component, "native_identities": [
                 {"native_id": native["names"]["service"], "scope": "user:" + str(uid)},
                 {"native_id": "pod/" + native["names"]["pod"], "scope": "user:" + str(uid)}]}],
             "datasets": [{"dataset": d["id"], "path": d["path"], "access": "write", "ownership": "unknown",
                           "ownership_check": "rootless mapping not verified by this deploy round"} for d in native["datasets"]],
             "endpoints": [{"endpoint": c["endpoint"], "address": c["address"], "host_port": c["port"]} for c in native["claims"]]}
    if fence:
        value["fence"] = fence
    placement = spec.Placement.model_validate(value)
    try:
        spec.check_placement(spec.Application.model_validate(app), placement)
    except ValueError as error:
        raise ValueError("Deployed placement does not satisfy its application: " + str(error)) from None
    return placement.model_dump(mode="json", exclude_none=True)


def fence_record(*, app_id, record, token, evidence, stopped=()):
    native = record["native"]
    item = {"application_id": app_id, "component": native["component"], "generation": record["generation"],
            "issued_at": token.get("issued_at") or token.get("revoked_at"), "token_path": native["paths"]["token"],
            "gates": [{"gate": GATE_ID, "evidence": native["paths"]["unit"] + " ExecStartPre checks " + native["paths"]["token"]
                       + " (unit sha256 " + native["files"]["unit"]["sha256"] + ")"}],
            "state": token["state"]}
    if token["state"] == "revoked":
        item["revoked_at"] = token["revoked_at"]
    return {"journal_generation": record["generation"], "host_generation": record["generation"], "tokens": [item],
            "activators": ["systemctl --user start " + native["names"]["service"],
                           "default.target at user-manager start (WantedBy; boot needs linger)",
                           "unit restart (Restart= policy of the generated unit)"],
            "previous_policy": "none: generated by Switchyard for this generation",
            "stopped_native_ids": list(stopped), "evidence": list(evidence)[:16] or ["no evidence"], "verified_at": now()}


# ---------------------------------------------------------------- manager

class DeployManager:
    """Controller side. Takes the broker for plans, receipts, leases and policy."""

    def __init__(self, broker, *, registry_hosts=None):
        """`registry_hosts`: callable returning the host registry's records (for the `registry-hosts`
        generator). Without it, plans of applications with that generator are refused."""
        self.broker = broker
        self.store = WorkloadStore(broker.store.directory)
        self.registry_hosts = registry_hosts

    def _registry(self):
        """Registry host records, or None when this manager was built without the registry."""
        return list(self.registry_hosts()) if self.registry_hosts else None

    # policy -------------------------------------------------------------
    def policy(self):
        config = self.broker._configuration()
        return {"enabled": bool(config and config.get("deploy_hosts")),
                "deploy_hosts": list(config.get("deploy_hosts", [])) if config else [],
                "deploy_devices": {key: list(value) for key, value in (config.get("deploy_devices") or {}).items()} if config else {}}

    def _authority(self, config, host_id):
        if host_id not in config.get("deploy_hosts", []):
            raise ValueError("Host is not listed in the operations policy deploy_hosts")
        hosts = self.broker.operation_hosts(config)
        return authority(config, host_id, hosts[host_id])

    # templates ----------------------------------------------------------
    def save_template(self, document, *, expected_revision):
        document, upgraded_from = spec.upgrade(document)
        try:
            app = spec.Application.model_validate(document)
        except ValidationError as error:
            raise ValueError("Invalid template: " + "; ".join(".".join(str(p) for p in e["loc"]) + ": " + e["msg"]
                                                              for e in error.errors()[:20])) from None
        if app.role != "template" or app.template_ref is not None:
            raise ValueError("Templates must have role template and no template_ref")
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("Expected revision must be a non-negative integer (0 for a new template)")
        result = self.store.save_template(app, expected_revision=expected_revision)
        if upgraded_from:
            result["upgraded_from"] = upgraded_from
        try:
            deployable(app)
            result["deployable"] = True
        except ValueError as error:
            result.update(deployable=False, reason=str(error))
        return result

    def templates(self):
        return self.store.templates()

    def template(self, reference):
        template_id, revision = parse_ref(reference)
        return self.store.template(template_id, revision)

    # registrations of adopted applications -----------------------------------
    def register_application(self, document, *, expected_revision, submitted_by=None, source=None,
                             source_bytes=None, host_ids=None):
        """Store a validated Bundle of one adopted application (metadata only; never contacts a host).

        `host_ids`: registry host IDs for the cross-check (None: not checked, reported as a warning)."""
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("Expected revision must be a non-negative integer (0 for a new registration)")
        if not isinstance(document, dict) or document.get("kind") != "Bundle":
            raise ValueError("Registration takes a Bundle (applications with their adopted placements)")
        placements = document.get("placements")
        if not isinstance(placements, list) or any(
                not isinstance(p, dict) or p.get("ownership") != "adopted" or p.get("ownership_id") is not None for p in placements):
            raise ValueError("Registration accepts only adopted placements without ownership IDs; "
                             "deployed ownership is issued by `deploy apply`, never declared")
        document, upgraded_from = spec.upgrade(document)
        bundle = _validated(document)
        ids = {app.id for app in bundle.applications}
        if len(ids) != 1:
            raise ValueError("A registration holds one application (its revisions share one ID)")
        app_id = ids.pop()
        if any(app.role != "instance" or app.template_ref for app in bundle.applications):
            raise ValueError("Registration is for adopted instances; store templates with `template save`")
        with self.store.transaction() as db:
            relation = self.store.relation_of(db, app_id)
        if relation == "deployed":
            raise ValueError("ID " + app_id + " belongs to a Switchyard-deployed instance")
        if relation == "observed":
            raise ValueError("ID " + app_id + " belongs to an observed workload; the owner registers under another ID")
        latest = max(bundle.applications, key=lambda app: app.revision)
        data = bundle.model_dump(mode="json")
        meta = {"submitted_by": submitted_by or latest.provenance.submitted_by, "source": source,
                "source_sha256": hashlib.sha256(source_bytes if source_bytes is not None else encode(document).encode()).hexdigest(),
                "document_sha256": hashlib.sha256(encode(data).encode()).hexdigest(), "upgraded_from": upgraded_from,
                "applications": [{"id": app.id, "revision": app.revision, "content_sha256": app.content_sha256()}
                                 for app in bundle.applications],
                "warnings": self._registration_warnings(bundle, app_id, host_ids),
                "authority": "none: metadata only; no lifecycle, deploy, fence or undeploy authority"}
        revision, stamp = self.store.save_registration(app_id, data, meta, expected_revision=expected_revision)
        return {"id": app_id, "revision": revision, "registered_at": stamp, **meta}

    def _registration_warnings(self, bundle, app_id, host_ids):
        warnings = []
        if host_ids is None:
            warnings.append("Registry hosts were not checked")
        else:
            for placement in bundle.placements:
                if placement.host_id not in host_ids:
                    warnings.append("Placement " + placement.id + " names host " + placement.host_id + ", which is not in the host registry")
        claims = self.store.all_claims()
        for placement in bundle.placements:
            if placement.state == "retired":
                continue
            app = next(a for a in bundle.applications if (a.id, a.revision) == (placement.application_id, placement.revision))
            protocols = {e.id: e.protocol for e in app.endpoints}
            for claim in placement.endpoints:
                for other in claims:
                    if (other["host_id"], other["protocol"], other["port"]) == (placement.host_id, protocols[claim.endpoint], claim.host_port) \
                            and overlaps(other["address"], claim.address):
                        warnings.append("Port " + protocols[claim.endpoint] + "/" + claim.address + ":" + str(claim.host_port) + " on "
                                        + placement.host_id + " collides with deploy registry claim of " + other["owner_id"])
        held = {}
        for registration in self.store.registrations():
            if registration["id"] != app_id:
                for app in registration["bundle"]["applications"]:
                    for identity in app.get("identities", []):
                        held.setdefault((identity["kind"], identity["name"]), set()).add("registered application " + registration["id"])
        for instance, _ in self.store.instances():
            for identity in instance["application"].get("identities", []):
                held.setdefault((identity["kind"], identity["name"]), set()).add("deployed instance " + instance["id"])
        for app in bundle.applications:
            for identity in app.identities:
                owners = held.get((identity.kind, identity.name))
                if owners and not identity.name.startswith(PLACEHOLDER):
                    warnings.append("Identity " + identity.kind + "/" + identity.name + " is also held by " + ", ".join(sorted(owners)))
        return sorted(set(warnings))

    def registered_applications(self):
        return [{"id": item["id"], "revision": item["revision"], "registered_at": item["registered_at"],
                 "submitted_by": item["meta"]["submitted_by"], "applications": item["meta"]["applications"],
                 "placements": [{"id": p["id"], "host_id": p["host_id"], "state": p["state"]} for p in item["bundle"]["placements"]],
                 "warnings": item["meta"]["warnings"]} for item in self.store.registrations()]

    def registered_application(self, reference):
        registration_id, revision = parse_ref(reference)
        item = self.store.registration(registration_id, revision)
        if item is None:
            raise ValueError("Unknown registration")
        return item

    def unregister_application(self, registration_id, *, expected_revision):
        _id(registration_id, "registration")
        if type(expected_revision) is not int:
            raise ValueError("Expected revision must be an integer")
        removed = self.store.delete_registration(registration_id, expected_revision=expected_revision)
        return {"id": registration_id, "removed_revisions": removed,
                "note": "Registration removed; no host was contacted and nothing native was changed"}

    # listing --------------------------------------------------------------
    def list(self):
        result = []
        for instance, placement in self.store.instances():
            with self.store.transaction() as db:
                verification = self.store.verification(db, instance["id"], placement["generation"]) if placement else None
            result.append({**summary(instance, placement, verification), **self._resources(instance, placement)})
        return result

    def _resources(self, instance, placement):
        """Devices, host-scoped exclusive resources (with who else contends for them) and the image's detached pull of
        one placed instance; empty for instances that have none of them."""
        if not placement or placement["state"] == "retired":
            return {}
        result = {}
        devices = placement["meta"]["native"].get("devices")
        if devices:
            result["devices"] = [{k: device.get(k) for k in ("id", "host", "container", "access", "major", "minor")} for device in devices]
        keys = exclusive_keys(instance["application"], placement["host_id"])
        if keys:
            others = contenders(self.store, instance["id"], placement["host_id"], instance["application"])
            result["exclusive"] = [{"resource": key, "holding": holds(placement),
                                    "contenders": [{k: item[k] for k in ("instance_id", "state", "holding")}
                                                   for item in others if key in item["resources"]]} for key in sorted(keys)]
        digest = (placement["meta"].get("image") or {}).get("digest")
        pull = self.store.pull(placement["host_id"], digest) if digest else None
        if pull:
            result["image_pull"] = {k: pull.get(k) for k in ("state", "reference", "size_bytes", "updated_at")}
        return result

    def workload_definitions(self):
        """Every placed (non-retired) instance in the shape of a workload definition, with its journal summary.

        The fleet view joins these with host observations exactly as it joins operator-defined workloads, so the
        web desk, CLI and MCP all show deployed workloads from this one journal."""
        result = []
        for instance, placement in self.store.instances():
            if not placement or placement["state"] == "retired":
                continue
            with self.store.transaction() as db:
                verification = self.store.verification(db, instance["id"], placement["generation"])
            meta, app = placement["meta"], instance["application"]
            scope = "user:" + str(meta["uid"]) if meta.get("uid") is not None else "user"
            item = summary(instance, placement, verification)
            item.update(updated_at=placement["updated_at"], **self._resources(instance, placement))
            result.append({"deployment": item, "definition": {
                "id": instance["id"], "name": app.get("name") or instance["id"], "purpose": app.get("purpose") or "",
                "device_id": placement["host_id"], "backend": "podman", "management": "deployed", "kind": "service",
                "bindings": [{"backend": "podman", "scope": scope, "selector": {"name": name},
                              "role": "supporting" if index else "primary"}
                             for index, name in enumerate(meta["native"]["names"].get("containers") or [])],
                "requirements": [str(req.get("name")) for req in app.get("requires") or [] if isinstance(req, dict)],
                "architectures": [], "recipe": None, "health_check": None, "data_locations": [], "dependencies": [],
                "notes": None, "supported_operations": ["observe"]}})
        return result

    def show(self, instance_id):
        with self.store.transaction() as db:
            instance = self.store.instance_row(db, instance_id)
            if instance is None:
                raise ValueError("Unknown deployed instance")
            placement = self.store.placement_row(db, instance_id)
            history = [self.store.placement_row(db, instance_id, row[0]) for row in
                       db.execute("SELECT generation FROM placements WHERE instance_id=? ORDER BY generation", (instance_id,))]
            claims = self.store.claims_for(db, instance_id)
            revisions = self.store.instance_revisions(db, instance_id)
            verification = self.store.verification(db, instance_id, placement["generation"]) if placement else None
        result = {"instance": {k: instance[k] for k in ("id", "revision", "template_ref", "content_sha256", "created_at", "meta")},
                  "application": instance["application"], "placement": placement, "claims": claims, "revisions": revisions,
                  "last_verification": verification,
                  "generations": [{"generation": p["generation"], "host_id": p["host_id"], "state": p["state"],
                                   "application_revision": p["placement"]["revision"],
                                   "updated_at": p["updated_at"]} for p in history],
                  **self._resources(instance, placement)}
        operation = placement["meta"].get("last_operation") if placement else None
        if operation:
            try:
                result["last_receipt"] = self.broker.receipt(operation)
            except ValueError:
                result["last_receipt"] = None
        return result

    def instance_revision(self, reference):
        """`INSTANCE@REVISION`: an immutable stored application revision (exact stored form and hash)."""
        instance_id, revision = parse_ref(reference)
        if revision is None:
            raise ValueError("Use INSTANCE@REVISION")
        with self.store.transaction() as db:
            item = self.store.instance_revision(db, instance_id, revision)
        if item is None:
            raise ValueError("Unknown instance revision")
        return item

    # plan -----------------------------------------------------------------
    def upgrade_plan(self, instance_id, template, *, params=None, request_id=None):
        """Replace the current placement with a newer saved revision of the same template."""
        with self.store.reading() as db:
            current = self.store.placement_row(db, instance_id)
        if current is None or current["state"] == "retired":
            raise ValueError("No current placement; use deploy plan --template ID@REVISION to redeploy a retired instance")
        return self.plan(instance_id=instance_id, host_id=current["host_id"], template=template,
                         params=params, request_id=request_id, _replace=True)

    def plan(self, *, instance_id, host_id, template=None, ports=None, addresses=None, datasets=None, request_id=None,
             params=None, records=None, install_fenced=False, _replace=False):
        """`install_fenced`: write everything with a revoked token and start nothing (the placement is `fenced`):
        how a second deployment that contends for an exclusive resource held by another is installed."""
        if type(install_fenced) is not bool:
            raise ValueError("install_fenced must be true or false")
        config = self.broker._enabled()
        _id(instance_id, "instance")
        fingerprint = self._authority(config, host_id)
        ports, addresses, datasets = dict(ports or {}), dict(addresses or {}), dict(datasets or {})
        with self.store.transaction() as db:
            instance = self.store.instance_row(db, instance_id)
            relation = self.store.relation_of(db, instance_id)
            latest = self.store.placement_row(db, instance_id)
            # The mark a host carries is the highest generation ever applied on THAT host; an instance that
            # moves to a host it never ran on must expect none there (found moving lan-dns to Pop!_OS).
            generation_on_host = db.execute("SELECT max(generation) FROM placements WHERE instance_id=? AND host_id=?",
                                            (instance_id, host_id)).fetchone()[0]
        retained, expected_host_generation, placement_revision, instance_upgrade = {}, None, None, None
        template_upgrade = None
        install = "fenced" if install_fenced else "start"
        if instance is None:
            if _replace:
                raise ValueError("Instance changed since planning began")
            if template is None:
                raise ValueError("A new instance requires --template ID[@revision]")
            if relation == "registered":
                raise ValueError("ID " + instance_id + " belongs to a registered adopted application; "
                                 "registration grants no deployment authority")
            if relation == "observed":
                raise ValueError("ID " + instance_id + " belongs to an observed workload; choose another instance ID")
            template_id, revision = parse_ref(template)
            stored = self.store.template(template_id, revision)
            component = deployable(stored["application"])
            app = instance_from_template(stored, instance_id, pod_name=native_names(instance_id, component)["pod"])
            app = deploy_config.change_records(deploy_config.set_parameters(app, dict(params or {})),
                                               add=dict(records or {}), hosts=self._registry())
            app = _validated({**app, "kind": "Application"}).model_dump(mode="json")
            generation = 1
            template_info = {k: stored[k] for k in ("id", "revision", "content_sha256")}
        else:
            placed = latest is not None and latest["state"] != "retired"
            if placed != _replace:
                raise ValueError("Instance is already placed; use deploy upgrade-plan for a template change" if placed
                                 else "Placement changed since upgrade planning began")
            generation = (latest["generation"] if latest else 0) + 1
            retained = instance["meta"].get("retained_datasets", {}) if latest and latest["host_id"] == host_id else {}
            expected_host_generation = generation_on_host
            placement_revision = latest["revision"] if latest else None
            ref = instance["template_ref"]
            requested = parse_ref(template) if template is not None else (ref["id"], ref["revision"])
            if _replace or requested != (ref["id"], ref["revision"]):
                if requested[0] != ref["id"] or requested[1] is None or requested[1] <= ref["revision"]:
                    raise ValueError("Upgrade requires an explicit higher revision of " + ref["id"] + "@"
                                     + str(ref["revision"]))
                if latest is None or latest["host_id"] != host_id:
                    raise ValueError("Upgrade stays on the existing placement host")
                if ports or addresses or datasets or records:
                    raise ValueError("Upgrade preserves host claims, dataset bindings and DNS records; change them separately")
                if placed and (latest["meta"].get("uncertain") or latest["meta"].get("pending")):
                    raise ValueError("Verify or fence the placement before upgrading its uncertain effects")
                stored = self.store.template(*requested)
                from_template = self.store.template(ref["id"], ref["revision"])
                component = deployable(stored["application"])
                if component.id != latest["meta"]["native"]["component"]:
                    raise ValueError("Upgrade cannot change the native component ID")
                app = instance_from_template(stored, instance_id, pod_name=native_names(instance_id, component)["pod"])
                app = deploy_upgrade.carry_settings(app, instance, from_template["application"], dict(params or {}))
                app = _validated(app).model_dump(mode="json")
                old = latest["meta"]["native"]
                protocols = {e["id"]: e["protocol"] for e in app["endpoints"]}
                for claim in old["claims"]:
                    key = claim["endpoint"]
                    if protocols.get(key) != claim["protocol"]:
                        raise ValueError("New template removes or changes protocol of bound endpoint " + key)
                    addresses[key], ports[key] = claim["address"], claim["port"]
                declared = {d["id"] for d in app["datasets"]}
                for binding in old["datasets"]:
                    key = binding["id"]
                    if key not in declared:
                        raise ValueError("New template removes bound dataset " + key)
                    if binding["default"]:
                        if placed:
                            retained[key] = binding["path"]
                    else:
                        datasets[key] = binding["path"]
                token = (latest["meta"].get("token") or {}).get("state")
                if placed:
                    if (latest["state"] == "active" and token != "valid"
                            or latest["state"] == "fenced" and token != "revoked"
                            or token not in ("valid", "revoked")):
                        raise ValueError("Upgrade requires a known generation token matching the placement state")
                    install = {"active": "start", "fenced": "fenced", "staged":
                               "staged" if token == "valid" else "staged-revoked"}[latest["state"]]
                template_info = {k: stored[k] for k in ("id", "revision", "content_sha256")}
                template_upgrade = {"from": ref, "to": app["template_ref"], "previous_generation": latest["generation"],
                                    "previous_state": latest["state"], "previous_token": token,
                                    "previous_claims": old["claims"],
                                    "exclusive_before": sorted(exclusive_keys(instance["application"], host_id)),
                                    "exclusive_after": sorted(exclusive_keys(app, host_id))}
            else:
                if params or records:
                    raise ValueError("Parameters and records of an existing instance change only through deploy refresh-plan")
                app = with_generation_gate(instance["application"])
                template_info = {**ref, "content_sha256": instance["meta"].get("template_content_sha256")}
            if template_upgrade or instance.get("upgraded_from") or app != instance["application"]:
                app["revision"] = instance["revision"] + 1
                instance_upgrade = {"from_revision": instance["revision"], "to_revision": app["revision"],
                                    "from_content_sha256": instance["content_sha256"],
                                    "reason": ("template revision upgrade" if template_upgrade else
                                               "stored instance upgraded to " + spec.API_VERSION + " with its generation gate")}
                if template_upgrade:
                    instance_upgrade.update(from_template=template_upgrade["from"], to_template=template_upgrade["to"])
        component = deployable(app)
        unknown = (set(ports) | set(addresses)) - {e.id for e in spec.Application.model_validate(app).endpoints}
        if unknown or set(datasets) - {d["id"] for d in app["datasets"]}:
            raise ValueError("Unknown endpoint or dataset in --port/--address/--dataset")
        for key, value in addresses.items():
            spec.EndpointClaim.model_validate({"endpoint": key, "address": value, "host_port": 1})
        for key, value in datasets.items():
            if not isinstance(value, str) or not PurePosixPath(value).is_absolute() or ".." in PurePosixPath(value).parts:
                raise ValueError("Dataset paths must be absolute")
        self._no_outstanding_plan(instance_id)
        rendered_config = deploy_config.render_files(app, self._registry())  # fails fast on missing parameters/duplicates
        sub_paths = sub_path_mounts(app)  # likewise for parameters in args, env values and subPath
        ownership_id = str(uuid.uuid4())
        names = native_names(instance_id, component)
        image = image_parts(component.native.manifest.spec.containers[0].image)
        request = {"action": "inspect", "instance_id": instance_id, "host_id": host_id, "generation": generation,
                   "ownership_id": ownership_id, "component": component.id, "names": names, "image": image,
                   "datasets": [{"id": d["id"], "path": datasets.get(d["id"]) or retained.get(d["id"]),
                                 **({"sub_paths": sub_paths[d["id"]]} if d["id"] in sub_paths else {})}
                                for d in app["datasets"]],
                   "devices": [d["host_path"] for d in app.get("devices") or []],
                   "operator_datasets": sorted(datasets), "retained_entries": ["data", "generation"] if instance else [],
                   "instance_upgrade": instance_upgrade, "template_upgrade": template_upgrade, "install": install,
                   "placement_revision": placement_revision,
                   **self._request_common(config, host_id, fingerprint)}
        intent = {"kind": "deploy", "action": "plan-inspect", "instance_id": instance_id, "host_id": host_id,
                  "nonce": uuid.uuid4().hex}
        receipt = self._run(request_id or "deploy-plan-" + uuid.uuid4().hex, intent, host_id, request, config)
        if receipt.get("status") != "succeeded":
            raise ValueError("Leased plan inspection did not succeed (" + str(receipt.get("status")) + "): "
                             + str(receipt.get("error")) + "; receipt " + receipt["id"])
        inspected = self.store.take_inspection(receipt["id"])
        if inspected is None:
            raise ValueError("Plan inspection result missing; receipt " + receipt["id"])
        return self._build_plan(config, fingerprint, app, template_info, inspected, receipt, request, generation,
                                ports, addresses, retained, expected_host_generation, placement_revision, bool(instance),
                                rendered_config)

    def _build_plan(self, config, fingerprint, app, template_info, inspected, receipt, request, generation,
                    ports, addresses, retained, expected_host_generation, placement_revision, redeploy, rendered_config):
        facts, inspection = inspected["facts"], inspected["inspection"]
        host_id, instance_id = request["host_id"], request["instance_id"]
        pre, warnings = [], []

        def check(name, ok, evidence, blocking=True):
            pre.append({"id": name, "ok": bool(ok), "blocking": blocking, "evidence": evidence})

        check("deploy-authority", True, "operations policy deploy_hosts includes " + host_id)
        check("rootless-podman", facts["rootless"] and facts["uid"] != 0, "podman " + facts["podman_version"] + ", uid " + str(facts["uid"]))
        check("quadlet-generator", inspection["quadlet"]["ok"] and inspection["quadlet"]["gate_present"],
              {k: inspection["quadlet"].get(k) for k in ("generated_sha256", "gate_present", "exec_start", "exec_stop_post", "reason")})
        # Found on CachyOS with Podman 6.2: nothing pulled the system's network-online.target into boot, so
        # every rootless Quadlet start waited 90 s for it and ran past the start deadline.
        waits = inspection["quadlet"].get("waits_network_online") and inspection.get("network_online") is False
        check("network-online", not waits, {
            "system_target": "inactive",
            "why": "Podman's generated unit waits up to 90 s for the system's network-online.target "
                   "(podman-user-wait-network-online.service) before every start; it is not active on " + host_id,
            "operator_command": "sudo systemctl add-wants multi-user.target network-online.target && "
                                "sudo systemctl start network-online.target",
            "note": "Switchyard never runs sudo; run the command on the host, then plan again",
        } if waits else "system network-online.target is active, or the generated unit does not wait for it")
        check("gate-tool", facts["grep"], "/usr/bin/grep executable (ExecStartPre gate)")
        check("pod-pause-binary", facts.get("catatonit"), facts.get("catatonit") or
              "catatonit not found: `podman kube play` cannot build its pause/service image, so no pod can start "
              "(Debian/Ubuntu: install the `catatonit` package)")
        check("user-manager", facts["user_manager"] in ("running", "degraded"), "systemctl --user is-system-running: " + facts["user_manager"])
        check("linger", facts["linger"] is True, "linger=" + str(facts["linger"]) + "; without linger user services stop with the last "
              "login session and do not start at boot (not changed by Switchyard)", blocking=False)
        resolution = inspection["image"]
        image = dict(request["image"])
        if resolution.get("digest"):
            image.update(digest=resolution["digest"], pull_reference=image["repository"] + "@" + resolution["digest"])
        image.update(resolution=resolution["method"], platforms=resolution.get("platforms"))
        if resolution.get("warning"):
            warnings.append(resolution["warning"])
        pending = resolution["method"] == "pull-at-apply"
        check("image-digest", True, ("tag " + str(image["tag"]) + " resolves to " + str(image.get("digest")) + " via " + resolution["method"])
              if not pending else "Read-only resolution failed (" + "; ".join(resolution.get("attempts", [])) + "): apply pulls "
              + image["pull_reference"] + " and pins the digest it observes", blocking=False)
        platforms = resolution.get("platforms")
        wanted = "linux/" + facts["architecture"]
        check("architecture", platforms is None or wanted in platforms,
              {"host": wanted, "image_platforms": platforms, "note": None if platforms else "verified after pull at apply"})
        if not pending:
            app = pin_image(app, image["digest"])
        store_facts = resolution.get("store") or {}
        size = (store_facts.get("size") or {}).get("bytes")
        image.update(size_bytes=size, layers=(store_facts.get("size") or {}).get("layers"), local=store_facts.get("local"),
                     requires_local=isinstance(size, int) and size > LARGE_IMAGE_BYTES)
        if image["requires_local"]:
            # A large image is never pulled inside apply's bounded step: a detached pull fetches it beforehand.
            reference = image["repository"] + "@" + image["digest"]
            check("image-present", store_facts.get("local") is True, {
                "image": reference, "compressed_bytes": size, "threshold_bytes": LARGE_IMAGE_BYTES, "local": store_facts.get("local"),
                "pull": self.store.pull(host_id, image["digest"]),
                "command": "switchyard deploy pull-start --host " + host_id + " --image " + reference,
                "note": "Images above the threshold are pulled beforehand by a detached pull on the host "
                        "(`deploy pull-start`, progress with `deploy pull-status`); apply then only verifies the local digest"})
        elif "store" in resolution and size is None:
            check("image-size", True, "The registry did not report the image size; apply pulls it inside its bounded step",
                  blocking=False)
        unresolved = [p for p in _placeholders(app) if not (pending and p.endswith(".image"))]
        check("no-placeholders", not unresolved, unresolved or "none")
        # Ports: registry claims, plan reservations and live listeners on the target.
        claims = {}
        component = spec.Application.model_validate(app).components[0]
        own = [e for e in app["endpoints"] if e["component"] == component.id]
        with self.store.transaction() as db:

            def conflicts(port, protocol, address):
                registry = self.store.conflicts(db, host_id, address, protocol, port, ignore_owner=instance_id)
                live = [l for l in inspection["listeners"] if l["protocol"] == protocol and l["port"] == port
                        and overlaps(l["address"], address)]
                taken = [c for c in claims.values() if c["protocol"] == protocol and c["port"] == port
                         and overlaps(c["address"], address)]
                return {"registry": registry, "listeners": live, "this_plan": taken} if registry or live or taken else None

            for endpoint in own:
                address = addresses.get(endpoint["id"], "127.0.0.1")
                wanted_port = ports.get(endpoint["id"])
                # Auto-picked endpoints on one container port (DNS over UDP and TCP) share one host port that is
                # free for every protocol of the group.
                group = [e for e in own if e["target_port"] == endpoint["target_port"] and not ports.get(e["id"])]
                shared = [claims[e["id"]]["port"] for e in group if e["id"] in claims and claims[e["id"]]["port"]]
                candidates = [wanted_port] if wanted_port else shared[:1] or list(PORT_RANGE)
                chosen, evidence = None, []
                for port in candidates:
                    members = [endpoint] if wanted_port or shared else group
                    found = [conflicts(port, m["protocol"], addresses.get(m["id"], "127.0.0.1")) for m in members]
                    if not any(found):
                        chosen = port
                        break
                    evidence = next(item for item in found if item)
                claims[endpoint["id"]] = {"endpoint": endpoint["id"], "address": address, "protocol": endpoint["protocol"],
                                          "port": chosen or (wanted_port or 0)}
                check("port-" + endpoint["id"], chosen is not None,
                      {"claim": endpoint["protocol"] + "/" + address + ":" + str(chosen or wanted_port),
                       "selected": "operator" if wanted_port else "first free in 18100-18999", "conflicts": evidence or None})
        lan_exposure, exposure_checks = exposure(list(claims.values()), facts, host_id,
                                                 notes={e["id"]: e.get("consumers") or [] for e in app["endpoints"]})
        for item in exposure_checks:
            check(*item)
        # Datasets: default per-instance directories, retained ones, or operator-provided existing directories.
        modes = dataset_mount_modes(app)
        bound = []
        for item, observed in zip(request["datasets"], inspection["datasets"]):
            default = item["id"] not in request["operator_datasets"]
            path = observed["path"]
            mode = modes.get(item["id"], "not mounted")
            if default and item["id"] in retained:
                ok = observed.get("exists") and observed.get("directory") and not observed.get("symlink")
                note = "retained from an earlier generation of this instance"
            elif default:
                ok = not observed.get("exists")
                note = "created at apply" if ok else "default path exists; never reused silently: pass --dataset " + item["id"] + "=" + path
            else:
                ok = observed.get("directory") and not observed.get("symlink") and observed.get("readable")
                note = ("operator-provided existing directory, mounted " + mode + "; Switchyard never creates, chowns, "
                        "relabels or deletes it (no :z, :Z or :U mount option is rendered), and undeploy leaves it in place")
                if ok and observed.get("owner_uid") != facts["uid"]:
                    warnings.append("Dataset " + item["id"] + " is owned by uid " + str(observed.get("owner_uid"))
                                    + "; rootless containers see it through the user namespace mapping")
            subs = item.get("sub_paths") or []
            bound.append({"id": item["id"], "path": path, "default": default, **({"sub_paths": subs} if subs else {})})
            check("dataset-" + item["id"], ok, {"path": path, "mount": mode, "note": note, **{k: observed.get(k) for k in
                  ("exists", "empty", "size", "owner_uid", "mode")}})
            if subs:
                states = observed.get("sub_paths") or []
                problems = [state["sub_path"] + ": " + ("missing" if state.get("exists") is False else "reached through a symlink"
                            if state.get("symlink") else "not a readable directory") for state in states
                            if not (state.get("directory") and state.get("symlink") is False and state.get("readable"))]
                if default and item["id"] not in retained:
                    problems = ["a subPath inside a dataset Switchyard creates empty cannot exist; bind an existing "
                                "directory with --dataset " + item["id"] + "=PATH"]
                elif len(states) != len(subs):
                    problems = problems or ["sub-paths not inspected: the dataset is not a readable directory"]
                check("dataset-" + item["id"] + "-sub-paths", not problems, {"sub_paths": states, "problems": problems or None,
                      "note": "each subPath is bound as its own read-" + ("only" if mode == "read-only" else "write")
                              + " directory; the container sees nothing else of the dataset"})
                for state in states:
                    if state.get("directory") and not state.get("other_readable"):
                        warnings.append("Dataset sub-path " + state["path"] + " (mode " + str(state.get("mode")) + ") is not "
                                        "readable by other users; a non-root container user may not read it")
        check("name-collisions", not inspection["collisions"], inspection["collisions"] or "none")
        check("host-generation", inspection["host_generation"] == expected_host_generation,
              {"host": inspection["host_generation"], "journal": expected_host_generation})
        image_reference = image["pull_reference"]
        rendered = render(app, generation=generation, ownership_id=request["ownership_id"], facts=facts,
                          datasets=bound, claims=claims, image_reference=image_reference, config=rendered_config)
        if rendered["files"]["unit"]["sha256"] != inspected["unit_sha256"]:
            check("unit-render", False, "Unit rendered for the plan differs from the inspected dry-run unit")
        if rendered["config"]:
            check("config-files", True, {"directory": rendered["paths"]["config_dir"], "mount": "read-only, config://" + component.id,
                                         "files": len(rendered["config"]), "bytes": sum(f["size"] for f in rendered["config"])})
        pod_spec = app["components"][0]["native"]["manifest"]["spec"]
        pod_user = (pod_spec.get("securityContext") or {}).get("runAsUser")
        users = {}
        for container in pod_spec["containers"]:
            own = (container.get("securityContext") or {}).get("runAsUser")
            users[rendered["names"]["base"] + "-" + container["name"]] = own if own is not None else pod_user
        devices, device_checks = device_review(rendered["devices"], inspection.get("devices") or [],
                                               (config.get("deploy_devices") or {}).get(host_id, []), facts, host_id, users)
        for item in device_checks:
            check(*item)
        observed_devices = {state["path"]: state for state in inspection.get("devices") or []}
        rendered_devices = [{**item, "major": observed_devices.get(item["host"], {}).get("major"),
                             "minor": observed_devices.get(item["host"], {}).get("minor")} for item in rendered["devices"]]
        install = request["install"]
        fenced_install = install == "fenced"
        found = contenders(self.store, instance_id, host_id, app)
        holders = [item for item in found if item["holding"]]
        exclusive = []
        for key, identity in exclusive_keys(app, host_id).items():
            mine = [item for item in holders if key in item["resources"]]
            exclusive.append({"resource": key, "identity": identity["id"], "description": identity["description"],
                              "contenders": [item for item in found if key in item["resources"]]})
            check("exclusive-" + identity["id"], not mine or install != "start", {
                "resource": key, "held_by": [item["instance_id"] + " (" + item["state"] + ")" for item in mine] or None,
                "note": ("does not start in this plan" if install != "start" else
                         "held by another placement; fence the holder separately before applying" if mine
                         else "no other placement holds it")})
        blockers = [p for p in pre if p["blocking"] and not p["ok"]]
        native = {k: rendered[k] for k in ("component", "names", "paths", "gate_command", "health_checks", "config")}
        native.update(files={k: {kk: vv for kk, vv in v.items()} for k, v in rendered["files"].items()},
                      datasets=bound, claims=list(claims.values()), pending_digest=pending)
        if rendered_devices:
            native["devices"] = rendered_devices
        start_step = ("Leave it fenced: the token is revoked before the unit is written; nothing is started"
                      if fenced_install else "systemctl --user start; verify pod ownership labels" + (
                          ", the containers' devices" if rendered_devices else "") + "; health checks with bounded retries"
                      + (" (readiness window " + str(ready_window(rendered["health_checks"])) + " s)"
                         if ready_window(rendered["health_checks"]) else ""))
        if install.startswith("staged"):
            start_step = "Leave it staged without starting; keep the previous token's valid or revoked state"
        plan = {"id": uuid.uuid4().hex, "kind": "deploy", "action": "deploy", "instance_id": instance_id,
                "host_id": host_id, "generation": generation, "ownership_id": request["ownership_id"],
                "redeploy": redeploy, "placement_revision": placement_revision, "instance_upgrade": request.get("instance_upgrade"),
                "expected_host_generation": expected_host_generation, "template": template_info,
                "application": app, "application_sha256": None if pending else spec.Application.model_validate(app).content_sha256(),
                "image": image, "native": native, "token_path": rendered["paths"]["token"], "install": request.get("install", "start"),
                "config_files": config_summary(rendered["config"], rendered_config), "lan_exposure": lan_exposure,
                "devices": devices, "exclusive": exclusive,
                "facts": {k: facts.get(k) for k in ("uid", "user", "home", "architecture", "podman_version", "linger", "user_manager",
                                                    "unprivileged_port_start")},
                "preconditions": pre, "warnings": warnings + (["Image digest is pinned at apply from the pulled image; "
                                                               "the yaml text and its hash are re-rendered then and recorded in the receipt"] if pending else []),
                "approvals": [{"gate": "deploy authority", "kind": "configured prerequisite",
                               "satisfied": "operations policy deploy_hosts includes " + host_id},
                              {"gate": "plan approval", "kind": "explicit",
                               "how": "switchyard deploy apply PLAN_ID --approve --request-id ID",
                               **({"includes": ["LAN exposure: " + item["claim"] + " (" + item["scope"] + ")"
                                                for item in lan_exposure]
                                               + ["Device access: " + item["host_path"] + " in container " + item["container"]
                                                  + " (" + item["access"] + ")" for item in devices]}
                                  if lan_exposure or devices else {})}],
                "checkpoints": {"destructive": False, "note": "deploy creates only new owned resources; nothing is deleted"},
                "steps": ["Acquire " + host_id + " canonical lease; recheck authority, identity, collisions, ports, devices, "
                          "exclusive resources and host generation",
                          ("Verify " + image["pull_reference"] + " is in the local image store (pulled beforehand; never pulled here)")
                          if image["requires_local"] else "Pull " + image["pull_reference"] + " and verify digest and platform",
                          "Journal intent: instance, staged placement generation " + str(generation) + ", port claims",
                          "Create dataset directories, owner marker, configuration files, Pod YAML, generation token and "
                          ".kube unit (atomic, no replace)",
                          "systemctl --user daemon-reload; verify generated unit and its ExecStartPre gate",
                          start_step,
                          "Record " + ("active" if install == "start" else "fenced" if fenced_install else "staged")
                          + " placement with its native identities and hashes",
                          "On failure after writing: stop, prove the pod is gone, revoke the token, leave staged; never retry"],
                "inspection_receipt": receipt["id"], "executable": not blockers,
                "blockers": [b["id"] for b in blockers],
                "expires_at": (datetime.now(timezone.utc) + PLAN_TTL).isoformat(), "approval_required": True}
        if upgrade := request.get("template_upgrade"):
            plan["template_upgrade"] = {**upgrade, "new_claims": native["claims"]}
            if upgrade["previous_state"] != "retired":
                plan["checkpoints"] = {"destructive": True, "note": "Only replaces the verified prior generation's "
                                      "Switchyard-owned runtime files; never deletes or migrates datasets"}
                plan["steps"].insert(2, "Re-verify the old generation; revoke its token, stop it and remove only owned runtime files")
                if upgrade["previous_state"] == "active":
                    plan["warnings"].append("This active service goes down between removal and successful health checks")
                plan["warnings"].append("If replacement fails after removal, inspect the receipt and redeploy; "
                                        "no automatic rollback of runtime or operator data")
        if blockers:
            return plan
        with self.broker.store.transaction() as db:
            db.execute("DELETE FROM plans WHERE consumed=0 AND json_extract(data,'$.expires_at') < ?", (now(),))
            if db.execute("SELECT count(*) FROM plans WHERE consumed=0").fetchone()[0] >= 256:
                raise ValueError("Too many outstanding plans")
            with self.store.transaction() as ddb:
                self.store.reserve(ddb, host_id, list(claims.values()), plan_id=plan["id"], generation=generation,
                                   expires_at=plan["expires_at"], ignore_owner=instance_id)
            db.execute("INSERT INTO plans(id,data,fingerprint) VALUES(?,?,?)", (plan["id"], encode(plan), fingerprint))
            self.broker.store.bump(db)
        return plan

    def _no_outstanding_plan(self, instance_id):
        with self.broker.store.transaction() as db:
            row = db.execute("SELECT count(*) FROM plans WHERE consumed=0 AND json_extract(data,'$.kind')='deploy' "
                             "AND json_extract(data,'$.instance_id')=? AND json_extract(data,'$.expires_at') > ?",
                             (instance_id, now())).fetchone()
        if row[0]:
            raise ValueError("Another unexpired plan already reserves this instance; apply it or wait for expiry")

    # execution helpers ------------------------------------------------------
    def _request_common(self, config, host_id, fingerprint):
        return {"config_path": str(self.broker.config_path.resolve()), "authority": fingerprint,
                "local": host_id in self.broker.local_host_ids(config)}

    def _replay(self, db, request_id, intent):
        self.broker._request_id(request_id)
        old = db.execute("SELECT intent_hash,receipt FROM operations WHERE request_id=?", (request_id,)).fetchone()
        if old is None:
            return None
        self.broker.store.reconcile(db)
        if old["intent_hash"] != digest(intent):
            raise ValueError("Request ID is already bound to a different intent")
        return {"receipt": json.loads(db.execute("SELECT receipt FROM operations WHERE request_id=?", (request_id,)).fetchone()[0]),
                "replayed": True}

    def _run(self, request_id, intent, host_id, request, config, *, plan_id=None, checks=None, worker_seconds=None,
             workload_id=None):
        with self.broker.store.transaction() as db:
            replay = self._replay(db, request_id, intent)
            if replay:
                return replay["receipt"]
            if checks:
                checks(db)
            result = self.broker._begin(db, request_id=request_id, intent=intent, kind="deploy", host_ids=[host_id],
                                        plan_id=plan_id, workload_id=workload_id)
        if result["receipt"]["status"] != "running" or result.get("replayed"):
            return result["receipt"]
        payload = {"kind": "deploy", "operation_hosts": self.broker.operation_hosts(config),
                   "local_host_ids": self.broker.local_host_ids(config), "request": request}
        if worker_seconds:
            payload["worker_seconds"] = worker_seconds
            request["dispatch_seconds"] = worker_seconds
        return self.broker._dispatch(result["receipt"], payload)["receipt"]

    def _outcome(self, receipt, instance_id):
        result = {"receipt": receipt}
        try:
            with self.store.transaction() as db:
                row = self.store.placement_row(db, instance_id)
            if row:
                result["placement"] = {"generation": row["generation"], "state": row["state"], "host_id": row["host_id"],
                                       "token": row["meta"].get("token"), "runtime": row["meta"].get("runtime"),
                                       "uncertain": row["meta"].get("uncertain", False)}
        except ValueError:
            pass
        return result

    # apply ------------------------------------------------------------------
    def apply(self, plan_id, *, approved, request_id):
        return self._execute_plan(plan_id, approved=approved, request_id=request_id, action="deploy")

    def undeploy_apply(self, plan_id, *, approved, request_id):
        return self._execute_plan(plan_id, approved=approved, request_id=request_id, action="undeploy")

    def refresh_apply(self, plan_id, *, approved, request_id):
        return self._execute_plan(plan_id, approved=approved, request_id=request_id, action="refresh")

    def switch_apply(self, plan_id, *, approved, request_id):
        """Execute an approved switch plan: one host lease, one receipt (see `switch_plan`)."""
        return self._execute_plan(plan_id, approved=approved, request_id=request_id, action="switch")

    def _execute_plan(self, plan_id, *, approved, request_id, action):
        if approved is not True:
            raise ValueError("Execution requires explicit approval (--approve)")
        self.broker._request_id(plan_id)
        config = self.broker._enabled()
        with self.broker.store.transaction() as db:
            row = db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown plan")
        plan = json.loads(row["data"])
        if plan.get("kind") != "deploy" or plan.get("action") != action:
            raise ValueError("Not a " + action + " plan")
        intent_action = ("upgrade-apply" if plan.get("template_upgrade") else "apply") if action == "deploy" else action + "-apply"
        intent = {"kind": "deploy", "action": intent_action, "plan_id": plan_id, "instance_id": plan["instance_id"]}

        def checks(db):
            if _expired(plan["expires_at"]):
                raise ValueError("Plan expired; plan again")
            if row["fingerprint"] != self._authority(config, plan["host_id"]):
                raise ValueError("Deploy authority or host configuration changed; plan again")
            with self.store.transaction() as ddb:
                instance = self.store.instance_row(ddb, plan["instance_id"])
                latest = self.store.placement_row(ddb, plan["instance_id"])
            if action == "deploy":
                if not _deploy_binding_matches(plan, latest, instance):
                    raise ValueError("Instance or placement changed since planning; plan again")
            elif latest is None or latest["generation"] != plan["generation"] or latest["revision"] != plan["placement_revision"]:
                raise ValueError("Placement changed since planning; plan again")

            if action == "switch":
                with self.store.transaction() as ddb:
                    for item in plan["previous"]:
                        other = self.store.placement_row(ddb, item["instance_id"])
                        if other is None or (other["generation"], other["revision"]) != (item["generation"], item["revision"]):
                            raise ValueError("Placement of " + item["instance_id"] + " changed since planning; plan again")

        request = {"action": "apply" if action == "deploy" else action, "plan": plan,
                   **self._request_common(config, plan["host_id"], row["fingerprint"])}
        receipt = self._run(request_id, intent, plan["host_id"], request, config, plan_id=plan_id, checks=checks,
                            worker_seconds=(SWITCH_DISPATCH_SECONDS if action == "switch" else
                                            UPGRADE_DISPATCH_SECONDS if action == "deploy" and plan.get("template_upgrade") else None))
        result = self._outcome(receipt, plan["instance_id"])
        if action == "switch":
            result["previous"] = [{**(self._outcome(receipt, item["instance_id"]).get("placement") or {}), "instance_id": item["instance_id"]}
                                  for item in plan["previous"]]
            with self.store.transaction() as db:
                target = self.store.placement_row(db, plan["instance_id"])
            result["switch"] = target["meta"].get("last_switch") if target else None
        return result

    # generic workload lifecycle ---------------------------------------------
    def lifecycle_plan(self, action, workload_id):
        """Plan only an existing placement's lifecycle; never deploy, remove or displace another workload."""
        if action not in LIFECYCLE_ACTIONS:
            raise ValueError("Unsupported workload lifecycle action")
        config = self.broker._enabled()
        with self.store.transaction() as db:
            row = self.store.placement_row(db, workload_id)
            instance = self.store.instance_row(db, workload_id)
        if row is None or row["state"] == "retired" or instance is None:
            raise ValueError("Workload has no current deployed placement")
        host_id = row["host_id"]
        fingerprint = self._authority(config, host_id)
        pre = []
        state_error = _lifecycle_state_error(action, row)
        pre.append({"id": "placement-state", "ok": state_error is None, "blocking": True,
                    "evidence": state_error or "Placement permits " + action})
        if action != "stop":
            missing = sorted({d["host"] for d in row["meta"]["native"].get("devices") or []}
                             - set(granted_devices(config, host_id)))
            pre.append({"id": "device-grants", "ok": not missing, "blocking": True,
                        "evidence": "Device grants missing: " + ", ".join(missing) if missing else "Declared devices are granted"})
            holders = [item for item in contenders(self.store, workload_id, host_id, instance["application"]) if item["holding"]]
            pre.append({"id": "exclusive-resources", "ok": not holders, "blocking": True,
                        "evidence": holder_refusal(action.capitalize(), workload_id, holders, generic=True) if holders
                        else "No other placement holds the declared exclusive resources"})
        blockers = [item["evidence"] for item in pre if not item["ok"]]
        steps = ["Acquire " + host_id + " canonical lease; recheck placement, authority and ownership"]
        if action != "stop":
            steps.append("Verify device access and every declared exclusive contender; never stop another workload")
        if action in ("stop", "restart"):
            steps.append("Stop this workload, prove its pod and containers gone, revoke its generation token and record fenced")
        if action != "stop":
            steps.extend(["Open only this workload's generation fence and start once under the same lease",
                          "Verify pod ownership, declared devices and health; on failure stop, prove down and revoke the token"])
        plan = {"id": uuid.uuid4().hex, "kind": "deploy-lifecycle", "action": action,
                "workload_id": workload_id, "instance_id": workload_id, "source_id": host_id, "target_id": host_id,
                "host_id": host_id, "generation": row["generation"], "placement_revision": row["revision"],
                "instance_revision": instance["revision"], "application_sha256": instance["content_sha256"],
                "authority": fingerprint, "from_state": row["state"], "preconditions": pre,
                "executable": not blockers, "blockers": blockers, "approval_required": True,
                "expires_at": (datetime.now(timezone.utc) + PLAN_TTL).isoformat(),
                "execution_timeout_seconds": 450, "steps": steps,
                "warnings": (["Restart causes downtime; no automatic retry or restoration"] if action == "restart" else [])
                            + ["Stop keeps the deployment and its data, but closes its boot/manual-start gate"
                               if action == "stop" else "Start never displaces another exclusive-resource holder"]}
        if blockers:
            return plan
        with self.broker.store.transaction() as db:
            db.execute("DELETE FROM plans WHERE consumed=0 AND json_extract(data,'$.expires_at') < ?", (now(),))
            if db.execute("SELECT count(*) FROM plans WHERE consumed=0").fetchone()[0] >= 256:
                raise ValueError("Too many outstanding plans")
            db.execute("INSERT INTO plans(id,data,fingerprint) VALUES(?,?,?)", (plan["id"], encode(plan), fingerprint))
            self.broker.store.bump(db)
        return plan

    def lifecycle_apply(self, plan_id, *, approved, request_id):
        if approved is not True:
            raise ValueError("Execution requires explicit approval")
        self.broker._request_id(plan_id)
        with self.broker.store.transaction() as db:
            stored = db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
        if stored is None:
            raise ValueError("Unknown plan")
        plan = json.loads(stored["data"])
        if plan.get("kind") != "deploy-lifecycle" or plan.get("action") not in LIFECYCLE_ACTIONS:
            raise ValueError("Not a workload lifecycle plan")
        intent = {"kind": "deploy-lifecycle", "action": plan["action"], "workload_id": plan["workload_id"],
                  "instance_id": plan["instance_id"], "target_id": plan["host_id"], "plan_id": plan_id}
        with self.broker.store.transaction() as db:
            replay = self._replay(db, request_id, intent)
        if replay:
            return {**self._outcome(replay["receipt"], plan["instance_id"]), "replayed": True}
        config = self.broker._enabled()

        def checks(db):
            if _expired(plan["expires_at"]):
                raise ValueError("Plan expired; plan again")
            if not plan["executable"]:
                raise ValueError("Plan is blocked: " + ", ".join(plan["blockers"]))
            if stored["fingerprint"] != self._authority(config, plan["host_id"]):
                raise ValueError("Deploy authority or host configuration changed; plan again")
            with self.store.transaction() as ddb:
                row = self.store.placement_row(ddb, plan["instance_id"])
                instance = self.store.instance_row(ddb, plan["instance_id"])
            if not _lifecycle_binding_matches(plan, row, instance):
                raise ValueError("Placement or workload changed since planning; plan again")

        request = {"action": "lifecycle", "plan": plan,
                   **self._request_common(config, plan["host_id"], stored["fingerprint"])}
        receipt = self._run(request_id, intent, plan["host_id"], request, config, plan_id=plan_id, checks=checks,
                            worker_seconds=LIFECYCLE_DISPATCH_SECONDS, workload_id=plan["workload_id"])
        return self._outcome(receipt, plan["instance_id"])

    # direct lifecycle -------------------------------------------------------
    def act(self, instance_id, action, *, approved=False, request_id=None):
        if action not in DIRECT_ACTIONS:
            raise ValueError("Unsupported deploy action")
        config = self.broker._enabled()
        intent = {"kind": "deploy", "action": action, "instance_id": instance_id}
        if approved and request_id:
            with self.broker.store.transaction() as db:
                replay = self._replay(db, request_id, intent)
            if replay:
                return self._outcome(replay["receipt"], instance_id)
        with self.store.transaction() as db:
            row = self.store.placement_row(db, instance_id)
            instance = self.store.instance_row(db, instance_id)
        allowed_from(action, row)
        host_id = row["host_id"]
        fingerprint = self._authority(config, host_id)
        if action in ("start", "unfence"):
            # A start path may open only while no other placement on the host holds its exclusive resources,
            # and only with the policy still granting its devices.
            holders = [item for item in contenders(self.store, instance_id, host_id, instance["application"]) if item["holding"]]
            if holders:
                raise ValueError(holder_refusal(action.capitalize(), instance_id, holders))
            missing = sorted({d["host"] for d in row["meta"]["native"].get("devices") or []} - set(granted_devices(config, host_id)))
            if missing:
                raise ValueError(action.capitalize() + " refused: the operations policy deploy_devices no longer grants "
                                 + ", ".join(missing) + " on " + host_id)
        preview = {"instance_id": instance_id, "action": action, "host_id": host_id, "generation": row["generation"],
                   "from": {"state": row["state"], "token": row["meta"].get("token"), "uncertain": row["meta"].get("uncertain", False)},
                   "to": TRANSITIONS[action], "steps": ACTION_STEPS[action], "approval_required": True,
                   "how": "switchyard deploy " + action + " " + instance_id + " --approve --request-id ID"}
        if not approved:
            return {"preview": preview}
        if not request_id:
            raise ValueError("Approved deploy actions require --request-id")
        request = {"action": action, "instance_id": instance_id, "generation": row["generation"],
                   "placement_revision": row["revision"], "host_id": host_id,
                   **self._request_common(config, host_id, fingerprint)}
        receipt = self._run(request_id, intent, host_id, request, config)
        return self._outcome(receipt, instance_id)

    # undeploy plan ------------------------------------------------------------
    def undeploy_plan(self, instance_id, *, delete_data=False, request_id=None):
        config = self.broker._enabled()
        with self.store.transaction() as db:
            row = self.store.placement_row(db, instance_id)
            claims = self.store.claims_for(db, instance_id)
        if row is None or row["state"] == "retired":
            raise ValueError("Instance has no placement to undeploy")
        host_id = row["host_id"]
        fingerprint = self._authority(config, host_id)
        request = {"action": "observe", "instance_id": instance_id, "generation": row["generation"],
                   "placement_revision": row["revision"], "host_id": host_id,
                   **self._request_common(config, host_id, fingerprint)}
        intent = {"kind": "deploy", "action": "undeploy-inspect", "instance_id": instance_id, "nonce": uuid.uuid4().hex}
        receipt = self._run(request_id or "deploy-undeploy-inspect-" + uuid.uuid4().hex, intent, host_id, request, config)
        if receipt.get("status") != "succeeded":
            raise ValueError("Leased ownership inspection did not succeed (" + str(receipt.get("status")) + "): "
                             + str(receipt.get("error")) + "; receipt " + receipt["id"])
        observation = self.store.take_inspection(receipt["id"])["observation"]
        native = row["meta"]["native"]
        data = []
        for item in observation["datasets"]:
            owned = item["default"]
            data.append({"id": item["id"], "path": item["path"], "created_by_switchyard": owned,
                         "exists": item.get("exists"), "size": item.get("size"),
                         "action": "delete" if delete_data and owned and item.get("exists") else "keep"})
        plan = {"id": uuid.uuid4().hex, "kind": "deploy", "action": "undeploy", "instance_id": instance_id,
                "host_id": host_id, "generation": row["generation"], "placement_revision": row["revision"],
                "ownership_id": row["meta"]["ownership_id"], "delete_data": bool(delete_data),
                "verified_ownership": {"owner_marker": observation["owner_present"], "files": observation["present"],
                                       "missing": observation["missing"], "token": observation["token"],
                                       "pod": observation["pod"], "unit": observation["unit_state"],
                                       "host_generation": observation["host_generation"]},
                "remove": {"unit": native["paths"]["unit"], "files": [native["paths"][k] for k in ("yaml", "token", "owner")],
                           "config_files": [item["path"] for item in native.get("config", [])],
                           "pod": native["names"]["pod"] if observation["pod"] else None,
                           "service": native["names"]["service"]},
                "release_claims": claims, "datasets": data,
                "checkpoints": {"destructive": {"required": any(d["action"] == "delete" for d in data),
                                                "delete": [d for d in data if d["action"] == "delete"],
                                                "retained": [d for d in data if d["action"] == "keep"]}},
                "keeps": ["template and instance records (redeploy creates generation " + str(row["generation"] + 1) + ")",
                          native["paths"]["app_dir"] + "/generation (host generation high-water mark)"],
                "steps": ["Acquire " + host_id + " lease; re-verify ownership ID, unit/yaml hashes and pod labels",
                          "Stop the unit; prove pod and containers are gone; revoke the token",
                          "Remove the .kube unit, daemon-reload, verify the generated service is gone",
                          "Remove Pod YAML, token, owner marker and configuration files"
                          + ("; delete Switchyard-created data" if delete_data else "; keep data"),
                          "Release port claims; record placement retired"],
                "approval_required": True, "inspection_receipt": receipt["id"],
                "expires_at": (datetime.now(timezone.utc) + PLAN_TTL).isoformat()}
        with self.broker.store.transaction() as db:
            db.execute("INSERT INTO plans(id,data,fingerprint) VALUES(?,?,?)", (plan["id"], encode(plan), fingerprint))
            self.broker.store.bump(db)
        return plan

    # refresh (configuration of a placed instance) --------------------------------
    def refresh_plan(self, instance_id, *, params=None, add_records=None, remove_records=(), request_id=None,
                     config_contents=None, expected_instance_revision=None):
        """Re-render the configuration files against the current registry (and any parameter/record changes),
        compare with the host under its lease (read-only) and store an expiring refresh plan."""
        config = self.broker._enabled()
        with self.store.transaction() as db:
            instance = self.store.instance_row(db, instance_id)
            row = self.store.placement_row(db, instance_id)
        if row is None or row["state"] == "retired":
            raise ValueError("Instance has no current placement to refresh")
        if expected_instance_revision is not None and instance["revision"] != expected_instance_revision:
            raise ValueError("Instance changed since the route plan; prepare a new plan")
        if row["meta"].get("uncertain") or row["meta"].get("pending"):
            raise ValueError("Refresh refused: earlier effects are uncertain or an operation is pending; fence or inspect first")
        native = row["meta"]["native"]
        if not native.get("config") or not native["paths"].get("config_dir"):
            raise ValueError("Instance has no configuration files to refresh")
        host_id = row["host_id"]
        fingerprint = self._authority(config, host_id)
        self._no_outstanding_plan(instance_id)
        current = with_generation_gate(instance["application"])
        hosts = self._registry()
        app = deploy_config.change_records(deploy_config.set_parameters(current, dict(params or {})),
                                           add=dict(add_records or {}), remove=list(remove_records or []), hosts=hosts)
        # Only the typed LAN route manager uses this; CLI and MCP still accept parameters and DNS records.
        if config_contents is not None:
            if instance["template_ref"]["id"] != "caddy-lan" or set(config_contents) != {"caddyfile"}:
                raise ValueError("Only the LAN gateway's literal Caddyfile can be replaced here")
            item = next((file for file in app["config_files"] if file["id"] == "caddyfile"), None)
            if not item or item.get("content") is None or item["path"] != "Caddyfile" or item["on_change"] != "restart":
                raise ValueError("The gateway needs a restart-on-change literal Caddyfile")
            item["content"] = config_contents["caddyfile"]
        application_changed = spec.Application.model_validate(app).content_sha256() != \
            spec.Application.model_validate(current).content_sha256()
        if application_changed:
            app["revision"] = instance["revision"] + 1
        app = _validated({**app, "kind": "Application"}).model_dump(mode="json")
        files = deploy_config.render_files(app, hosts)
        names = native["names"]
        home = native["paths"]["unit"][:-len("/" + QUADLET_DIR + "/" + names["unit_file"])]
        rendered = render(app, generation=row["generation"], ownership_id=row["meta"]["ownership_id"], facts={"home": home},
                          datasets=native["datasets"], claims={c["endpoint"]: c for c in native["claims"]},
                          image_reference=row["meta"]["image"]["pull_reference"], config=files)
        if any(rendered["files"][key]["sha256"] != native["files"][key]["sha256"] for key in ("unit", "yaml")):
            raise ValueError("Refresh changes only configuration files; the rendered unit/Pod YAML differ "
                             "(image, ports and datasets cannot change through refresh)")
        recorded = {item["name"]: item for item in native["config"]}
        if set(recorded) != {item["name"] for item in rendered["config"]}:
            raise ValueError("Refresh cannot add or remove configuration files")
        changed = [item["name"] for item in rendered["config"] if item["sha256"] != recorded[item["name"]]["sha256"]]
        request = {"action": "config-read", "instance_id": instance_id, "generation": row["generation"],
                   "placement_revision": row["revision"], "host_id": host_id, "texts_for": changed,
                   **self._request_common(config, host_id, fingerprint)}
        if config_contents is not None and "Caddyfile" in changed:
            request["caddyfile"] = config_contents["caddyfile"]
        intent = {"kind": "deploy", "action": "refresh-inspect", "instance_id": instance_id, "nonce": uuid.uuid4().hex}
        receipt = self._run(request_id or "deploy-refresh-inspect-" + uuid.uuid4().hex, intent, host_id, request, config,
                            worker_seconds=LAN_ROUTE_INSPECT_SECONDS if expected_instance_revision is not None else None)
        if receipt.get("status") != "succeeded":
            raise ValueError("Leased configuration read did not succeed (" + str(receipt.get("status")) + "): "
                             + str(receipt.get("error")) + "; receipt " + receipt["id"])
        inspected = self.store.take_inspection(receipt["id"])
        observation, host = inspected["observation"], inspected["config"]
        pre = []

        def check(name, ok, evidence, blocking=True):
            pre.append({"id": name, "ok": bool(ok), "blocking": blocking, "evidence": evidence})

        token = observation["token"].get("state") if isinstance(observation["token"], dict) else observation["token"]
        unit_yaml = {key: observation["files"].get(key) for key in ("unit", "yaml")}
        check("deploy-authority", True, "operations policy deploy_hosts includes " + host_id)
        check("ownership", observation["owner"] == "match" and token not in ("foreign", "unreadable")
              and unit_yaml == {key: native["files"][key]["sha256"] for key in ("unit", "yaml")},
              {"owner": observation["owner"], "token": token, "unit_yaml": unit_yaml})
        drifted = {name: value for name, value in host["files"].items() if value != recorded[name]["sha256"]}
        # An unexpected file in the directory is drift too (verify reports it): a refresh must not report
        # success while leaving it there, so it blocks the plan like an edited file does.
        extra = sorted(host["extra"])
        check("config-files-match-journal", not drifted and not extra, {"drifted": drifted, "extra": extra} if drifted or extra
              else "every recorded file on the host matches the journal and the directory holds nothing else")
        check("changes", bool(changed), changed or "rendered files equal the journal: nothing to write")
        restart_files = [name for name in changed if next(f for f in rendered["config"] if f["name"] == name)["on_change"] == "restart"]
        active = observation["unit"].get("ActiveState") == "active" and row["state"] == "active"
        if expected_instance_revision is not None:
            check("service-active", active, "The LAN gateway and DNS service must be running before changing routes")
        restart = bool(restart_files) and active
        changes = []
        for item in rendered["config"]:
            name = item["name"]
            entry = {"id": item["id"], "path": item["path"], "on_change": item["on_change"], "size": item["size"],
                     "sha256": item["sha256"], "journal_sha256": recorded[name]["sha256"], "host_sha256": host["files"].get(name),
                     "change": "update" if name in changed else "unchanged"}
            if name in changed:
                old = host["texts"].get(name)
                entry["diff"] = deploy_config.diff(old, item["text"], name) if old is not None else \
                    "(host text not shown: unreadable or over the read budget; host sha256 " + str(host["files"].get(name)) + ")"
            changes.append(entry)
        blockers = [p["id"] for p in pre if p["blocking"] and not p["ok"]]
        effect = ("restart " + names["service"] + " (changed: " + ", ".join(restart_files) + ")" if restart
                  else "none: the running service reloads changed files by itself" if active
                  else "none: the unit is not active (" + row["state"] + "); files take effect at the next start")
        plan = {"id": uuid.uuid4().hex, "kind": "deploy", "action": "refresh", "instance_id": instance_id, "host_id": host_id,
                "generation": row["generation"], "placement_revision": row["revision"], "state": row["state"],
                "ownership_id": row["meta"]["ownership_id"], "instance_revision": instance["revision"],
                "application": app, "application_changed": application_changed, "application_revision": app["revision"],
                "parameters": deploy_config.parameter_values(app),
                "config_files": config_summary(rendered["config"], files), "changes": changes,
                "config": rendered["config"], "restart": restart, "effect": effect,
                "health_checks": rendered["health_checks"], "preconditions": pre, "executable": not blockers,
                "blockers": blockers, "inspection_receipt": receipt["id"], "approval_required": True,
                "approvals": [{"gate": "deploy authority", "kind": "configured prerequisite",
                               "satisfied": "operations policy deploy_hosts includes " + host_id},
                              {"gate": "plan approval", "kind": "explicit",
                               "how": "switchyard deploy refresh-apply PLAN_ID --approve --request-id ID"}],
                "unchanged": ["generation " + str(row["generation"]), "start token", "image, ports and datasets",
                              "unit and Pod YAML (sha256 " + native["files"]["unit"]["sha256"][:12] + "…, "
                              + native["files"]["yaml"]["sha256"][:12] + "…)"],
                "steps": ["Acquire " + host_id + " lease; re-verify ownership, unit/YAML hashes and that every configuration file "
                          "still matches the journal",
                          "Journal intent (pending refresh with the new file hashes)",
                          "Replace each changed file atomically (rename) and verify its hash",
                          "Effect: " + effect, "Run the health checks when the unit is active",
                          "Record the new configuration" + (", instance revision " + str(app["revision"]) if application_changed else "")
                          + " and a new placement revision; never retried"],
                "expires_at": (datetime.now(timezone.utc) + PLAN_TTL).isoformat()}
        if blockers:
            return plan
        with self.broker.store.transaction() as db:
            db.execute("INSERT INTO plans(id,data,fingerprint) VALUES(?,?,?)", (plan["id"], encode(plan), fingerprint))
            self.broker.store.bump(db)
        return plan

    # verify (read-only reconcile on contact) ----------------------------------
    def verify(self, instance_id, *, request_id=None):
        """Observe one placement's host under its lease and compare with the journal. Changes nothing. Placements on
        the same host that contend for one of its exclusive resources are observed in the same operation, so two
        holders at once are found."""
        config = self.broker._enabled()
        with self.store.transaction() as db:
            row = self.store.placement_row(db, instance_id)
            instance = self.store.instance_row(db, instance_id)
        if row is None or row["state"] == "retired":
            raise ValueError("Instance has no current deployed placement to verify")
        others = [item["instance_id"] for item in contenders(self.store, instance_id, row["host_id"], instance["application"])]
        return self._verify_host(config, row["host_id"], [instance_id, *others], request_id=request_id)

    def verify_all(self):
        """Every non-retired placement; one leased read-only operation per host, hosts sequentially."""
        config = self.broker._enabled()
        by_host = {}
        for instance, placement in self.store.instances():
            if placement and placement["state"] != "retired":
                by_host.setdefault(placement["host_id"], []).append(instance["id"])
        hosts = []
        for host_id in sorted(by_host):
            ids = by_host[host_id]
            try:
                # One leased operation per host; the worker batches remote calls inside that lease.
                hosts.append(self._verify_host(config, host_id, ids))
            except ValueError as error:
                hosts.append({"host_id": host_id, "instance_ids": sorted(ids), "error": str(error), "verifications": []})
        verifications = [v for item in hosts for v in item["verifications"]]
        return {"consistent": bool(verifications) and all(v["consistent"] is True for v in verifications)
                and not any("error" in item for item in hosts), "hosts": hosts}

    def _verify_host(self, config, host_id, instance_ids, *, request_id=None):
        fingerprint = self._authority(config, host_id)
        if len(instance_ids) > VERIFY_HOST_LIMIT:
            raise ValueError("More than " + str(VERIFY_HOST_LIMIT) + " placements on " + host_id
                             + "; verify them individually (receipt event bound)")
        intent = {"kind": "deploy", "action": "verify", "host_id": host_id, "instance_ids": sorted(instance_ids)}
        if len(instance_ids) == 1:
            intent["instance_id"] = instance_ids[0]
        if request_id is None:
            intent["nonce"] = uuid.uuid4().hex  # each default verify is a fresh observation
        request = {"action": "verify", "host_id": host_id, "instance_ids": sorted(instance_ids),
                   **self._request_common(config, host_id, fingerprint)}
        receipt = self._run(request_id or "deploy-verify-" + uuid.uuid4().hex, intent, host_id, request, config)
        recorded = {v["instance_id"]: v for v in self.store.verifications_for(receipt["id"])}
        verifications = []
        for instance_id in sorted(instance_ids):
            if instance_id in recorded:
                verifications.append(recorded[instance_id])
                continue
            # Nothing recorded for this receipt: never "consistent".
            with self.store.transaction() as db:
                row = self.store.placement_row(db, instance_id)
            if receipt.get("status") == "succeeded":
                # A replayed request whose result a later verification replaced; the stored one is current.
                result = unobserved(row, "This receipt's verification was superseded; see deploy show", receipt["id"])
            else:
                result = unobserved(row, "Host not observed: receipt " + str(receipt.get("status")) + ": "
                                    + str(receipt.get("error")), receipt["id"])
                if row is not None and receipt.get("status") != "busy":
                    self.store.save_verification(instance_id, row["generation"], receipt["id"], result)
            verifications.append(result)
        return {"host_id": host_id, "instance_ids": sorted(instance_ids), "receipt": receipt, "verifications": verifications,
                "consistent": all(v["consistent"] is True for v in verifications)}

    # switch (one exclusive resource, one holder at a time) ---------------------------
    def switch_plan(self, instance_id, *, restore_on_failure=False, request_id=None):
        """Plan moving the target's host-scoped exclusive resources to it: fence every current holder (stop, prove
        the pod gone, revoke its token), then unfence and start the target and run its health checks, all under one
        host lease and one receipt. `restore_on_failure` (default off): if the target fails to start or to become
        healthy and is proven stopped, unfence and start the previous holder again (once, never retried)."""
        if type(restore_on_failure) is not bool:
            raise ValueError("restore_on_failure must be true or false")
        config = self.broker._enabled()
        with self.store.transaction() as db:
            row = self.store.placement_row(db, instance_id)
            instance = self.store.instance_row(db, instance_id)
        if row is None or row["state"] == "retired":
            raise ValueError("Instance has no current placement to switch to")
        host_id, meta = row["host_id"], row["meta"]
        keys = exclusive_keys(instance["application"], host_id)
        if not keys:
            raise ValueError("Switch moves a host-scoped exclusive resource; " + instance_id + " declares none (use deploy start)")
        if meta.get("uncertain") or meta.get("pending"):
            raise ValueError("Switch refused: " + instance_id + " has uncertain effects or an unfinished operation; fence it first")
        if not (row["state"] == "fenced" or (row["state"] == "staged" and (meta.get("token") or {}).get("state") in ("revoked", "absent"))):
            raise ValueError("Switch target must be fenced (or staged with a revoked token); " + instance_id + " is " + row["state"]
                             + " with token " + str((meta.get("token") or {}).get("state")))
        fingerprint = self._authority(config, host_id)
        missing = sorted({d["host"] for d in meta["native"].get("devices") or []} - set(granted_devices(config, host_id)))
        if missing:
            raise ValueError("Switch refused: the operations policy deploy_devices does not grant " + ", ".join(missing) + " on " + host_id)
        found = contenders(self.store, instance_id, host_id, instance["application"])
        previous = [item for item in found if item["holding"]]
        for item in previous:
            if item["uncertain"] or item["pending"]:
                raise ValueError("Switch refused: " + item["instance_id"] + " has uncertain effects or an unfinished operation; "
                                 "fence it explicitly first")
        for item in [instance_id, *(p["instance_id"] for p in previous)]:
            self._no_outstanding_plan(item)
        ids = [instance_id, *(item["instance_id"] for item in previous)]
        request = {"action": "switch-inspect", "host_id": host_id, "instance_ids": ids,
                   "devices": sorted({d["host"] for d in meta["native"].get("devices") or []}),
                   **self._request_common(config, host_id, fingerprint)}
        intent = {"kind": "deploy", "action": "switch-inspect", "instance_id": instance_id, "nonce": uuid.uuid4().hex}
        receipt = self._run(request_id or "deploy-switch-inspect-" + uuid.uuid4().hex, intent, host_id, request, config)
        if receipt.get("status") != "succeeded":
            raise ValueError("Leased switch inspection did not succeed (" + str(receipt.get("status")) + "): "
                             + str(receipt.get("error")) + "; receipt " + receipt["id"])
        inspected = self.store.take_inspection(receipt["id"])
        pre = []

        def check(name, ok, evidence, blocking=True):
            pre.append({"id": name, "ok": bool(ok), "blocking": blocking, "evidence": evidence})

        check("deploy-authority", True, "operations policy deploy_hosts includes " + host_id)
        if meta["native"].get("devices"):
            check("device-grants", True, "operations policy deploy_devices grants " + ", ".join(
                sorted({d["host"] for d in meta["native"]["devices"]})) + " on " + host_id)
        rows = {}
        with self.store.transaction() as db:
            for item in ids:
                rows[item] = self.store.placement_row(db, item)
        for item in ids:
            observed = inspected["observations"].get(item)
            if observed is None or "observation" not in observed:
                check("host-state-" + item, False, "not observed: " + str((observed or {}).get("error")))
                continue
            verification = compare(rows[item], observed["observation"], receipt["id"])
            drift = [f for f in verification["findings"] if f["severity"] != "info"]
            check("host-state-" + item, not drift, {"journal_state": rows[item]["state"],
                  "observed": {k: verification["observed"][k] for k in ("running", "token", "owner")},
                  "findings": drift or None, "note": "the host must match the journal before anything is switched"})
        target = {"instance_id": instance_id, "generation": row["generation"], "revision": row["revision"], "state": row["state"]}
        prior = [{k: item[k] for k in ("instance_id", "generation", "revision", "state", "resources")} for item in previous]
        window = ready_window(meta["native"]["health_checks"])
        blockers = [p["id"] for p in pre if p["blocking"] and not p["ok"]]
        names = ", ".join(p["instance_id"] for p in prior) or "nothing (no current holder)"
        plan = {"id": uuid.uuid4().hex, "kind": "deploy", "action": "switch", "instance_id": instance_id, "host_id": host_id,
                "generation": row["generation"], "placement_revision": row["revision"], "target": target, "previous": prior,
                "resources": sorted(keys), "contenders": found, "restore_on_failure": restore_on_failure,
                "devices": inspected.get("devices"), "preconditions": pre, "executable": not blockers, "blockers": blockers,
                "steps": ["Acquire " + host_id + " canonical lease (one lease and one receipt for every step below)",
                          "Recheck: placements unchanged since this plan, the same holders, authority and device grants",
                          "Journal the switch intent on " + instance_id + " and every previous holder",
                          "Fence " + names + ": systemctl --user stop, prove pod and containers gone, revoke the token",
                          "Read the devices (GPU memory in use) after the fence",
                          "Unfence " + instance_id + ": reissue its token",
                          "Start " + instance_id + "; verify pod labels" + (", devices" if meta["native"].get("devices") else "")
                          + " and health checks" + (" (readiness window " + str(window) + " s)" if window else ""),
                          "Record " + instance_id + " active and the previous holders fenced; never retried"],
                "on_failure": {
                    "fence_refused": "A previous holder's fence is refused before any change (ownership or file drift): nothing "
                                     "switched, every placement as before; receipt failed",
                    "fence_unknown": "Transport lost or the stop could not be proven while fencing: that holder becomes uncertain, "
                                     "the target is untouched; receipt needs-inspection; deploy verify explains, deploy fence recovers",
                    "target_failed": "The target does not start or become healthy: it is stopped, its pod proven gone and its "
                                     "token revoked, and it is recorded fenced. " + (
                                         "restore_on_failure is set: each previous holder is then unfenced and started once; "
                                         "if that fails too, it is left fenced the same way" if restore_on_failure else
                                         "The previous holders stay fenced (restore_on_failure not chosen): nothing runs on "
                                         "the resource until the operator starts or switches") + "; receipt failed",
                    "target_unknown": "Transport lost while starting the target: the target is uncertain (it may hold the "
                                      "resource), the previous holders stay fenced, no restore is attempted; receipt "
                                      "needs-inspection",
                    "crash": "Each placement keeps the journaled switch intent (pending); deploy verify reports "
                             "operation-interrupted with what the host shows; fence or switch again explicitly"},
                "in_container_lock": "Switchyard does not depend on any lock inside the containers: the start gate "
                                     "(revoked tokens) keeps every holder but one from starting by any path",
                "approval_required": True,
                "approvals": [{"gate": "deploy authority", "kind": "configured prerequisite",
                               "satisfied": "operations policy deploy_hosts includes " + host_id},
                              {"gate": "plan approval", "kind": "explicit",
                               "how": "switchyard deploy switch-apply PLAN_ID --approve --request-id ID",
                               "includes": ["Downtime: " + names + " stop" + ("s" if len(prior) == 1 else "") + " before "
                                            + instance_id + " starts"]}],
                "inspection_receipt": receipt["id"], "expires_at": (datetime.now(timezone.utc) + PLAN_TTL).isoformat()}
        if blockers:
            return plan
        with self.broker.store.transaction() as db:
            db.execute("INSERT INTO plans(id,data,fingerprint) VALUES(?,?,?)", (plan["id"], encode(plan), fingerprint))
            self.broker.store.bump(db)
        return plan

    # detached image pulls ---------------------------------------------------------
    def _image(self, image, template):
        if (image is None) == (template is None):
            raise ValueError("Name exactly one of an image reference or a template")
        if template is not None:
            stored = self.store.template(*parse_ref(template))
            image = deployable(stored["application"]).native.manifest.spec.containers[0].image
        if not isinstance(image, str) or not re.fullmatch(r"[^@\s]+(?:@sha256:(?:[a-f0-9]{64}|PLACEHOLDER(?:[-:].+)?))?", image):
            raise ValueError("Image must be registry/repository[:tag][@sha256:digest]")
        return image_parts(image)

    def pull_start(self, host_id, *, image=None, template=None, approved=False, request_id=None):
        """Start a detached pull of one image on a deploy host (resolved by digest; bounded disk checks first). The
        pull runs on the host under the user's systemd manager; this returns once it is started or found running."""
        parts = self._image(image, template)
        config = self.broker._enabled()
        fingerprint = self._authority(config, host_id)
        if approved is not True:
            return {"preview": {"host_id": host_id, "image": parts["reference"], "approval_required": True,
                                "steps": ["Acquire the host lease; resolve the image digest and its size from the registry",
                                          "Refuse unless the Podman storage has 3 x the compressed size + 1 GiB free "
                                          "(20 GiB when the registry reports no size)",
                                          "Journal the pull, then start it as a transient systemd --user unit "
                                          "(RuntimeMaxSec " + str(deploy_remote.PULL_MAX_SECONDS) + " s); one per image digest",
                                          "Read its state; follow it with deploy pull-status"],
                                "how": "switchyard deploy pull-start --host " + host_id + " --image " + parts["reference"]
                                       + " --approve --request-id ID"}}
        if not request_id:
            raise ValueError("Starting a pull requires --request-id")
        request = {"action": "pull-start", "host_id": host_id, "image": parts, **self._request_common(config, host_id, fingerprint)}
        receipt = self._run(request_id, {"kind": "deploy", "action": "pull-start", "host_id": host_id, "image": parts["reference"]},
                            host_id, request, config)
        return self._pull_result(receipt, host_id)

    def pull_status(self, host_id, *, image=None, template=None, request_id=None):
        """Leased, read-only: the state of one image's detached pull on the host (and whether the image is there)."""
        parts = self._image(image, template)
        config = self.broker._enabled()
        fingerprint = self._authority(config, host_id)
        request = {"action": "pull-status", "host_id": host_id, "image": parts, **self._request_common(config, host_id, fingerprint)}
        intent = {"kind": "deploy", "action": "pull-status", "host_id": host_id, "image": parts["reference"]}
        if request_id is None:
            intent["nonce"] = uuid.uuid4().hex
        receipt = self._run(request_id or "deploy-pull-status-" + uuid.uuid4().hex, intent, host_id, request, config)
        return self._pull_result(receipt, host_id)

    def _pull_result(self, receipt, host_id):
        found = self.store.take_inspection(receipt["id"]) or {}
        digest = found.get("digest")
        pull = self.store.pull(host_id, digest) if digest else next(
            (item for item in self.store.pulls() if receipt["id"] in (item.get("operation_id"), item.get("observed_by"))), None)
        return {"receipt": receipt, "host_id": host_id, "image": found.get("image"), "pull": pull}

    def pulls(self):
        """Every journaled detached pull with its last known state (no host access)."""
        return self.store.pulls()


TRANSITIONS = {"fence": "fenced (stop verified, token revoked; re-enforced when already fenced)",
               "unfence": "staged (token reissued; not started)",
               "start": "active (started, health verified)", "stop": "staged (stopped; token stays valid)"}
VERIFY_BATCH = 16  # placements per remote call inside one leased verify operation
VERIFY_HOST_LIMIT = 256  # placements per host per operation (two receipt events per batch, 128 maximum)
RUNNING_UNIT = {"active", "activating", "reloading", "deactivating"}
# Finding codes. Severity `info` is allowed by design and keeps a placement consistent.
FINDINGS = {
    "running-while-fenced": "drift", "valid-token-while-fenced": "drift", "running-while-staged": "info",
    "token-mismatch-while-staged": "drift", "stopped-while-active": "drift",
    "token-missing-or-revoked-while-active": "drift", "ownership-mismatch": "drift", "native-files-changed": "drift",
    "config-files-changed": "drift", "health-check-failed": "drift",
    "host-generation-ahead": "drift", "host-generation-behind": "drift", "unreachable": "unknown",
    "devices-changed": "drift", "exclusive-resource-contended": "drift", "operation-interrupted": "drift"}
ACTION_STEPS = {
    "fence": ["Acquire host lease; verify ownership", "systemctl --user stop; prove pod/containers gone",
              "Revoke the generation token (gate now refuses every start path)", "Record fenced with evidence",
              "Already fenced: the same steps re-enforce the fence (no-op with fresh evidence if the host is clean)"],
    "unfence": ["Acquire host lease; verify ownership, unit inactive and host generation",
                "Reissue the token for the current generation", "Record staged; nothing is started"],
    "start": ["Acquire host lease; verify ownership and a valid token", "systemctl --user start",
              "Verify pod ownership labels and health checks", "Record active; on failure stop and stay staged"],
    "stop": ["Acquire host lease; verify ownership", "systemctl --user stop; prove pod/containers gone",
             "Record staged (token stays valid: boot or manual start remain possible; fence to prevent)"]}


def _lifecycle_state_error(action, row):
    if row is None or row["state"] == "retired":
        return "Workload has no current deployed placement"
    if action == "stop":  # Like an explicit fence, Stop can recover uncertain or interrupted effects.
        return None
    meta = row["meta"]
    if meta.get("uncertain") or meta.get("pending"):
        return "Placement has uncertain effects or an unfinished operation; Stop it first"
    if action == "restart" and row["state"] != "active":
        return "Restart requires an active placement"
    if action == "start" and row["state"] not in ("staged", "fenced"):
        return "Start requires a stopped placement"
    return None


def _lifecycle_binding_matches(plan, row, instance):
    return (row is not None and instance is not None
            and (row["host_id"], row["generation"], row["revision"])
            == (plan["host_id"], plan["generation"], plan["placement_revision"])
            and (instance["revision"], instance["content_sha256"])
            == (plan["instance_revision"], plan["application_sha256"]))


def _deploy_binding_matches(plan, row, instance):
    if (instance is not None) != plan["redeploy"] or (row["revision"] if row else None) != plan["placement_revision"]:
        return False
    change = plan.get("instance_upgrade")
    if change and (instance is None or (instance["revision"], instance["content_sha256"]) !=
                   (change["from_revision"], change["from_content_sha256"])):
        return False
    upgrade = plan.get("template_upgrade")
    if upgrade:
        return (row is not None and (row["host_id"], row["generation"], row["state"]) ==
                (plan["host_id"], upgrade["previous_generation"], upgrade["previous_state"]) and
                not row["meta"].get("pending") and not row["meta"].get("uncertain") and
                (row["meta"].get("token") or {}).get("state") == upgrade["previous_token"])
    return True


def allowed_from(action, row):
    if row is None or row["state"] == "retired":
        raise ValueError("Instance has no current deployed placement")
    state, token = row["state"], (row["meta"].get("token") or {}).get("state")
    uncertain = row["meta"].get("uncertain", False)
    # fence on an already fenced placement re-enforces it (filesystem rollback, manual token restore).
    if action == "unfence" and not (state == "fenced" or (state == "staged" and token != "valid")) or (action == "unfence" and uncertain):
        raise ValueError("Unfence requires a fenced placement (or staged with a revoked token) without uncertain effects")
    if action == "start":
        if state == "fenced":
            raise ValueError("Start refused: placement is fenced; unfence first")
        if uncertain:
            raise ValueError("Start refused: earlier effects are uncertain; fence or inspect first")
        if state != "staged" or token != "valid":
            raise ValueError("Start requires a staged placement with a valid generation token")
    if action == "stop" and (state != "active" or uncertain):
        raise ValueError("Stop requires an active placement; use fence for uncertain or staged placements")


def summary(instance, placement, verification=None):
    item = {"instance_id": instance["id"], "template_ref": instance["template_ref"], "content_sha256": instance["content_sha256"]}
    if placement:
        meta = placement["meta"]
        item.update(host_id=placement["host_id"], generation=placement["generation"], state=placement["state"],
                    token=(meta.get("token") or {}).get("state"), runtime=meta.get("runtime"),
                    uncertain=meta.get("uncertain", False), service=meta["native"]["names"]["service"],
                    claims=[c["protocol"] + "/" + c["address"] + ":" + str(c["port"]) for c in meta["native"]["claims"]],
                    last_operation=meta.get("last_operation"))
        item["last_verified"] = None if verification is None else {
            "verified_at": verification["verified_at"], "consistent": verification["consistent"],
            "drift": [f["code"] for f in verification["findings"] if f["severity"] != "info"],
            "info": [f["code"] for f in verification["findings"] if f["severity"] == "info"]}
    return item


def _finding(code, detail):
    return {"code": code, "severity": FINDINGS[code], "detail": detail}


def unobserved(row, detail, operation_id):
    return {"instance_id": row["instance_id"] if row else None, "generation": row["generation"] if row else None,
            "journal_state": row["state"] if row else None, "operation_id": operation_id, "verified_at": now(),
            "consistent": False, "findings": [_finding("unreachable", detail)], "observed": None}


def compare(row, observation, operation_id, extra=()):
    """Journal placement vs one read-only host observation → findings with stable codes. Pure function.
    `extra`: findings the caller derived from other placements (exclusive contention, interrupted operations)."""
    meta, state, generation = row["meta"], row["state"], row["generation"]
    findings = []
    unit, pod = observation["unit"], observation["pod"]
    token = observation["token"]
    host_token = token.get("state") if isinstance(token, dict) else token  # valid|revoked|absent|foreign|unreadable
    running_containers = [c["id"] for c in observation["owned_containers"] + observation["unit_containers"]
                          if c.get("state") == "running"]
    unit_running = unit.get("ActiveState") in RUNNING_UNIT
    pod_running = pod is not None and str(pod.get("state")).lower() in ("running", "degraded")
    running = unit_running or pod_running or bool(running_containers)
    evidence = "unit " + str(unit.get("ActiveState")) + "/" + str(unit.get("SubState")) + "; pod " + (
        "absent" if pod is None else str(pod.get("state"))) + "; running containers " + str(len(running_containers))
    # Ownership: anything carrying this deployment's names must carry its identity.
    wrong = []
    if observation["owner"] in ("mismatch", "unreadable"):
        wrong.append("owner.json " + observation["owner"])
    if host_token in ("foreign", "unreadable"):
        wrong.append("token file " + host_token)
    if pod is not None and (pod["labels"].get("ownership-id") != meta["ownership_id"]
                            or pod["labels"].get("instance") != row["instance_id"]
                            or pod["labels"].get("generation") != str(generation)):
        wrong.append("pod " + str(pod.get("name")) + " labels " + json.dumps(pod["labels"], sort_keys=True))
    if wrong:
        findings.append(_finding("ownership-mismatch", "; ".join(wrong)))
    changed = []
    for key in ("unit", "yaml"):
        observed, recorded = observation["files"].get(key), meta["native"]["files"][key]["sha256"]
        if observed != recorded:
            changed.append(key + " " + ("missing" if observed is None else observed if observed == "unreadable"
                                        else "sha256 " + observed + " != recorded " + recorded))
    if observation["owner"] == "missing":
        changed.append("owner.json missing")
    if changed:
        findings.append(_finding("native-files-changed", "; ".join(changed)))
    config = observation.get("config") or {"files": {}, "extra": []}
    drifted = []
    for item in meta["native"].get("config", []):
        observed = config["files"].get(item["name"], "missing")
        if observed != item["sha256"]:
            drifted.append(item["name"] + " " + (observed if observed in ("missing", "unreadable")
                                                 else "sha256 " + observed + " != recorded " + item["sha256"]))
    drifted += ["unexpected file " + name for name in config.get("extra", [])]
    if drifted:
        findings.append(_finding("config-files-changed", "; ".join(drifted)))
    host_generation = observation["host_generation"]
    if isinstance(host_generation, int) and host_generation > generation:
        findings.append(_finding("host-generation-ahead", "host mark " + str(host_generation) + " > journal " + str(generation)))
    elif host_generation != generation:
        findings.append(_finding("host-generation-behind", "host mark " + str(host_generation) + " vs journal " + str(generation)))
    journal_token = (meta.get("token") or {}).get("state")
    if state == "fenced":
        if running:
            findings.append(_finding("running-while-fenced", evidence))
        if host_token == "valid":
            findings.append(_finding("valid-token-while-fenced", "token file holds the valid identity line for generation "
                                     + str(generation) + " (restored or rolled back); every start path is open"))
    elif state == "staged":
        if running:
            findings.append(_finding("running-while-staged", evidence + " (manual or boot start through a valid token)"))
        if host_token in ("valid", "revoked", "absent") and journal_token in ("valid", "revoked", "absent") and host_token != journal_token:
            findings.append(_finding("token-mismatch-while-staged", "journal token " + str(journal_token) + ", host token " + host_token))
    elif state == "active":
        if not running:
            findings.append(_finding("stopped-while-active", evidence))
        if host_token != "valid":
            findings.append(_finding("token-missing-or-revoked-while-active", "host token " + str(host_token)))
        failed = [probe for probe in observation.get("health") or [] if probe.get("ok") is False]
        if failed and running:  # a stopped placement is already `stopped-while-active`
            findings.append(_finding("health-check-failed", "; ".join(
                probe["id"] + ": " + json.dumps(probe.get("last"), sort_keys=True) for probe in failed)))
    devices = observation.get("devices")
    if devices and devices["observed"] != devices["expected"]:
        findings.append(_finding("devices-changed", "running containers' devices " + json.dumps(devices["observed"], sort_keys=True)
                                 + " differ from the journal " + json.dumps(devices["expected"], sort_keys=True)))
    findings += list(extra)
    return {"instance_id": row["instance_id"], "generation": generation, "journal_state": state,
            "operation_id": operation_id, "verified_at": now(),
            "consistent": not any(f["severity"] != "info" for f in findings), "findings": findings,
            "observed": {"unit": unit, "pod": None if pod is None else {k: pod.get(k) for k in ("id", "state", "labels")},
                         "running": running, "token": host_token, "owner": observation["owner"],
                         "files": observation["files"], "config": config, "health": observation.get("health"),
                         "host_generation": host_generation, "devices": devices,
                         "observed_at": observation.get("observed_at")}}


def observed_holding(observation):
    """Whether one observation shows a placement able to use its exclusive resources: running, or a valid token."""
    unit, pod = observation["unit"], observation["pod"]
    token = observation["token"]
    running = (unit.get("ActiveState") in RUNNING_UNIT or (pod is not None and str(pod.get("state")).lower() in ("running", "degraded"))
               or any(c.get("state") == "running" for c in observation["owned_containers"] + observation["unit_containers"]))
    return running or (token.get("state") if isinstance(token, dict) else token) == "valid"


def parse_ref(reference):
    if not isinstance(reference, str):
        raise ValueError("Template reference must be ID or ID@REVISION")
    template_id, _, revision = reference.partition("@")
    _id(template_id, "template")
    if revision and not revision.isdigit():
        raise ValueError("Template revision must be a positive integer")
    return template_id, int(revision) if revision else None


def _id(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value):
        raise ValueError("Invalid " + label + " ID (lowercase [a-z0-9-], at most 64)")


def authority(config, host_id, host):
    value = {"deploy_hosts": sorted(config.get("deploy_hosts", [])), "host": _validate_config(host),
             "local_target": config.get("local_targets", {}).get(host_id)}
    devices = (config.get("deploy_devices") or {}).get(host_id)
    if devices:  # absent for hosts without device grants, so existing fingerprints are unchanged
        value["deploy_devices"] = sorted(devices)
    return digest(value)


def granted_devices(config, host_id):
    return list((config.get("deploy_devices") or {}).get(host_id) or [])


# ---------------------------------------------------------------- worker side

def _live_authority(request, hosts):
    """The dispatched snapshot must still match the live operator file under the lease."""
    try:
        with Path(request["config_path"]).open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            return False
        config = _json(raw)
        host_id = request.get("host_id") or request["plan"]["host_id"]
        if (host_id in config.get("local_targets", {})) != (request.get("local") is True):
            return False
        return host_id in config.get("deploy_hosts", []) and authority(config, host_id, hosts[host_id]) == request["authority"]
    except (OSError, ValueError, TypeError, KeyError):
        return False


class Worker:
    """One leased deploy operation. No SQLite transaction spans a remote call."""

    def __init__(self, request, hosts, store, operation_id, local_host_ids, started=None):
        self.request, self.hosts, self.ops, self.operation_id = request, hosts, store, operation_id
        self.store = WorkloadStore(store.directory)
        self.host_id = request.get("host_id") or request["plan"]["host_id"]
        self.local = self.host_id in local_host_ids
        bound = request.get("dispatch_seconds") or DISPATCH_SECONDS
        self.deadline = time.monotonic() + bound - (DISPATCH_SECONDS - WORKER_SECONDS)
        if started is not None:
            # The broker's bound on the worker process includes the lease wait: never plan past it.
            self.deadline = min(self.deadline, started + bound - 15)
        self.source = Path(deploy_remote.__file__).read_text() + "\nprint(json.dumps(main(PAYLOAD)))\n"

    def event(self, name, data):
        self.ops.event(self.operation_id, name, data)

    def call(self, action, payload, budget):
        remaining = int(self.deadline - time.monotonic())
        if remaining < 10:
            raise _Deadline("Operation deadline reached before " + action + "; nothing further was started")
        timeout = max(5, min(budget, remaining - 5))
        self.event("remote-step", {"host_id": self.host_id, "action": action})
        result = run_remote(self.hosts[self.host_id], self.source, {**payload, "action": action}, timeout=timeout, local=self.local)
        if not isinstance(result, dict) or result.get("status") not in {"succeeded", "failed", "needs-inspection"}:
            raise RemoteError("Malformed deploy step result")
        return result

    def row(self):
        with self.store.transaction() as db:
            instance_id = self.request.get("instance_id") or self.request["plan"]["instance_id"]
            return self.store.placement_row(db, instance_id)

    def update(self, row, *, state=None, meta=None, fence=None, keep_fence=False):
        meta = {**row["meta"], **(meta or {}), "last_operation": self.operation_id}
        with self.store.transaction() as db:
            instance = self.store.instance_row(db, row["instance_id"])
            placement = build_placement(app=with_generation_gate(instance["application"]), host_id=row["host_id"], generation=row["generation"],
                                        state=state or row["state"], ownership_id=meta["ownership_id"], native=meta["native"],
                                        uid=meta["uid"], fence=fence if fence is not None else (row["placement"].get("fence") if keep_fence else None))
            revision = self.store.cas_placement(db, row["instance_id"], row["generation"], row["revision"], placement, meta)
            if placement["state"] == "retired":
                self.store.release_claims(db, row["instance_id"])
        return {**row, "state": placement["state"], "placement": placement, "meta": meta, "revision": revision}

    # actions ----------------------------------------------------------------
    def run(self):
        if not _live_authority(self.request, self.hosts):
            return {"status": "failed", "error": "Deploy authority changed before the lease was acquired; no remote command executed"}
        action = self.request["action"]
        try:
            if action == "inspect":
                return self.inspect()
            if action == "apply":
                return self.apply()
            if action == "observe":
                return self.observe()
            if action == "verify":
                return self.verify()
            if action == "undeploy":
                return self.undeploy()
            if action == "config-read":
                return self.config_read()
            if action in ("lan-route-probe", "lan-dns-probe"):
                return self.lan_route_probe(action)
            if action == "refresh":
                return self.refresh()
            if action == "switch-inspect":
                return self.switch_inspect()
            if action == "switch":
                return self.switch()
            if action == "lifecycle":
                return self.lifecycle()
            if action == "pull-start":
                return self.pull_start()
            if action == "pull-status":
                return self.pull_status()
            return self.direct(action)
        except _Deadline as error:
            return {"status": "needs-inspection" if self.journaled else "failed", "error": str(error)}

    journaled = False

    def _previous(self, row, upgrade):
        return {**self._base(row), "state": upgrade["previous_state"], "expected_token": upgrade["previous_token"]}

    def inspect(self):
        request = self.request
        facts = self.call("facts", {}, 30)
        if facts["status"] != "succeeded":
            return {"status": "failed", "error": facts.get("error", "facts failed")}
        facts = facts["facts"]
        names = request["names"]
        paths = layout(facts["home"], request["instance_id"], request["component"], names)
        datasets = [{"id": d["id"], "path": d["path"] or paths["data_root"] + "/" + d["id"],
                     **({"sub_paths": d["sub_paths"]} if d.get("sub_paths") else {})} for d in request["datasets"]]
        identity = identity_line(request["instance_id"], request["component"], request["generation"], request["ownership_id"])
        gate = gate_command(identity, paths["token"])
        unit = render_unit(request["instance_id"], request["component"], request["generation"], request["ownership_id"], paths, gate)
        payload = {"instance_id": request["instance_id"], "component": request["component"], "generation": request["generation"],
                   "ownership_id": request["ownership_id"], "names": names, "paths": paths, "unit_text": unit,
                   "gate_command": gate, "datasets": datasets, "image": request["image"],
                   "retained_entries": request["retained_entries"], "devices": request.get("devices") or []}
        upgrade = request.get("template_upgrade")
        if upgrade and upgrade["previous_state"] != "retired":
            with self.store.reading() as db:
                instance = self.store.instance_row(db, request["instance_id"])
                row = self.store.placement_row(db, request["instance_id"])
            if not _deploy_binding_matches({**request, "redeploy": True}, row, instance):
                return {"status": "failed", "error": "Upgrade source changed before inspection"}
            payload["previous"] = self._previous(row, upgrade)
        result = self.call("inspect", payload, 120)
        if result["status"] != "succeeded":
            return {"status": "failed", "error": result.get("error", "inspection failed")}
        self.store.put_inspection(self.operation_id, {"facts": facts, "inspection": result["inspection"], "unit_sha256": _sha(unit)})
        return {"status": "succeeded"}

    def apply(self):
        plan = self.request["plan"]
        instance_id, generation = plan["instance_id"], plan["generation"]
        with self.store.transaction() as db:
            instance = self.store.instance_row(db, instance_id)
            relation = self.store.relation_of(db, instance_id)
            latest = self.store.placement_row(db, instance_id)
        if not _deploy_binding_matches(plan, latest, instance):
            return {"status": "failed", "error": "Instance or placement changed before the lease; no remote command executed"}
        if plan.get("install", "start") == "start":
            holders = [item for item in contenders(self.store, instance_id, self.host_id, plan["application"]) if item["holding"]]
            if holders:
                return {"status": "failed", "error": holder_refusal("Deploy", instance_id, holders) + "; no remote command executed"}
        facts = self.call("facts", {}, 30)
        if facts["status"] != "succeeded" or any(facts["facts"][k] != plan["facts"][k] for k in ("home", "uid", "user", "architecture")):
            return {"status": "failed", "error": "Host account facts changed since planning; nothing written"}
        image = plan["image"]
        pulled = self.call("pull", {"image": {"pull_reference": image["pull_reference"], "digest": image.get("digest")},
                                    "architecture": plan["facts"]["architecture"], "timeout": 120,
                                    "local_only": bool(image.get("requires_local"))}, 130)
        if pulled["status"] != "succeeded":
            return {"status": "failed", "error": "Image pull/verification failed; nothing written: " + str(pulled.get("error"))}
        observed = pulled["image"]["digest"]
        app = plan["application"]
        native = deepcopy(plan["native"])
        if native["pending_digest"]:
            app = pin_image(app, observed)
            image = {**image, "digest": observed, "pull_reference": image["repository"] + "@" + observed}
        elif observed != image["digest"]:
            return {"status": "failed", "error": "Pulled digest differs from the plan; nothing written"}
        claims = {c["endpoint"]: c for c in native["claims"]}
        rendered = render(app, generation=generation, ownership_id=plan["ownership_id"], facts=plan["facts"],
                          datasets=native["datasets"], claims=claims, image_reference=image["pull_reference"],
                          config=native.get("config", []))
        if not native["pending_digest"] and {k: v["sha256"] for k, v in rendered["files"].items()} != {k: v["sha256"] for k, v in native["files"].items()}:
            return {"status": "failed", "error": "Re-rendered native files differ from the approved plan; nothing written"}
        native["files"] = rendered["files"]
        config_files = [{"name": item["name"], "text": item["text"], "sha256": item["sha256"]} for item in native.get("config", [])]
        native["config"] = [{k: v for k, v in item.items() if k != "text"} for item in native.get("config", [])]  # journal: hashes
        app_sha = spec.Application.model_validate(app).content_sha256()
        record = {"instance_id": instance_id, "generation": generation, "ownership_id": plan["ownership_id"], "native": native}
        meta = {"ownership_id": plan["ownership_id"], "uid": plan["facts"]["uid"], "native": native, "image": image,
                "token": {"state": "pending"}, "runtime": "stopped", "uncertain": False, "plan_id": plan["id"],
                "application_sha256": app_sha, "last_operation": self.operation_id}
        placement = build_placement(app=app, host_id=self.host_id, generation=generation, state="staged",
                                    ownership_id=plan["ownership_id"], native=native, uid=plan["facts"]["uid"])
        template_upgrade = plan.get("template_upgrade")
        replacing = bool(template_upgrade and template_upgrade["previous_state"] != "retired")
        if replacing:
            check = self.call("upgrade-check", {"previous": self._previous(latest, template_upgrade),
                                                "paths": native["paths"], "names": native["names"],
                                                "retained_entries": ["data", "generation"], "datasets": native["datasets"],
                                                "devices": native.get("devices") or [], "claims": native["claims"]}, 60)
            if check["status"] != "succeeded":
                return {"status": "failed", "error": "Upgrade source check refused; no runtime changes: " + str(check.get("error"))}
            start_budget = (start_seconds(native["health_checks"]) + 15) if plan["install"] == "start" else 0
            if self.deadline - time.monotonic() < 180 + 60 + start_budget + 10:
                return {"status": "failed", "error": "Not enough time to replace the old generation; nothing stopped"}
            self.event("template-upgrade", template_upgrade)
            outcome = self._retire(latest, delete_data=False, revoke_first=True)
            if outcome["status"] != "succeeded":
                return outcome
            with self.store.reading() as db:
                instance = self.store.instance_row(db, instance_id)
        # Journal intent before the first owned host write.
        try:
            with self.store.transaction() as db:
                previous = self.store.raw_instance(db, instance_id)
                if instance is None:
                    self.store.insert_instance(db, app, {"content_sha256": app_sha, "template_content_sha256": plan["template"].get("content_sha256"),
                                                         "retained_datasets": {}})
                elif plan.get("instance_upgrade"):
                    upgrade = plan["instance_upgrade"]
                    self.store.replace_instance(db, instance_id, upgrade["from_revision"], app,
                                                {**instance["meta"], "content_sha256": app_sha,
                                                 "template_content_sha256": plan["template"].get("content_sha256"),
                                                 "history": [*instance["meta"].get("history", []), {**upgrade, "at": now()}]})
                self.store.insert_placement(db, placement, meta)
                self.store.convert_reservation(db, self.host_id, native["claims"], plan_id=plan["id"],
                                               instance_id=instance_id, generation=generation)
        except ValueError as error:
            message = "Old generation retired; replacement not installed" if replacing else "Nothing written on the host"
            return {"status": "failed", "error": message + ": " + str(error)}
        self.journaled = True
        self.event("deploy-intent", {"instance_id": instance_id, "generation": generation, "ownership_id": plan["ownership_id"],
                                     "application_sha256": app_sha, "image": {k: image.get(k) for k in ("reference", "digest", "resolution")},
                                     "image_id": pulled["image"]["image_id"],
                                     "files": {k: {"path": v["path"], "sha256": v["sha256"]} for k, v in native["files"].items()},
                                     "config": [{"path": item["path"], "sha256": item["sha256"]} for item in native["config"]],
                                     "claims": native["claims"], "token_path": native["paths"]["token"]})
        row = self.row()
        base = remote_base(record)
        try:
            prepared = self.call("prepare", {**base, "unit_text": native["files"]["unit"]["text"], "config_files": config_files,
                                             "yaml_text": native["files"]["yaml"]["text"],
                                             "expected_host_generation": plan["expected_host_generation"],
                                             "retained_entries": ["data", "generation"] if plan["redeploy"] else [],
                                             "install": plan.get("install", "start")}, 60)
        except RemoteError:
            self.update(row, meta={"uncertain": True, "token": {"state": "unknown"}, "runtime": "unknown"})
            raise
        if prepared["status"] != "succeeded":
            if not prepared.get("written"):
                with self.store.transaction() as db:
                    self.store.delete_placement(db, instance_id, generation, row["revision"])
                    self.store.release_claims(db, instance_id)
                    if instance is None:
                        self.store.withdraw_instance(db, instance_id)
                    elif plan.get("instance_upgrade"):
                        self.store.restore_instance(db, previous, plan["instance_upgrade"]["to_revision"])
                self.event("deploy-rolled-back", {"reason": prepared.get("error"), "written": False})
                message = "Old generation retired; replacement wrote no files" if replacing else "Nothing written on the host"
                return {"status": "failed", "error": message + "; journal intent withdrawn: " + str(prepared.get("error"))}
            cleanup = prepared.get("cleanup", {})
            written = prepared.get("written_steps", [])
            revoked = cleanup.get("token_revoked_at")
            token = {"state": "revoked", "revoked_at": revoked} if revoked else {"state": "unknown" if "token" in written else "absent"}
            # Runtime only from observation: an unwritten unit cannot run; a written one needs stop evidence.
            runtime = "not-installed" if "unit" not in written else ("stopped" if "stop" in cleanup else "unknown")
            uncertain = prepared["status"] == "needs-inspection" or token["state"] == "unknown" or runtime == "unknown"
            self.update(row, meta={"token": token, "uncertain": uncertain, "runtime": runtime})
            self.event("deploy-failed", {"step": "prepare", "written_steps": prepared.get("written_steps"), "cleanup": prepared.get("cleanup")})
            return {"status": "needs-inspection" if uncertain else "failed",
                    "error": "Preparation failed after writing; placement staged: " + str(prepared.get("error"))}
        if plan.get("install") == "fenced":
            token = {"state": "revoked", "issued_at": prepared["token_issued_at"], "revoked_at": prepared["token_revoked_at"]}
            names = native["names"]
            fence = fence_record(app_id=instance_id, record={**row, "native": native}, token=token, stopped=[], evidence=[
                "installed fenced by apply: token revoked at " + str(prepared["token_revoked_at"]) + " before the unit was written; never started",
                "unit " + native["paths"]["unit"] + " ExecStartPre gate verified in the generated fragment " + prepared["generated"]["fragment_path"],
                "start with `switchyard deploy switch-plan " + instance_id + "` (or unfence, then start, when no other placement holds "
                "its exclusive resources)"])
            self.update(row, state="fenced", fence=fence, meta={"token": token, "runtime": "stopped", "generated": prepared["generated"],
                                                                "installed_fenced": True})
            self.event("deploy-installed-fenced", {"files": prepared["files"], "generated": prepared["generated"],
                                                   "service": names["service"], "revoked_at": prepared["token_revoked_at"]})
            return {"status": "succeeded"}
        if plan.get("install") == "staged-revoked":
            token = {"state": "revoked", "issued_at": prepared["token_issued_at"], "revoked_at": prepared["token_revoked_at"]}
            self.update(row, meta={"token": token, "generated": prepared["generated"]})
            self.event("deploy-prepared", {"files": prepared["files"], "generated": prepared["generated"], "started": False})
            return {"status": "succeeded"}
        row = self.update(row, meta={"token": {"state": "valid", "issued_at": prepared["token_issued_at"]}, "generated": prepared["generated"]})
        self.event("deploy-prepared", {"files": prepared["files"], "generated": prepared["generated"]})
        if plan.get("install") == "staged":
            return {"status": "succeeded"}
        return self._start(row, base, revoke_on_failure=True)

    def _start(self, row, base, *, revoke_on_failure, evidence=()):
        self.journaled = True
        # The step must fit the operation: a declared readiness window lengthens it; never past the worker deadline.
        seconds = min(start_seconds(base["health_checks"]), int(self.deadline - time.monotonic()) - 20)
        if seconds < 60:
            raise _Deadline("Operation deadline too close to start " + row["instance_id"] + "; nothing was started")
        try:
            started = self.call("start", {**base, "revoke_on_failure": revoke_on_failure, "timeout": seconds}, seconds + 15)
        except RemoteError:
            self.update(row, meta={"uncertain": True, "runtime": "unknown"})
            raise
        if started["status"] != "succeeded":
            cleanup = started.get("cleanup", {})
            token = row["meta"]["token"]
            if revoke_on_failure:
                token = {"state": "revoked", "revoked_at": cleanup["token_revoked_at"]} if cleanup.get("token_revoked_at") else {"state": "unknown"}
            if "stop" in cleanup:
                runtime = "stopped"
            elif cleanup.get("stopped") == "not-started":
                runtime = row["meta"].get("runtime", "unknown")  # refused before any native change
            else:
                runtime = "unknown"
            uncertain = started["status"] == "needs-inspection" or token["state"] == "unknown" or runtime == "unknown"
            self.update(row, state="staged", meta={"token": token, "uncertain": uncertain, "runtime": runtime})
            self.event("start-failed", {"instance_id": row["instance_id"], "error": started.get("error"), "cleanup": cleanup,
                                        "health": started.get("health")})
            return {"status": "needs-inspection" if uncertain else "failed",
                    "error": "Start failed; placement staged: " + str(started.get("error")),
                    "cleanup": cleanup, "health": started.get("health")}
        pod = started["native"]["pod"]
        proof = [*evidence, "unit " + base["files"]["unit"] + " ExecStartPre gate verified in generated fragment",
                 "systemd invocation " + str(started["native"]["invocation_id"]),
                 "pod " + str(pod["id"]) + " labelled ownership-id " + row["meta"]["ownership_id"]]
        proof += ["health " + p["id"] + " passed after " + str(p["attempts"]) + " attempt(s)" for p in started["health"]]
        if started.get("devices"):
            proof.append("devices in the running containers' OCI configuration: " + json.dumps(started["devices"], sort_keys=True))
        fence = fence_record(app_id=row["instance_id"], record={**row, **{"native": row["meta"]["native"]}},
                             token=row["meta"]["token"], evidence=proof)
        row = self.update(row, state="active", fence=fence, meta={"runtime": "running", "uncertain": False,
                          "native_identities": {"service": started["native"]["service"], "invocation_id": started["native"]["invocation_id"],
                                                "pod_id": pod["id"], "containers": pod["containers"]}})
        self.event("deploy-verified", {"instance_id": row["instance_id"], "pod_id": pod["id"], "containers": pod["containers"],
                                       "health": started["health"], "devices": started.get("devices"),
                                       "invocation_id": started["native"]["invocation_id"]})
        return {"status": "succeeded", "health": started["health"], "devices": started.get("devices")}

    def _current(self):
        row = self.row()
        if row is None or row["generation"] != self.request["generation"] or row["revision"] != self.request["placement_revision"]:
            return None
        return row

    def _holders(self, row):
        """Other placements on this host that hold one of this placement's exclusive resources (journal, under the lease)."""
        with self.store.transaction() as db:
            instance = self.store.instance_row(db, row["instance_id"])
        return [item for item in contenders(self.store, row["instance_id"], row["host_id"], instance["application"]) if item["holding"]]

    def direct(self, action):
        row = self._current()
        if row is None:
            return {"status": "failed", "error": "Placement changed before the lease; no remote command executed"}
        try:
            allowed_from(action, row)
        except ValueError as error:
            return {"status": "failed", "error": str(error) + "; no remote command executed"}
        if action in ("start", "unfence"):
            holders = self._holders(row)
            if holders:
                return {"status": "failed", "error": holder_refusal(action.capitalize(), row["instance_id"], holders)
                        + "; no remote command executed"}
        record = {"instance_id": row["instance_id"], "generation": row["generation"], "ownership_id": row["meta"]["ownership_id"],
                  "native": row["meta"]["native"]}
        base = remote_base(record)
        # Journal intent precedes token issue/revocation and starts.
        row = self.update(row, meta={"pending": {"action": action, "operation_id": self.operation_id}}, keep_fence=True)
        self.journaled = True
        return self._step(row, action, base)[0]

    def lifecycle(self):
        """One approved generic lifecycle operation, wholly inside this worker's one host lease."""
        plan = self.request["plan"]
        action = plan.get("action")
        if plan.get("kind") != "deploy-lifecycle" or action not in LIFECYCLE_ACTIONS or not plan.get("executable"):
            return {"status": "failed", "error": "Not a workload lifecycle plan; no remote command executed"}
        row = self.row()
        with self.store.transaction() as db:
            instance = self.store.instance_row(db, plan["instance_id"])
        if _expired(plan["expires_at"]) or not _lifecycle_binding_matches(plan, row, instance):
            return {"status": "failed", "error": "Plan expired or placement changed before the lease; no remote command executed"}
        error = _lifecycle_state_error(action, row)
        if error:
            return {"status": "failed", "error": error + "; no remote command executed"}
        base = self._base(row)
        if action != "stop":
            found = contenders(self.store, row["instance_id"], self.host_id, instance["application"])
            holders = [item for item in found if item["holding"]]
            if holders:
                return {"status": "failed", "error": holder_refusal(action.capitalize(), row["instance_id"], holders, generic=True)
                        + "; no remote command executed"}
            # A rolled-back token may make a journal-fenced contender runnable. Observe every contender,
            # not only journal holders, before opening this placement's gate.
            rows = [row, *(self._row(item["instance_id"]) for item in found)]
            for offset in range(0, len(rows), VERIFY_BATCH):
                batch = rows[offset:offset + VERIFY_BATCH]
                verified = self.call("verify", {"items": [{**self._base(item), "run_health": False} for item in batch]}, 60)
                observations = {item["instance_id"]: item for item in verified.get("results") or []}
                for item in batch:
                    observation = observations.get(item["instance_id"], {}).get("observation")
                    if verified["status"] != "succeeded" or observation is None:
                        return {"status": "failed", "error": "Could not verify " + item["instance_id"] + "; nothing changed"}
                    verification = compare(item, observation, self.operation_id)
                    drift = [finding for finding in verification["findings"] if finding["severity"] != "info"
                             and not (action == "restart" and item["instance_id"] == row["instance_id"]
                                      and finding["code"] == "stopped-while-active")]
                    if drift or (item["instance_id"] != row["instance_id"] and observed_holding(observation)):
                        self.event("lifecycle-precondition-failed", verification)
                        return {"status": "failed", "error": "Host state of " + item["instance_id"]
                                + " does not match its safe placement state; nothing changed"}
            devices = row["meta"]["native"].get("devices") or []
            if devices:
                # Re-read the granted nodes and rootless access permissions before token issue or stop/start.
                config = _json(Path(self.request["config_path"]).read_bytes())
                facts = self.call("facts", {}, 30)
                observed = self.call("devices", {"paths": [item["host"] for item in devices]}, 30)
                states = {item["path"]: item for item in observed.get("devices") or []}
                pod = spec.Application.model_validate(instance["application"]).components[0].native.manifest.spec
                pod_user = pod.securityContext.runAsUser if pod.securityContext else None
                users = {row["meta"]["native"]["names"]["base"] + "-" + container.name:
                         container.securityContext.runAsUser if container.securityContext and container.securityContext.runAsUser is not None
                         else pod_user for container in pod.containers}
                ordered = [states.get(item["host"], {"path": item["host"], "exists": False}) for item in devices]
                _, checks = device_review(devices, ordered, granted_devices(config, self.host_id),
                                          facts.get("facts") or {}, self.host_id, users)
                changed = any((state.get("major"), state.get("minor")) != (device.get("major"), device.get("minor"))
                              for device, state in zip(devices, ordered))
                if facts["status"] != "succeeded" or observed["status"] != "succeeded" or changed or any(not c[1] for c in checks):
                    return {"status": "failed", "error": "Declared device grants, identity or access changed; nothing changed"}
        if not _live_authority(self.request, self.hosts):
            return {"status": "failed", "error": "Deploy authority changed during preflight; nothing changed"}
        marker = {"action": action, "operation_id": self.operation_id, "plan_id": plan["id"]}
        row = self.update(row, meta={"pending": marker}, keep_fence=True)
        self.journaled = True
        self.event("lifecycle-intent", {"action": action, "instance_id": row["instance_id"], "generation": row["generation"]})
        try:
            if action in ("stop", "restart"):
                result, row = self._step(row, "fence", base, pending_after=marker if action == "restart" else None)
                if result["status"] != "succeeded" or action == "stop":
                    if result["status"] == "needs-inspection":
                        self.update(row, meta={"pending": marker, "uncertain": True, "token": {"state": "unknown"}}, keep_fence=True)
                    return result
            # Reserve the start's cleanup tail before opening a stopped placement's gate.
            if self.deadline - time.monotonic() < 100:
                self._clear_pending(row["instance_id"])
                return {"status": "failed", "error": "Insufficient operation time to start safely; placement was not unfenced"}
            if (row["meta"].get("token") or {}).get("state") != "valid":
                result, row = self._step(row, "unfence", base, pending_after=marker)
                if result["status"] != "succeeded":
                    if result["status"] == "needs-inspection":
                        self.update(row, meta={"pending": marker, "uncertain": True, "token": {"state": "unknown"}}, keep_fence=True)
                    return result
            result, row = self._step(row, "start", base, revoke_on_failure=True)
            if result["status"] != "succeeded":
                row = self._fence_failed_start(row, result, "workload " + action)
                if row["state"] != "fenced":
                    self.update(row, meta={"pending": marker, "uncertain": True}, keep_fence=True)
                    return {**result, "status": "needs-inspection"}
            return result
        except (RemoteError, _Deadline) as error:
            # An unacknowledged mutation is never repeated or reported as stopped. Keep the intent and hold
            # the exclusive resources in the journal until an explicit Stop can prove the fence.
            self.update(self.row(), meta={"pending": marker, "uncertain": True, "runtime": "unknown",
                                          "token": {"state": "unknown"}}, keep_fence=True)
            return {"status": "needs-inspection", "error": str(error)}

    def _step(self, row, action, base, *, revoke_on_failure=False, evidence=(), pending_after=None):
        """One fence/unfence/start/stop of a journaled placement (intent already recorded as `pending`).
        Returns (result, row after). `pending_after`: the pending marker left on success (a switch keeps its own)."""
        if action == "start":
            result = self._start(row, base, revoke_on_failure=revoke_on_failure, evidence=evidence)
            # This placement's row (a switch acts on several; `self.row()` is the request's own instance).
            row = self.update(self._row(row["instance_id"]), meta={"pending": pending_after if result["status"] == "succeeded" else None},
                              keep_fence=True)
            return result, row
        try:
            result = self.call(action, base, 150)
        except RemoteError:
            self.update(row, meta={"uncertain": True, "runtime": "unknown"}, keep_fence=True)
            raise
        if result["status"] != "succeeded":
            uncertain = result["status"] == "needs-inspection"
            row = self.update(row, meta={"uncertain": uncertain or row["meta"].get("uncertain", False), "pending": None,
                                         **({"runtime": "unknown"} if uncertain else {})}, keep_fence=True)
            return {"status": result["status"], "error": action + " failed: " + str(result.get("error"))}, row
        if action == "fence":
            token = {**row["meta"].get("token", {}), "state": "revoked", "revoked_at": result["revoked_at"]}
            names = row["meta"]["native"]["names"]
            stopped = [names["service"], "pod/" + names["pod"], *names["containers"]]
            before = result.get("before") or {}
            proof = [*evidence,
                     "unit " + str(result["stop"]["unit"]) + "; pod and owned containers absent at " + result["stop"]["verified_at"],
                     "token revoked at " + result["revoked_at"] + " (gate refuses every start path)",
                     "before: unit " + str(before.get("unit")) + ", pod " + ("present" if before.get("pod") else "absent")
                     + ", token " + str(before.get("token"))]
            if row["state"] == "fenced":
                proof.insert(0, "re-enforced fence on an already fenced placement (" + (
                    "host had drifted" if before.get("token") == "valid" or before.get("pod") or before.get("unit") in RUNNING_UNIT
                    else "host was already clean; no-op with fresh evidence") + ")")
            fence = fence_record(app_id=row["instance_id"], record={**row, "native": row["meta"]["native"]}, token=token,
                                 evidence=proof, stopped=stopped)
            row = self.update(row, state="fenced", fence=fence, meta={
                "token": token, "runtime": "stopped", "uncertain": False, "pending": pending_after,
                "fence_history": [*row["meta"].get("fence_history", []), {"fenced_at": result["revoked_at"], "operation_id": self.operation_id}][-16:]})
            self.event("fenced", {"instance_id": row["instance_id"], "stopped": stopped, "revoked_at": result["revoked_at"],
                                  "host_generation": result.get("host_generation")})
        elif action == "unfence":
            token = {"state": "valid", "issued_at": result["issued_at"]}
            row = self.update(row, state="staged", meta={"token": token, "pending": pending_after})
            self.event("unfenced", {"instance_id": row["instance_id"], "issued_at": result["issued_at"]})
        else:  # stop
            row = self.update(row, state="staged", meta={"runtime": "stopped", "pending": pending_after})
            self.event("stopped", result["stop"])
        return {"status": "succeeded"}, row

    def verify(self):
        """Read-only: one remote observation for every requested placement on this host; records findings only."""
        rows = []
        with self.store.transaction() as db:
            for instance_id in self.request["instance_ids"]:
                row = self.store.placement_row(db, instance_id)
                if row is not None and row["state"] != "retired" and row["host_id"] == self.host_id:
                    rows.append(row)
        if not rows:
            return {"status": "failed", "error": "No current placement of the requested instances on this host; nothing observed"}
        summary_event, unreachable, error = {}, False, None
        observed = {}
        for start in range(0, len(rows), VERIFY_BATCH):
            batch = rows[start:start + VERIFY_BATCH]
            if error is None or not isinstance(error, _Deadline):
                items = [{**remote_base({"instance_id": row["instance_id"], "generation": row["generation"],
                                         "ownership_id": row["meta"]["ownership_id"], "native": row["meta"]["native"]}),
                          "run_health": row["state"] == "active"}
                         for row in batch]
                # A declared readiness window lets verify wait for a loading model, inside a bounded budget.
                window = max([ready_window(item["health_checks"]) for item in items if item["run_health"]] or [0])
                budget = min(READY_WINDOW_LIMIT, max(30, window + 5))
                try:
                    result = self.call("verify", {"items": items, "health_budget": budget}, budget + 30)
                    if result["status"] != "succeeded":
                        raise RemoteError(str(result.get("error")))
                    observed.update({item["instance_id"]: item for item in result["results"]})
                except (RemoteError, _Deadline) as failure:
                    error = failure
        extra = self._cross_findings(rows, observed)
        for start in range(0, len(rows), VERIFY_BATCH):
            for row in rows[start:start + VERIFY_BATCH]:
                item = observed.get(row["instance_id"])
                if item is not None and "observation" in item:
                    verification = compare(row, item["observation"], self.operation_id, extra.get(row["instance_id"], ()))
                else:
                    unreachable = True
                    reason = ("Observation failed: " + str(item["error"]) if item is not None
                              else "Missing from the remote result" if error is None
                              else "Host unreachable or operation deadline reached: " + str(error))
                    verification = unobserved(row, reason[:300], self.operation_id)
                    verification["findings"] += extra.get(row["instance_id"], [])
                self.store.save_verification(row["instance_id"], row["generation"], self.operation_id, verification)
                summary_event[row["instance_id"]] = {"consistent": verification["consistent"],
                                                     "findings": [f["code"] for f in verification["findings"]]}
            self.event("verified", summary_event)  # one bounded event per batch
            summary_event = {}
        if unreachable:
            return {"status": "needs-inspection", "error": "Some placements could not be observed; none of them is known to be consistent"}
        return {"status": "succeeded"}

    def _cross_findings(self, rows, observed):
        """Findings that need more than one placement or the operation journal: two observed holders of one
        exclusive resource, and a placement still marked with another operation's unfinished intent."""
        extra = {}
        holding = {}
        with self.store.transaction() as db:
            apps = {row["instance_id"]: self.store.instance_row(db, row["instance_id"])["application"] for row in rows}
        for row in rows:
            item = observed.get(row["instance_id"])
            if item is not None and "observation" in item and observed_holding(item["observation"]):
                for key in exclusive_keys(apps[row["instance_id"]], row["host_id"]):
                    holding.setdefault(key, []).append(row["instance_id"])
        for key, holders in holding.items():
            if len(holders) > 1:
                for instance_id in holders:
                    extra.setdefault(instance_id, []).append(_finding("exclusive-resource-contended", key + " is held (running or "
                                                                      "valid token) by " + ", ".join(sorted(holders)) + " at once"))
        for row in rows:
            pending = row["meta"].get("pending")
            if pending:
                try:
                    status = self.ops.get(pending.get("operation_id"))["status"]
                except (ValueError, KeyError, TypeError):
                    status = "unknown"
                extra.setdefault(row["instance_id"], []).append(_finding("operation-interrupted", (
                    "journal still holds the intent of " + str(pending.get("action")) + " from operation " + str(pending.get("operation_id"))
                    + " (receipt " + str(status) + "); the host state above is what that operation left; fence or act explicitly")))
        return extra

    # switch -------------------------------------------------------------------
    @staticmethod
    def _base(row):
        return remote_base({"instance_id": row["instance_id"], "generation": row["generation"],
                            "ownership_id": row["meta"]["ownership_id"], "native": row["meta"]["native"]})

    def _row(self, instance_id):
        with self.store.transaction() as db:
            return self.store.placement_row(db, instance_id)

    def switch_inspect(self):
        """Read-only, for a switch plan: the target and every current holder as the host shows them, and the devices."""
        rows = [self._row(instance_id) for instance_id in self.request["instance_ids"]]
        if any(row is None or row["host_id"] != self.host_id or row["state"] == "retired" for row in rows):
            return {"status": "failed", "error": "A placement of the switch is not on this host; nothing observed"}
        result = self.call("verify", {"items": [{**self._base(row), "run_health": False} for row in rows]}, 60)
        if result["status"] != "succeeded":
            return {"status": "failed", "error": "Observation failed: " + str(result.get("error"))}
        devices = []
        if self.request.get("devices"):
            devices = self.call("devices", {"paths": self.request["devices"]}, 30).get("devices") or []
        self.store.put_inspection(self.operation_id, {"observations": {item["instance_id"]: item for item in result["results"]},
                                                      "devices": devices})
        return {"status": "succeeded"}

    def _devices_now(self, paths, label, report, began):
        """GPU memory and device facts at one point of a switch (read-only; recorded, never decisive)."""
        if not paths:
            return
        try:
            states = self.call("devices", {"paths": paths}, 30).get("devices") or []
        except RemoteError:
            states = None
        report["devices"].append({"at": label, "seconds": round(time.monotonic() - began, 1), "devices": None if states is None else [
            {"path": state["path"], "vram_used": (state.get("gpu") or {}).get("mem_info_vram_used"),
             "vram_total": (state.get("gpu") or {}).get("mem_info_vram_total")} for state in states]})

    def _clear_pending(self, *instance_ids):
        for instance_id in instance_ids:
            row = self._row(instance_id)
            if row is not None and (row["meta"].get("pending") or {}).get("operation_id") == self.operation_id:
                self.update(row, meta={"pending": None}, keep_fence=True)

    def _fence_failed_start(self, row, result, why):
        """A start that failed with its cleanup proven (stopped, pod gone, token revoked) is recorded fenced."""
        row = self._row(row["instance_id"])
        meta = row["meta"]
        if not (row["state"] == "staged" and (meta.get("token") or {}).get("state") == "revoked"
                and meta.get("runtime") == "stopped" and not meta.get("uncertain")):
            return row
        stop = (result.get("cleanup") or {}).get("stop") or {}
        names = meta["native"]["names"]
        fence = fence_record(app_id=row["instance_id"], record={**row, "native": meta["native"]}, token=meta["token"],
                             stopped=[names["service"], "pod/" + names["pod"], *names["containers"]], evidence=[
                                 "start failed during " + why + ": " + str(result.get("error"))[:1000],
                                 "cleanup: unit " + str(stop.get("unit")) + "; pod and owned containers absent at " + str(stop.get("verified_at")),
                                 "token revoked at " + str(meta["token"].get("revoked_at")) + " (gate refuses every start path)"])
        return self.update(row, state="fenced", fence=fence, meta={"pending": None})

    def switch(self):
        """Execute an approved switch plan under this one lease: fence the holders, then unfence and start the target."""
        plan = self.request["plan"]
        target_id, began = plan["instance_id"], time.monotonic()
        rows = {item["instance_id"]: self._row(item["instance_id"]) for item in [plan["target"], *plan["previous"]]}
        for item in [plan["target"], *plan["previous"]]:
            row = rows[item["instance_id"]]
            if row is None or (row["generation"], row["revision"]) != (item["generation"], item["revision"]):
                return {"status": "failed", "error": "Placement of " + item["instance_id"] + " changed before the lease; "
                                                     "no remote command executed"}
        holders = sorted(item["instance_id"] for item in self._holders(rows[target_id]))
        previous = [item["instance_id"] for item in plan["previous"]]
        if holders != sorted(previous):
            return {"status": "failed", "error": "The holders changed since planning (now " + (", ".join(holders) or "none")
                                                 + "); no remote command executed"}
        marker = {"action": "switch", "operation_id": self.operation_id, "target": target_id, "previous": previous}
        # Journal intent on every placement before the first host change (a crash leaves it for verify to report).
        for instance_id in previous:
            rows[instance_id] = self.update(rows[instance_id], meta={"pending": {**marker, "role": "previous"}}, keep_fence=True)
        target = self.update(rows[target_id], meta={"pending": {**marker, "role": "target"}}, keep_fence=True)
        self.journaled = True
        paths = sorted({device["host"] for device in target["meta"]["native"].get("devices") or []})
        report = {"operation_id": self.operation_id, "target": target_id, "previous": previous,
                  "restore_on_failure": plan["restore_on_failure"], "started_at": now(), "steps": [], "devices": []}
        self.event("switch-intent", {"target": target_id, "previous": previous, "restore_on_failure": plan["restore_on_failure"]})

        def step(name, instance_id, result, since):
            report["steps"].append({"step": name, "instance_id": instance_id, "status": result["status"],
                                    "seconds": round(time.monotonic() - since, 1),
                                    **({"error": str(result["error"])[:500]} if result.get("error") else {})})

        def finish(status, outcome, error=None):
            report.update(status=status, outcome=outcome, seconds=round(time.monotonic() - began, 1), finished_at=now(),
                          states={instance_id: (self._row(instance_id) or {}).get("state") for instance_id in [target_id, *previous]})
            self.update(self._row(target_id), meta={"last_switch": report}, keep_fence=True)
            self.event("switch-" + outcome, report)
            return {"status": status, **({"error": error} if error else {})}

        self._devices_now(paths, "before", report, began)
        for index, instance_id in enumerate(previous):
            since = time.monotonic()
            try:
                result, rows[instance_id] = self._step(rows[instance_id], "fence", self._base(rows[instance_id]), evidence=[
                    "fenced by a switch to " + target_id + " (operation " + self.operation_id + ")"])
            except RemoteError:
                step("fence", instance_id, {"status": "needs-inspection", "error": "transport lost"}, since)
                self._clear_pending(target_id, *previous[index + 1:])
                return finish("needs-inspection", "fence-unknown", "Transport lost while fencing " + instance_id + " (now uncertain); "
                              + target_id + " was not touched")
            step("fence", instance_id, result, since)
            if result["status"] != "succeeded":
                self._clear_pending(target_id, *previous[index + 1:])
                done = previous[:index]
                return finish(result["status"], "fence-refused" if result["status"] == "failed" else "fence-unknown",
                              "Could not fence " + instance_id + ": " + str(result.get("error")) + "; " + target_id + " was not touched"
                              + ("; already fenced by this switch: " + ", ".join(done) if done else ""))
        self._devices_now(paths, "after-fence", report, began)
        base, since = self._base(target), time.monotonic()
        try:
            result, target = self._step(target, "unfence", base, pending_after={**marker, "role": "target"})
        except RemoteError:
            step("unfence", target_id, {"status": "needs-inspection", "error": "transport lost"}, since)
            return finish("needs-inspection", "target-unknown", "Transport lost while unfencing " + target_id + " (now uncertain); "
                          "the previous holders stay fenced")
        step("unfence", target_id, result, since)
        if result["status"] != "succeeded":
            if result["status"] == "failed" and plan["restore_on_failure"]:
                restored = self._restore(previous, target_id, report, marker, step)
                return finish("failed" if restored else "needs-inspection", "target-failed-restored" if restored else "restore-failed",
                              "Could not unfence " + target_id + ": " + str(result.get("error")) + "; restore of the previous "
                              "holders " + ("succeeded" if restored else "did not complete"))
            return finish(result["status"], "target-failed", "Could not unfence " + target_id + ": " + str(result.get("error"))
                          + "; the previous holders stay fenced")
        since = time.monotonic()
        try:
            result, target = self._step(target, "start", base, revoke_on_failure=True, evidence=[
                "started by a switch from " + (", ".join(previous) or "no holder") + " (operation " + self.operation_id + ")"])
        except RemoteError:
            step("start", target_id, {"status": "needs-inspection", "error": "transport lost"}, since)
            return finish("needs-inspection", "target-unknown", "Transport lost while starting " + target_id + ": it may be running; "
                          "the previous holders stay fenced; no restore attempted")
        step("start", target_id, result, since)
        if result["status"] == "succeeded":
            report.update(health=result.get("health"), target_devices=result.get("devices"))
            self._devices_now(paths, "after-start", report, began)
            return finish("succeeded", "switched")
        target = self._fence_failed_start(target, result, "a switch from " + (", ".join(previous) or "no holder"))
        if target["state"] != "fenced":
            return finish("needs-inspection", "target-unknown", "Start of " + target_id + " failed and its stop could not be proven ("
                          + str(result.get("error")) + "); the previous holders stay fenced; no restore attempted")
        self._devices_now(paths, "after-target-failure", report, began)
        if plan["restore_on_failure"] and previous:
            restored = self._restore(previous, target_id, report, marker, step)
            return finish("failed" if restored else "needs-inspection", "target-failed-restored" if restored else "restore-failed",
                          target_id + " did not start or become healthy (" + str(result.get("error")) + "); it is fenced again; "
                          "restore of " + ", ".join(previous) + (" succeeded" if restored else " did not complete"))
        return finish("failed", "target-failed", target_id + " did not start or become healthy (" + str(result.get("error"))
                      + "); it is fenced again; " + ("the previous holders stay fenced (restore_on_failure not chosen)"
                                                    if previous else "no previous holder"))

    def _restore(self, previous, target_id, report, marker, step):
        """Once, never retried: unfence and start each previous holder after the target was proven stopped."""
        restored = True
        for instance_id in previous:
            row, since = self._row(instance_id), time.monotonic()
            if row is None or row["state"] != "fenced" or row["meta"].get("uncertain"):
                step("restore", instance_id, {"status": "failed", "error": "not cleanly fenced; not restored"}, since)
                restored = False
                continue
            base = self._base(row)
            try:
                row = self.update(row, meta={"pending": {**marker, "role": "restore"}}, keep_fence=True)
                result, row = self._step(row, "unfence", base, pending_after={**marker, "role": "restore"})
                step("restore-unfence", instance_id, result, since)
                if result["status"] != "succeeded":
                    restored = False
                    continue
                since = time.monotonic()
                result, row = self._step(row, "start", base, revoke_on_failure=True, evidence=[
                    "restored by a switch after " + target_id + " failed (operation " + self.operation_id + ")"])
                step("restore-start", instance_id, result, since)
                if result["status"] != "succeeded":
                    self._fence_failed_start(row, result, "a restore after a failed switch to " + target_id)
                    restored = False
            except RemoteError:
                step("restore", instance_id, {"status": "needs-inspection", "error": "transport lost"}, since)
                return False
        return restored

    # detached image pulls --------------------------------------------------------
    def _image_info(self):
        info = self.call("image-info", {"image": self.request["image"]}, 60)
        return (info["image"], None) if info["status"] == "succeeded" else (None, str(info.get("error")))

    def pull_start(self):
        image = self.request["image"]
        info, error = self._image_info()
        if info is None:
            return {"status": "failed", "error": "Image could not be resolved; no pull started: " + error}
        digest, size = info["digest"], info["store"].get("size") or {}
        reference = image["repository"] + "@" + digest
        self.store.put_inspection(self.operation_id, {"digest": digest, "image": info})
        data = {"image": image["reference"], "repository": image["repository"], "size_bytes": size.get("bytes"),
                "layers": size.get("layers"), "operation_id": self.operation_id}
        if info["store"].get("local"):
            self.store.save_pull(self.host_id, digest, reference, "present", {**data, "note": "already in the local image store; nothing pulled"})
            return {"status": "succeeded"}
        self.store.save_pull(self.host_id, digest, reference, "starting", data)  # journal intent before the host is changed
        self.journaled = True
        try:
            result = self.call("pull-start", {"repository": image["repository"], "digest": digest, "size_bytes": size.get("bytes"),
                                              "layers": size.get("layers"), "operation_id": self.operation_id}, 60)
        except RemoteError:
            self.store.save_pull(self.host_id, digest, reference, "unknown", {**data, "note": "transport lost while starting; "
                                                                                         "read it with deploy pull-status"})
            raise
        pull = result.get("pull")
        state = pull["state"] if pull else "unknown" if result["status"] == "needs-inspection" else "refused"
        self.store.save_pull(self.host_id, digest, reference, state, {**data, "observed": pull, "started": result.get("started"),
                                                                      **({"error": result["error"]} if result.get("error") else {})})
        self.event("pull-start", {"image": reference, "state": state, "started": result.get("started"), "size_bytes": size.get("bytes")})
        return {"status": result["status"], **({"error": result["error"]} if result.get("error") else {})}

    def pull_status(self):
        image = self.request["image"]
        info, error = self._image_info()
        if info is None:
            return {"status": "failed", "error": "Image could not be resolved: " + error}
        digest = info["digest"]
        result = self.call("pull-status", {"repository": image["repository"], "digest": digest}, 60)
        if result["status"] != "succeeded":
            return {"status": "failed", "error": "Pull status could not be read: " + str(result.get("error"))}
        pull, known = result["pull"], self.store.pull(self.host_id, digest)
        if known is not None or pull["state"] not in ("absent", "present"):
            kept = {k: v for k, v in (known or {}).items() if k not in ("host_id", "digest", "reference", "state", "updated_at")}
            self.store.save_pull(self.host_id, digest, image["repository"] + "@" + digest, pull["state"],
                                 {**kept, "observed": pull, "observed_by": self.operation_id})
        self.store.put_inspection(self.operation_id, {"digest": digest, "image": info, "pull": pull})
        return {"status": "succeeded"}

    def observe(self):
        row = self._current()
        if row is None:
            return {"status": "failed", "error": "Placement changed before the lease; no remote command executed"}
        record = {"instance_id": row["instance_id"], "generation": row["generation"], "ownership_id": row["meta"]["ownership_id"],
                  "native": row["meta"]["native"]}
        result = self.call("observe", remote_base(record), 60)
        if result["status"] != "succeeded":
            return {"status": "failed", "error": "Ownership verification failed: " + str(result.get("error"))}
        self.store.put_inspection(self.operation_id, {"observation": result["observation"]})
        return {"status": "succeeded"}

    def config_read(self):
        """Read-only, for a refresh plan: ownership state, recorded configuration hashes and changing texts."""
        row = self._current()
        if row is None:
            return {"status": "failed", "error": "Placement changed before the lease; no remote command executed"}
        record = {"instance_id": row["instance_id"], "generation": row["generation"], "ownership_id": row["meta"]["ownership_id"],
                  "native": row["meta"]["native"]}
        extra = {"caddyfile": self.request["caddyfile"]} if "caddyfile" in self.request else {}
        result = self.call("config-read", {**remote_base(record), "texts_for": self.request["texts_for"], **extra}, 60)
        if result["status"] != "succeeded":
            return {"status": "failed", "error": "Configuration read failed: " + str(result.get("error"))}
        self.store.put_inspection(self.operation_id, {"observation": result["observation"], "config": result["config"]})
        return {"status": "succeeded"}

    def lan_route_probe(self, action):
        row = self._current()
        if not row or row["state"] != "active":
            return {"status": "failed", "error": "LAN service placement changed or is not active"}
        result = self.call(action, {**self._base(row), **self.request["probe"]}, 45)
        self.event(action, {key: result[key] for key in ("verified", "error") if key in result})
        return result

    def refresh(self):
        """Write an approved refresh plan's configuration files; restart or not as declared; record the outcome."""
        plan = self.request["plan"]
        self.request = {**self.request, "instance_id": plan["instance_id"], "generation": plan["generation"],
                        "placement_revision": plan["placement_revision"]}
        row = self._current()
        if row is None or row["meta"]["ownership_id"] != plan["ownership_id"]:
            return {"status": "failed", "error": "Placement changed before the lease; no remote command executed"}
        if row["meta"].get("uncertain") or row["state"] != plan["state"]:
            return {"status": "failed", "error": "Placement state changed or is uncertain; no remote command executed"}
        with self.store.transaction() as db:
            instance = self.store.instance_row(db, plan["instance_id"])
        if instance["revision"] != plan["instance_revision"]:
            return {"status": "failed", "error": "Instance revision changed since planning; no remote command executed"}
        native = row["meta"]["native"]
        record = {"instance_id": row["instance_id"], "generation": row["generation"], "ownership_id": row["meta"]["ownership_id"],
                  "native": native}
        new_hashes = {item["name"]: item["sha256"] for item in plan["config"]}
        row = self.update(row, meta={"pending": {"action": "refresh", "operation_id": self.operation_id, "files": new_hashes}},
                          keep_fence=True)
        self.journaled = True
        self.event("refresh-intent", {"changes": [{"path": c["path"], "from": c["journal_sha256"], "to": c["sha256"]}
                                                  for c in plan["changes"] if c["change"] == "update"],
                                      "restart": plan["restart"], "application_revision": plan["application_revision"]})
        try:
            result = self.call("refresh", {**remote_base(record), "restart": plan["restart"], "health_checks": plan["health_checks"],
                                           "config_files": [{k: item[k] for k in ("name", "text", "sha256")} for item in plan["config"]],
                                           "timeout": 150}, 170)
        except RemoteError:
            self.update(row, meta={"uncertain": True, "runtime": "unknown"}, keep_fence=True)
            raise
        if result.get("status") == "failed" and not result.get("written") and not result.get("write_phase_entered"):
            self.update(row, meta={"pending": None}, keep_fence=True)
            self.event("refresh-refused", {"error": result.get("error")})
            return {"status": "failed", "error": "Nothing written: " + str(result.get("error"))}
        if "files" not in result:  # write phase failed: the host may hold old, new or partly replaced files
            self.update(row, meta={"uncertain": True}, keep_fence=True)  # `pending` keeps the intended hashes
            self.event("refresh-partial", {"verified": result.get("verified_files"), "error": result.get("error")})
            return {"status": "needs-inspection", "error": str(result.get("error"))}
        app = with_generation_gate(plan["application"])
        new_native = {**native, "config": [{k: v for k, v in item.items() if k != "text"} for item in plan["config"]],
                      "health_checks": plan["health_checks"]}
        meta = {**row["meta"], "native": new_native, "pending": None, "last_operation": self.operation_id,
                "refreshes": [*row["meta"].get("refreshes", []), {
                    "operation_id": self.operation_id, "at": now(), "application_revision": app["revision"],
                    "written": result["written_files"], "restarted": result.get("restarted", False)}][-16:]}
        state, fence = row["state"], row["placement"].get("fence")
        if result.get("restart_failed"):
            stopped = "stop" in (result.get("cleanup") or {})
            state, fence = "staged", None
            meta.update(runtime="stopped" if stopped else "unknown", uncertain=not stopped)
        elif result.get("restarted"):
            pod = result["native"]["pod"]
            meta["native_identities"] = {"service": native["names"]["service"], "invocation_id": result["native"]["invocation_id"],
                                         "pod_id": pod["id"], "containers": pod["containers"]}
        app_sha = spec.Application.model_validate(app).content_sha256()
        with self.store.transaction() as db:
            if plan["application_changed"]:
                self.store.replace_instance(db, row["instance_id"], plan["instance_revision"], app, {
                    **instance["meta"], "content_sha256": app_sha,
                    "history": [*instance["meta"].get("history", []), {"refresh": self.operation_id, "from_revision": plan["instance_revision"],
                                                                        "to_revision": app["revision"], "at": now()}]})
            placement = build_placement(app=app, host_id=row["host_id"], generation=row["generation"], state=state,
                                        ownership_id=meta["ownership_id"], native=new_native, uid=meta["uid"], fence=fence)
            self.store.cas_placement(db, row["instance_id"], row["generation"], row["revision"], placement, meta)
        self.event("refreshed", {"written": result["written_files"], "files": result["files"], "restarted": result.get("restarted", False),
                                 "health": result.get("health"), "state": state, "application_revision": app["revision"],
                                 **({"cleanup": result.get("cleanup")} if result.get("restart_failed") else {})})
        if result["status"] != "succeeded":
            return {"status": "needs-inspection" if meta.get("uncertain") else "failed", "error": str(result.get("error"))}
        return {"status": "succeeded"}

    def undeploy(self):
        plan = self.request["plan"]
        self.request = {**self.request, "instance_id": plan["instance_id"], "generation": plan["generation"],
                        "placement_revision": plan["placement_revision"]}
        row = self._current()
        if row is None or row["meta"]["ownership_id"] != plan["ownership_id"]:
            return {"status": "failed", "error": "Placement changed before the lease; no remote command executed"}
        return self._retire(row, delete_data=plan["delete_data"], review=plan)

    def _retire(self, row, *, delete_data, review=None, revoke_first=False):
        base = self._base(row)
        row = self.update(row, meta={"pending": {"action": "undeploy", "operation_id": self.operation_id}}, keep_fence=True)
        self.journaled = True
        event = {"delete_data": delete_data}
        if review:
            event.update(remove=review["remove"], datasets=[{k: d[k] for k in ("id", "path", "action")}
                                                             for d in review["datasets"]])
        self.event("undeploy-intent", event)
        try:
            result = self.call("undeploy", {**base, "delete_data": delete_data, "revoke_first": revoke_first}, 180)
        except RemoteError:
            self.update(row, meta={"uncertain": True, "runtime": "unknown"}, keep_fence=True)
            raise
        if result["status"] != "succeeded":
            uncertain = result["status"] == "needs-inspection"
            self.update(row, meta={"uncertain": uncertain or row["meta"].get("uncertain", False), "pending": None}, keep_fence=True)
            return {"status": result["status"], "error": "Undeploy failed: " + str(result.get("error"))}
        kept = {d["id"]: d["path"] for d in row["meta"]["native"]["datasets"]
                if d["default"] and d["path"] not in result["deleted_data"]}
        self.update(row, state="retired", meta={"token": {"state": "removed"}, "runtime": "absent", "uncertain": False,
                                                 "pending": None, "retired": {"removed": result["removed"],
                                                 "deleted_data": result["deleted_data"], "kept": result["kept"]}})
        with self.store.transaction() as db:
            instance = self.store.instance_row(db, row["instance_id"])
            self.store.update_instance_meta(db, row["instance_id"], {**instance["meta"], "retained_datasets": kept})
        self.event("undeployed", {"removed": result["removed"], "deleted_data": result["deleted_data"], "kept_datasets": kept})
        return {"status": "succeeded"}


class _Deadline(Exception):
    pass


def execute_worker(request, hosts, store, operation_id, *, local_host_ids=(), started=None):
    """Called by operation_worker inside the whole-operation canonical lease; `started`: the worker process's
    monotonic start (the broker's bound runs from there, lease wait included)."""
    return Worker(request, hosts, store, operation_id, local_host_ids, started).run()


# ---------------------------------------------------------------- CLI

def register_cli(commands):
    spec_parser = commands.add_parser("spec", help="Workload spec tools and adopted-application registration (no host access)")
    spec_commands = spec_parser.add_subparsers(dest="spec_command", required=True)
    validate = spec_commands.add_parser("validate", help="Validate an Application/Placement/ActivationInput/Bundle; print hashes")
    validate.add_argument("file", help="JSON file or - for stdin")
    register = spec_commands.add_parser("register", help="Register an adopted application Bundle (metadata only; grants no authority)")
    register.add_argument("file", help="JSON Bundle file or - for stdin")
    register.add_argument("--expected-revision", type=int, required=True, help="Current registration revision (0 for new)")
    register.add_argument("--submitted-by", help="Provenance: who submits (default: the application's provenance)")
    spec_commands.add_parser("registered", help="List registered adopted applications")
    show_registration = spec_commands.add_parser("show", help="Read one registration")
    show_registration.add_argument("reference", help="ID or ID@REVISION")
    unregister = spec_commands.add_parser("unregister", help="Remove a registration only (no host is contacted)")
    unregister.add_argument("id")
    unregister.add_argument("--expected-revision", type=int, required=True)
    template = commands.add_parser("template", help="Stored host-free templates (immutable revisions)")
    templates = template.add_subparsers(dest="template_command", required=True)
    save = templates.add_parser("save", help="Save a new template revision (compare-and-swap)")
    save.add_argument("file")
    save.add_argument("--expected-revision", type=int, required=True, help="Current latest revision (0 for a new template)")
    templates.add_parser("list")
    show = templates.add_parser("show")
    show.add_argument("reference", help="ID or ID@REVISION")
    deploy = commands.add_parser("deploy", help="Deploy owned Quadlet .kube workloads (plan, apply, fence, undeploy)")
    actions = deploy.add_subparsers(dest="deploy_command", required=True)
    plan = actions.add_parser("plan", help="Leased read-only inspection, then an expiring plan; never executes")
    plan.add_argument("--template", help="ID[@REVISION] (required for a new instance)")
    plan.add_argument("--instance", required=True)
    plan.add_argument("--host", required=True)
    plan.add_argument("--port", action="append", default=[], metavar="ENDPOINT=PORT")
    plan.add_argument("--address", action="append", default=[], metavar="ENDPOINT=IP")
    plan.add_argument("--dataset", action="append", default=[], metavar="ID=ABSOLUTE_PATH")
    plan.add_argument("--param", action="append", default=[], metavar="NAME=VALUE", help="Template parameter value (new instance)")
    plan.add_argument("--record", action="append", default=[], metavar="NAME=ADDRESS",
                      help="Operator DNS record for the registry-hosts file (one label, or a name inside the zone)")
    plan.add_argument("--request-id", help="Receipt ID for the leased inspection (default: generated)")
    plan.add_argument("--fenced", action="store_true",
                      help="Install fenced: write everything with a revoked token, start nothing (a second holder of an "
                           "exclusive resource; move the resource with switch-plan)")
    for name in ("apply", "undeploy-apply", "refresh-apply", "switch-apply"):
        sub = actions.add_parser(name, help="Execute one approved plan under the host lease")
        sub.add_argument("plan_id")
        sub.add_argument("--approve", action="store_true")
        sub.add_argument("--request-id", required=True)
    upgrade = actions.add_parser("upgrade-plan", help="Plan replacing a placement with a newer revision of its template")
    upgrade.add_argument("instance")
    upgrade.add_argument("--template", required=True, metavar="ID@REVISION")
    upgrade.add_argument("--param", action="append", default=[], metavar="NAME=VALUE")
    upgrade.add_argument("--request-id", help="Receipt ID for the leased inspection (default: generated)")
    refresh = actions.add_parser("refresh-plan", help="Re-render configuration files (registry, parameters, records); "
                                                      "leased read-only diff against the host; never executes")
    refresh.add_argument("instance")
    refresh.add_argument("--param", action="append", default=[], metavar="NAME=VALUE")
    refresh.add_argument("--record", action="append", default=[], metavar="NAME=ADDRESS", help="Add an operator record")
    refresh.add_argument("--remove-record", action="append", default=[], metavar="NAME", help="Remove an operator record")
    refresh.add_argument("--request-id", help="Receipt ID for the leased read (default: generated)")
    actions.add_parser("list", help="Instances, placements and claims (no host access)")
    show = actions.add_parser("show")
    show.add_argument("instance", help="INSTANCE, or INSTANCE@REVISION for one stored application revision")
    for name in DIRECT_ACTIONS:
        sub = actions.add_parser(name, help=TRANSITIONS[name] + "; previews without --approve")
        sub.add_argument("instance")
        sub.add_argument("--approve", action="store_true")
        sub.add_argument("--request-id")
    undeploy = actions.add_parser("undeploy-plan", help="Leased ownership verification, then an expiring undeploy plan")
    undeploy.add_argument("instance")
    undeploy.add_argument("--delete-data", action="store_true", help="Destructive: delete Switchyard-created dataset directories")
    undeploy.add_argument("--request-id")
    actions.add_parser("claims", help="Port registry (no host access)")
    verify = actions.add_parser("verify", help="Leased read-only comparison of host and journal; changes nothing")
    verify.add_argument("instance", nargs="?")
    verify.add_argument("--all", action="store_true", help="Every non-retired placement, one lease per host")
    verify.add_argument("--request-id", help="Receipt ID (single instance only; default: generated)")
    switch = actions.add_parser("switch-plan", help="Plan moving an exclusive host resource (a GPU) to TARGET: fence the "
                                                    "current holder, then unfence and start TARGET, under one lease")
    switch.add_argument("target")
    switch.add_argument("--restore-on-failure", action="store_true",
                        help="If TARGET fails to start or become healthy (and is proven stopped), start the previous holder "
                             "again once (default: it stays fenced)")
    switch.add_argument("--request-id", help="Receipt ID for the leased inspection (default: generated)")
    for name, text in (("pull-start", "Start a detached image pull on the host (preview without --approve)"),
                       ("pull-status", "Leased read-only state of one image's detached pull")):
        sub = actions.add_parser(name, help=text)
        sub.add_argument("--host", required=True)
        source = sub.add_mutually_exclusive_group(required=True)
        source.add_argument("--image", help="registry/repository[:tag][@sha256:digest]")
        source.add_argument("--template", help="ID[@REVISION]: the template's image")
        sub.add_argument("--request-id")
        if name == "pull-start":
            sub.add_argument("--approve", action="store_true")
    actions.add_parser("pulls", help="Journaled detached pulls with their last known state (no host access)")


def _pairs(values, label, convert=str):
    result = {}
    for value in values:
        key, sep, item = value.partition("=")
        if not sep or not key or not item or key in result:
            raise ValueError("--" + label + " expects unique KEY=VALUE")
        try:
            result[key] = convert(item)
        except ValueError:
            raise ValueError("Invalid --" + label + " value: " + value) from None
    return result


def _port(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    return port


def _manager(service):
    factory = getattr(service, "deployments", None)
    manager = factory() if factory else DeployManager(service._broker)
    hosts = getattr(service, "hosts", None)
    if manager.registry_hosts is None and hosts is not None:
        # Until Service.deployments() passes it: the registry feeds the registry-hosts generator.
        manager.registry_hosts = lambda: hosts()["hosts"]
    return manager


def _registry_host_ids(service):
    """Registry host IDs for registration cross-checks; None when the service has no registry."""
    hosts = getattr(service, "hosts", None)
    if hosts is None:
        return None
    return sorted(record["id"] for record in hosts()["hosts"])


def handle_cli(args, service):
    if args.command == "spec":
        command = args.spec_command
        if command == "validate":
            return validate_document(read_json_file(args.file))
        manager = _manager(service)
        if command == "register":
            raw, document = read_spec_file(args.file)
            return manager.register_application(document, expected_revision=args.expected_revision,
                                                submitted_by=args.submitted_by, source=args.file, source_bytes=raw,
                                                host_ids=_registry_host_ids(service))
        if command == "registered":
            return manager.registered_applications()
        if command == "show":
            return manager.registered_application(args.reference)
        return manager.unregister_application(args.id, expected_revision=args.expected_revision)
    if args.command == "template":
        manager = _manager(service)
        if args.template_command == "save":
            return manager.save_template(read_json_file(args.file), expected_revision=args.expected_revision)
        if args.template_command == "list":
            return manager.templates()
        return manager.template(args.reference)
    if args.command != "deploy":
        return None
    manager = _manager(service)
    command = args.deploy_command
    if command == "plan":
        return manager.plan(template=args.template, instance_id=args.instance, host_id=args.host,
                            ports=_pairs(args.port, "port", _port), addresses=_pairs(args.address, "address"),
                            datasets=_pairs(args.dataset, "dataset"), request_id=args.request_id,
                            params=_pairs(args.param, "param"), records=_pairs(args.record, "record"),
                            install_fenced=args.fenced)
    if command == "upgrade-plan":
        return manager.upgrade_plan(args.instance, args.template, params=_pairs(args.param, "param"),
                                    request_id=args.request_id)
    if command == "apply":
        return manager.apply(args.plan_id, approved=args.approve, request_id=args.request_id)
    if command == "undeploy-apply":
        return manager.undeploy_apply(args.plan_id, approved=args.approve, request_id=args.request_id)
    if command == "switch-plan":
        return manager.switch_plan(args.target, restore_on_failure=args.restore_on_failure, request_id=args.request_id)
    if command == "switch-apply":
        return manager.switch_apply(args.plan_id, approved=args.approve, request_id=args.request_id)
    if command == "pull-start":
        return manager.pull_start(args.host, image=args.image, template=args.template, approved=args.approve,
                                  request_id=args.request_id)
    if command == "pull-status":
        return manager.pull_status(args.host, image=args.image, template=args.template, request_id=args.request_id)
    if command == "pulls":
        return manager.pulls()
    if command == "refresh-plan":
        return manager.refresh_plan(args.instance, params=_pairs(args.param, "param"), add_records=_pairs(args.record, "record"),
                                    remove_records=args.remove_record, request_id=args.request_id)
    if command == "refresh-apply":
        return manager.refresh_apply(args.plan_id, approved=args.approve, request_id=args.request_id)
    if command == "undeploy-plan":
        return manager.undeploy_plan(args.instance, delete_data=args.delete_data, request_id=args.request_id)
    if command == "list":
        return manager.list()
    if command == "show":
        if "@" in args.instance:
            return manager.instance_revision(args.instance)
        return manager.show(args.instance)
    if command == "claims":
        return manager.store.all_claims()
    if command == "verify":
        if args.all == bool(args.instance):
            raise ValueError("deploy verify takes exactly one of INSTANCE or --all")
        if args.all:
            if args.request_id:
                raise ValueError("--request-id applies to a single instance")
            return manager.verify_all()
        return manager.verify(args.instance, request_id=args.request_id)
    return manager.act(args.instance, command, approved=args.approve, request_id=args.request_id)
