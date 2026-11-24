"""Carry instance settings across an explicitly selected template revision."""
from . import deploy_config


def carry_settings(app, instance, previous_template, supplied):
    """The new template supplies runtime; the existing instance supplies its local settings."""
    old = instance["application"]
    app["name"] = old["name"]
    declared = {p["id"] for p in app["parameters"]}
    removed = sorted(p["id"] for p in old["parameters"] if p["id"] not in declared and p.get("value") is not None)
    if removed:
        raise ValueError("New template removes instance parameter(s): " + ", ".join(removed))
    values = {key: value for key, value in deploy_config.parameter_values(old).items()
              if key in declared and value is not None}
    values.update(supplied)
    app = deploy_config.set_parameters(app, values)

    before = {item["id"]: item for item in previous_template["config_files"]}
    after = {item["id"]: item for item in app["config_files"]}
    for item in old["config_files"]:
        key = item["id"]
        original = before.get(key, {})
        target = after.get(key, {})
        content = item.get("content")
        if content is not None and content != original.get("content"):
            if target.get("content") not in (original.get("content"), content) or target.get("content") is None:
                raise ValueError("New template conflicts with instance configuration override: " + key)
            target["content"] = content
        records = (item.get("generator") or {}).get("records") or []
        if records:
            generator = target.get("generator") or {}
            if generator.get("kind") != "registry-hosts":
                raise ValueError("New template removes operator DNS records in " + key)
            combined = {row["name"]: row for row in generator.get("records") or []}
            for row in records:
                if row["name"] in combined and combined[row["name"]] != row:
                    raise ValueError("New template conflicts with operator DNS record " + row["name"])
                combined[row["name"]] = row
            generator["records"] = [combined[name] for name in sorted(combined)]
    return app
