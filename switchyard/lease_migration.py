"""Offline import of the old lease files and audit ledgers. Never modify them."""
from collections import defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat

from . import locks
from .lease_db import LeaseStore

LEASE_ID = re.compile(r"[0-9a-f]{32}\Z")
LABEL = re.compile(r"[A-Z0-9]{1,64}\Z")
UNCERTAIN_ENDINGS = {"expired", "owner-exited", "signal", "broken", "error"}


def _read(path, limit, *, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or (private and info.st_mode & 0o077):
            raise ValueError(f"Untrusted legacy lease file: {path.name}")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f"Legacy lease file exceeds import limit: {path.name}")
        return data.decode("utf-8", errors="strict")


def _legacy_audit(paths):
    """Preserve raw history; unmatched starts are recovery evidence, not free grants."""
    events, unresolved, raw_pending = [], defaultdict(dict), set()
    for path, label in sorted(paths.items()):
        if not LABEL.fullmatch(label):
            raise ValueError(f"Invalid legacy device ledger label: {path.name}")
        for line in _read(path, 64 << 20).splitlines():
            if not line:
                continue
            if not line.lstrip().startswith("{"):
                events.append({"resource": label, "event": "LEGACY", "text": line})
                match = locks._TEXT_ENTRY.match(line)
                if match:
                    if match[2] == "CLAIM":
                        raw_pending.add(label)
                    elif not any(f"reason={reason}" in match[3] for reason in UNCERTAIN_ENDINGS):
                        raw_pending.discard(label)
                continue
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError(f"Invalid legacy audit event: {path.name}")
            events.append({**event, "resource": label})
            lease_id, kind = event.get("lease_id"), event.get("event")
            if kind == "CLAIM":
                if not isinstance(lease_id, str) or not LEASE_ID.fullmatch(lease_id):
                    raise ValueError(f"Invalid legacy audit claim: {path.name}")
                unresolved[label][lease_id] = event
            elif kind == "RELEASE" and lease_id in unresolved[label]:
                # These old terminal reasons could release without proof of remote completion.
                if event.get("reason") not in UNCERTAIN_ENDINGS:
                    unresolved[label].pop(lease_id)
            elif kind == "CLEAR" or (kind == "BREAK" and event.get("attested_stopped")):
                unresolved[label].clear()
                raw_pending.discard(label)
    return events, unresolved, raw_pending


def migrate(state_dir, *, ledger_dir=None, legacy_ledgers=(), dry_run):
    """Caller must fence all old writers before import. The kernel check is an additional guard."""
    directory = Path(state_dir).resolve() / "leases"
    ledger_dir = Path(ledger_dir if ledger_dir is not None else locks.DEFAULT_LEDGER_DIR).resolve()
    if directory.is_symlink() or (directory.exists() and (directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077)):
        raise ValueError("Legacy lease state directory must be private and owned")
    paths = {path: path.name.removeprefix("DEVICE_ACCESS_").removesuffix(".md")
             for path in ledger_dir.glob("DEVICE_ACCESS_*.md")}
    for item in legacy_ledgers:
        label, separator, filename = item.partition("=")
        path = Path(filename)
        if (not separator or not LABEL.fullmatch(label) or not path.is_absolute()
                or path != path.resolve(strict=True)):
            raise ValueError("--legacy-ledger requires LABEL=/canonical/absolute/path")
        if path in paths and paths[path] != label:
            raise ValueError("Legacy ledger path is assigned to multiple labels")
        paths[path] = label
    if len(set(paths.values())) != len(paths):
        raise ValueError("Multiple legacy ledger files claim the same resource label; inspect before migrating")
    if len(paths) > 64:
        raise ValueError("Too many legacy ledgers for a verified drain")
    if paths:
        observed = locks.device_locks(paths=paths)["ledgers"]
        states = {row["path"]: row["state"] for row in observed}
        busy = sorted(label for path, label in paths.items() if states.get(str(path)) != "free")
        if busy:
            raise ValueError("Legacy ledger drain not verified: " + ", ".join(busy))
    events, unresolved, raw_pending = _legacy_audit(paths)
    rows, blocks = {}, {}
    if any(directory.glob("*.jsonl")):
        raise ValueError("Unexpected JSONL files in the legacy lease directory; inspect before migrating")
    for path in sorted(directory.glob("*.json")):
        state = json.loads(_read(path, 65536, private=True))
        if not isinstance(state, dict) or not LABEL.fullmatch(state.get("device") or ""):
            raise ValueError(f"Invalid legacy lease state: {path.name}")
        label = state["device"]
        if path.stem == "blocked-" + label:
            blocks[label] = state
        elif LEASE_ID.fullmatch(path.stem) and state.get("lease_id") == path.stem:
            rows[path.stem] = state
        else:
            raise ValueError(f"Invalid legacy lease identity: {path.name}")
    for label in raw_pending:
        blocks.setdefault(label, {"device": label, "reason": "unmatched legacy text claim",
                                  "operator": "legacy import", "pending": True})
    for label, claims in unresolved.items():
        for lease_id, event in claims.items():
            previous = rows.get(lease_id, {})
            if previous and previous["device"] != label:
                raise ValueError(f"Legacy lease identity spans devices: {lease_id}")
            rows[lease_id] = {"device": label, "lease_id": lease_id, "owner": event.get("owner") or "legacy",
                              "scope": event.get("scope") or "legacy operation", "created_at": event.get("at"),
                              **previous, "status": "suspect", "suspect": True,
                              "suspect_cause": "legacy completion unconfirmed"}
    active = {row["device"] for row in rows.values()
              if row.get("status") not in {"released", "error", "completed", "broken", "cancelled", "failed"}}
    result = {"dry_run": dry_run, "legacy_ledgers": len(paths), "legacy_leases": len(rows),
              "legacy_events": len(events), "blocked_devices": sorted(blocks), "unresolved_devices": sorted(active)}
    if not dry_run:
        LeaseStore(directory, allow_legacy=True, legacy_dir=ledger_dir, legacy_paths=paths).import_legacy(
            list(rows.values()), blocks, events)
    return result
