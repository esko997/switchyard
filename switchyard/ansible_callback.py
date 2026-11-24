"""Ansible notification callback that records bounded, content-free task events for Switchyard.

Not imported by Switchyard: ansible_runner copies this file into a private callback plugin
directory, and the pinned ansible-core loads it as `switchyard_events`. It writes JSON lines to
the file named by SWITCHYARD_ANSIBLE_EVENTS: task names, statuses, diff sizes and short failure
messages, never module results or diff contents. no_log results record only that they were hidden.
"""
from __future__ import annotations

import json
import os
import time

from ansible import context
from ansible.plugins.callback import CallbackBase

DOCUMENTATION = """
name: switchyard_events
type: notification
short_description: Bounded structured task events for Switchyard plans and receipts
description:
  - Writes JSON lines to the file named by the SWITCHYARD_ANSIBLE_EVENTS environment variable.
requirements:
  - enable in callbacks_enabled
"""

LIMIT = 8 * 1024 * 1024
MESSAGE = 300


def _part(result, name):
    # ansible-core 2.19 exposes task/host/result; older releases only the underscored names.
    value = getattr(result, name, None)
    return value if value is not None else getattr(result, "_" + name, None)


def _size(value):
    try:
        return len(json.dumps(value, default=str))
    except (TypeError, ValueError):
        return 0


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "notification"
    CALLBACK_NAME = "switchyard_events"
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self, display=None):
        super().__init__(display=display)
        self._fd = None
        self._written = 0
        self._truncated = False
        path = os.environ.get("SWITCHYARD_ANSIBLE_EVENTS")
        if path:
            self._fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)

    def _check_mode(self):
        try:
            return bool(context.CLIARGS.get("check"))
        except Exception:
            return False

    def _emit(self, event, **data):
        if self._fd is None:
            return
        line = (json.dumps({"at": time.time(), "event": event, **data}, default=str) + "\n").encode()
        if self._written + len(line) > LIMIT:
            if self._truncated:
                return
            self._truncated = True
            line = (json.dumps({"at": time.time(), "event": "truncated"}) + "\n").encode()
        os.write(self._fd, line)
        self._written += len(line)

    def _result(self, status, result, **extra):
        task = _part(result, "task")
        host = _part(result, "host")
        data = _part(result, "result")
        data = data if isinstance(data, dict) else {}
        no_log = bool(getattr(task, "no_log", False)) or bool(data.get("_ansible_no_log")) or "censored" in data
        items = data.get("results") if isinstance(data.get("results"), list) else []
        if status == "ok" and data.get("changed"):
            status = "changed"
        event = {"status": status, "host": host.get_name() if host else None,
                 "task": (task.get_name() if task else "")[:256], "action": getattr(task, "action", None),
                 "handler": type(task).__name__ == "Handler", "no_log": no_log}
        if not no_log:
            diffs = [data["diff"]] if data.get("diff") else []
            diffs += [item["diff"] for item in items if isinstance(item, dict) and item.get("diff")]
            if diffs:
                event["diff_bytes"] = sum(_size(diff) for diff in diffs)
        check = self._check_mode()
        if check and getattr(task, "check_mode", None) is False:
            event["forced_run"] = True  # check_mode: false executes for real even in a check run
        if check and status == "skipped":
            texts = [str(data.get("msg", "")), str(data.get("skip_reason", ""))]
            texts += [str(item.get("msg", "")) for item in items if isinstance(item, dict)]
            when = " ".join(str(value) for value in (getattr(task, "when", None) or []))
            if any("check mode" in text.lower() for text in texts) or "ansible_check_mode" in when:
                event["not_predicted"] = True
        if status in {"failed", "unreachable"}:
            event["msg"] = "(hidden by no_log)" if no_log else str(data.get("msg", ""))[:MESSAGE]
        event.update(extra)
        self._emit("result", **event)

    def v2_playbook_on_start(self, playbook):
        self._emit("start", check_mode=self._check_mode())

    def v2_playbook_on_play_start(self, play):
        self._emit("play", name=str(play.get_name())[:256])

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._emit("task", name=(task.get_name() if task else "")[:256])

    def v2_playbook_on_handler_task_start(self, task):
        self._emit("task", name=(task.get_name() if task else "")[:256], handler=True)

    def v2_playbook_on_no_hosts_matched(self):
        self._emit("no_hosts_matched")

    def v2_runner_on_ok(self, result):
        self._result("ok", result)

    def v2_runner_on_skipped(self, result):
        self._result("skipped", result)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._result("failed", result, ignored=bool(ignore_errors))

    def v2_runner_on_unreachable(self, result):
        self._result("unreachable", result)

    def v2_playbook_on_stats(self, stats):
        hosts = {}
        for host in sorted(stats.processed.keys()):
            summary = stats.summarize(host)
            hosts[host] = {key: int(summary.get(key, 0)) for key in
                           ("ok", "changed", "unreachable", "failures", "skipped", "rescued", "ignored")}
        self._emit("stats", hosts=hosts)
        self._emit("end")
