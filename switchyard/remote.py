"""Strict, bounded SSH for operations whose caller already owns every device lease."""
import json
import os
import selectors
import signal
import subprocess
import sys
import time

from .collector import _json, _ssh_command
from . import host_context

MAX_OUTPUT = 262144
MAX_ERRORS = 16384
MAX_INPUT = 2097152


class RemoteError(RuntimeError):
    """Transport loss cannot establish whether a remote mutation happened."""
    uncertain = True


def run_bounded(command, source, *, timeout, cleanup_seconds=1.0):
    """Reap the owned local process group; never retry or retain unbounded output."""
    if len(source) > MAX_INPUT:
        raise ValueError("Operation input exceeds transport limit")
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
    output, errors = bytearray(), bytearray()
    sent = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for stream, events in ((child.stdin, selectors.EVENT_WRITE),
                                   (child.stdout, selectors.EVENT_READ), (child.stderr, selectors.EVENT_READ)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, events)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RemoteError("Operation transport deadline exceeded; effects need inspection")
                for key, event in selector.select(min(remaining, 0.1)):
                    if event == selectors.EVENT_WRITE:
                        try:
                            sent += os.write(key.fd, source[sent:sent + 8192])
                        except BrokenPipeError:
                            sent = len(source)
                        if sent == len(source):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        part = os.read(key.fd, 8192)
                        if not part:
                            selector.unregister(key.fileobj)
                        else:
                            buffer = output if key.fileobj is child.stdout else errors
                            buffer.extend(part)
                            if len(buffer) > (MAX_OUTPUT if buffer is output else MAX_ERRORS):
                                raise RemoteError("Operation transport output limit exceeded; effects need inspection")
            try:
                status = child.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                raise RemoteError("Operation transport deadline exceeded; effects need inspection") from error
        return status, bytes(output)
    finally:
        # Even a process that exited can have live descendants holding its pipes.
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=cleanup_seconds)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


def run_remote(host: dict, source: str, payload: dict, *, timeout: int = 60, local: bool = False) -> dict:
    """Run fixed source on a host; `local` executes it in a local child for a collector-local host."""
    if host.get("transport") != "ssh" or type(timeout) is not int or not 1 <= timeout <= 270:
        raise ValueError("Operations require configured SSH and a bounded deadline")
    if not isinstance(source, str) or not isinstance(payload, dict):
        raise ValueError("Invalid fixed operation source or payload")
    # No script, pathname, host or payload is interpolated into the SSH command.
    # Python verifies identity before evaluating any action source.
    preamble = ("import json,os,platform,pwd,sys\n"
                "if platform.node() != " + repr(host["expected_hostname"]) + ":\n"
                "    sys.exit(78)\n"
                "if os.getuid() == 0 or pwd.getpwuid(os.getuid()).pw_name != "
                + repr(host["target"].split("@", 1)[0]) + ":\n    sys.exit(78)\n"
                "PAYLOAD = json.loads(" + repr(json.dumps(payload, allow_nan=False)) + ")\n"
                "exec(compile(" + repr(source) + ", '<switchyard-action>', 'exec'))\n")
    try:
        if local:
            with host_context.execution(preamble.encode(), timeout=timeout) as (command, data):
                status, output = run_bounded(command, data, timeout=timeout)
        else:
            status, output = run_bounded(_ssh_command(host), preamble.encode(), timeout=timeout)
        if status != 0:
            raise RemoteError("SSH operation failed; remote effects need inspection")
        value = _json(output)
        if not isinstance(value, dict):
            raise ValueError("Expected object")
        return value
    except RemoteError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError, subprocess.SubprocessError) as error:
        raise RemoteError("Invalid or unavailable SSH operation response; effects need inspection") from error


SHELL_SOURCE = r'''
import json, os, selectors, signal, subprocess, time
child = None
out, err = bytearray(), bytearray()
status = 'needs-inspection'
reason = None
code = None
try:
    child = subprocess.Popen(['/bin/sh', '-c', PAYLOAD['script']], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    deadline = time.monotonic() + PAYLOAD['timeout_seconds']
    with selectors.DefaultSelector() as selector:
        for stream in (child.stdout, child.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = 'Shell deadline exceeded; detached or remote work may still exist'
                break
            for key, _ in selector.select(min(0.1, remaining)):
                part = os.read(key.fd, 4096)
                if not part:
                    selector.unregister(key.fileobj)
                else:
                    buffer = out if key.fileobj is child.stdout else err
                    available = max(0, 16384 - len(buffer))
                    buffer.extend(part[:available])
                    if len(part) > available:
                        reason = 'Shell output limit exceeded; effects need inspection'
                        break
            if reason:
                break
        if not reason:
            try:
                code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
                status = 'succeeded' if code == 0 else 'failed'
            except subprocess.TimeoutExpired:
                reason = 'Shell deadline exceeded; effects need inspection'
except Exception:
    reason = 'Shell execution interrupted; effects need inspection'
finally:
    if child is not None:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=0.3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.stdout.close()
        child.stderr.close()
print(json.dumps({'status': status, 'exit_code': code, 'error': reason,
                  'stdout': out.decode('utf-8', 'replace'), 'stderr': err.decode('utf-8', 'replace')}))
'''
