"""Supervise the desk listeners and monitor as one container service."""
import signal
import subprocess
import sys
from threading import Event
import time


# The desks need up to 30 seconds to cancel and record active Ansible runs.
SHUTDOWN_SECONDS = 40


def serve_stack(args):
    stop = Event()
    previous = {sig: signal.signal(sig, lambda *_: stop.set()) for sig in (signal.SIGINT, signal.SIGTERM)}
    command = [sys.executable, "-m", "switchyard.cli", "--catalog", args.catalog]
    for flag, value in (("--state-dir", args.state_dir), ("--collectors", args.collectors),
                        ("--operations", args.operations)):
        if value is not None:
            command.extend((flag, value))
    jobs = {"loopback desk": ["web", "--port", str(args.port)]}
    if args.lan_host:
        lan = ["web", "--lan", "--host", args.lan_host, "--port", str(args.lan_port)]
        if args.allowed_clients:
            lan.extend(("--allowed-clients", args.allowed_clients))
        for name in args.name:
            lan.extend(("--name", name))
        jobs["HTTPS desk"] = lan
    if args.collectors:
        jobs["monitor"] = ["monitor"]
    children = {}
    try:
        for name, options in jobs.items():
            if stop.is_set():
                break
            children[name] = subprocess.Popen([*command, *options], stdin=subprocess.DEVNULL)
        while not stop.wait(0.25):
            for name, process in children.items():
                if (code := process.poll()) is not None:
                    print(f"switchyard: {name} exited ({code}); stopping container service", file=sys.stderr)
                    return 1
        return 0
    finally:
        deadline = time.monotonic() + SHUTDOWN_SECONDS
        for process in children.values():
            if process.poll() is None:
                process.terminate()
        for process in children.values():
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
