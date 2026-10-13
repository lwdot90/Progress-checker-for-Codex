#!/usr/bin/env python3
"""Open the real embedded panel in this terminal, without paid authentication."""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        type=Path,
        default=root / ".local/source/codex/codex-rs/target/debug/codex",
        help="Already built modified Codex executable",
    )
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error(f"No executable at {binary}; build the prototype first")
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error("Run this command from an interactive terminal")

    spec = importlib.util.spec_from_file_location("panel_smoke", root / "scripts/smoke-prototype.py")
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = root / ".local/demo" / f"{stamp}-{os.getpid()}"
    project, marker = smoke.make_project(run / "project", "opted-in", root)
    home = run / "codex-home"
    provider = smoke.Provider()
    smoke.write_config(home, project, provider.server_port)
    environment = smoke.local_environment(home, os.environ.get("TERM", "xterm-256color"))
    thread = threading.Thread(target=provider.serve_forever, daemon=True)
    thread.start()
    print(f"Phase 0 panel demo: {run}")
    print("The three sample claims are unvalidated. Use /progress to hide/show and /quit to exit.")
    print("Resize this terminal to review the compact panel. Model requests are disabled; no project checks run.")
    print("This demo uses fresh local settings and does not copy your login.\n", flush=True)
    report = {
        "binary": str(binary),
        "project": str(project),
        "codex_home": str(home),
        "model_requests_enabled": False,
        "status": "failed",
    }
    previous_interrupt = signal.signal(signal.SIGINT, lambda _signum, _frame: None)
    try:
        process = subprocess.run(
            [str(binary), "--no-daemon", "--no-alt-screen", "--ask-for-approval", "on-request", "--sandbox", "read-only"],
            cwd=project,
            env=environment,
            check=False,
        )
        report["exit_code"] = process.returncode
        report["configured_checks_executed"] = marker.exists()
        report["status"] = "exited" if process.returncode == 0 and not marker.exists() else "failed"
    finally:
        signal.signal(signal.SIGINT, previous_interrupt)
        provider.shutdown()
        thread.join(timeout=2)
        provider.server_close()
        report["provider_requests"] = provider.requests
        report["blocked_model_requests"] = sum(request["method"] == "POST" for request in provider.requests)
        path = run / "report.json"
        path.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Demo report: {path}", flush=True)
    return 0 if report["status"] == "exited" else 1


if __name__ == "__main__":
    sys.exit(main())
