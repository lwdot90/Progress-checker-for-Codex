#!/usr/bin/env python3
"""Create an isolated fixture and demonstrate human-approved local verification."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

PROJECT = Path(__file__).resolve().parent.parent
BINARY = PROJECT / ".local/checker-target/debug/progress-checker"


def main() -> int:
    if not BINARY.is_file():
        print("Run scripts/build-checker.sh first.", file=sys.stderr)
        return 1
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("This demo requires your interactive terminal for command approval.", file=sys.stderr)
        return 1
    if not Path("/usr/bin/python3").is_file() or not shutil.which("git"):
        print("This demo requires /usr/bin/python3 and Git.", file=sys.stderr)
        return 1
    base = PROJECT / ".local/checker-demo"
    base.mkdir(parents=True, exist_ok=True)
    session = Path(tempfile.mkdtemp(prefix="session-", dir=base))
    fixture = session / "project"
    state = session / "s"
    fixture.mkdir()
    state.mkdir(mode=0o700)
    (fixture / ".progress-checker").mkdir()
    (fixture / "check.py").write_text(
        'from pathlib import Path\n'
        'assert Path("feature.txt").read_text() == "demo implemented\\n"\n'
        'print("Feature fixture and content checks passed")\n',
        encoding="utf-8",
    )
    (fixture / "feature.txt").write_text("demo implemented\n", encoding="utf-8")
    config = {
        "schema_version": 1, "project_id": "phase1-human-demo", "enabled": True,
        "panel": {"show_on_start": True},
        "execution": {"max_parallel": 1, "default_timeout_seconds": 10},
        "fingerprint": {"extra_inputs": [], "exclude_outputs": []},
        "checks": [{"id": "demo-check", "argv": ["/usr/bin/python3", "check.py"],
                    "cwd": ".", "kind": "test", "timeout_seconds": 10}],
        "milestones": [
            {"id": "fixture", "title": "Fixture exists", "in_scope": True, "depends_on": [],
             "criteria": [{"id": "exists", "description": "Read the feature fixture", "check_id": "demo-check", "required": True}]},
            {"id": "content", "title": "Fixture has expected content", "in_scope": True, "depends_on": ["fixture"],
             "criteria": [{"id": "matches", "description": "Assert exact fixture contents", "check_id": "demo-check", "required": True}]},
        ],
    }
    (fixture / ".progress-checker/config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    git_environment = os.environ.copy()
    git_environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
    for arguments in (["init", "--quiet"], ["add", "."],
                      ["-c", "user.name=Checker demo", "-c", "user.email=checker-demo@localhost",
                       "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "Isolated demo fixture"]):
        subprocess.run(["git", "-C", str(fixture), *arguments], env=git_environment, check=True)
    command = [str(BINARY), "--root", str(fixture), "--state-dir", str(state)]

    def result(*arguments: str) -> dict:
        return json.loads(subprocess.check_output([*command, *arguments], text=True))

    print(f"Isolated demo project: {fixture}", flush=True)
    print("Review the approval below. It runs /usr/bin/python3 check.py only in this fixture.", flush=True)
    subprocess.run([*command, "approve", "demo-check"], check=True)
    # Approval requires the writer lock before the service starts. Every later
    # operation attaches to this one service instead of opening another Engine.
    socket_path = state / f"ipc-{hashlib.sha256(os.fsencode(fixture.resolve())).hexdigest()[:24]}.sock"
    service_log_path = session / "service.log"
    service = None
    keep_service = False
    try:
        with service_log_path.open("w") as service_log:
            service = subprocess.Popen(
                [*command, "serve"], stdin=subprocess.DEVNULL,
                stdout=service_log, stderr=service_log, start_new_session=True,
            )
        (session / "service.pid").write_text(f"{service.pid}\n", encoding="utf-8")
        deadline = time.monotonic() + 15
        while not socket_path.exists():
            if service.poll() is not None or time.monotonic() >= deadline:
                raise ValueError(f"Service did not become ready; inspect {service_log_path}")
            time.sleep(0.05)
        status = result("status")
        for milestone in ("fixture", "content"):
            status = result("claim", milestone, "implemented", "--expected-revision", str(status["revision"]))
        print("Two milestones are claimed implemented. Neither is verified yet.", flush=True)
        status = result("run", "demo-check")
        print(json.dumps(status, indent=2))
        if status["progress"]["verified"] != 2:
            print("Demo did not verify both milestones. Review the result and blockers above.", file=sys.stderr)
            return 1
        print("Both fixture milestones are verified. Edit feature.txt, then run status to see stale evidence:")
        import shlex
        print(shlex.join([*command, "status"]))
        print(f"Shared service remains running as PID {service.pid}; stop it when finished:")
        print(f"kill -TERM {service.pid}")
        print(f"PID record: {session / 'service.pid'}; log: {service_log_path}")
        print(f"Demo files and evidence retained at {session}")
        keep_service = True
    finally:
        if service is not None and not keep_service and service.poll() is None:
            service.terminate()
            try:
                service.wait(timeout=10)
            except subprocess.TimeoutExpired:
                service.kill()
                service.wait()

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (subprocess.CalledProcessError, OSError, ValueError) as error:
        print(f"Demo stopped: {error}", file=sys.stderr)
        raise SystemExit(1)
