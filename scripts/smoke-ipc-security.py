#!/usr/bin/env python3
"""Exercise real Phase 2 service boundaries in an isolated, unapproved fixture."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
MAX_FRAME = 256 * 1024


def exact(stream, length):
    result = bytearray()
    while len(result) < length:
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise EOFError("closed bounded stream")
        result.extend(chunk)
    return bytes(result)


def receive(stream):
    length = struct.unpack("!I", exact(stream, 4))[0]
    assert 0 < length <= MAX_FRAME
    return json.loads(exact(stream, length))


def connect(path):
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(4)
    stream.connect(str(path))
    return stream


def rpc(path, operation, request_id="security-test"):
    request = {"schema_version": 1, "request_id": request_id, "operation": operation}
    payload = json.dumps(request).encode()
    with connect(path) as stream:
        stream.sendall(struct.pack("!I", len(payload)) + payload)
        result = receive(stream)
    assert result["schema_version"] == 1 and result["request_id"] == request_id
    assert bool("result" in result) != bool("error" in result)
    return result


def wait_socket(process, path):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"service exited {process.returncode}")
        try:
            return rpc(path, {"operation": "progress"})
        except (OSError, EOFError):
            time.sleep(.05)
    raise AssertionError("service startup timed out")


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise AssertionError("service failed graceful shutdown")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / ".local/checker-target/debug/progress-checker")
    parser.add_argument("--artifacts", type=Path, default=ROOT / ".local/ipc-security")
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    session = Path(tempfile.mkdtemp(prefix="run-", dir=args.artifacts)).resolve()
    project = session / "project"
    state = session / "state"
    project.mkdir()
    state.mkdir(mode=0o700)
    (project / ".progress-checker").mkdir()
    marker = project / "executed"
    config = {"schema_version": 1, "project_id": "ipc-security", "enabled": True,
              "panel": {"show_on_start": True}, "execution": {"max_parallel": 1, "default_timeout_seconds": 5},
              "fingerprint": {"extra_inputs": [], "exclude_outputs": []},
              "checks": [{"id": "trap", "argv": ["/usr/bin/touch", "executed"], "cwd": ".", "kind": "test", "timeout_seconds": 5}],
              "milestones": [{"id": "fixture", "title": "Fixture", "in_scope": True, "depends_on": [],
                              "criteria": [{"id": "exists", "description": "Trap must remain unapproved", "check_id": "trap", "required": True}]}]}
    (project / ".progress-checker/config.json").write_text(json.dumps(config))
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    for git_args in (["init", "-q"], ["add", "."], ["-c", "user.name=IPC fixture", "-c", "user.email=ipc@localhost", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture"]):
        subprocess.run(["git", "-C", str(project), *git_args], env=env, check=True)
    path = state / ("ipc-" + hashlib.sha256(os.fsencode(project)).hexdigest()[:24] + ".sock")
    command = [str(args.binary.resolve()), "--root", str(project), "--state-dir", str(state), "serve"]
    report = {"status": "failed", "assertions": [], "session": str(session),
              "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest()}
    process = None
    log = (session / "service.log").open("wb")
    try:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        before = wait_socket(process, path)
        assert before["result"]["canonical_root"] == str(project)
        assert path.stat().st_mode & 0o077 == 0
        with connect(path) as stream:
            pid, uid, gid = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            assert uid == os.geteuid() and pid == process.pid
        report["assertions"].append("private socket and actual same-user peer credentials")
        duplicate = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        assert duplicate.returncode != 0
        assert rpc(path, {"operation": "progress"})["service_instance_id"] == before["service_instance_id"]
        report["assertions"].append("duplicate service cannot displace sole writer")
        for payload in (b"{", b'{"schema_version":99,"request_id":"bad","operation":{"operation":"progress"}}', b'{"schema_version":1,"request_id":"bad","operation":{"operation":"progress","argv":["sh"]}}', b'{"schema_version":1,"request_id":"bad","operation":{"operation":"progress","root":"/"}}'):
            with connect(path) as stream:
                stream.sendall(struct.pack("!I", len(payload)) + payload)
                try:
                    reply = receive(stream)
                    assert "error" in reply
                except (EOFError, ConnectionResetError):
                    pass
        for length in (0, MAX_FRAME + 1, 0xffffffff):
            with connect(path) as stream:
                stream.sendall(struct.pack("!I", length))
                try:
                    reply = receive(stream)
                    assert "error" in reply
                except (EOFError, ConnectionResetError):
                    pass
        assert rpc(path, {"operation": "progress"})["revision"] == before["revision"]
        report["assertions"].append("malformed unknown and oversized frames fail without state mutation")
        update = rpc(path, {"operation": "set_claim", "milestone_id": "fixture", "claim": "implemented", "note": "IPC fixture", "expected_revision": before["revision"]})
        assert "error" not in update and update["revision"] > before["revision"]
        stale = rpc(path, {"operation": "set_claim", "milestone_id": "fixture", "claim": "planned", "note": "stale", "expected_revision": before["revision"]})
        assert "error" in stale
        assert rpc(path, {"operation": "progress"})["revision"] == update["revision"]
        report["assertions"].append("conflicting optimistic mutations leave accepted claim intact")
        subscribe = rpc(path, {"operation": "subscribe", "after_revision": 0})
        assert "error" not in subscribe and subscribe["revision"] == update["revision"]
        project_info = rpc(path, {"operation": "project"})
        # Config hash is public service metadata; command remains defined only locally.
        def find_hash(value):
            if isinstance(value, dict):
                if "config_hash" in value:
                    return value["config_hash"]
                for item in value.values():
                    found = find_hash(item)
                    if found:
                        return found
            return None
        config_hash = find_hash(project_info.get("result")) or find_hash(subscribe.get("result"))
        assert config_hash, "service project/snapshot omits config identity"
        denied = rpc(path, {"operation": "run_checks", "check_ids": ["trap"], "idempotency_key": "denied", "expected_config_hash": config_hash, "expected_revision": update["revision"]})
        assert "error" in denied and not marker.exists()
        report["assertions"].append("unapproved command denied without spawning trap")
        stop(process)
        assert not path.exists(), "owned socket survives graceful shutdown"
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        restarted = wait_socket(process, path)
        assert restarted["service_instance_id"] != before["service_instance_id"]
        assert restarted["revision"] >= update["revision"]
        assert not marker.exists()
        report["assertions"].append("reconnect receives new instance and durable revision without reexecution")
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        if process is not None:
            try:
                stop(process)
            except Exception as error:
                report["shutdown_error"] = str(error)
        log.close()
        (session / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(session / "report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
