#!/usr/bin/env python3
"""Exercise two real embedded-panel clients against one existing local service.

No builds, command approvals, or model prompts. Supply an isolated opted-in
project and its already-running service socket; generated TUI homes are private.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import signal
from pathlib import Path
import socket
import struct
import subprocess
import time
import sys

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("phase0_smoke", ROOT / "scripts/smoke-prototype.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def rpc(path: Path, operation: dict) -> dict:
    request = {"schema_version": 1, "request_id": "terminal-smoke", "operation": operation}
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(5)
        client.connect(str(path))
        payload = json.dumps(request).encode()
        client.sendall(struct.pack("!I", len(payload)) + payload)
        def exact(size: int) -> bytes:
            data = bytearray()
            while len(data) < size:
                chunk = client.recv(size - len(data))
                if not chunk:
                    raise AssertionError("Truncated service response")
                data.extend(chunk)
            return bytes(data)
        length = struct.unpack("!I", exact(4))[0]
        if not 0 < length <= 256 * 1024:
            raise AssertionError("Missing or oversized service response")
        response = json.loads(exact(length))
    assert response["schema_version"] == 1
    assert response["request_id"] == request["request_id"]
    if response.get("error"):
        raise AssertionError(response["error"])
    return response


def mcp_progress(binary: Path, project: Path, state: Path) -> dict:
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "terminal-smoke", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "checker_get_progress", "arguments": {}}},
    ]
    result = subprocess.run([str(binary), "--root", str(project), "--state-dir", str(state)],
        input="".join(json.dumps(message) + "\n" for message in messages), text=True,
        capture_output=True, timeout=10, check=True)
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    call = next(response for response in responses if response.get("id") == 2)
    assert not call.get("error") and not call["result"].get("isError"), call
    return call["result"]["structuredContent"]


def local_command(session, command: str):
    assert command.startswith(("/progress details", "/progress log"))
    os.write(session.fd, b"\x15\x0b" + command.encode())
    session.settle(0.2)
    os.write(session.fd, b"\r")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=ROOT / ".local/source/codex/codex-rs/target/debug/codex")
    parser.add_argument("--artifacts", type=Path, default=ROOT / ".local/phase2-terminal")
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--ready-text", default="verified")
    parser.add_argument("--claim-milestone", help="Isolated fixture milestone to claim implemented through IPC")
    parser.add_argument("--service-pid", type=int, help="Owned fixture service PID to terminate for disconnect coverage")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--mcp-binary", type=Path, default=ROOT / ".local/checker-target/debug/progress-checker-mcp")
    parser.add_argument("--details-milestone")
    parser.add_argument("--log-check")
    parser.add_argument("--responsive-check", help="Previously approved synthetic check to run while typing")
    parser.add_argument("--wait-mode", type=Path, help="Owned fixture mode file to change to wait")
    parser.add_argument("--stale-source", type=Path, help="Owned fixture input to append a change after live checks")
    args = parser.parse_args()
    run = args.artifacts / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}")
    run.mkdir(parents=True)
    report = {"status": "failed", "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(), "project": str(args.project.resolve()), "socket": str(args.socket.resolve()), "assertions": []}
    clients = []
    previous = os.environ.get("PROGRESS_CHECKER_SOCKET")
    os.environ["PROGRESS_CHECKER_SOCKET"] = str(args.socket.resolve())
    try:
        before = rpc(args.socket, {"operation": "progress"})
        report["service_snapshot"] = before
        if args.state_dir:
            mcp = mcp_progress(args.mcp_binary, args.project.resolve(), args.state_dir.resolve())
            assert mcp["service_instance_id"] == before["service_instance_id"]
            assert mcp["revision"] == before["revision"]
            assert mcp["result"]["status"]["progress"] == before["result"]["status"]["progress"]
            report["mcp_snapshot"] = mcp
            report["assertions"].append("MCP and IPC report identical instance, revision and progress")
        for index in range(2):
            session = smoke.Session(args.binary.resolve(), args.project.resolve(), run / f"home-{index}", run / f"client-{index}", args.timeout)
            clients.append(session)
            progress = before["result"]["status"]["progress"]
            counts = f"{progress['verified']}/{progress['scoped']} verified"
            session.until(lambda text: counts in text and f"revision {before['revision']}" in text and smoke.composer_ready(text), "live service panel with shared revision and counts")
            session.capture("live-wide")
        report["assertions"].append("two actual TUI clients render the service-backed panel")
        if args.claim_milestone:
            updated = rpc(args.socket, {"operation": "set_claim", "milestone_id": args.claim_milestone,
                "claim": "implemented", "note": "isolated terminal smoke", "expected_revision": before["revision"]})
            assert updated["revision"] > before["revision"]
            for session in clients:
                session.until(lambda text: f"revision {updated['revision']}" in text, "new shared revision")
                session.capture("updated-revision")
            report["updated_snapshot"] = updated
            report["assertions"].append("IPC claim update reaches both visible clients at the same revision")
        for session in clients:
            os.write(session.fd, b"Testing my phase2 draft")
            session.until(lambda text: "Testing my phase2 draft" in text, "unsent draft")
            session.set_size(52, 32)
            session.until(lambda text: "Testing my phase2 draft" in text, "narrow draft")
            session.capture("narrow-draft")
            session.set_size(110, 32)
            session.until(lambda text: "Testing my phase2 draft" in text, "wide draft")
            session.capture("wide-draft")
            session.command("/progress")
            session.until(lambda text: not any(line.strip().startswith(("Progress ·", "Checker current ·", "current V:")) for line in text.splitlines()), "hidden panel")
            session.capture("hidden")
            session.command("/progress")
            session.until(lambda text: args.ready_text.lower() in text.lower(), "reshown live panel")
            session.capture("reshown")
        report["assertions"].append("resize preserves drafts; hide/show restores live panel on both clients")
        if args.details_milestone or args.log_check:
            session = clients[0]
            for command, expected in ((f"/progress details {args.details_milestone}", "Checker revision"),
                    (f"/progress log {args.log_check}", "log line 000")):
                if "None" in command:
                    continue
                local_command(session, command)
                session.until(lambda text: expected in text, command)
                first_page = session.capture("details" if "details" in command else "log-first")
                os.write(session.fd, b"\x1b[6~")
                session.settle()
                next_page = session.capture("details-scroll" if "details" in command else "log-scroll")
                assert first_page != next_page, "Page Down did not scroll the fixture details/log pager"
                os.write(session.fd, b"q")
                session.until(smoke.composer_ready, "composer after pager")
            report["assertions"].append("read-only milestone details and check log pagers open, scroll and close")
        after = rpc(args.socket, {"operation": "progress"})
        assert before["service_instance_id"] == after["service_instance_id"]
        assert after["revision"] >= before["revision"]
        assert after["result"]["status"]["latest"] == before["result"]["status"]["latest"], "TUI startup or local read-only interactions unexpectedly executed a check"
        report["assertions"].append("TUI startup and local interactions never execute configured checks")
        report["assertions"].append("both clients use one service instance without starting a second writer")
        original_source = args.stale_source.read_bytes() if args.stale_source else None
        if args.stale_source:
            assert after["result"]["status"]["progress"]["verified"] > 0, "stale coverage needs current verified evidence"
            with args.stale_source.open("a") as output:
                output.write("terminal smoke changed source\n")
            for session in clients:
                session.until(lambda text: "stale" in text.lower() or "pending" in text.lower(), "stale input")
                text = session.capture("source-stale")
                assert "100%" not in text
            deadline = time.monotonic() + args.timeout
            while True:
                try:
                    stale = rpc(args.socket, {"operation": "progress"})
                    if stale["result"]["status"]["progress"]["verified"] == 0:
                        break
                except AssertionError:
                    pass
                assert time.monotonic() < deadline, "service never published stale progress"
                time.sleep(0.1)
            report["stale_snapshot"] = stale
            report["assertions"].append("source edit drops current verification on both clients and shared snapshot")
        if args.responsive_check:
            assert args.wait_mode, "responsive check requires fixture wait-mode file"
            args.wait_mode.write_text("wait\n")
            deadline = time.monotonic() + args.timeout
            while True:
                try:
                    ready = rpc(args.socket, {"operation": "progress"})
                    break
                except AssertionError:
                    assert time.monotonic() < deadline
                    time.sleep(0.1)
            accepted = rpc(args.socket, {"operation": "run_checks", "check_ids": [args.responsive_check],
                "idempotency_key": f"terminal-{os.getpid()}", "expected_config_hash": ready["result"]["status"]["source"]["config_hash"],
                "expected_revision": ready["revision"]})
            report["responsive_run"] = accepted
            for session in clients:
                session.until(lambda text: "running" in text.lower() or "queued" in text.lower(), "running synthetic check")
                started = time.monotonic()
                os.write(session.fd, b"\x15\x0bTyping while check runs")
                session.until(lambda text: "Typing while check runs" in text, "responsive composer", timeout=2)
                report.setdefault("input_latency_seconds", []).append(time.monotonic() - started)
                session.set_size(52, 32)
                session.until(lambda text: "Typing while check runs" in text, "responsive narrow composer", timeout=2)
                session.capture("running-draft-narrow")
                session.set_size(110, 32)
            current = rpc(args.socket, {"operation": "progress"})
            rpc(args.socket, {"operation": "cancel_run", "run_id": accepted["result"]["run_id"], "expected_revision": current["revision"]})
            report["assertions"].append("both composers remain responsive during an explicitly approved synthetic running check")
        if args.service_pid:
            if args.responsive_check and args.stale_source:
                args.stale_source.write_bytes(original_source)
                args.wait_mode.write_text("pass\n")
                deadline = time.monotonic() + args.timeout
                while True:
                    current = rpc(args.socket, {"operation": "progress"})
                    if not current["result"]["running"]:
                        break
                    assert time.monotonic() < deadline, "cancelled fixture check remained running"
                    time.sleep(0.1)
                restored_run = rpc(args.socket, {"operation": "run_checks", "check_ids": [args.responsive_check],
                    "idempotency_key": f"terminal-restore-{os.getpid()}",
                    "expected_config_hash": current["result"]["status"]["source"]["config_hash"],
                    "expected_revision": current["revision"]})
                report["restored_run"] = restored_run
                deadline = time.monotonic() + args.timeout
                while True:
                    restored = rpc(args.socket, {"operation": "progress"})
                    progress = restored["result"]["status"]["progress"]
                    if progress["verified"] == progress["scoped"] and progress["scoped"] > 0:
                        break
                    assert time.monotonic() < deadline, "restored fixture never regained current verification"
                    time.sleep(0.1)
                for session in clients:
                    session.until(lambda text: "2/2 verified" in text and "100%" in text, "restored green before disconnect")
                    session.capture("restored-green-before-disconnect")
                report["restored_snapshot"] = restored
                report["assertions"].append("explicit approved fixture rerun restores current green before disconnect")
            assert args.service_pid > 1 and args.service_pid != os.getpid()
            os.kill(args.service_pid, signal.SIGTERM)
            for session in clients:
                session.until(lambda text: "Checker unavailable" in text, "service disconnect")
                text = session.capture("unavailable")
                assert "/2 verified" not in text and "100%" not in text
            report["assertions"].append("service loss replaces verification with unavailable, never stale green")
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
    finally:
        for session in clients:
            try:
                if "q close" in session.screen.text():
                    os.write(session.fd, b"q")
                    session.settle()
                session.close()
            except Exception as error:
                report["status"] = "failed"
                report["cleanup_error"] = str(error)
        if previous is None:
            os.environ.pop("PROGRESS_CHECKER_SOCKET", None)
        else:
            os.environ["PROGRESS_CHECKER_SOCKET"] = previous
        report["provider_requests"] = [session.provider.requests for session in clients]
        if any(report["provider_requests"]):
            report["status"] = "failed"
            report["provider_error"] = "Unexpected provider request during local terminal smoke"
        report["binary_sha256_after"] = hashlib.sha256(args.binary.read_bytes()).hexdigest()
        if report["binary_sha256_after"] != report["binary_sha256"]:
            report["status"] = "failed"
            report["binary_error"] = "Binary changed during terminal smoke"
        (run / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"status": report["status"], "report": str(run / "report.json")}, indent=2))
    return 0 if report["status"] == "passed" else 1

if __name__ == "__main__":
    sys.exit(main())
