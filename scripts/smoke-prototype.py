#!/usr/bin/env python3
"""Drive the real Phase 0 Codex TUI without credentials or an agent prompt.

Uses only Python's standard library on Linux. All generated fixtures, Codex homes,
PTY transcripts, screen captures, and a JSON report stay under --artifacts.
The local mock provider rejects inference requests; configured checks are traps
that must remain unexecuted. This script never builds Codex or installs anything.
"""

from __future__ import annotations

import argparse
import codecs
import datetime
import errno
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import threading
import time
import unicodedata


class Screen:
    """Small VT screen sufficient for crossterm's cursor/erase drawing commands."""

    def __init__(self, width: int, height: int):
        self.width, self.height = width, height
        self.cells = [[" "] * width for _ in range(height)]
        self.row = self.col = 0
        self.saved = (0, 0)
        self.scroll_top, self.scroll_bottom = 0, height - 1
        self.mode, self.sequence = "text", ""
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")

    def resize(self, width: int, height: int):
        old = self.cells
        self.width, self.height = width, height
        self.cells = [
            (old[row][:width] + [" "] * width)[:width]
            if row < len(old)
            else [" "] * width
            for row in range(height)
        ]
        self.row, self.col = min(self.row, height - 1), min(self.col, width - 1)
        self.scroll_top, self.scroll_bottom = 0, height - 1

    def text(self) -> str:
        return "\n".join("".join(row).rstrip() for row in self.cells).rstrip() + "\n"

    def linefeed(self):
        if self.row == self.scroll_bottom:
            self.cells.pop(self.scroll_top)
            self.cells.insert(self.scroll_bottom, [" "] * self.width)
        else:
            self.row += 1

    def feed(self, data: bytes) -> bytes:
        replies = bytearray()
        for char in self.decoder.decode(data):
            if self.mode == "osc":
                if char == "\a":
                    replies.extend(self.finish_osc())
                elif char == "\x1b":
                    self.mode = "osc-escape"
                else:
                    self.sequence += char
                continue
            if self.mode == "osc-escape":
                if char == "\\":
                    replies.extend(self.finish_osc())
                else:
                    self.sequence += char
                    self.mode = "osc"
                continue
            if self.mode == "csi":
                if "@" <= char <= "~":
                    replies.extend(self.csi(char))
                    self.mode, self.sequence = "text", ""
                else:
                    self.sequence += char
                continue
            if self.mode == "charset":
                self.mode = "text"
                continue
            if self.mode == "escape":
                self.mode = "text"
                if char == "[":
                    self.mode, self.sequence = "csi", ""
                elif char == "]":
                    self.mode, self.sequence = "osc", ""
                elif char in "()*+":
                    self.mode = "charset"
                elif char == "7":
                    self.saved = (self.row, self.col)
                elif char == "8":
                    self.row, self.col = self.saved
                elif char in "DE":
                    self.linefeed()
                    if char == "E":
                        self.col = 0
                elif char == "M":
                    if self.row == self.scroll_top:
                        self.cells.pop(self.scroll_bottom)
                        self.cells.insert(self.scroll_top, [" "] * self.width)
                    else:
                        self.row = max(0, self.row - 1)
                continue
            if char == "\x1b":
                self.mode = "escape"
            elif char == "\r":
                self.col = 0
            elif char == "\n":
                self.linefeed()
            elif char == "\b":
                self.col = max(0, self.col - 1)
            elif char == "\t":
                self.col = min(self.width - 1, (self.col // 8 + 1) * 8)
            elif ord(char) >= 32 and char != "\x7f":
                if unicodedata.combining(char):
                    if self.col:
                        self.cells[self.row][self.col - 1] += char
                    continue
                columns = 2 if unicodedata.east_asian_width(char) in "WF" else 1
                if self.col >= self.width:
                    self.col = 0
                    self.linefeed()
                self.cells[self.row][self.col] = char
                if columns == 2 and self.col + 1 < self.width:
                    self.cells[self.row][self.col + 1] = ""
                self.col += columns
        return bytes(replies)

    def finish_osc(self) -> bytes:
        sequence = self.sequence
        self.mode, self.sequence = "text", ""
        if sequence in ("10;?", "11;?"):
            color = "ffff/ffff/ffff" if sequence.startswith("10") else "0000/0000/0000"
            return f"\x1b]{sequence[:2]};rgb:{color}\x1b\\".encode()
        return b""

    def csi(self, command: str) -> bytes:
        if self.sequence.startswith("?"):
            return b""
        try:
            values = [int(value) if value else 0 for value in self.sequence.split(";")]
        except ValueError:
            return b""
        first = values[0] or 1
        if command in "Hf":
            self.row = min(self.height - 1, first - 1)
            self.col = min(self.width - 1, (values[1] or 1) - 1) if len(values) > 1 else 0
        elif command == "A":
            self.row = max(0, self.row - first)
        elif command == "B":
            self.row = min(self.height - 1, self.row + first)
        elif command == "C":
            self.col = min(self.width - 1, self.col + first)
        elif command == "D":
            self.col = max(0, self.col - first)
        elif command in "EF":
            self.row = max(0, min(self.height - 1, self.row + (first if command == "E" else -first)))
            self.col = 0
        elif command == "G":
            self.col = min(self.width - 1, first - 1)
        elif command == "d":
            self.row = min(self.height - 1, first - 1)
        elif command == "J":
            if values[0] in (2, 3):
                self.cells = [[" "] * self.width for _ in range(self.height)]
            elif values[0] == 0:
                self.cells[self.row][self.col:] = [" "] * (self.width - self.col)
                for row in range(self.row + 1, self.height):
                    self.cells[row] = [" "] * self.width
            elif values[0] == 1:
                for row in range(self.row):
                    self.cells[row] = [" "] * self.width
                self.cells[self.row][:self.col + 1] = [" "] * (self.col + 1)
        elif command == "K":
            start, end = (0, self.width) if values[0] == 2 else ((0, self.col + 1) if values[0] == 1 else (self.col, self.width))
            self.cells[self.row][start:end] = [" "] * (end - start)
        elif command == "X":
            end = min(self.width, self.col + first)
            self.cells[self.row][self.col:end] = [" "] * (end - self.col)
        elif command == "P":
            row = self.cells[self.row]
            self.cells[self.row] = (row[:self.col] + row[self.col + first:] + [" "] * first)[:self.width]
        elif command == "@":
            row = self.cells[self.row]
            self.cells[self.row] = (row[:self.col] + [" "] * first + row[self.col:])[:self.width]
        elif command == "s":
            self.saved = (self.row, self.col)
        elif command == "u":
            self.row, self.col = self.saved
        elif command == "n" and values[0] == 6:
            return f"\x1b[{self.row + 1};{min(self.col, self.width - 1) + 1}R".encode()
        elif command == "r":
            self.scroll_top = min(self.height - 1, first - 1)
            self.scroll_bottom = min(self.height - 1, values[1] - 1) if len(values) > 1 and values[1] else self.height - 1
            self.row = self.col = 0
        elif command == "c":
            return b"\x1b[?1;2c"
        return b""


class Provider(http.server.HTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), ProviderHandler)
        self.requests: list[dict] = []


class ProviderHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.requests.append({"method": "GET", "path": self.path})
        self.reply(200, {"data": []})

    def do_POST(self):
        self.server.requests.append({"method": "POST", "path": self.path})
        self.reply(500, {"error": "Model requests are disabled in the local panel demo"})

    def reply(self, status: int, value: dict):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Session:
    def __init__(self, binary: Path, project: Path, home: Path, artifacts: Path, timeout: float, config_overrides: tuple[str, ...] = ()):
        self.artifacts, self.timeout = artifacts, timeout
        artifacts.mkdir(parents=True)
        self.provider = Provider()
        write_config(home, project, self.provider.server_port)
        env = local_environment(home)
        self.screen = Screen(110, 32)
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(project)
            arguments = [str(binary), "--no-daemon", "--no-alt-screen", "--ask-for-approval", "on-request", "--sandbox", "read-only"]
            for override in config_overrides:
                arguments.extend(("-c", override))
            os.execve(binary, arguments, env)
        self.set_size(110, 32)
        self.thread = threading.Thread(target=self.provider.serve_forever, daemon=True)
        self.thread.start()
        self.raw = (artifacts / "terminal.ansi").open("wb")
        self.started, self.exited, self.status = time.monotonic(), False, None

    def set_size(self, width: int, height: int):
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
        self.screen.resize(width, height)
        os.kill(self.pid, signal.SIGWINCH)

    def pump(self, duration: float = 0.1):
        ready, _, _ = select.select([self.fd], [], [], duration)
        if ready:
            try:
                data = os.read(self.fd, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                data = b""
            if data:
                self.raw.write(data)
                self.raw.flush()
                reply = self.screen.feed(data)
                if reply:
                    os.write(self.fd, reply)
        if not self.exited:
            waited, status = os.waitpid(self.pid, os.WNOHANG)
            if waited:
                self.exited, self.status = True, os.waitstatus_to_exitcode(status)

    def until(self, predicate, description: str, timeout: float | None = None):
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while time.monotonic() < deadline:
            self.pump()
            if predicate(self.screen.text()):
                return
            if self.exited:
                raise AssertionError(f"Codex exited {self.status} before {description}")
        raise AssertionError(f"Timed out waiting for {description}")

    def settle(self, duration: float = 0.4):
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            self.pump(0.05)

    def command(self, command: str, typing_delay: float = 0.15):
        assert command in ("/progress", "/quit"), "Only local slash commands are permitted"
        # A failed slash command can leave a draft on either side of the cursor.
        os.write(self.fd, b"\x15\x0b")
        os.write(self.fd, command.encode())
        self.settle(typing_delay)
        os.write(self.fd, b"\r")

    def capture(self, name: str) -> str:
        self.settle()
        value = self.screen.text()
        (self.artifacts / f"{name}.txt").write_text(value)
        return value

    def close(self):
        if not self.exited:
            self.command("/quit")
            self.settle(2)
        if not self.exited:
            os.write(self.fd, b"\x03")
            self.settle(0.25)
            os.write(self.fd, b"\x03")
            self.settle(1)
        if not self.exited:
            os.kill(self.pid, signal.SIGTERM)
            os.waitpid(self.pid, 0)
            self.exited = True
        self.raw.close()
        os.close(self.fd)
        self.provider.shutdown()
        self.thread.join(timeout=2)
        self.provider.server_close()
        (self.artifacts / "provider-requests.json").write_text(json.dumps(self.provider.requests, indent=2) + "\n")
        assert not any(request["method"] == "POST" for request in self.provider.requests), "Unexpected inference request"


def write_config(home: Path, project: Path, port: int):
    home.mkdir(parents=True, exist_ok=True)
    config = f'''model = "gpt-6.1-sol"
model_provider = "panel-smoke"
check_for_update_on_startup = false
cli_auth_credentials_store = "file"

[model_providers.panel-smoke]
name = "Panel smoke (local mock)"
base_url = "http://127.0.0.1:{port}/v1"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
request_max_retries = 0

[analytics]
enabled = false

[tui]
notifications = false
show_tooltips = false
screen_reader_detection_done = true

[projects.{json.dumps(str(project))}]
trust_level = "trusted"
'''
    (home / "config.toml").write_text(config)


def local_environment(home: Path, terminal_name: str = "xterm-256color") -> dict[str, str]:
    """Keep demo credentials, settings, and caches inside the fresh local home."""
    env = os.environ.copy()
    for key in ("OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID"):
        env.pop(key, None)
    env.update({"CODEX_HOME": str(home), "TERM": terminal_name, "COLORTERM": "truecolor", "OTEL_SDK_DISABLED": "true"})
    for key, directory in (("XDG_CONFIG_HOME", "xdg-config"), ("XDG_CACHE_HOME", "xdg-cache"), ("XDG_DATA_HOME", "xdg-data"), ("TMPDIR", "tmp")):
        path = home / directory
        path.mkdir(exist_ok=True)
        env[key] = str(path)
    return env


def make_project(directory: Path, kind: str, project_root: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True)
    subprocess.run(["git", "-c", "init.defaultBranch=smoke", "init", "--quiet", str(directory)], check=True)
    marker = directory / "configured-check-was-executed"
    if kind != "no-config":
        fixture = directory / ".progress-checker"
        fixture.mkdir()
        if kind == "invalid-config":
            (fixture / "config.json").write_text("{invalid JSON\n")
        else:
            original = project_root / "examples/prototype/.progress-checker"
            config = json.loads((original / "config.json").read_text())
            if kind == "disabled":
                config["enabled"] = False
            trap = directory / "configured-check-trap.py"
            trap.write_text("from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text('executed')\n")
            for check in config["checks"]:
                check["argv"] = [sys.executable, str(trap), str(marker)]
            (fixture / "config.json").write_text(json.dumps(config, indent=2) + "\n")
            (fixture / "state.json").write_bytes((original / "state.json").read_bytes())
    return directory, marker


def has_panel(text: str) -> bool:
    return "freshness unknown" in text or ("unvalidated progress" in text and "I:" in text)


def composer_ready(text: str) -> bool:
    return "Ask Codex to do anything" in text and "GPT-6.1-Sol" in text and "loading" not in text


def preference(home: Path, project: Path) -> Path:
    config = (project / ".progress-checker/config.json").resolve()
    digest = hashlib.sha256(os.fsencode(config)).hexdigest()
    return home / "progress-checker/visibility" / f"{digest}.json"


def check_preference(session: Session, path: Path, visible: bool):
    def matches(_):
        try:
            return json.loads(path.read_text()) == {"schema_version": 1, "visible": visible}
        except (OSError, ValueError):
            return False
    session.until(matches, f"visibility preference visible={visible}", timeout=5)


def run_case(binary: Path, run: Path, root: Path, kind: str, timeout: float) -> dict:
    project, marker = make_project(run / kind / "project", kind, root)
    home = run / kind / "codex-home"
    session = Session(binary, project, home, run / kind / "first-launch", timeout)
    result = {"case": kind, "status": "failed"}
    try:
        session.until(composer_ready, "composer readiness")
        result["composer_ready_seconds"] = round(time.monotonic() - session.started, 3)
        if kind == "opted-in":
            session.until(lambda text: "2 implemented" in text and "1 planned" in text and "Unvalidated claims" in text and "freshness unknown" in text, "restored unvalidated claims")
            wide = session.capture("wide-panel")
            assert "Restore saved claims as unvalidated" in wide, "Milestone titles missing"
            draft = "unsent panel draft"
            os.write(session.fd, draft.encode())
            session.until(lambda text: draft in text, "unsent composer draft")
            session.capture("wide-draft")
            session.set_size(52, 24)
            session.until(lambda text: "unvalidated progress" in text and "I:2 P:1" in text and draft in text, "narrow panel with preserved draft")
            session.capture("narrow-panel")
            session.set_size(110, 32)
            session.until(lambda text: "Unvalidated claims" in text and draft in text, "wide panel with preserved draft after resize")
            session.capture("wide-draft-after-resize")
            result["unsent_draft_preserved_across_resize"] = True
            session.command("/progress")
            session.until(lambda text: "Progress panel hidden." in text and not has_panel(text), "panel hidden with composer usable")
            check_preference(session, preference(home, project), False)
            session.capture("hidden-panel")
        elif kind in ("no-config", "disabled"):
            assert not has_panel(session.capture("no-panel")), f"{kind} project has a panel"
            session.command("/progress")
            session.until(lambda text: "No opted-in .progress-checker/config.json" in text, f"{kind} slash-command feedback")
            session.capture("not-opted-in-feedback")
        else:
            session.until(lambda text: "Invalid panel JSON" in text, "configuration error inside live TUI")
            session.capture("invalid-config-error")
        assert not marker.exists(), "Startup executed a configured project check"
        result["configured_checks_executed"] = False
        result["status"] = "passed"
    finally:
        session.capture("final-screen")
        session.close()
    if kind == "opted-in":
        session = Session(binary, project, home, run / kind / "restored-launch", timeout)
        try:
            session.until(composer_ready, "restored composer")
            session.settle(0.5)
            assert not has_panel(session.capture("restored-hidden")), "Hidden visibility was not restored"
            session.command("/progress")
            session.until(lambda text: "Progress panel shown." in text and "Unvalidated claims" in text and "2 implemented" in text, "panel shown after relaunch")
            check_preference(session, preference(home, project), True)
            session.capture("shown-panel")
            assert not marker.exists(), "Relaunch executed a configured check"
            result["hide_show_and_visibility_restore"] = "passed"
        finally:
            session.capture("final-screen")
            session.close()
    return result


def rapid_exit_diagnostic(binary: Path, run: Path, root: Path, timeout: float) -> dict:
    """Report immediate-exit durability independently of ordinary UI acceptance."""
    project, marker = make_project(run / "rapid-exit" / "project", "opted-in", root)
    home = run / "rapid-exit" / "codex-home"
    path = preference(home, project)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"schema_version": 1, "visible": True}) + "\n")
    result = {
        "name": "rapid_toggle_exit_persistence",
        "status": "failed",
        "input_setting": "tui.disable_paste_burst=true",
    }
    # Upstream intentionally treats sub-120ms unbracketed input bursts as pasted
    # text, including Enter. This documented local setting makes rapid input
    # deterministic so the diagnostic measures shutdown durability.
    session = Session(binary, project, home, run / "rapid-exit" / "launch", timeout, config_overrides=("tui.disable_paste_burst=true",))
    try:
        session.until(lambda text: composer_ready(text) and "Unvalidated claims" in text, "shown panel before rapid exit")
        session.capture("before-rapid-exit")
        session.command("/progress")
        entered = time.monotonic()
        session.command("/quit", typing_delay=0)
        result["submit_interval_ms"] = round((time.monotonic() - entered) * 1000, 3)
        session.until(lambda _: session.exited, "rapid /quit exit")
        result["exit_code"] = session.status
        assert session.status == 0, f"Rapid /quit exited {session.status}"
        persisted = json.loads(path.read_text())
        result["persisted_visibility"] = persisted
        assert persisted == {"schema_version": 1, "visible": False}, "Rapid hide→quit lost the visibility preference write"
        assert not marker.exists(), "Rapid exit executed a configured project check"
        result["configured_checks_executed"] = False
        result["status"] = "passed"
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        session.capture("after-rapid-exit")
        try:
            session.close()
        except Exception as error:
            result["status"] = "failed"
            result["error"] = f"{type(error).__name__}: {error}"
    (run / "rapid-exit" / "diagnostic.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="Already built modified Codex executable")
    parser.add_argument("--case", choices=("all", "opted-in", "no-config", "disabled", "invalid-config", "rapid-exit"), default="all")
    parser.add_argument("--artifacts", type=Path, default=Path(".local/smoke"))
    parser.add_argument("--timeout", type=float, default=35)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error(f"No executable at {binary}; build the prototype first")
    root = Path(__file__).resolve().parent.parent
    artifacts = args.artifacts.resolve()
    if not artifacts.is_relative_to(root / ".local"):
        parser.error("--artifacts must stay inside this project's .local directory")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run = artifacts / f"{stamp}-{os.getpid()}"
    run.mkdir(parents=True)
    report = {"binary": str(binary), "artifacts": str(run), "agent_prompts_sent": 0, "cases": [], "diagnostics": [], "status": "failed"}
    try:
        if args.case == "all":
            kinds = ("opted-in", "no-config", "disabled", "invalid-config")
        elif args.case == "rapid-exit":
            kinds = ()
        else:
            kinds = (args.case,)
        for kind in kinds:
            report["cases"].append({"case": kind, "status": "failed"})
            result = run_case(binary, run, root, kind, args.timeout)
            report["cases"][-1] = result
            print(f"PASS {kind}", flush=True)
        report["status"] = "passed"
        if args.case in ("all", "rapid-exit"):
            result = rapid_exit_diagnostic(binary, run, root, args.timeout)
            report["diagnostics"].append(result)
            print(f"{result['status'].upper()} rapid_toggle_exit_persistence", flush=True)
            if result["status"] != "passed":
                report["status"] = "passed_cases_with_failed_diagnostic" if kinds else "failed"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
        print(report["error"], file=sys.stderr)
    finally:
        path = run / "report.json"
        path.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Report: {path}", flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
