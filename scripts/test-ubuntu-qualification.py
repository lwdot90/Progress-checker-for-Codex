#!/usr/bin/env python3
"""Mocked Ubuntu scaffold regressions; executes no recipient/container commands."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("ubuntu_qualification", Path(__file__).with_name("qualify-ubuntu.py"))
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / "candidate.tar.gz"
        self.archive.write_bytes(b"reviewed artifact")
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.output = self.root / "fixture" / "receipt.json"

    def main(self, extra=(), release='ID=ubuntu\nVERSION_ID="24.04"\n', uid=1000, machine="x86_64"):
        original = Path.read_text
        def read(path, *args, **kwargs):
            return release if path == Path("/etc/os-release") else original(path, *args, **kwargs)
        argv = ["qualify-ubuntu.py", "--archive", str(self.archive), "--sha256", self.digest,
                "--output", str(self.output), *extra]
        with patch("sys.argv", argv), patch.object(Path, "read_text", read), \
             patch.object(qualification.os, "geteuid", return_value=uid), \
             patch.object(qualification.platform, "machine", return_value=machine), \
             patch.object(qualification, "observe", return_value={"exit_code": 0}) as observe, \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            qualification.main()
            return observe

    def test_checksum_identity(self):
        self.assertEqual(qualification.archive_identity(self.archive)["sha256"], self.digest)

    def test_symlink_refused(self):
        link = self.root / "link"
        link.symlink_to(self.archive)
        with self.assertRaises(OSError):
            qualification.archive_identity(link)

    def test_fifo_refused_without_blocking(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular"):
            qualification.archive_identity(fifo)

    def test_archive_size_cap(self):
        with self.archive.open("wb") as source:
            source.truncate(256 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, "256 MiB"):
            qualification.archive_identity(self.archive)

    def test_changed_archive_metadata_refused(self):
        before = self.archive.stat()
        from types import SimpleNamespace
        after = SimpleNamespace(**{field: getattr(before, field) for field in
            ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")})
        after.st_ctime_ns += 1
        with patch.object(qualification.os, "fstat", side_effect=[before, after]):
            with self.assertRaisesRegex(ValueError, "changed"):
                qualification.archive_identity(self.archive)

    def test_prerequisites_always_incomplete(self):
        observe = self.main()
        report = json.loads(self.output.read_text())
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(set(report["required_evidence"].values()), {"missing"})
        self.assertEqual(observe.call_count, 4)
        for call in observe.call_args_list:
            self.assertEqual(call.args[0][-1], "--version")

    def test_root_and_other_platforms_refused(self):
        for settings in ({"uid": 0}, {"release": "ID=fedora\nVERSION_ID=44\n"},
                         {"machine": "aarch64"}):
            with self.subTest(settings=settings), self.assertRaises(SystemExit):
                self.main(**settings)
        self.assertFalse(self.output.exists())

    def test_output_never_overwrites(self):
        self.output.parent.mkdir()
        self.output.write_text("existing")
        with self.assertRaises(FileExistsError):
            self.main()
        self.assertEqual(self.output.read_text(), "existing")

    def test_prepare_keeps_security_flags_and_executes_no_observations(self):
        observe = self.main(["--prepare-podman", "ubuntu@sha256:" + "a" * 64])
        observe.assert_not_called()
        report = json.loads(self.output.read_text())
        self.assertEqual(report["status"], "prepared_not_executed")
        argv = report["run_argv"]
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", "--user=1000:1000", "--pull=never"):
            self.assertIn(flag, argv)
        self.assertFalse(any("unconfined" in value or "privileged" in value for value in argv))
        self.assertEqual(argv.count("--volume"), 3)

    def test_unpinned_image_refused(self):
        with self.assertRaises(SystemExit):
            self.main(["--prepare-podman", "ubuntu:24.04"])

    def test_optional_snapshot_sources_and_declared_profile_do_not_claim_reproducibility(self):
        sources = self.root / "ubuntu.sources"
        sources.write_text("Types: deb\nURIs: https://example.invalid/snapshot\nSuites: noble\n")
        self.main(["--prepare-podman", "ubuntu@sha256:" + "a" * 64,
                   "--apt-sources-file", str(sources), "--artifact-profile", "debug"])
        report = json.loads(self.output.read_text())
        self.assertFalse(report["reproducible_build_established"])
        self.assertFalse(report["artifact_profile_verified"])
        self.assertEqual(report["artifact_profile_declared"], "debug")
        self.assertEqual(report["apt_sources"]["sha256"], hashlib.sha256(sources.read_bytes()).hexdigest())
        self.assertIn("COPY reviewed-ubuntu.sources", report["containerfile"])

    def test_missing_observer_tool_is_reported(self):
        with patch.object(qualification.subprocess, "Popen", side_effect=FileNotFoundError("missing")):
            self.assertIn("error", qualification.observe(["/missing", "--version"]))

    def test_observer_output_cap_kills_process_group(self):
        from types import SimpleNamespace
        process = MagicMock(pid=123, returncode=-9)
        selector = MagicMock()
        key = SimpleNamespace(fileobj=process.stdout, data="stdout")
        selector.get_map.return_value = {1: key}
        selector.select.return_value = [(key, 1)]
        with patch.object(qualification.subprocess, "Popen", return_value=process), \
             patch.object(qualification.selectors, "DefaultSelector", return_value=selector), \
             patch.object(qualification.os, "read", return_value=b"x" * 8192), \
             patch.object(qualification.time, "monotonic", return_value=0), \
             patch.object(qualification.os, "killpg") as kill:
            result = qualification.observe(["/usr/bin/python3", "--version"])
        self.assertIn("64-KiB", result["error"])
        self.assertEqual(len(result["stdout"]["text"]), 65536)
        kill.assert_called_once()

    def test_observer_deadline_kills_process_group(self):
        process = MagicMock(pid=123, returncode=-9)
        selector = MagicMock()
        selector.get_map.return_value = {1: "pending"}
        with patch.object(qualification.subprocess, "Popen", return_value=process), \
             patch.object(qualification.selectors, "DefaultSelector", return_value=selector), \
             patch.object(qualification.time, "monotonic", side_effect=[0, 11]), \
             patch.object(qualification.os, "killpg") as kill:
            result = qualification.observe(["/usr/bin/python3", "--version"])
        self.assertIn("ten-second", result["error"])
        kill.assert_called_once()


if __name__ == "__main__":
    unittest.main()
