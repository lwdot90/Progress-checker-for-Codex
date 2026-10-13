#!/usr/bin/env python3
"""Unit tests for the qualification guard; these do not qualify any platform."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

_SPEC = importlib.util.spec_from_file_location(
    "platform_support_guard", Path(__file__).with_name("check-platform-support.py")
)
_GUARD = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_GUARD)


def host(system="Linux", distribution="ubuntu", wsl=False):
    return {"system": system, "distribution_id": distribution,
            "wsl_kernel_hint": wsl, "architecture": "x86_64",
            "kernel_release": "mock-kernel"}


class PlatformGuardTests(unittest.TestCase):
    def test_wsl_does_not_satisfy_native_windows_or_ordinary_ubuntu(self):
        observed = host(wsl=True)
        with patch.object(_GUARD.sys, "platform", "linux"):
            self.assertFalse(_GUARD.host_candidate_matches("windows", observed))
            self.assertFalse(_GUARD.host_candidate_matches("ubuntu", observed))
            self.assertTrue(_GUARD.host_candidate_matches("wsl2", observed))

    def test_native_windows_requires_native_process_and_system(self):
        with patch.object(_GUARD.sys, "platform", "win32"):
            self.assertTrue(_GUARD.host_candidate_matches("windows", host("Windows", None)))
            self.assertFalse(_GUARD.host_candidate_matches("windows", host(wsl=True)))
        with patch.object(_GUARD.sys, "platform", "linux"):
            self.assertFalse(_GUARD.host_candidate_matches("windows", host("Windows", None)))

    def test_every_matching_target_is_blocked_without_collector(self):
        targets = {
            "ubuntu": ("linux", host()),
            "macos": ("darwin", host("Darwin", None)),
            "windows": ("win32", host("Windows", None)),
            "wsl2": ("linux", host(wsl=True)),
        }
        for target, (native_platform, observed) in targets.items():
            with self.subTest(target=target), patch.object(_GUARD.sys, "platform", native_platform), \
                 patch.object(_GUARD.sys, "argv", ["check-platform-support.py", "--platform", target]), \
                 patch.object(_GUARD, "host_observation", return_value=observed):
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    self.assertEqual(_GUARD.main(), 2)
                report = json.loads(stdout.getvalue())
                self.assertTrue(report["host_candidate_matches"])
                self.assertFalse(report["verified"])
                self.assertFalse(report["trusted_collector_available"])
                self.assertEqual(report["outcome"], "blocked")
                self.assertIn("BLOCKED", stderr.getvalue())

    def test_human_receipt_input_is_rejected(self):
        for flag in ("--receipt", "--human-report", "--verified"):
            with self.subTest(flag=flag), patch.object(
                _GUARD.sys, "argv", ["check-platform-support.py", "--platform", "windows", flag, "report.json"]
            ), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as rejected:
                    _GUARD.main()
                self.assertEqual(rejected.exception.code, 2)

    def test_native_macos_and_ubuntu_host_validators(self):
        with patch.object(_GUARD.sys, "platform", "darwin"):
            self.assertTrue(_GUARD.host_candidate_matches("macos", host("Darwin", None)))
            self.assertFalse(_GUARD.host_candidate_matches("macos", host("Linux", None)))
        with patch.object(_GUARD.sys, "platform", "linux"):
            self.assertFalse(_GUARD.host_candidate_matches("macos", host("Darwin", None)))
            self.assertTrue(_GUARD.host_candidate_matches("ubuntu", host()))
            self.assertFalse(_GUARD.host_candidate_matches("ubuntu", host(distribution="fedora")))
            self.assertFalse(_GUARD.host_candidate_matches("ubuntu", host("Windows", "ubuntu")))

    def test_platform_names_require_exact_supported_case(self):
        for target in ("Windows", "WINDOWS", "native-windows", "WSL2"):
            with self.subTest(target=target), patch.object(
                _GUARD.sys, "argv", ["check-platform-support.py", "--platform", target]
            ), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as rejected:
                    _GUARD.main()
                self.assertEqual(rejected.exception.code, 2)

    def test_unknown_and_aggregate_targets_are_rejected(self):
        with patch.object(_GUARD.sys, "argv", ["check-platform-support.py", "--platform", "all"]), \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as rejected:
                _GUARD.main()
            self.assertEqual(rejected.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
