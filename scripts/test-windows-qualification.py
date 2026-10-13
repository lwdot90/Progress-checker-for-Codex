#!/usr/bin/env python3
"""Tests only the blocked scaffold protocol; never Windows sandbox evidence."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("windows_qualification", Path(__file__).with_name("qualify-windows.py"))
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


class BlockedQualificationProtocol(unittest.TestCase):
    def invoke(self, native=False, backend=False):
        with tempfile.TemporaryDirectory(prefix="pc-windows-scaffold-") as temporary:
            folder = Path(temporary)
            output = folder / "receipt.json"
            arguments = ["qualify-windows.py", "--output", str(output)]
            if backend:
                candidate = folder / "candidate.exe"
                # Deliberately non-executable fixture: identity collection must
                # never mistake an .exe filename for safe launch qualification.
                candidate.write_bytes(b"not an executable\n")
                arguments += ["--backend", str(candidate)]
            with patch("sys.argv", arguments), patch.object(qualification, "os", types.SimpleNamespace(name="nt" if native else "posix")), patch.object(qualification.platform, "system", return_value="Windows" if native else "Linux"), patch("subprocess.run", side_effect=AssertionError("scaffold attempted execution")), patch("subprocess.Popen", side_effect=AssertionError("scaffold attempted execution")), contextlib.redirect_stdout(io.StringIO()):
                status = qualification.main()
            return status, json.loads(output.read_text(encoding="utf-8"))

    def assert_blocked(self, receipt):
        self.assertEqual(receipt["outcome"], "blocked")
        self.assertIs(receipt["execution_started"], False)
        self.assertEqual(len(receipt["probes"]), 12)
        for probe in receipt["probes"]:
            self.assertEqual(probe["status"], "blocked")
            self.assertIs(probe["executed"], False)

    def test_linux_and_wsl_cannot_produce_windows_qualification(self):
        status, receipt = self.invoke()
        self.assertEqual(status, 3)
        self.assert_blocked(receipt)
        self.assertIs(receipt["platform"]["native_windows"], False)
        self.assertTrue(any("WSL" in reason for reason in receipt["reasons"]))

    def test_native_host_with_candidate_still_requires_real_backend(self):
        status, receipt = self.invoke(native=True, backend=True)
        self.assertEqual(status, 3)
        self.assert_blocked(receipt)
        self.assertIs(receipt["platform"]["native_windows"], True)
        self.assertEqual(len(receipt["backend_identity"]["sha256"]), 64)
        self.assertTrue(any("not implemented" in reason for reason in receipt["reasons"]))

    def test_native_host_missing_candidate_is_explicitly_blocked(self):
        status, receipt = self.invoke(native=True)
        self.assertEqual(status, 3)
        self.assert_blocked(receipt)
        self.assertIsNone(receipt["backend_identity"])
        self.assertIn("No native backend candidate supplied", receipt["reasons"])


if __name__ == "__main__":
    unittest.main()
