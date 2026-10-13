#!/usr/bin/env python3
"""Run the actual packaging verifier in an explicitly excluded scratch copy."""
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
scratch = root / "pilot-output" / "packaging"
if scratch.exists():
    shutil.rmtree(scratch)
scratch.mkdir(parents=True)
for name in ("upstream-base", "prototype-overlay", "patches", "scripts"):
    shutil.copytree(root / name, scratch / name)
subprocess.run([sys.executable, str(scratch / "scripts/verify-patches.py")], check=True)
