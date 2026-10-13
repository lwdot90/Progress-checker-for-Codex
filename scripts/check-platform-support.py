#!/usr/bin/env python3
"""Fail-closed platform qualification entrypoint until a trusted collector exists.

This command never treats a report, receipt schema, or prerequisite observation as
recipient qualification. No success path exists yet. Root registration must bind
this exact script; adding a real collector requires reviewed plan/check changes.
"""
import argparse
import json
from pathlib import Path
import platform
import sys


def os_release_id():
    try:
        values = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                values[key] = value.strip('"')
        return values.get("ID")
    except (OSError, UnicodeError):
        return None


def host_observation():
    release = platform.release()
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text().strip()
    except (OSError, UnicodeError):
        pass
    wsl_hint = "microsoft" in release.lower() or "wsl" in release.lower()
    return {"system": platform.system(), "architecture": platform.machine(),
            "kernel_release": release, "distribution_id": os_release_id(),
            "wsl_kernel_hint": wsl_hint}


def host_candidate_matches(target, host):
    if target == "windows":
        # A Linux kernel under WSL cannot qualify native Windows.
        return sys.platform == "win32" and host["system"] == "Windows"
    if target == "macos":
        return sys.platform == "darwin" and host["system"] == "Darwin"
    if target == "ubuntu":
        # WSL needs its own recipient job; do not silently substitute it.
        return host["system"] == "Linux" and host["distribution_id"] == "ubuntu" and not host["wsl_kernel_hint"]
    return host["system"] == "Linux" and host["wsl_kernel_hint"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=("ubuntu", "macos", "windows", "wsl2"))
    args = parser.parse_args()
    host = host_observation()
    matches = host_candidate_matches(args.platform, host)
    blockers = []
    if not matches:
        blockers.append("This process is not running on the requested native recipient target.")
    if args.platform == "wsl2":
        blockers.append("Kernel hints alone cannot prove WSL2; the recipient collector must verify the Windows-side distribution version.")
    blockers.append("A trusted original source-free recipient qualification collector job is not implemented and bound to this entrypoint.")
    blockers.append("Required install, human approval, confined execution, freshness, restart, update and removal evidence is missing.")
    print(json.dumps({
        "schema_version": 1, "platform": args.platform, "outcome": "blocked",
        "verified": False, "host": host, "host_candidate_matches": matches,
        "trusted_collector_available": False, "blockers": blockers,
        "policy": "External receipts, human reports and schema-only validation cannot make this entrypoint pass.",
    }, indent=2))
    print("BLOCKED: platform recipient qualification has no trusted collector; no passing evidence produced.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
