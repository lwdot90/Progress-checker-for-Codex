#!/usr/bin/env python3
"""Collect read-only WSL prerequisites; never execute checks or grant approval."""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import stat


def read_text(path):
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeError):
        return None


def executable_observation(path):
    try:
        target = Path(path).resolve(strict=True)
        info = target.stat()
        return {
            "path": path, "resolved": str(target),
            "regular": stat.S_ISREG(info.st_mode), "owner_uid": info.st_uid,
            "group_or_world_writable": bool(info.st_mode & 0o022),
            "executable": os.access(target, os.X_OK),
        }
    except OSError as exc:
        return {"path": path, "available": False, "error": str(exc)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.project.resolve()
    release = read_text("/proc/sys/kernel/osrelease") or platform.release()
    marker = "microsoft" in release.lower() or "wsl" in release.lower()
    mounted_windows = len(root.parts) >= 3 and root.parts[1] == "mnt" and len(root.parts[2]) == 1
    report = {
        "schema_version": 1,
        "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": "windows-hosted-wsl2-candidate",
        "qualification": "not_verified",
        "observation_only": True,
        "host": {"system": platform.system(), "architecture": platform.machine(),
                 "kernel_release": release, "wsl_kernel_marker": marker,
                 "os_release": read_text("/etc/os-release")},
        "project": {"resolved_path": str(root), "windows_drive_mount_hint": mounted_windows,
                    "filesystem_verified": False},
        "namespace_policy": {
            "unprivileged_userns_clone": read_text("/proc/sys/kernel/unprivileged_userns_clone"),
            "max_user_namespaces": read_text("/proc/sys/user/max_user_namespaces"),
            "apparmor_restrict_unprivileged_userns": read_text("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
            "namespace_execution_verified": False},
        "executables": [executable_observation(path) for path in
                        ("/usr/bin/python3", "/usr/bin/git", "/usr/bin/bwrap", "/usr/bin/dpkg-query")],
        "blockers": ["No WSL2 recipient qualification evidence has been collected.",
                     "Confirm the distribution is VERSION 2 with Windows-side wsl --list --verbose.",
                     "Qualify the Linux distribution and source-free release before claiming WSL support.",
                     "Human approval and sandbox execution require separately approved live checks."],
    }
    if not marker:
        report["blockers"].append("This host has no observed WSL kernel marker.")
    if mounted_windows:
        report["blockers"].append("Use a repository in the Linux distribution filesystem for the initial trial.")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
