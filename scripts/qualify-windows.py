#!/usr/bin/env python3
"""Native-Windows qualification scaffold. Never substitutes WSL or host launch.

This intentionally exits 3 (blocked) until the project's restricted preparation
factory and native adversarial test adapter are implemented. It records missing
prerequisites, never fabricates passing sandbox evidence or executes arbitrary
supplied binaries. Run only through a separately human-approved check definition.
"""
import argparse
import datetime
import hashlib
import json
import os
import platform
from pathlib import Path

PROBES = {
    "exact-approval": "Missing/revoked/changed human approval refuses launch before process creation",
    "argument-roundtrip": "Native CRT child observes exact approved empty/Unicode/quote/backslash arguments",
    "fixed-environment": "Only approved fixed keys appear; host secrets and drive-current-directory entries absent",
    "stdio-handles": "Only the three designated stdio handles are inherited; private state and parent handles unavailable",
    "private-state": "Child cannot read/write actual checker state, authorization, evidence, or service IPC",
    "home": "Child cannot read/write user-home sentinel outside its isolated project snapshot",
    "filesystem-escape": "Junction/symlink/rename races cannot reach any ungranted path",
    "network": "Internet, intranet, IPv4/IPv6, DNS, loopback and broker-mediated connections fail",
    "runtime-replacement": "Executable/DLL/helper changes invalidate runtime bindings and cannot race creation",
    "broker-escape": "COM/WMI/task-scheduler/service/parent-handle attempts cannot create uncontained processes",
    "descendants": "Detached and nested descendants terminate on timeout, cancellation, parent death and job close",
    "logs": "Large/unterminated output stays bounded, redacts known credentials and cannot forge host outcome",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", type=Path, help="candidate native backend executable; identity only, never executed")
    parser.add_argument("--output", type=Path, default=Path(".local/qualification/windows.json"))
    args = parser.parse_args()
    native = os.name == "nt" and platform.system() == "Windows"
    reasons = []
    if not native:
        reasons.append("A native Windows host is required; Linux/WSL/macOS cannot qualify Win32 isolation")
    identity = None
    if args.backend is None:
        reasons.append("No native backend candidate supplied")
    else:
        try:
            resolved = args.backend.resolve(strict=True)
            if not resolved.is_file() or resolved.suffix.lower() != ".exe":
                raise ValueError("backend must be an existing .exe file")
            if resolved.stat().st_size > 512 * 1024 * 1024:
                raise ValueError("candidate identity exceeds 512 MiB scaffold limit")
            # Hash only; executing the candidate is not authorized by this script.
            hasher = hashlib.sha256()
            with resolved.open("rb") as stream:
                total = 0
                for chunk in iter(lambda: stream.read(65536), b""):
                    total += len(chunk)
                    if total > 512 * 1024 * 1024:
                        raise ValueError("candidate grew beyond identity limit")
                    hasher.update(chunk)
            identity = {"path": str(resolved), "sha256": hasher.hexdigest()}
        except (OSError, ValueError) as error:
            reasons.append(f"Native candidate identity unavailable: {error}")
    reasons.append("PreparedWindowsLaunch.prepare is deliberately unavailable until ACL/broker/exact-approval preparation is implemented and reviewed")
    reasons.append("Native adversarial qualification adapter is not implemented; no probes were executed")
    receipt = {
        "schema": 1,
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": {"native_windows": native, "system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "backend_identity": identity,
        "outcome": "blocked",
        "execution_started": False,
        "reasons": reasons,
        "probes": [{"id": key, "criterion": criterion, "status": "blocked", "executed": False} for key, criterion in PROBES.items()],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"BLOCKED: native Windows qualification; no commands or adversarial probes started. Receipt: {args.output}")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
