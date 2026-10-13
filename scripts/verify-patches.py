#!/usr/bin/env python3
"""Verify packaged patches in temporary trees without a source checkout or Rust."""

import argparse
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "upstream-base"
OVERLAY = ROOT / "prototype-overlay"
PATCHES = ROOT / "patches"


def tree_bytes(directory: Path) -> dict[str, bytes]:
    files = {}
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory)
        if relative.parts[0] == ".git":
            continue
        if path.is_symlink():
            raise ValueError(f"Verification input contains a symlink: {path}")
        if path.is_file():
            files[relative.as_posix()] = path.read_bytes()
    return files


def require_tree(actual: dict[str, bytes], expected: dict[str, bytes], label: str) -> None:
    different = sorted(
        name for name in actual.keys() | expected.keys()
        if actual.get(name) != expected.get(name)
    )
    if different:
        raise ValueError(f"{label} differs at: {', '.join(different)}")


def git(directory: Path, *arguments: str) -> None:
    result = subprocess.run(
        [
            "git", "--git-dir", str(directory / ".git"),
            "--work-tree", str(directory), "-C", str(directory), *arguments,
        ],
        capture_output=True,
        text=True,
        check=False,
        env={key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
    )
    if result.returncode:
        raise ValueError(f"Git {' '.join(arguments[:2])} failed: {result.stderr.strip()}")


def check_lockfile(before: dict[str, bytes], after: dict[str, bytes]) -> int:
    manifests = [name for name in after if Path(name).name == "Cargo.toml"]
    for name in manifests:
        if name not in before or after[name] != before[name]:
            raise ValueError(f"Dependency manifest changed: {name}")
    workspace = tomllib.loads(before["codex-rs/Cargo.toml"].decode("utf-8"))
    version = workspace["workspace"]["package"]["version"]
    tui = tomllib.loads(before["codex-rs/tui/Cargo.toml"].decode("utf-8"))
    if not isinstance(version, str) or tui["package"]["version"] != {"workspace": True}:
        raise ValueError("Workspace/TUI manifests do not declare the expected inherited version")
    original = tomllib.loads(before["codex-rs/Cargo.lock"].decode("utf-8"))
    repaired = tomllib.loads(after["codex-rs/Cargo.lock"].decode("utf-8"))
    if {k: v for k, v in original.items() if k != "package"} != {
        k: v for k, v in repaired.items() if k != "package"
    } or len(original["package"]) != len(repaired["package"]):
        raise ValueError("Lockfile structure changed beyond workspace versions")
    normalized = 0
    for old, new in zip(original["package"], repaired["package"]):
        if "source" in old:
            if old != new:
                raise ValueError(f"External lockfile package changed: {old['name']}")
        else:
            if new.get("version") != version or {
                k: v for k, v in old.items() if k != "version"
            } != {k: v for k, v in new.items() if k != "version"}:
                raise ValueError(f"Local lockfile package does not match the workspace: {old['name']}")
            if old != new:
                if old["version"] != "0.0.0":
                    raise ValueError(f"Unexpected original local version: {old['name']}")
                normalized += 1
    if not normalized:
        raise ValueError("The release lockfile stage did not normalize any local versions")
    return normalized


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    if shutil.which("git") is None:
        raise ValueError("Git is required to check patch application")
    check_source = runpy.run_path(str(ROOT / "scripts/check-source.py"))["check_source"]
    check_source(BASE, BASE / "MANIFEST.json")
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/generate-patch.py"), "--check"],
        check=True,
    )
    baseline, overlay = tree_bytes(BASE), tree_bytes(OVERLAY)
    if not overlay:
        raise ValueError("The prototype overlay is empty")
    expected = baseline | overlay
    generator = runpy.run_path(str(ROOT / "scripts/generate-patch.py"))
    release_snapshots = generator["RELEASE_SNAPSHOT_PATHS"] | generator["RELEASE_EXACT_SNAPSHOTS"].keys()
    release_paths = {"codex-rs/Cargo.lock"} | (overlay.keys() & release_snapshots)
    stages = sorted(PATCHES.glob("[0-9][0-9]-*.patch"))
    if not stages or stages[0].name != "00-release-lockfile.patch":
        raise ValueError("Numeric stages must begin with the release lockfile repair")
    for label, sequence in (("Combined", [PATCHES / "codex-progress-panel.patch"]), ("Staged", stages)):
        with tempfile.TemporaryDirectory(prefix=".verify-patches.", dir=ROOT) as temporary:
            target = Path(temporary) / "source"
            shutil.copytree(BASE, target)
            # Isolate Git from any repository containing this project copy.
            git(target, "init", "--quiet")
            for patch in sequence:
                git(target, "apply", "--check", str(patch))
                git(target, "apply", str(patch))
                if patch.name == "00-release-lockfile.patch":
                    stage_zero = tree_bytes(target)
                    require_tree(
                        stage_zero,
                        baseline | {name: expected[name] for name in release_paths},
                        "Stage 00",
                    )
                    check_lockfile(baseline, stage_zero)
            final = tree_bytes(target)
            require_tree(final, expected, f"{label} patch")
            normalized = check_lockfile(baseline, final)
            for patch in reversed(sequence):
                git(target, "apply", "--reverse", "--check", str(patch))
                git(target, "apply", "--reverse", str(patch))
            require_tree(tree_bytes(target), baseline, f"{label} reverse application")
            print(f"{label} patches reproduce all {len(overlay)} overlay files and reverse to baseline.")
    print(f"Only {normalized} local lockfile versions changed; Cargo manifests and external packages match upstream.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"Patch verification failed: {error}", file=sys.stderr)
        sys.exit(1)
