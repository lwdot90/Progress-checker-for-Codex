#!/usr/bin/env python3
"""Check pinned upstream files using their Git blob SHA-1 identifiers."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

PINNED_COMMIT = "a956835d020762cb2b570053af06f643a11c0ecc"


def check_source(source: Path, manifest_path: Path) -> int:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("Manifest must be a JSON object")
    if manifest.get("upstream_commit") != PINNED_COMMIT:
        raise ValueError("Manifest does not name the pinned Codex commit")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("Manifest must contain a nonempty files-to-Git-blob-SHA mapping")
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("Source path must be a directory")
    for name, expected in files.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError(f"Unsafe manifest path: {name}")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{40}", expected):
            raise ValueError(f"Invalid Git blob SHA for: {name}")
        path = (source / relative).resolve(strict=True)
        if not path.is_relative_to(source) or not path.is_file():
            raise ValueError(f"Manifest file escapes source or is not a file: {name}")
        data = path.read_bytes()
        payload = f"blob {len(data)}\0".encode("ascii") + data
        actual = hashlib.sha1(payload, usedforsecurity=False).hexdigest()
        if actual != expected:
            raise ValueError(f"Upstream mismatch: {name} (expected {expected}, got {actual})")
    return len(files)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Unmodified pinned Codex source directory")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "upstream-base/MANIFEST.json",
    )
    args = parser.parse_args()
    try:
        count = check_source(args.source, args.manifest)
    except (OSError, ValueError, TypeError) as error:
        print(f"Source verification failed: {error}", file=sys.stderr)
        return 1
    print(f"Verified {count} pinned upstream Git blobs at {PINNED_COMMIT}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
