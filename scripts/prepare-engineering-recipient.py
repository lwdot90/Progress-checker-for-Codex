#!/usr/bin/env python3
"""Prepare bounded public source inputs; create no grant and execute no check."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import importlib.util
import stat
import os

ROOT = Path(__file__).resolve().parents[1]
# Explicit public roots only. Never copy the parent project's live config,
# claims, grants or private evidence directory as a recipient execution plan.
INPUTS = (
    'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
    'checker-core', 'checker-cli', 'checker-service', 'checker-mcp', 'checker-global',
    'scripts', 'plugins', 'examples', 'docs', 'schemas', '.github',
    'README.md', 'LICENSE', 'NOTICE', 'SOURCE_MANIFEST.json',
    '.progress-checker/plugin-plan.json',
    '.progress-checker/acceptance-inputs/progress-checker-0.2.0-dev-linux-x86_64-fbf12375255a.tar.gz',
    '.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz',
    '.progress-checker/acceptance-inputs/progress-checker-0.3.0-dev-linux-x86_64-0169944a4289.tar.gz',
    '.progress-checker/acceptance-inputs/progress-checker-0.4.0-dev-linux-x86_64-4bd153b6c43b.tar.gz',
)

EXCLUDED = {'.git', '.local', 'target', '__pycache__', '.pytest_cache'}
SPEC = importlib.util.spec_from_file_location('recipient_source_gates', ROOT/'scripts/plugin-live-acceptance.py')
GATES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATES)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    destination = args.output.absolute()
    if destination.exists() or destination.is_symlink():
        raise SystemExit('Use a new output directory; previous job inputs are preserved')
    # Only an excluded local directory may hold the snapshot, avoiding recursive
    # source capture and public fingerprint changes during preparation.
    local = ROOT / '.local'
    if not destination.is_relative_to(local) or destination.parent.resolve() != destination.parent:
        raise SystemExit('Output must be beneath the real project .local directory')
    selected = []
    scanned = 0
    estimated_bytes = 0
    pending = [ROOT/name for name in reversed(INPUTS)]
    while pending:
        path = pending.pop()
        if path.name in EXCLUDED:
            continue
        if not path.exists() and not path.is_symlink():
            continue
        scanned += 1
        if scanned > 20000:
            raise SystemExit('Source traversal exceeds preparation bounds')
        relative = path.relative_to(ROOT)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise SystemExit(f'Source symlink requires explicit review: {relative}')
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    if entry.name not in EXCLUDED:
                        pending.append(Path(entry.path))
                        if len(pending) + scanned > 20000:
                            raise SystemExit('Source traversal exceeds preparation bounds')
        elif stat.S_ISREG(info.st_mode):
            selected.append((path, relative))
            estimated_bytes += info.st_size
            if len(selected) > 10000 or estimated_bytes > 128 * 1024 * 1024:
                raise SystemExit('Recipient public inputs exceed preparation bounds')
    selected.sort(key=lambda item: str(item[1]))
    destination.mkdir(parents=True, mode=0o700)
    inventory = {}
    actual_bytes = 0
    for path, relative in selected:
        target = destination / 'source' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        data = GATES.bounded(path, 32 * 1024 * 1024)
        actual_bytes += len(data)
        if actual_bytes > 128 * 1024 * 1024:
            raise SystemExit('Actual source bytes exceed preparation bounds; incomplete snapshot retained')
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(stat.S_IMODE(path.stat().st_mode) & 0o755)
        inventory[str(relative)] = hashlib.sha256(data).hexdigest()
    for path, relative in selected:
        if hashlib.sha256(GATES.bounded(path, 32 * 1024 * 1024)).hexdigest() != inventory[str(relative)]:
            raise SystemExit('Source changed during preparation; incomplete snapshot retained: ' + str(relative))
    manifest_bytes = (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode()
    (destination / 'inputs.json').write_bytes(manifest_bytes)
    descriptor = {
        'schema_version': 1,
        'purpose': 'engineering-recipient-preparation-only',
        'inputs_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
        'source': 'source',
        'proposed_job_argv': ['/usr/bin/bash', 'scripts/check-engineering.sh', 'tests'],
        'approval_created': False,
        'check_executed': False,
        'qualification_possible': False,
        'blockers': [
            'Recipient image, offline Rust toolchain and dependency cache are not bound.',
            'External recipient execution adapter and exact human approval are not implemented.',
            'Existing project checker evidence cannot import an untrusted host receipt.',
        ],
    }
    (destination / 'job.json').write_text(json.dumps(descriptor, indent=2) + '\n')
    print(json.dumps({'prepared': str(destination), **descriptor}, indent=2))


if __name__ == '__main__':
    main()
