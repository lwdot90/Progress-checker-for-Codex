#!/usr/bin/env python3
"""Fail-closed immutable recipient preflight; never execute or import evidence."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import os
import stat

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('engineering_job_gates', ROOT/'scripts/plugin-live-acceptance.py')
GATES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATES)
PREPARE_SPEC = importlib.util.spec_from_file_location('engineering_public_roster', ROOT/'scripts/prepare-engineering-recipient.py')
PREPARE = importlib.util.module_from_spec(PREPARE_SPEC)
PREPARE_SPEC.loader.exec_module(PREPARE)
TRUST = 'explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(value, message):
    GATES.require(value, message)


def preparation(path, expected_sha):
    path = path.resolve(strict=True)
    require(path.is_relative_to(ROOT/'.local') and path.name == 'job.json', 'Fixed local preparation job required')
    require(re.fullmatch('[0-9a-f]{64}', expected_sha) is not None, 'Literal reviewed job SHA required')
    raw = GATES.bounded(path, 65536)
    require(sha(raw) == expected_sha, 'Prepared job differs from reviewed hash')
    job = GATES.strict(raw)
    require(type(job.get('schema_version')) is int and job.get('schema_version') == 1 and job.get('purpose') == 'engineering-recipient-preparation-only'
            and job.get('source') == 'source'
            and job.get('proposed_job_argv') == ['/usr/bin/bash', 'scripts/check-engineering.sh', 'tests']
            and job.get('approval_created') is False and job.get('check_executed') is False
            and job.get('qualification_possible') is False, 'Exact non-executing preparation schema required')
    inventory_raw = GATES.bounded(path.parent/'inputs.json', 2*1024*1024)
    require(sha(inventory_raw) == job.get('inputs_sha256'), 'Bound inventory changed')
    inventory = GATES.strict(inventory_raw)
    require(type(inventory) is dict and 0 < len(inventory) <= 10000, 'Bounded nonempty input roster required')
    # Validate all names before opening ANY current-source path. Membership in
    # a copied/human-reviewed manifest alone does not make private state public.
    for name, expected in inventory.items():
        require(type(name) is str, 'Typed public inventory path required')
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts
                and not any(part in PREPARE.EXCLUDED for part in relative.parts)
                and type(expected) is str and re.fullmatch('[0-9a-f]{64}', expected),
                'Unsafe source inventory entry')
        allowed = False
        for selected in PREPARE.INPUTS:
            roster_path = Path(selected)
            if relative == roster_path:
                allowed = True
            elif relative.is_relative_to(roster_path) and (ROOT/roster_path).is_dir():
                allowed = True
            if allowed:
                break
        require(allowed, 'Inventory entry is outside explicit public source roster: '+name)
    source = path.parent/'source'
    seen = set()
    pending = [source]
    scanned = 0
    while pending:
        entry = pending.pop()
        scanned += 1
        require(scanned <= 20000, 'Snapshot traversal exceeds bounds')
        info = entry.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'Recipient source symlinks refused')
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(entry) as children:
                for child in children:
                    pending.append(Path(child.path))
                    require(len(pending)+scanned <= 20000, 'Snapshot traversal exceeds bounds')
        elif stat.S_ISREG(info.st_mode):
            seen.add(str(entry.relative_to(source)))
            require(len(seen) <= 10000, 'Snapshot file count exceeds bounds')
        else:
            require(False, 'Snapshot requires regular files and directories only')
    require(seen == set(inventory), 'Recipient includes missing or unregistered source files')
    aggregate_bytes = 0
    for name, expected in inventory.items():
        relative = Path(name)
        snapshot_bytes = GATES.bounded(source/relative, 32*1024*1024)
        aggregate_bytes += len(snapshot_bytes)
        require(aggregate_bytes <= 128*1024*1024, 'Snapshot aggregate bytes exceed bounds')
        require(sha(snapshot_bytes) == expected, 'Snapshot source changed: '+name)
        current_bytes = GATES.bounded(ROOT/relative, 32*1024*1024)
        require(sha(current_bytes) == expected, 'Current source differs: '+name)
    require(GATES.bounded(path, 65536) == raw and GATES.bounded(path.parent/'inputs.json', 2*1024*1024) == inventory_raw,
            'Preparation changed during validation')
    return {'job_sha256': expected_sha, 'inputs_sha256': sha(inventory_raw), 'input_count': len(inventory)}


def registration(path, expected_sha, prepared):
    """Validate identity only; no file can substitute for a live trusted producer."""
    require(re.fullmatch('[0-9a-f]{64}', expected_sha) is not None, 'Literal reviewed registration SHA required')
    raw = GATES.bounded(path, 1024*1024, True)
    require(sha(raw) == expected_sha, 'Immutable registration differs')
    value = GATES.strict(raw)
    require(value.get('schema_version') == 1 and value.get('mode') == 'engineering-recipient'
            and value.get('trust_policy') == TRUST, 'Explicit engineering host registration required')
    require(value.get('boot_id') == Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'Different boot registration')
    require(type(value.get('job_id')) is str and re.fullmatch('[0-9a-f]{32}', value['job_id'])
            and type(value.get('nonce')) is str and re.fullmatch('[0-9a-f]{64}', value['nonce']), 'Exact fresh job identity required')
    require(value.get('source_inputs_sha256') == prepared['inputs_sha256']
            and value.get('preparation_job_sha256') == prepared['job_sha256'], 'Registration source binding differs')
    require(value.get('argv') == ['/usr/bin/bash', 'scripts/check-engineering.sh', 'tests'], 'Reader-selected work refused')
    require(type(value.get('image_sha256')) is str and re.fullmatch('[0-9a-f]{64}', value['image_sha256'])
            and type(value.get('runtime_files')) is dict and bool(value['runtime_files']), 'Bound image and runtime inventory required')
    require(GATES.bounded(path, 1024*1024, True) == raw, 'Registration changed during validation')
    return {'registration_sha256': expected_sha, 'job_id': value['job_id'], 'identity_validated_only': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job', type=Path, required=True)
    parser.add_argument('--job-sha256', required=True)
    parser.add_argument('--registration', type=Path)
    parser.add_argument('--registration-sha256')
    args = parser.parse_args()
    require(bool(args.registration) == bool(args.registration_sha256), 'Registration path and hash must be paired')
    result = preparation(args.job, args.job_sha256)
    if args.registration:
        result.update(registration(args.registration, args.registration_sha256, result))
    print(json.dumps({'status': 'preflight-valid', **result, 'approval_created': False,
                      'check_executed': False, 'qualification_possible': False,
                      'remaining': 'Live producer activation, kernel peer lifetime and one-use result consumption are not implemented.'}, indent=2))


if __name__ == '__main__':
    main()
