#!/usr/bin/env python3
"""Collect native signing preflight observations; never authorize check execution."""
import argparse
import hashlib
import json
import os
import platform
import plistlib
import re
import select
import signal
import subprocess
import time
from pathlib import Path
from package_version import source_version


def bounded_command(argv, limit=16384):
    data = bytearray()
    deadline = time.monotonic() + 10
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True,
                             env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([child.stdout], [], [], remaining)[0]:
                raise subprocess.TimeoutExpired(argv[0], 10)
            chunk = os.read(child.stdout.fileno(), min(limit + 1, 4096))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError('Native observation output exceeds bound')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv[0], 10)
        if child.wait(timeout=remaining) != 0:
            raise ValueError('Native signature observation command failed')
        return bytes(data)
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=2)
        child.stdout.close()


def observed_file(path):
    if not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError('Observation requires a canonical absolute non-symlink file')
    before = path.stat()
    if not path.is_file() or before.st_size > 64 * 1024 * 1024:
        raise ValueError('Observation requires a regular file no larger than 64 MiB')
    digest = hashlib.sha256()
    count = 0
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > before.st_size:
                raise ValueError('Observation input grew')
            digest.update(chunk)
    after = path.stat()
    if path.resolve(strict=True) != path or count != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('Observation input changed')
    return {'path': str(path), 'size': count, 'sha256': 'sha256:' + digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--team', required=True)
    parser.add_argument('--identifier', required=True)
    parser.add_argument('--artifact', type=Path, required=True, help='Exact staged archive for hash binding')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    candidate_version = source_version(Path(__file__).resolve().parent.parent)
    if platform.system() != 'Darwin':
        parser.error('Actual macOS host required; copied receipts cannot satisfy this collector')
    if not re.fullmatch(r'[A-Z0-9]{10}', args.team) or not re.fullmatch(r'[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)+', args.identifier):
        parser.error('Supply reviewed safe team and helper identifier policy inputs')
    before = observed_file(args.helper)
    artifact = observed_file(args.artifact)
    requirement = (f'anchor apple generic and identifier "{args.identifier}" '
                   'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
                   'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
                   f'and certificate leaf[subject.OU] = "{args.team}"')
    bounded_command(['/usr/bin/codesign', '--verify', '--strict', '--verbose=2', '-R', requirement, str(args.helper)])
    raw = bounded_command(['/usr/bin/codesign', '--display', '--entitlements', '-', str(args.helper)])
    start = raw.find(b'<?xml')
    end = raw.find(b'</plist>', start)
    if start < 0 or end < 0:
        raise ValueError('Actual signed XML entitlements unavailable')
    entitlements = plistlib.loads(raw[start:end + len(b'</plist>')])
    security = {key: value for key, value in entitlements.items() if key.startswith('com.apple.security.')}
    if security != {'com.apple.security.app-sandbox': True, 'com.apple.security.inherit': True}:
        raise ValueError('Actual child sandbox entitlements differ from exact inherited contract')
    details = bounded_command(['/usr/bin/codesign', '--display', '--verbose=4', str(args.helper)])
    if not re.search(rb'flags=0x[0-9a-fA-F]+\([^\n)]*\bruntime\b', details):
        raise ValueError('Actual helper lacks observed Hardened Runtime signing flag')
    if observed_file(args.helper) != before or observed_file(args.artifact) != artifact:
        raise ValueError('Helper or archive changed across signing observations')
    receipt = {'schema_version': 1, 'collector': 'native-macos-signing-preflight-v1',
               'source_candidate_version': candidate_version,
               'helper_version_observed': False,
               'observed_at_unix_seconds': int(time.time()), 'host': {'system': platform.system(),
               'release': platform.release(), 'architecture': platform.machine()},
               'helper': before, 'artifact': artifact, 'expected_requirement': requirement,
               'codesign_verification_passed': True, 'actual_child_entitlements': entitlements,
               'hardened_runtime_observed': True, 'execution_support': False,
               'qualified': False, 'closure_complete': False,
               'missing': ['protected installed helper ownership and retained identity',
                           'parent sandbox and runtime dependency closure', 'human approval broker',
                           'descendant lifecycle containment', 'native recipient installation trial'],
               'scope': 'preflight only; archive/helper hashes do not prove helper is an archive member'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as output:
        json.dump(receipt, output, indent=2, sort_keys=True)
        output.write('\n')
    print(json.dumps({'receipt': str(args.output), 'qualified': False, 'execution_support': False}))
    raise SystemExit(2)


if __name__ == '__main__':
    main()
