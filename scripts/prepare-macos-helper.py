#!/usr/bin/env python3
"""Generate reviewable signing inputs and argv; never execute signing or a helper."""
import argparse
import hashlib
import json
import plistlib
import re
from pathlib import Path

from package_version import source_version


def identity_file(path, bundle):
    if path.is_symlink() or not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError(f'Expected a canonical absolute regular input: {path}')
    before = path.stat()
    if not path.is_relative_to(bundle) or not path.is_file() or before.st_size > 64 * 1024 * 1024:
        raise ValueError(f'Input must be a bounded file inside bundle: {path}')
    digest = hashlib.sha256()
    count = 0
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > before.st_size:
                raise ValueError(f'Input grew during preparation: {path}')
            digest.update(chunk)
    after = path.stat()
    if (count != before.st_size or path.resolve(strict=True) != path
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
        raise ValueError(f'Input changed during preparation: {path}')
    return 'sha256:' + digest.hexdigest()


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, action='append', required=True,
                        help='Each separately reviewed packaged runtime file; not a closure completeness proof')
    parser.add_argument('--identity', required=True, help='40-hex signing certificate identity hash')
    parser.add_argument('--team', required=True, help='Reviewed 10-character Developer ID team identifier')
    parser.add_argument('--identifier', required=True, help='Reviewed helper signing identifier')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Fa-f0-9]{40}', args.identity):
        parser.error('Use an explicit 40-hex certificate identity, never ad-hoc signing')
    if not re.fullmatch(r'[A-Z0-9]{10}', args.team):
        parser.error('Team must contain exactly 10 uppercase letters or digits')
    if not re.fullmatch(r'[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)+', args.identifier):
        parser.error('Use a safe dotted helper signing identifier')
    bundle = args.bundle
    if not bundle.is_absolute() or bundle.resolve(strict=True) != bundle or not bundle.is_dir():
        parser.error('Bundle must be an existing canonical absolute directory')
    inputs = {str(path): identity_file(path, bundle) for path in [args.helper] + args.runtime}
    output = args.output.resolve()
    if output.is_relative_to(bundle):
        parser.error('Preparation files must be outside the bundle to avoid changing its signing contents')
    output.mkdir(parents=True, exist_ok=False)
    child = {'com.apple.security.app-sandbox': True, 'com.apple.security.inherit': True}
    entitlements = plistlib.dumps(child, fmt=plistlib.FMT_XML, sort_keys=True)
    entitlement_path = output / 'child.entitlements.plist'
    entitlement_path.write_bytes(entitlements)
    requirement = (f'anchor apple generic and identifier "{args.identifier}" '
                   'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
                   'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
                   f'and certificate leaf[subject.OU] = "{args.team}"')
    commands = [
        ['/usr/bin/codesign', '--sign', args.identity, '--timestamp', '--options', 'runtime',
         '--identifier', args.identifier, '--entitlements', str(entitlement_path), str(args.helper)],
        ['/usr/bin/codesign', '--verify', '--strict', '--verbose=2', '-R', requirement, str(args.helper)],
        ['/usr/bin/codesign', '--display', '--entitlements', '-', str(args.helper)],
        ['/usr/bin/codesign', '--display', '--requirements', '-', str(args.helper)],
    ]
    plan = {'schema_version': 1, 'source_version': source_version(root),
            'status': 'preparation only; no commands executed; no signature verified',
            'canonical_bundle': str(bundle), 'canonical_helper': str(args.helper),
            'pre_signing_input_sha256': inputs,
            'child_entitlements_sha256': 'sha256:' + hashlib.sha256(entitlements).hexdigest(),
            'requested_team_identifier': args.team, 'requested_designated_requirement': requirement,
            'signing_commands_argv': commands,
            'required_before_use': ['review and sign nested runtimes before enclosing bundle',
                                   'verify actual Security.framework identity and extracted entitlements',
                                   'rehash every file after signing into SignedHelperContract',
                                   'qualify closure completeness, sandboxed parent, approval and descendant cleanup'],
            'qualified': False, 'signature_verified': False,
            'reproducibility': 'deterministic entitlement bytes and source hashes; timestamped signatures are not byte reproducible'}
    (output / 'signing-plan.json').write_text(json.dumps(plan, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'preparation': str(output), 'qualified': False, 'commands_executed': False}))


if __name__ == '__main__':
    main()
