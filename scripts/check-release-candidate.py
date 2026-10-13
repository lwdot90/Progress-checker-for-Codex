#!/usr/bin/env python3
"""Inspect candidate archive bytes only; this does not qualify installation or runtime."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = {
    'install.py', 'README.md', 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md',
    'plugin/plugin.json', 'plugin/LICENSE', 'plugin/NOTICE',
    'plugin/THIRD_PARTY_NOTICES.md', 'plugin/third-party/inventory.json',
    'plugin/bin/checker-global', 'plugin/bin/checker-plugin',
    'plugin/bin/progress-checker', 'plugin/bin/progress-checker-mcp',
    'plugin/skills/progress-checker/SKILL.md',
}


def bounded_archive_hash(path):
    before = path.stat()
    if path.is_symlink() or not path.is_file() or before.st_size > 512 * 1024 * 1024:
        raise ValueError('Archive must be a bounded regular file')
    digest = hashlib.sha256()
    count = 0
    with path.open('rb') as handle:
        while chunk := handle.read(1024 * 1024):
            count += len(chunk)
            if count > before.st_size or count > 512 * 1024 * 1024:
                raise ValueError('Archive grew during inspection')
            digest.update(chunk)
    after = path.stat()
    if count != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('Archive changed during inspection')
    return digest.hexdigest()


def inspect_archive(archive, expected_sha256, expected_version):
    actual = bounded_archive_hash(archive)
    if actual != expected_sha256:
        raise ValueError('Archive SHA-256 differs from reviewed identity')
    files, executable_modes = {}, {}
    prefix = f'progress-checker-{expected_version}-linux-x86_64'
    with tarfile.open(archive, 'r:gz') as bundle:
        seen = set()
        aggregate = 0
        for member in bundle:
            if len(seen) >= 10000:
                raise ValueError('Archive exceeds member-count cap')
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != prefix:
                raise ValueError('Unsafe or unexpected archive path: ' + member.name)
            if member.name in seen:
                raise ValueError('Duplicate archive member: ' + member.name)
            seen.add(member.name)
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError('Links and special archive members are refused: ' + member.name)
            if member.size < 0:
                raise ValueError('Negative archive member size')
            if member.size > 256 * 1024 * 1024:
                raise ValueError('Archive member exceeds inspection size cap')
            aggregate += member.size
            if aggregate > 512 * 1024 * 1024:
                raise ValueError('Archive exceeds aggregate size cap')
            relative = str(PurePosixPath(*path.parts[1:]))
            with bundle.extractfile(member) as stream:
                payload = stream.read(member.size + 1)
            if len(payload) != member.size:
                raise ValueError('Archive member length differs from its header')
            files[relative] = payload
            executable_modes[relative] = member.mode
    missing = REQUIRED - files.keys()
    if missing:
        raise ValueError('Missing package files: ' + ', '.join(sorted(missing)))
    checksums = json.loads(files.get('checksums.json', b'{}'))
    if not isinstance(checksums, dict) or set(checksums) != set(files) - {'checksums.json'}:
        raise ValueError('Checksum inventory must cover exactly every packaged file except itself')
    for path, expected in checksums.items():
        if hashlib.sha256(files[path]).hexdigest() != expected:
            raise ValueError('Packaged file checksum differs: ' + path)
    manifest = json.loads(files['plugin/plugin.json'])
    if not isinstance(manifest, dict) or manifest.get('name') != 'progress-checker' or manifest.get('version') != expected_version:
        raise ValueError('Plugin identity/version differs from reviewed candidate')
    inventory = json.loads(files['plugin/third-party/inventory.json'])
    if not isinstance(inventory, dict) or inventory.get('workspace_version') != expected_version:
        raise ValueError('Dependency inventory workspace version differs')
    for name in ('checker-global', 'checker-plugin', 'progress-checker', 'progress-checker-mcp'):
        if executable_modes['plugin/bin/' + name] & 0o111 == 0:
            raise ValueError('Packaged entry point is not executable: ' + name)
    # Check retained historical inputs without changing or treating them as candidate evidence.
    plan = json.loads((ROOT / '.progress-checker/plugin-plan.json').read_text())
    preserved = []
    for key in ('acceptance_archive', 'acceptance_old_archive', 'global_archive', 'native_onboarding_release'):
        entry = plan[key]
        relative = entry.get('path', entry.get('archive_path'))
        retained = ROOT / relative
        if bounded_archive_hash(retained) != entry['sha256']:
            raise ValueError('Frozen archive changed: ' + relative)
        preserved.append(relative)
    if bounded_archive_hash(archive) != actual:
        raise ValueError('Archive changed across inspection')
    return {'schema_version': 1, 'archive_sha256': actual, 'version': expected_version,
            'file_count': len(files), 'frozen_archives_preserved': preserved,
            'coverage': 'static archive integrity only', 'runtime_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    try:
        result = inspect_archive(args.archive, args.sha256, args.version)
    except (ValueError, KeyError, OSError, tarfile.TarError, json.JSONDecodeError) as error:
        parser.exit(1, 'FAIL: ' + str(error) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
