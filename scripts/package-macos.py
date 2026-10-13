#!/usr/bin/env python3
"""Stage an experimental native macOS artifact; this does not qualify a release."""
import argparse
import hashlib
import json
import platform
import os
import select
import signal
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import time
from pathlib import Path

from package_version import source_version


def file_hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def macho_arch(path):
    """Reject Linux executables and ambiguous universal binaries."""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'{path}: expected a regular native executable')
    with path.open('rb') as handle:
        header = handle.read(8)
    if len(header) != 8 or header[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError(f'{path}: expected a thin 64-bit Mach-O executable')
    cpu = struct.unpack('<I', header[4:])[0]
    architectures = {0x01000007: 'x86_64', 0x0100000c: 'aarch64'}
    if cpu not in architectures:
        raise ValueError(f'{path}: unsupported Mach-O architecture')
    return architectures[cpu]


def native_versions(directory, expected):
    for name in ('progress-checker', 'progress-checker-mcp'):
        data = bytearray()
        deadline = time.monotonic() + 10
        child = subprocess.Popen([str(directory / name), '--version'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([child.stdout], [], [], remaining)[0]:
                    raise subprocess.TimeoutExpired(name, 10)
                chunk = os.read(child.stdout.fileno(), 513)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > 512:
                    raise ValueError(f'{name}: excessive native version output')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(name, 10)
            if child.wait(timeout=remaining) != 0:
                raise ValueError(f'{name}: native version command failed')
        finally:
            # Bound ordinary descendants holding the output pipe too. This is
            # packaging hygiene, not proof of sandbox execution containment.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=2)
            child.stdout.close()
        if data.decode('utf-8').strip() != name + ' ' + expected:
            raise ValueError(f'{name}: unexpected or excessive native version output')


def runtime_identity(path):
    """Preflight the current inventory contract, without asserting dependency closure."""
    before = path.stat()
    if (path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_uid != 0
            or before.st_mode & 0o022 or before.st_size > 256 * 1024 * 1024):
        raise ValueError(f'Untrusted or oversized macOS runtime identity: {path}')
    digest = hashlib.sha256()
    count = 0
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > before.st_size:
                raise ValueError(f'macOS runtime identity grew during reading: {path}')
            digest.update(chunk)
    after = path.stat()
    if count != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError(f'macOS runtime identity changed during reading: {path}')
    return {'path': str(path), 'sha256': digest.hexdigest(), 'size': before.st_size}


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True,
                        choices=('aarch64-apple-darwin', 'x86_64-apple-darwin'))
    parser.add_argument('--binary-dir', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=root / '.local/macos-build')
    parser.add_argument('--python', type=Path, default=Path(sys.executable),
                        help='Python 3.11+ absolute path on the recipient host')
    args = parser.parse_args()
    if platform.system() != 'Darwin':
        parser.error('Packaging requires a native macOS host to inspect and execute the binaries')
    architecture = args.target.split('-')[0]
    host = {'arm64': 'aarch64', 'x86_64': 'x86_64'}.get(platform.machine())
    if architecture != host:
        parser.error('Target must match the native packaging host; qualify each architecture separately')
    python = args.python.resolve(strict=True)
    if not python.is_file() or any(character.isspace() for character in str(python)):
        parser.error('Python must be a regular executable with a shebang-safe absolute path')
    subprocess.run([str(python), '-c', 'import sys; assert sys.version_info >= (3, 11)'],
                   check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    version = source_version(root)
    binaries = args.binary_dir.resolve(strict=True)
    for name in ('progress-checker', 'progress-checker-mcp'):
        if macho_arch(binaries / name) != architecture:
            parser.error(f'{name} architecture differs from --target')
    native_versions(binaries, version)
    runtime_identities = [runtime_identity(Path(path)) for path in (
        '/System/Library/CoreServices/SystemVersion.plist', '/usr/lib/dyld')]
    inventory_path = root / 'plugins/progress-checker/third-party/inventory.json'
    inventory = json.loads(inventory_path.read_text())
    if inventory['cargo_lock_sha256'] != file_hash(root / 'Cargo.lock'):
        parser.error('Dependency notices are stale; regenerate before packaging')
    for entry in inventory['packages'] + [inventory['rust_standard_library']]:
        for relative, expected in entry['files_sha256'].items():
            material = inventory_path.parent / relative
            if (material.is_symlink() or not material.is_file()
                    or not material.resolve().is_relative_to(inventory_path.parent.resolve())):
                parser.error(f'Dependency license path is not regular contained material: {relative}')
            if file_hash(material) != expected:
                parser.error(f'Dependency license material changed: {relative}')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    package = output / f'progress-checker-{version}-macos-{architecture}-experimental'
    archive = output / (package.name + '.tar.gz')
    if archive.exists():
        raise FileExistsError(f'Refuse to replace existing archive: {archive}')
    plugin_source = root / 'plugins/progress-checker'
    if plugin_source.is_symlink() or not plugin_source.is_dir():
        parser.error('Plugin source must be a real directory')
    for path in plugin_source.rglob('*'):
        mode = path.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            parser.error(f'Refuse symbolic links or special files in staged plugin: {path}')
    # Never remove an existing artifact implicitly.
    package.mkdir()
    shutil.copytree(root / 'plugins/progress-checker', package / 'plugin',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for name in ('progress-checker', 'progress-checker-mcp'):
        shutil.copy2(binaries / name, package / 'plugin/bin' / name)
    for name in ('checker-global', 'checker-plugin', 'checker-project'):
        wrapper = package / 'plugin/bin' / name
        lines = wrapper.read_text().splitlines(keepends=True)
        lines[0] = f'#!{python}\n'
        wrapper.write_text(''.join(lines))
        wrapper.chmod(0o755)
    for name in ('LICENSE', 'NOTICE'):
        shutil.copy2(root / name, package / name)
        shutil.copy2(root / name, package / 'plugin' / name)
    shutil.copy2(root / 'docs/MACOS.md', package / 'README.md')
    metadata = {'version': version, 'target': args.target, 'python': str(python),
                'qualification': 'unverified', 'distribution': 'experimental',
                'minimum_macos': 'not established', 'signed': False, 'notarized': False,
                'runtime_identity_contract': runtime_identities,
                'dependency_closure_qualified': False}
    (package / 'platform.json').write_text(json.dumps(metadata, indent=2) + '\n')
    checksums = {str(path.relative_to(package)): file_hash(path)
                 for path in sorted(package.rglob('*')) if path.is_file()}
    (package / 'checksums.json').write_text(json.dumps(checksums, indent=2) + '\n')
    with tarfile.open(archive, 'x:gz') as handle:
        handle.add(package, arcname=package.name)
    print(json.dumps({'archive': str(archive), 'qualification': 'unverified',
                      'sha256': file_hash(archive)}, indent=2))


if __name__ == '__main__':
    main()
