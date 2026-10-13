#!/usr/bin/env python3
"""Stage an unqualified native Windows development ZIP from native binaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import zipfile
from package_version import source_version
from windows_artifact_process import inspect_version

ROOT = Path(__file__).resolve().parent.parent


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def windows_image(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Missing regular native Windows file: {path}')
    with path.open('rb') as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b'MZ':
            raise ValueError(f'Not a PE executable: {path}')
        stream.seek(struct.unpack_from('<I', header, 60)[0])
        signature = stream.read(6)
        if signature != b'PE\x00\x00\x64\x86':
            raise ValueError(f'Expected Windows x86_64 PE image: {path}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, required=True,
                        help='Native progress-checker.exe, progress-checker-mcp.exe and checker-global.exe')
    parser.add_argument('--runtime-dll', type=Path, action='append', default=[],
                        help='Include each audited non-system runtime DLL required by these binaries')
    parser.add_argument('--runtime-dll-license', action='append', default=[],
                        metavar='DLL_NAME=LICENSE_PATH',
                        help='Required redistribution license material for each supplied runtime DLL')
    parser.add_argument('--output', type=Path, default=ROOT / '.local/windows-package')
    args = parser.parse_args()
    if os.name != 'nt':
        raise SystemExit('Run on native Windows: compiled version checks must execute on the target OS')
    version = source_version(ROOT)
    binaries = [args.bin_dir / (name + '.exe') for name in
                ('progress-checker', 'progress-checker-mcp', 'checker-global')]
    for binary in binaries:
        windows_image(binary)
        response = inspect_version(str(binary.resolve()))
        if response.strip() != binary.stem + ' ' + version:
            raise ValueError(f'Native binary version differs from source: {binary.name}')
    names = {binary.name.casefold() for binary in binaries}
    for dll in args.runtime_dll:
        windows_image(dll)
        if dll.suffix.lower() != '.dll' or dll.name.casefold() in names:
            raise ValueError(f'Invalid or duplicate runtime DLL: {dll}')
        names.add(dll.name.casefold())
    dll_licenses = {}
    for specification in args.runtime_dll_license:
        name, separator, raw = specification.partition('=')
        key = name.casefold()
        license_path = Path(raw)
        if not separator or key in dll_licenses or not license_path.is_file() or license_path.is_symlink():
            raise ValueError('Each DLL license must be a unique DLL_NAME=regular-file entry')
        if license_path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('DLL license material exceeds 4 MiB bound')
        dll_licenses[key] = license_path
    if set(dll_licenses) != {path.name.casefold() for path in args.runtime_dll}:
        raise ValueError('Every supplied runtime DLL requires exactly one redistribution license file')
    source_plugin = ROOT / 'plugins/progress-checker'
    if any(path.is_symlink() for path in source_plugin.rglob('*')):
        raise ValueError('Plugin staging rejects symlinks')
    inventory_path = source_plugin / 'third-party/inventory.json'
    inventory = json.loads(inventory_path.read_text())
    if inventory['cargo_lock_sha256'] != file_sha256(ROOT / 'Cargo.lock'):
        raise ValueError('Dependency license inventory is stale')
    for entry in inventory['packages'] + [inventory['rust_standard_library']]:
        for relative, expected in entry['files_sha256'].items():
            path = inventory_path.parent / relative
            if not path.resolve().is_relative_to(inventory_path.parent.resolve()) or path.is_symlink():
                raise ValueError(f'License material must remain within third-party: {relative}')
            if not path.is_file() or file_sha256(path) != expected:
                raise ValueError(f'Dependency license material missing or changed: {relative}')
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / f'progress-checker-{version}-windows-x86_64-development.zip'
    if archive.exists():
        raise ValueError(f'Refusing to overwrite archive: {archive}')
    with tempfile.TemporaryDirectory(dir=args.output) as temporary:
        package = Path(temporary) / archive.stem
        plugin = package / 'plugin'
        shutil.copytree(ROOT / 'plugins/progress-checker', plugin,
                        ignore=shutil.ignore_patterns('bin', '__pycache__', '*.pyc', 'mcp.json'))
        (plugin / 'bin').mkdir()
        for binary in binaries + args.runtime_dll:
            shutil.copyfile(binary, plugin / 'bin' / binary.name)
        if dll_licenses:
            license_directory = plugin / 'third-party' / 'windows-runtime'
            license_directory.mkdir()
            for dll_name, license_path in dll_licenses.items():
                shutil.copyfile(license_path, license_directory / (dll_name + '.license.txt'))
        (plugin / 'mcp.json').write_text(json.dumps({
            '$schema': 'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json',
            'mcpServers': {'progress_checker': {'type': 'stdio',
                'command': './bin/checker-global.exe', 'args': []}},
        }, indent=2) + '\n')
        for name in ('LICENSE', 'NOTICE'):
            shutil.copyfile(ROOT / name, package / name)
            shutil.copyfile(ROOT / name, plugin / name)
        shutil.copyfile(ROOT / 'docs/WINDOWS.md', package / 'README.md')
        (package / 'support-status.json').write_text(json.dumps({
            'platform': 'windows-x86_64', 'version': version,
            'status': 'development archive; native runtime and installation qualification required',
            'qualified': False, 'dll_dependency_audit_required': True,
            'dll_dependency_audit_performed': False,
            'recipient_python_required': False,
            'runtime_dlls': [path.name for path in args.runtime_dll],
            'runtime_dll_license_files_present': True,
            'binaries': [path.name for path in binaries],
        }, indent=2) + '\n')
        checksums = {str(path.relative_to(package)).replace('\\', '/'):
                     file_sha256(path)
                     for path in sorted(package.rglob('*')) if path.is_file()}
        (package / 'checksums.json').write_text(json.dumps(checksums, indent=2) + '\n')
        staged_archive = Path(temporary) / archive.name
        with zipfile.ZipFile(staged_archive, 'w', zipfile.ZIP_DEFLATED) as output:
            for path in sorted(package.rglob('*')):
                if path.is_file():
                    output.write(path, str(path.relative_to(package.parent)))
        # Create-only publication never overwrites a concurrent destination.
        try:
            with archive.open('xb') as destination, staged_archive.open('rb') as source:
                shutil.copyfileobj(source, destination)
        except Exception:
            # Do not unlink: another actor may have won exclusive creation.
            raise
    print(json.dumps({'archive': str(archive), 'version': version,
                      'sha256': file_sha256(archive),
                      'qualified': False}, indent=2))


if __name__ == '__main__':
    main()
