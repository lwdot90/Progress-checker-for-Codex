#!/usr/bin/env python3
"""Preserve local Cargo dependency notices for the backend plugin package.

This reads cached manifests and license files, without invoking Cargo or fetching
dependencies. The inventory deliberately covers the whole lockfile, including
build-only and other-target crates, rather than guessing a linked-binary SBOM.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tomllib


ROOT = Path(__file__).resolve().parent.parent
LEGAL_NAME = re.compile(r"^(?:licen[sc]e|copying|copyright|notice|authors)(?:$|[-_.])", re.I)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registry', type=Path, default=ROOT / '.local/cargo/registry/src')
    parser.add_argument('--rust-docs', type=Path, default=ROOT / '.local/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/share/doc/rust')
    args = parser.parse_args()
    lock_path = ROOT / 'Cargo.lock'
    lock = tomllib.loads(lock_path.read_text())
    workspace = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']
    apache = args.rust_docs / 'licenses/Apache-2.0.txt'
    llvm = args.rust_docs / 'licenses/LLVM-exception.txt'
    library_copyright = args.rust_docs / 'COPYRIGHT-library.html'
    for required in (apache, llvm, library_copyright):
        if not required.is_file():
            raise SystemExit(f'Missing installed Rust license material: {required}')
    destination = ROOT / 'plugins/progress-checker/third-party'
    staging = destination.with_name('third-party-generating')
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    packages = []
    try:
        for package in sorted(lock['package'], key=lambda item: (item['name'], item['version'])):
            if 'source' not in package:
                continue
            if not package['source'].startswith('registry+'):
                raise SystemExit(f'Unreviewed non-registry dependency: {package["name"]}')
            identity = f'{package["name"]}-{package["version"]}'
            candidates = list(args.registry.glob(f'*/{identity}/Cargo.toml'))
            if len(candidates) != 1:
                raise SystemExit(f'Expected one cached manifest for {identity}, found {len(candidates)}')
            source = candidates[0].parent
            metadata = tomllib.loads(candidates[0].read_text())['package']
            if not metadata.get('license'):
                raise SystemExit(f'Missing declared license: {identity}')
            output = staging / 'crates' / identity
            output.mkdir(parents=True)
            legal_files = [path for path in source.rglob('*')
                           if path.is_file() and LEGAL_NAME.match(path.name)
                           and path.suffix.lower() not in ('.rs', '.py')]
            if metadata.get('license-file'):
                explicit = source / metadata['license-file']
                if not explicit.is_file() or not explicit.resolve().is_relative_to(source.resolve()):
                    raise SystemExit(f'Invalid license-file: {identity}')
                if explicit not in legal_files:
                    legal_files.append(explicit)
            license_files = [path for path in legal_files
                             if re.match(r'^(?:licen[sc]e|copying)(?:$|[-_.])', path.name, re.I)]
            mode = 'upstream_files_preserved'
            selected = None
            if not license_files:
                # Some published optional UEFI/Wasm crates omit standalone texts.
                # Use an alternative explicitly granted by their Cargo metadata;
                # record that this text was supplied, not shipped by that crate.
                expression = metadata['license']
                if 'Apache-2.0 WITH LLVM-exception' in expression:
                    selected = 'Apache-2.0 WITH LLVM-exception'
                elif 'Apache-2.0' in expression.split(' OR '):
                    selected = 'Apache-2.0'
                else:
                    raise SystemExit(f'License text needs review: {identity}: {expression}')
                text = apache.read_bytes()
                if selected.endswith('LLVM-exception'):
                    text += b'\n\n' + llvm.read_bytes()
                (output / 'LICENSE-SUPPLIED').write_bytes(text)
                mode = 'declared_alternative_with_supplied_standard_text'
                readme = source / 'README.md'
                if readme.is_file():
                    shutil.copyfile(readme, output / 'UPSTREAM-README.md')
            for path in sorted(legal_files):
                relative = path.relative_to(source)
                target = output / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
            retained = {str(path.relative_to(staging)): digest(path)
                        for path in sorted(output.rglob('*')) if path.is_file()}
            packages.append({
                'name': package['name'], 'version': package['version'],
                'source': package['source'], 'cargo_checksum': package['checksum'],
                'declared_license': metadata['license'],
                'authors': metadata.get('authors', []),
                'repository': metadata.get('repository'),
                'license_material': mode, 'selected_alternative': selected,
                'files_sha256': retained,
            })
        rust = staging / 'rust-standard-library'
        rust.mkdir()
        shutil.copyfile(library_copyright, rust / library_copyright.name)
        shutil.copytree(args.rust_docs / 'licenses', rust / 'licenses')
        inventory = {
            'schema_version': 1, 'scope': 'complete_backend_cargo_lock_not_linked_binary_sbom',
            'workspace_version': workspace['version'], 'workspace_license': workspace['license'],
            'cargo_lock_sha256': digest(lock_path), 'external_package_count': len(packages),
            'packages': packages,
            'rust_standard_library': {
                'toolchain': '1.95.0-x86_64-unknown-linux-gnu',
                'scope': 'installed_standard_library_copyright_and_license_material; compiler not bundled',
                'files_sha256': {str(path.relative_to(staging)): digest(path)
                                 for path in sorted(rust.rglob('*')) if path.is_file()},
            },
        }
        (staging / 'inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
        if destination.exists():
            shutil.rmtree(destination)
        staging.rename(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    supplied = sum(item['selected_alternative'] is not None for item in packages)
    lines = [
        '# Third-party notices for Progress Checker', '',
        'The backend and native plugin are licensed under Apache-2.0; see `LICENSE`.',
        'Third-party components retain their own licenses and copyright notices.', '',
        f'This inventory covers all **{len(packages)} external packages** in the backend `Cargo.lock`.',
        'It includes build, test, optional, and other-platform dependencies and is not a claim that',
        'every listed crate is linked into the Linux executables. Four local workspace crates',
        'are covered by the project license. The Codex fork, Codex executable, Rust compiler,',
        'Python, Git, bubblewrap, and system libraries are not distributed in this package.', '',
        '`third-party/inventory.json` records exact versions, declared license expressions,',
        'registry checksums, and hashes of the retained notice files. The lockfile digest binds',
        'this inventory to its reviewed dependency resolution. Rebuild these notices when',
        'that resolution changes with `python3 scripts/generate-plugin-notices.py`.', '',
        'Original license, copyright, notice, and author files are retained verbatim under',
        '`third-party/crates/`. Dual-license alternatives are preserved; mandatory combined',
        'terms such as unicode-ident\'s Unicode-3.0 license are included.',
        f'For {supplied} cached packages that omit standalone license text, `LICENSE-SUPPLIED`',
        'provides the standard Apache-2.0 text (with LLVM exception where declared), selected',
        'from the package\'s explicit Cargo license alternatives. These files are labeled in',
        'the inventory and are not represented as original files shipped by those crates.', '',
        'The installed Rust 1.95.0 standard-library copyright document and its license texts',
        'are under `third-party/rust-standard-library/`. This preserves linked-library',
        'attribution without claiming that the complete toolchain is distributed.', '',
        'System dependencies must be supplied by the recipient\'s operating system. This',
        'inventory does not qualify another target, a changed toolchain, a different link',
        'configuration, or a future dependency update. The release archive remains subject',
        'to the project\'s separate behavioral and distribution acceptance gates.', '',
        '| Crate | Version | Declared license | Retained material |',
        '| --- | --- | --- | --- |',
    ]
    for item in packages:
        identity = f'{item["name"]}-{item["version"]}'
        mode = 'supplied declared alternative' if item['selected_alternative'] else 'upstream files'
        lines.append(f'| {item["name"]} | {item["version"]} | {item["declared_license"]} | [{mode}](third-party/crates/{identity}/) |')
    (destination.parent / 'THIRD_PARTY_NOTICES.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps({'external_packages': len(packages), 'supplied_license_texts': supplied,
                      'inventory': str(destination / 'inventory.json')}, indent=2))


if __name__ == '__main__':
    main()
