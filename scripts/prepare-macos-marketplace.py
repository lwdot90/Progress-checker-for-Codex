#!/usr/bin/env python3
"""Stage experimental macOS payload/specifications, never publish or install."""
import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import urllib.parse
from pathlib import Path

from package_version import source_version

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('native_preparation', ROOT / 'scripts/prepare-native-marketplace.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
    path.chmod(0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True, help='Extracted experimental macOS archive')
    parser.add_argument('--architecture', choices=('aarch64', 'x86_64'), required=True)
    parser.add_argument('--sha', required=True, help='Full future payload commit; independently review before publishing')
    parser.add_argument('--source-url', default=native.SOURCE_URL)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-fA-F]{40}', args.sha):
        parser.error('Payload commit requires full 40-hex SHA')
    url = urllib.parse.urlsplit(args.source_url)
    if (url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None
            or url.query or url.fragment or not url.path.strip('/')):
        parser.error('Source URL requires credential-free HTTPS Git URL')
    package, version, checksums = native.validate_package(args.package)
    if version != source_version(ROOT):
        parser.error('Package version differs from current source candidate')
    platform = native.read_json(package / 'platform.json')
    if (platform.get('target') != args.architecture + '-apple-darwin'
            or platform.get('version') != version or platform.get('qualification') != 'unverified'
            or platform.get('distribution') != 'experimental'):
        parser.error('Package must carry matching unverified native macOS architecture metadata')
    inventory = native.read_json(package / 'plugin/third-party/inventory.json')
    if inventory.get('cargo_lock_sha256') != hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest():
        parser.error('Dependency inventory must be regenerated for the current source lockfile')
    output = native.fresh_output(args.output)
    if output.resolve().is_relative_to(package):
        parser.error('Output must be outside input package')
    output.mkdir(parents=True)
    payload_path = f'native/macos-{args.architecture}/progress-checker'
    target = output / payload_path
    shutil.copytree(package / 'plugin', target)
    write_json(target / 'mcp.json', {
        '$schema': native.SCHEMA + '/mcp.schema.json',
        'mcpServers': {'progress_checker': {'type': 'stdio', 'command': './bin/checker-global', 'args': []}}})
    marketplace = f'progress-macos-{args.architecture}-experimental'
    selector = 'progress-checker@' + marketplace
    catalog = {'name': marketplace, 'plugins': [{'name': 'progress-checker',
               'description': 'Unqualified native macOS engineering candidate; do not install for normal use.',
               'source': {'source': 'git-subdir', 'url': args.source_url,
                          'path': './' + payload_path, 'sha': args.sha.lower()},
               'policy': {'installation': 'AVAILABLE', 'authentication': 'ON_INSTALL'},
               'category': 'Productivity'}]}
    # Deliberately not an active .agents/plugins/marketplace.json: Codex has no
    # established architecture-selection contract in this engineering scaffold.
    write_json(output / 'MACOS_MARKETPLACE_PROPOSAL.json', {
        'schema_version': 1, 'version': version, 'architecture': args.architecture,
        'runtime_profile': 'macos-native-execution-disabled-v1', 'catalog_proposal': catalog,
        'publish_ready': False, 'install_ready': False, 'existing_linux_catalog_changed': False,
        'package_checksums_sha256': hashlib.sha256(checksums.read_bytes()).hexdigest(),
        'qualification_required': ['native gateway lifecycle', 'human approval broker',
                                   'sandbox descendant containment', 'fresh recipient install/update/remove'],
        'files': [{'path': name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                  for name, path in native.files_in(target).items()],
        'lifecycle_commands_proposal': {
            'install': ['codex', 'plugin', 'add', selector, '--json'],
            'update': ['codex', 'plugin', 'remove', selector, '--json'],
            'update_followup': ['codex', 'plugin', 'add', selector, '--json'],
            'remove': ['codex', 'plugin', 'remove', selector, '--json']},
        'lifecycle_policy': 'Codex owns cache; retain canonical private-state binding and project plans on update/removal; no cleanup of approvals/evidence; quiesce writer first; do not execute proposals before qualification'})
    print(json.dumps({'payload': str(target), 'proposal': str(output / 'MACOS_MARKETPLACE_PROPOSAL.json'),
                      'published': False, 'installed': False, 'qualified': False}))


if __name__ == '__main__':
    main()
