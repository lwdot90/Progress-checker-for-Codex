#!/usr/bin/env python3
"""Stage a native Git plugin payload, or its separately pinned marketplace.

Payload: --package EXTRACTED_PACKAGE --output NEW_DIRECTORY
Catalog: --sha FULL_ARTIFACT_COMMIT --output NEW_DIRECTORY [--source-url URL]
Neither mode runs package code, installs a plugin, or performs Git/network work.
Commit the payload first; generate the catalog with that commit's full SHA.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import urllib.parse

SOURCE_URL = 'https://github.com/lwdot90/Progress-checker-for-Codex.git'
PLUGIN_PATH = 'native/linux-x86_64/progress-checker'
SCHEMA = 'https://agent-plugins.org/schemas/1.0.0'
EXECUTABLES = (
    'checker-global', 'checker-plugin', 'checker-project',
    'progress-checker', 'progress-checker-mcp',
)
EXCLUDED = {'.git', '.local', '.codex', '.progress-checker', '__pycache__'}


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON key: ' + key)
        value[key] = item
    return value


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=strict_object)


def relative_path(value):
    if (not isinstance(value, str) or not value or '\\' in value
            or '\0' in value or PurePosixPath(value).is_absolute()
            or PurePosixPath(value).as_posix() != value
            or any(part in ('.', '..') for part in value.split('/'))):
        raise ValueError('Invalid relative inventory path')
    return value


def files_in(root):
    files, total = {}, 0

    def visit(directory):
        nonlocal total
        for path in sorted(directory.iterdir()):
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if path.name in EXCLUDED or path.suffix == '.pyc':
                raise ValueError('Excluded package path: ' + relative)
            if stat.S_ISDIR(info.st_mode):
                visit(path)
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
                if (len(files) >= 4096 or info.st_size > 64 * 1024 * 1024
                        or total > 128 * 1024 * 1024):
                    raise ValueError('Package exceeds preparation bounds')
                if stat.S_IMODE(info.st_mode) not in (0o644, 0o755):
                    raise ValueError('Package files must have mode 0644 or 0755: ' + relative)
                files[relative] = path
            else:
                raise ValueError('Package contains a symlink or special file: ' + relative)
    visit(root)
    return files


def validate_package(package):
    if package.is_symlink() or not package.is_dir():
        raise ValueError('--package must be a real extracted package directory')
    package = package.resolve(strict=True)
    files = files_in(package)
    checksums_path = files.get('checksums.json')
    if checksums_path is None or checksums_path.stat().st_size > 1024 * 1024:
        raise ValueError('Package needs a bounded checksums.json')
    checksums = read_json(checksums_path)
    if not isinstance(checksums, dict) or set(checksums) != set(files) - {'checksums.json'}:
        raise ValueError('Package checksums must cover every payload file exactly')
    for name, digest in checksums.items():
        relative_path(name)
        if (not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest)
                or hashlib.sha256(files[name].read_bytes()).hexdigest() != digest):
            raise ValueError('Package checksum mismatch: ' + name)
    required = {
        'plugin/plugin.json', 'plugin/LICENSE', 'plugin/NOTICE',
        'plugin/THIRD_PARTY_NOTICES.md', 'plugin/third-party/inventory.json',
        'plugin/skills/progress-checker/SKILL.md',
        *('plugin/bin/' + name for name in EXECUTABLES),
    }
    if required - set(files):
        raise ValueError('Package is missing required native files: ' + ', '.join(sorted(required - set(files))))
    for name in EXECUTABLES:
        if stat.S_IMODE(files['plugin/bin/' + name].stat().st_mode) != 0o755:
            raise ValueError('Native executable must have mode 0755: ' + name)
    manifest = read_json(files['plugin/plugin.json'])
    version = manifest.get('version')
    if (manifest.get('name') != 'progress-checker'
            or manifest.get('$schema') != SCHEMA + '/plugin.schema.json'
            or not isinstance(version, str)
            or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+[-.A-Za-z0-9]*', version)):
        raise ValueError('Package must have the portable Progress Checker manifest and version')
    # Inspect syntax only: never import or execute a packaged launcher.
    tree = ast.parse(files['plugin/bin/checker-global'].read_bytes())
    options = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
               and isinstance(node.func, ast.Attribute) and node.func.attr == 'add_argument'
               and any(isinstance(arg, ast.Constant) and arg.value == '--state-dir' for arg in node.args)]
    if (len(options) != 1 or any(keyword.arg == 'required'
            and not (isinstance(keyword.value, ast.Constant) and keyword.value.value is False)
            for keyword in options[0].keywords)):
        raise ValueError('Global gateway must support omitted --state-dir before native preparation')
    inventory = read_json(files['plugin/third-party/inventory.json'])
    for entry in inventory['packages'] + [inventory['rust_standard_library']]:
        for name, digest in entry['files_sha256'].items():
            name = 'plugin/third-party/' + relative_path(name)
            if name not in files or hashlib.sha256(files[name].read_bytes()).hexdigest() != digest:
                raise ValueError('Dependency license inventory mismatch: ' + name)
    return package, version, checksums_path


def fresh_output(output):
    if output.exists() or output.is_symlink():
        raise ValueError('--output must not already exist')
    return output.absolute()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o644)


def prepare_payload(package, output):
    output = fresh_output(output)
    package, version, checksums_path = validate_package(package)
    if output.resolve() == package or package in output.resolve().parents:
        raise ValueError('--output must be outside the input package')
    output.mkdir(parents=True)
    try:
        target = output / PLUGIN_PATH
        shutil.copytree(package / 'plugin', target)
        write_json(target / 'mcp.json', {
            '$schema': SCHEMA + '/mcp.schema.json',
            'mcpServers': {'progress_checker': {
                'type': 'stdio', 'command': './bin/checker-global', 'args': [],
            }},
        })
        receipt = {
            'schema_version': 1, 'plugin_version': version, 'plugin_path': PLUGIN_PATH,
            'package_checksums_sha256': hashlib.sha256(checksums_path.read_bytes()).hexdigest(),
            'generated_files': ['mcp.json'],
            'files': [{'path': name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                       'mode': oct(stat.S_IMODE(path.stat().st_mode))}
                      for name, path in files_in(target).items()],
        }
        write_json(output / 'NATIVE_PAYLOAD.json', receipt)
        return receipt
    except BaseException:
        shutil.rmtree(output)
        raise


def prepare_catalog(sha, source_url, output):
    if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-fA-F]{40}', sha):
        raise ValueError('--sha must be the full 40-hex artifact commit')
    url = urllib.parse.urlsplit(source_url)
    if (url.scheme != 'https' or not url.hostname or url.username is not None
            or url.password is not None or url.query or url.fragment or not url.path.strip('/')):
        raise ValueError('--source-url must be an HTTPS Git URL without credentials, query or fragment')
    output = fresh_output(output)
    catalog = {
        'name': 'progress-global', 'interface': {'displayName': 'Progress Checker'},
        'plugins': [{
            'name': 'progress-checker',
            'description': 'Track project milestones with current local check evidence.',
            'source': {'source': 'git-subdir', 'url': source_url,
                       'path': './' + PLUGIN_PATH, 'sha': sha.lower()},
            'policy': {'installation': 'AVAILABLE', 'authentication': 'ON_INSTALL'},
            'category': 'Productivity',
        }],
    }
    output.mkdir(parents=True)
    try:
        write_json(output / '.agents/plugins/marketplace.json', catalog)
        return catalog
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--package', type=Path, help='Extracted self-contained release package')
    mode.add_argument('--sha', help='Full commit containing the separately committed native payload')
    parser.add_argument('--output', required=True, type=Path, help='New staging directory; must not exist')
    parser.add_argument('--source-url', default=SOURCE_URL, help='HTTPS Git source for catalog mode')
    args = parser.parse_args()
    try:
        if args.package is not None:
            if args.source_url != SOURCE_URL:
                parser.error('--source-url applies only with --sha')
            value = prepare_payload(args.package, args.output)
        else:
            value = prepare_catalog(args.sha, args.source_url, args.output)
    except (ValueError, OSError, KeyError, TypeError, SyntaxError) as error:
        parser.error(str(error))
    print(json.dumps(value, indent=2))


if __name__ == '__main__':
    main()
