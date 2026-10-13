"""One source version, with compiled binaries checked before creating an archive."""
import json
import re
import subprocess
import tomllib


def source_version(root):
    cargo = tomllib.loads((root / 'Cargo.toml').read_text())['workspace']['package']['version']
    plugin = json.loads((root / 'plugins/progress-checker/plugin.json').read_text())['version']
    if cargo != plugin or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+[-.A-Za-z0-9]*', cargo):
        raise ValueError('Cargo and plugin manifest versions must match a safe release version')
    return cargo


def binary_versions(directory, expected):
    for name in ('progress-checker', 'progress-checker-mcp'):
        path = directory / name
        result = subprocess.run([str(path), '--version'], check=True, capture_output=True, text=True, timeout=10)
        if result.stdout.strip() != name + ' ' + expected:
            raise ValueError('Built ' + name + ' version differs from the source manifest; rebuild before packaging')
