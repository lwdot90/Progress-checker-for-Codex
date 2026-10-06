#!/usr/bin/env python3
"""Package already-built executables; recipients do not need Rust or this source."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import shutil
import tarfile

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=root / '.local/plugin-build')
args = parser.parse_args()
version = json.loads((root / 'plugins/progress-checker/plugin.json').read_text())['version']
if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+[-.A-Za-z0-9]*', version):
    raise SystemExit('Manifest version is not a safe release version')
inventory_path = root / 'plugins/progress-checker/third-party/inventory.json'
if not inventory_path.is_file():
    raise SystemExit('Generate dependency notices first: python3 scripts/generate-plugin-notices.py')
inventory = json.loads(inventory_path.read_text())
if inventory['cargo_lock_sha256'] != hashlib.sha256((root / 'Cargo.lock').read_bytes()).hexdigest():
    raise SystemExit('Dependency notices are stale; run python3 scripts/generate-plugin-notices.py')
for entry in inventory['packages'] + [inventory['rust_standard_library']]:
    for relative, expected in entry['files_sha256'].items():
        path = inventory_path.parent / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit(f'Dependency license material changed or missing: {relative}')
package = args.output.resolve() / f'progress-checker-{version}-linux-x86_64'
if package.exists():
    shutil.rmtree(package)
package.mkdir(parents=True)
shutil.copytree(root / 'plugins/progress-checker', package / 'plugin', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
shutil.copyfile(root / 'plugins/install.py', package / 'install.py')
shutil.copyfile(root / 'plugins/README.md', package / 'README.md')
for name in ('LICENSE', 'NOTICE'):
    shutil.copyfile(root / name, package / name)
    shutil.copyfile(root / name, package / 'plugin' / name)
notice_text = (root / 'plugins/progress-checker/THIRD_PARTY_NOTICES.md').read_text()
# The installed plugin keeps its notice links relative to its own directory;
# the archive's convenience copy points at the same material under plugin/.
(package / 'THIRD_PARTY_NOTICES.md').write_text(notice_text.replace('third-party/', 'plugin/third-party/'))
for name in ('progress-checker', 'progress-checker-mcp'):
    binary = root / '.local/checker-target/debug' / name
    if not binary.is_file():
        raise SystemExit(f'Build the checker first: missing {binary}')
    shutil.copyfile(binary, package / 'plugin/bin' / name)
for binary in (package / 'plugin/bin').iterdir():
    binary.chmod(0o755)
checksums = {str(path.relative_to(package)): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(package.rglob('*')) if path.is_file()}
(package / 'checksums.json').write_text(json.dumps(checksums, indent=2) + '\n')
archive = package.parent / (package.name + '.tar.gz')
with tarfile.open(archive, 'w:gz') as output:
    output.add(package, arcname=package.name)
print(json.dumps({'package': str(package), 'archive': str(archive),
    'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
    'status': 'development package with dependency notices; release qualification remains planned'}, indent=2))
