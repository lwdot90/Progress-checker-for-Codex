#!/usr/bin/env python3
"""Collect explicit native build artifact metadata, never private state/logs."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
from windows_artifact_process import inspect_version

ROOT = Path(__file__).resolve().parent.parent


def main():
    if os.name != 'nt':
        raise SystemExit('Collect only on native Windows')
    binaries = {}
    for name in ('progress-checker', 'progress-checker-mcp', 'checker-global'):
        path = ROOT / '.local/checker-target/debug' / (name + '.exe')
        if not path.is_file() or path.is_symlink():
            binaries[name] = {'built': False}
            continue
        digest = hashlib.sha256()
        with path.open('rb') as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(chunk)
        try:
            version = inspect_version(str(path)).strip()
            if not re.fullmatch(re.escape(name) + r' [0-9]+\.[0-9]+\.[0-9]+[-.A-Za-z0-9]*', version):
                binaries[name] = {'built': True, 'sha256': digest.hexdigest(), 'version_probe': 'unexpected output withheld'}
            else:
                binaries[name] = {'built': True, 'sha256': digest.hexdigest(), 'version': version}
        except Exception:
            # OS errors and executable text can contain private local paths.
            binaries[name] = {'built': True, 'sha256': digest.hexdigest(), 'version_probe': 'failed; details withheld'}
    receipt = {'schema_version': 1, 'platform': {'system': platform.system(), 'release': platform.release(),
                                               'version': platform.version(), 'architecture': platform.machine()},
               'binaries': binaries, 'qualified': False, 'approval_executed': False, 'checks_executed': False,
               'blocked_expected': ['native activation backend', 'qualified approval authority',
                                    'native check sandbox', 'qualified installation/update'],
               'data_collection': 'explicit OS metadata and owned build artifacts only; no private logs or state'}
    destination = ROOT / '.local/windows-trial/diagnostics.json'
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('x', encoding='utf-8') as output:
        json.dump(receipt, output, indent=2); output.write('\n')
    print('Saved safe trial diagnostics. Review .local/windows-trial/diagnostics.json before sharing.')


if __name__ == '__main__':
    main()
