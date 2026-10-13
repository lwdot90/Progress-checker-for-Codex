#!/usr/bin/env python3
"""Create a deterministic public-source native Windows friend trial ZIP.

Does not install, publish, contact a participant, or execute build/check commands.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent.parent
DIRECTORIES = ('checker-core', 'checker-cli', 'checker-service', 'checker-mcp', 'checker-global', 'schemas', 'plugins/progress-checker')
FILES = ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'LICENSE', 'NOTICE',
         'scripts/prototype-env.sh', 'scripts/windows_artifact_process.py',
         'scripts/collect-windows-trial.py', 'docs/WINDOWS.md')

BUILD = r'''[CmdletBinding()]
param([switch]$Build)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This trial requires native Windows, not WSL.' }
$root = Split-Path -Parent $PSCommandPath
Set-Location -LiteralPath $root
# Review all instructions and source before explicitly requesting compilation.
if (-not $Build) { Write-Output 'Review WINDOWS_TRIAL.md, then run: .\build-windows-trial.ps1 -Build'; return }
$bash = Join-Path $env:ProgramFiles 'Git\bin\bash.exe'
if (-not (Test-Path -LiteralPath $bash -PathType Leaf)) { throw 'Install Git for Windows; expected Git\bin\bash.exe.' }
# Source the project environment before every Rust command. Git Bash adapts
# project-local cache paths for native rustup/cargo on Windows.
$command = @'
set -euo pipefail
source scripts/prototype-env.sh
export CARGO_HOME="$(cygpath -w "$CARGO_HOME")"
export RUSTUP_HOME="$(cygpath -w "$RUSTUP_HOME")"
export CARGO_TARGET_DIR="$(cygpath -w "$PROTOTYPE_ROOT/.local/checker-target")"
rustc --version --verbose
cargo --version
cargo check --workspace --all-targets --locked
cargo build -p checker-global -p checker-cli -p checker-mcp --locked
'@
# Never run registered acceptance checks, approval commands or a tracked project.
& $bash --noprofile --norc -c $command
if ($LASTEXITCODE -ne 0) { throw 'Native compilation failed. This is a useful result; no runtime support is inferred.' }
Write-Output 'Compilation only. Collect safe artifact diagnostics with Python 3.11: python scripts/collect-windows-trial.py'
'''

README = '''# Native Windows friend trial

This is a source/build experiment, not an installer or a supported release.
Do not use it on a private repository or grant approval to any checks. No project
tracking, registered acceptance checks or sandbox execution is part of this trial.
A failed build is useful feedback; it does not mean you installed anything wrong.

1. Extract into a new ordinary-user local directory outside other repositories.
   Review `trial-manifest.json`, source files, and `build-windows-trial.ps1`.
2. Prerequisites: native Windows x86_64, Git for Windows, the Rust toolchain pinned
   in `rust-toolchain.toml`, and Visual Studio Build Tools with the MSVC C++ tools
   and Windows SDK. Python 3.11+ is only needed for collecting bounded diagnostics.
   This bundle contains no installer. Obtain prerequisites from their official
   distributors. Build commands fetch pinned Cargo dependencies when needed.
3. The build uses project-local `.local/cargo` and `.local/rustup` caches. Before
   building, install the pinned native Rust toolchain into those caches using
   rustup's documented CARGO_HOME/RUSTUP_HOME support. Existing global caches are
   deliberately not selected. Do not bypass the project environment script.
4. In PowerShell, run `./build-windows-trial.ps1` to display the review instruction.
   After review, `./build-windows-trial.ps1 -Build` compiles native targets. It runs
   no tests, check approvals, services, tracking, installation or updates.
5. Run `python scripts/collect-windows-trial.py`. Review the emitted
   `.local/windows-trial/diagnostics.json` and share only that file with the owner.
   It reports OS version/architecture, bounded executable version responses,
   build artifact hashes and explicit blocked cases. It does not read home files,
   Codex configuration, private checker state, environment dumps or tokens.

Expected blocked cases: native project activation backend absent; human approval
transport unqualified; native sandbox execution unavailable; installation/update
unqualified. These are expected development limits, not tests to bypass. Windows
build success alone does not establish native runtime support. Do not send a full
terminal transcript, source tree, home directory or environment dump. Build errors
can be reported manually after removing local paths and unrelated private text.
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / '.local/windows-trial-source.zip')
    args = parser.parse_args()
    material = {}
    for relative in FILES:
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError(f'Missing regular public source: {relative}')
        material[relative] = path.read_bytes()
    for relative in DIRECTORIES:
        for path in sorted((ROOT / relative).rglob('*')):
            if path.is_symlink():
                raise ValueError(f'Source bundle refuses symlink: {path}')
            if not path.is_file() or '__pycache__' in path.parts or path.suffix == '.pyc':
                continue
            if 'target' in path.parts or '.local' in path.parts or '.git' in path.parts:
                continue
            material[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    material['build-windows-trial.ps1'] = BUILD.encode()
    material['WINDOWS_TRIAL.md'] = README.encode()
    manifest = {'schema_version': 1, 'purpose': 'native Windows source compilation and safe artifact diagnostics',
                'qualified': False, 'installation_enabled': False, 'checks_enabled': False,
                'files': {relative: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                          for relative, data in sorted(material.items())}}
    material['trial-manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('xb') as destination:
        with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as archive:
            for relative, data in sorted(material.items()):
                info = zipfile.ZipInfo(relative, date_time=(2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, data)
    print(json.dumps({'archive': str(args.output), 'sha256': hashlib.sha256(args.output.read_bytes()).hexdigest(),
                      'files': len(material), 'qualified': False, 'sent_to_participant': False}, indent=2))


if __name__ == '__main__':
    main()
