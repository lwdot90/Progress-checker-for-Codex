#!/usr/bin/python3
"""Install a packaged Progress Checker plugin for an existing Git repository."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import shutil
import subprocess
import tempfile
import tomllib


def atomic_text(path, text, *, create_only=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as output:
            temporary = Path(output.name)
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(mode)
        if create_only:
            os.link(temporary, path)
            temporary.unlink()
        else:
            temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def validate_project_paths(root):
    for directory in (root / '.codex', root / '.progress-checker'):
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise ValueError(f'Project setup directory must not be a symlink: {directory}')
        if directory.exists() and directory.resolve().parent != root:
            raise ValueError(f'Project setup directory escapes worktree: {directory}')
    for path in (root / '.codex/config.toml', root / '.progress-checker/config.json', root / 'AGENTS.md'):
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError(f'Project setup file must be regular: {path}')


def file_snapshot(path):
    if path.is_symlink():
        raise ValueError(f'Refuse symlink setup file: {path}')
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Refuse non-regular setup file: {path}')
    return path.read_bytes(), stat.S_IMODE(path.stat().st_mode)


def restore_file(path, before, expected):
    if file_snapshot(path) != expected:
        print(f'Concurrent change preserved; review rollback for {path}', file=sys.stderr)
        return
    if before is None:
        path.unlink(missing_ok=True)
    else:
        atomic_text(path, before[0].decode('utf-8'))
        path.chmod(before[1])


def preflight_agents(helper, root, action):
    module = runpy.run_path(str(helper))
    before = module['read_agents'](root / 'AGENTS.md')
    begin, end = module['BEGIN'], module['END']
    counts = before.count(begin), before.count(end)
    if counts not in ((0, 0), (1, 1)):
        raise ValueError('Ambiguous managed markers; installation remains unchanged')
    if counts == (1, 1):
        start = before.index(begin)
        stop = before.index(end) + len(end)
        if stop < start or start < 2 or before[start-2:start] != b'\n\n':
            raise ValueError('Edited managed boundaries; installation remains unchanged')
        if before[stop:stop+1] == b'\n':
            stop += 1
        if before[start-2:stop] != module['BLOCK']:
            raise ValueError('Managed instructions were edited; review before changing installation')


def plugin_setting(path, selector, enabled):
    """Edit only this plugin's table, preserving all unrelated TOML text."""
    existing = path.read_text() if path.exists() else ''
    tomllib.loads(existing)
    header = '[plugins.' + json.dumps(selector) + ']'
    pattern = re.compile(r'^' + re.escape(header) + r'[ \t]*(?:#.*)?\n(.*?)(?=^\[|\Z)', re.M | re.S)
    match = pattern.search(existing)
    if enabled is None:
        if not match:
            return
        changed = existing[:match.start()] + existing[match.end():]
    else:
        line = 'enabled = ' + str(enabled).lower() + '\n'
        if match:
            body = match.group(1)
            if re.search(r'^enabled\s*=', body, re.M):
                body = re.sub(r'^enabled\s*=.*$', line.rstrip(), body, flags=re.M)
            else:
                body = line + body
            changed = existing[:match.start(1)] + body + existing[match.end(1):]
        else:
            changed = existing.rstrip() + '\n\n' + header + '\n' + line
    tomllib.loads(changed)
    atomic_text(path, changed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=['install', 'update', 'remove', 'list'], default='install')
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--codex', default='codex')
    parser.add_argument('--skip-agent-instructions', action='store_true', help='Keep AGENTS.md unchanged during setup')
    parser.add_argument('--codex-home', type=Path, default=Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex'))))
    parser.add_argument('--data-home', type=Path, default=Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share'))))
    parser.add_argument('--state-dir', type=Path,
                        help='Retained private checker state outside the project; updates preserve the existing binding')
    args = parser.parse_args()
    root = args.project.resolve(strict=True)
    git_root = Path(subprocess.check_output(['/usr/bin/git', '-C', str(root), 'rev-parse', '--show-toplevel'], text=True).strip()).resolve()
    if git_root != root:
        raise SystemExit('--project must be the exact existing Git worktree root')
    validate_project_paths(root)
    package = Path(__file__).resolve().parent
    for relative, digest in (json.loads((package / 'checksums.json').read_text()).items() if args.action in ('install', 'update') else []):
        target = package / relative
        if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise SystemExit(f'Package checksum mismatch: {relative}')
    key = hashlib.sha256(os.fsencode(root)).hexdigest()[:12]
    marketplace = 'progress-local-' + key
    selector = 'progress-checker@' + marketplace
    data = args.data_home.resolve()
    state = (args.state_dir or (data / 'progress-checker')).resolve()
    destination = data / 'progress-checker-plugins' / key
    if root == data or root in data.parents:
        raise SystemExit('--data-home must be outside the repository')
    environment = os.environ.copy()
    environment['CODEX_HOME'] = str(args.codex_home.resolve())
    installed = destination / 'plugins/progress-checker'
    binding = installed / 'mcp.json'
    if os.path.lexists(binding):
        if binding.is_symlink() or not binding.is_file() or binding.stat().st_size > 64 * 1024:
            raise SystemExit('Installed MCP binding must be a bounded regular file')
        definition = json.loads(binding.read_text())['mcpServers']['progress_checker']
        bound_args = definition['args']
        if (len(bound_args) != 4 or bound_args[0] != '--root'
                or Path(bound_args[1]).resolve() != root or bound_args[2] != '--state-dir'):
            raise SystemExit('Installed MCP binding differs from this project; review it before updating')
        retained_state = Path(bound_args[3]).resolve()
        if args.state_dir and state != retained_state:
            raise SystemExit('Existing installation uses a different state directory; retain that binding when updating')
        state = retained_state
    if state == root or root in state.parents or state in root.parents:
        raise SystemExit('--state-dir and the repository must not overlap')
    if state.exists():
        info = state.lstat()
        if (not state.is_dir() or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise SystemExit('--state-dir must be a private owned directory')
    args.codex_home.mkdir(parents=True, mode=0o700, exist_ok=True)
    if args.action == 'list':
        subprocess.run([args.codex, 'plugin', 'list', '--marketplace', marketplace, '--json'], env=environment, check=True)
        return
    if args.action == 'remove':
        for settings in (args.codex_home / 'config.toml', root / '.codex/config.toml'):
            if settings.exists():
                tomllib.loads(settings.read_text())
        helper = installed / 'bin/checker-project'
        if helper.is_file():
            preflight_agents(helper, root, 'remove')
        # Codex owns its cache; evidence and project configuration are never removed.
        subprocess.run([args.codex, 'plugin', 'remove', selector, '--json'], env=environment, check=True)
        helper = installed / 'bin/checker-project'
        if helper.is_file():
            subprocess.run([str(helper), 'remove', '--root', str(root)], check=True)
        plugin_setting(args.codex_home / 'config.toml', selector, None)
        plugin_setting(root / '.codex/config.toml', selector, None)
        subprocess.run([args.codex, 'plugin', 'marketplace', 'remove', marketplace, '--json'], env=environment, check=True)
        print(json.dumps({'removed': selector, 'preserved_project_config': str(root / '.progress-checker/config.json'), 'preserved_state_directory': str(state)}, indent=2))
        return
    if args.action == 'update' and not installed.is_dir():
        raise SystemExit('No existing installation for this project; use install first')
    destination.mkdir(parents=True, exist_ok=True)
    installed.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.progress-checker-stage-', dir=installed.parent))
    backup = installed.parent / (staging.name + '-previous')
    activated = False
    had_previous = installed.exists()
    native_changed = False
    setup_paths = (args.codex_home / 'config.toml', root / '.codex/config.toml',
                   root / '.progress-checker/config.json', root / 'AGENTS.md')
    original = {path: file_snapshot(path) for path in setup_paths}
    expected = dict(original)
    def observe(paths=setup_paths):
        expected.update({path: file_snapshot(path) for path in paths})
    def native(command):
        try:
            subprocess.run(command, env=environment, check=True)
        finally:
            # Native Codex owns profile settings, not project files.
            observe((setup_paths[0],))
    try:
        # Copy and validate complete replacement before touching the working source.
        replacement = staging / 'plugin'
        shutil.copytree(package / 'plugin', replacement)
        atomic_text(replacement / 'mcp.json', json.dumps({
            '$schema': 'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json',
            'mcpServers': {'progress_checker': {'type': 'stdio', 'command': './bin/checker-plugin',
                'args': ['--root', str(root), '--state-dir', str(state)]}},
        }, indent=2) + '\n')
        if not args.skip_agent_instructions:
            preflight_agents(replacement / 'bin/checker-project', root, 'install')
        for settings in (args.codex_home / 'config.toml', root / '.codex/config.toml'):
            if settings.exists():
                tomllib.loads(settings.read_text())
        if had_previous:
            installed.rename(backup)
        replacement.rename(installed)
        activated = True
        marketplace_file = destination / '.agents/plugins/marketplace.json'
        atomic_text(marketplace_file, json.dumps({'name': marketplace, 'plugins': [{
            'name': 'progress-checker', 'source': {'source': 'local', 'path': './plugins/progress-checker'},
            'policy': {'installation': 'AVAILABLE', 'authentication': 'ON_INSTALL'}, 'category': 'Productivity',
        }]}, indent=2) + '\n')
        native([args.codex, 'plugin', 'marketplace', 'add', str(destination), '--json'])
        if had_previous:
            native_changed = True
            native([args.codex, 'plugin', 'remove', selector, '--json'])
        native([args.codex, 'plugin', 'add', selector, '--json'])
        # Globally disabled; only this explicitly chosen trusted repository enables it.
        plugin_setting(args.codex_home / 'config.toml', selector, False)
        observe((setup_paths[0],))
        validate_project_paths(root)
        plugin_setting(root / '.codex/config.toml', selector, True)
        observe((setup_paths[1],))
        project_config = root / '.progress-checker/config.json'
        validate_project_paths(root)
        if not project_config.exists():
            project_config.parent.mkdir(exist_ok=True)
            atomic_text(project_config, json.dumps({
                'schema_version': 1, 'project_id': 'project-' + key, 'enabled': True,
                'panel': {'show_on_start': True},
                'execution': {'max_parallel': 1, 'default_timeout_seconds': 300},
                'fingerprint': {'extra_inputs': [], 'exclude_outputs': []},
                'checks': [], 'milestones': [],
            }, indent=2) + '\n', create_only=True)
            observe((setup_paths[2],))
        if not args.skip_agent_instructions:
            validate_project_paths(root)
            try:
                subprocess.run([str(installed / 'bin/checker-project'), 'install', '--root', str(root)], check=True)
            finally:
                observe((setup_paths[3],))
    except Exception:
        if activated:
            shutil.rmtree(installed)
        if backup.exists():
            backup.rename(installed)
        profile_unchanged = file_snapshot(setup_paths[0]) == expected[setup_paths[0]]
        if had_previous and native_changed and profile_unchanged:
            restored = subprocess.run([args.codex, 'plugin', 'add', selector, '--json'], env=environment, check=False)
            if restored.returncode:
                print('Previous source restored, but native cache restoration failed; run install again.', file=sys.stderr)
            observe((setup_paths[0],))
        elif had_previous and native_changed:
            print('Previous source restored; concurrent profile change preserved. Review native cache restoration.', file=sys.stderr)
        elif not had_previous and activated and profile_unchanged:
            # A first-install failure must not leave a globally enabled cached plugin.
            subprocess.run([args.codex, 'plugin', 'remove', selector, '--json'], env=environment, check=False)
            observe((setup_paths[0],))
        validate_project_paths(root)
        for path in setup_paths:
            restore_file(path, original[path], expected[path])
        raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    if backup.exists():
        shutil.rmtree(backup)
    print(json.dumps({'installed': selector, 'action': args.action, 'project': str(root), 'marketplace': str(destination),
        'state_directory': str(state), 'next': 'Restart Codex in this repository. Project plugin settings require Codex project trust.'}, indent=2))


if __name__ == '__main__':
    main()
