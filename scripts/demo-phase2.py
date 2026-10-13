#!/usr/bin/env python3
"""Run an isolated, human-approved checker and show its live embedded panel."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('Run this demo from your interactive terminal')
    checker = ROOT / '.local/checker-target/debug/progress-checker'
    codex = ROOT / '.local/source/codex/codex-rs/target/debug/codex'
    mcp = ROOT / '.local/checker-target/debug/progress-checker-mcp'
    for binary in (checker, codex, mcp):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError(f'Missing executable: {binary}; build the checker and prototype first')
    panel = load('panel_demo', 'smoke-prototype.py')
    checker_smoke = load('checker_demo', 'smoke-checker.py')
    transport = load('panel_transport', 'smoke-phase2-panel.py')
    base = ROOT / '.local/p2d'
    base.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix='s-', dir=base))
    # Disable inherited signing, hooks, and user configuration in this disposable Git fixture.
    git_keys = {'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
                'GIT_CONFIG_COUNT': '2', 'GIT_CONFIG_KEY_0': 'commit.gpgsign',
                'GIT_CONFIG_VALUE_0': 'false', 'GIT_CONFIG_KEY_1': 'core.hooksPath',
                'GIT_CONFIG_VALUE_1': os.devnull}
    previous_git = {key: os.environ.get(key) for key in git_keys}
    os.environ.update(git_keys)
    try:
        project, config = checker_smoke.fixture(run)
    finally:
        for key, value in previous_git.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    state = run / 'state'
    state.mkdir(mode=0o700)
    home = run / 'codex-home'
    command = [str(checker), '--root', str(project), '--state-dir', str(state)]
    print(f'Isolated Phase 2 project: {project}')
    print('Review and approve only the synthetic fixture check below.', flush=True)
    subprocess.run([*command, 'approve', 'check'], check=True)
    service_log = (run / 'service.log').open('w')
    service = None
    socket_path = state / ('ipc-' + hashlib.sha256(os.fsencode(project.resolve())).hexdigest()[:24] + '.sock')
    provider = panel.Provider()
    thread = threading.Thread(target=provider.serve_forever, daemon=True)
    previous_interrupt = None
    try:
        service = subprocess.Popen([*command, 'serve'], stdout=service_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 45
        while not socket_path.exists():
            if service.poll() is not None:
                raise RuntimeError(f'Checker service exited; see {run / "service.log"}')
            if time.monotonic() > deadline:
                raise RuntimeError('Checker service startup timed out')
            time.sleep(0.1)
        # Binding the socket precedes cold inventory; require an actual snapshot.
        while True:
            remaining = deadline - time.monotonic()
            if service.poll() is not None or remaining <= 0:
                raise RuntimeError(f'Service inventory did not become ready; see {run / "service.log"}')
            try:
                json.loads(subprocess.check_output([*command, 'status'], text=True, stderr=subprocess.PIPE, timeout=remaining))
                break
            except subprocess.CalledProcessError:
                time.sleep(0.1)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError('Service readiness deadline expired') from error
        for milestone in ('feature', 'dependent'):
            current = transport.rpc(socket_path, {'operation': 'progress'})
            transport.rpc(socket_path, {'operation': 'set_claim', 'milestone_id': milestone,
                'claim': 'implemented', 'note': 'isolated human demo', 'expected_revision': current['revision']})
        completed = json.loads(subprocess.check_output([*command, 'run', 'check'], text=True))
        if completed['progress']['verified'] != 2:
            raise RuntimeError(f'The fixture did not verify both milestones: {completed}')
        panel.write_config(home, project, provider.server_port)
        with (home / 'config.toml').open('a') as settings:
            settings.write('\n[mcp_servers.progress_checker]\ncommand = ' + json.dumps(str(mcp)) + '\nargs = ' + json.dumps(['--root', str(project), '--state-dir', str(state)]) + '\n')
        environment = panel.local_environment(home, os.environ.get('TERM', 'xterm-256color'))
        environment['PROGRESS_CHECKER_SOCKET'] = str(socket_path)
        thread.start()
        print('\nLive shared-service panel: 2/2 verified after the fixture check passes.')
        print('Try /progress, /progress details feature, and /progress log check.')
        print('Details/log pagers scroll with Page Up/Down; q returns to the composer.')
        print('Type an unsent draft and resize; /quit exits. Model requests are disabled.')
        print('MCP is explicitly configured to attach to this service; it cannot approve commands.')
        print(f'Edit {project / "source.txt"} in another terminal to watch verification become stale.\n', flush=True)
        previous_interrupt = signal.signal(signal.SIGINT, lambda *_: None)
        result = subprocess.run([str(codex), '--no-daemon', '--no-alt-screen', '--ask-for-approval', 'on-request', '--sandbox', 'read-only'],
            cwd=project, env=environment, check=False)
        return result.returncode
    finally:
        if previous_interrupt is not None:
            signal.signal(signal.SIGINT, previous_interrupt)
        if thread.is_alive():
            provider.shutdown()
            thread.join(timeout=2)
        provider.server_close()
        if service is not None and service.poll() is None:
            service.terminate()
            try:
                service.wait(timeout=10)
            except subprocess.TimeoutExpired:
                service.kill()
                service.wait()
        service_log.close()
        (run / 'provider-requests.json').write_text(json.dumps(provider.requests, indent=2) + '\n')
        print(f'Demo artifacts retained at {run}', flush=True)

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'Demo stopped: {error}', file=sys.stderr)
        sys.exit(1)
