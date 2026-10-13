#!/usr/bin/env python3
"""Measured maintenance pilot: approve only a disposable copy of real project files."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
import os
import platform
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

phase1 = load('pilot_approval', ROOT / 'scripts/smoke-checker.py')
phase2 = load('pilot_transport', ROOT / 'scripts/smoke-service.py')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / '.local/checker-target/debug/progress-checker')
    parser.add_argument('--output', type=Path, default=ROOT / '.local/pilot')
    parser.add_argument('--samples', type=int, default=20)
    args = parser.parse_args()
    if not 20 <= args.samples <= 100:
        parser.error('samples must be between 20 and 100')
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='pc-pilot-'))
    project, state = directory / 'project', directory / 's'
    shutil.copytree(ROOT, project, ignore=shutil.ignore_patterns('.local', '.git', '__pycache__', 'pilot-output'))
    (project / '.progress-checker').mkdir(exist_ok=True)
    shutil.copyfile(project / 'examples/pilot/config.json', project / '.progress-checker/config.json')
    with (project / '.gitignore').open('a') as stream:
        stream.write('\npilot-output/\n')
    environment = {key: value for key, value in os.environ.items() if key in ('PATH', 'LANG', 'LC_ALL', 'TERM')}
    environment['HOME'] = str(directory / 'home')
    Path(environment['HOME']).mkdir(mode=0o700)
    git_environment = dict(environment, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                           GIT_CONFIG_COUNT='2', GIT_CONFIG_KEY_0='commit.gpgsign',
                           GIT_CONFIG_VALUE_0='false', GIT_CONFIG_KEY_1='core.hooksPath',
                           GIT_CONFIG_VALUE_1=os.devnull)
    for command in (['git', 'init', '-q', str(project)], ['git', '-C', str(project), 'add', '.'],
                    ['git', '-C', str(project), '-c', 'user.name=Disposable Pilot', '-c', 'user.email=pilot@example.invalid', 'commit', '-qm', 'Actual source maintenance pilot']):
        subprocess.run(command, check=True, env=git_environment)
    inventory = {str(path.relative_to(project)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in sorted(project.rglob('*')) if path.is_file() and '.git' not in path.relative_to(project).parts}
    report = {'schema_version': 1, 'complete': False, 'disposable_project': str(project), 'state_dir': str(state),
              'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'source_inventory': inventory,
              'source_files': len(inventory), 'source_bytes': sum((project / name).stat().st_size for name in inventory),
              'assertions': [], 'measurements': {}, 'configured_checks': json.loads((project / '.progress-checker/config.json').read_text())['checks']}
    report['baseline'] = {'platform': platform.platform(), 'cpu_count': os.cpu_count(),
                          'cpu_model': next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'),
                          'memory_total': next((line.split(':', 1)[1].strip() for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:')), 'unknown'),
                          'clock': vars(time.get_clock_info('monotonic')),
                          'started_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    processes = []
    def save():
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    def check(name, condition):
        report['assertions'].append({'name': name, 'passed': bool(condition)})
        save()
        assert condition, name
    state.mkdir(mode=0o700)
    socket = state / ('ipc-' + hashlib.sha256(os.fsencode(project.resolve())).hexdigest()[:24] + '.sock')
    client = phase2.IPC(socket)
    def snapshot():
        deadline = time.monotonic() + 60
        while True:
            response = client.request('progress')
            if 'result' in response:
                return response['result']
            if response.get('error', {}).get('code') != 'FRESHNESS_PENDING' or time.monotonic() > deadline:
                raise AssertionError(response)
            time.sleep(.05)
    def start():
        log = open(output / f'service-{len(processes)}.log', 'wb')
        process = subprocess.Popen([str(binary), '--root', str(project), '--state-dir', str(state), 'serve'], stdout=log, stderr=log, env=environment)
        processes.append((process, log))
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError('Service startup failed; inspect log')
            try:
                snapshot()
                return process
            except OSError:
                time.sleep(.1)
        raise AssertionError('Service startup deadline')
    def stop(process):
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    def run(check_ids, key):
        current = snapshot()
        started = time.monotonic()
        result = client.result('run_checks', check_ids=check_ids, idempotency_key=key,
                               expected_config_hash=current['status']['source']['config_hash'], expected_revision=current['revision'])
        elapsed = (time.monotonic() - started) * 1000
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            current = snapshot()
            if all(current['status']['latest'].get(check_id, {}).get('run_id') in result['run_ids'] and
                   current['status']['latest'][check_id]['execution_state'] == 'finished' for check_id in check_ids):
                return current, elapsed
            time.sleep(.1)
        raise AssertionError('Pilot run did not finish')
    save()
    try:
        approvals = phase1.Harness(binary, output / 'disposable-approvals')
        approvals.state_dir, approvals.environment = state, environment
        for check_id in ('pinned-source', 'patch-roundtrip'):
            approvals.approve(project, check_id, 'approve ' + check_id)
        service = start()
        for milestone in ('pinned-baseline', 'packaging-rollback'):
            current = snapshot()
            client.result('set_claim', milestone_id=milestone, claim='implemented', note='Actual maintenance tool coverage only', expected_revision=current['revision'])
        current, _ = run(['pinned-source', 'patch-roundtrip'], 'baseline')
        check('actual baseline and packaging checks pass', current['status']['progress']['verified'] == 2)
        samples = []
        for _ in range(args.samples):
            started = time.monotonic()
            snapshot()
            samples.append((time.monotonic() - started) * 1000)
        report['measurements']['warm_snapshot_ms'] = samples
        accepted = []
        for index in range(args.samples):
            current, elapsed = run(['pinned-source'], f'warm-{index}')
            check(f'warm actual check {index} passes', current['status']['latest']['pinned-source']['outcome'] == 'passed')
            accepted.append(elapsed)
        report['measurements']['accepted_run_start_ms'] = accepted
        for name, values in (('warm_snapshot', samples), ('accepted_run_start', accepted)):
            report['measurements'][name + '_p95_ms'] = sorted(values)[math.ceil(len(values) * .95) - 1]
        patch = project / 'patches/codex-progress-panel.patch'
        original = patch.read_bytes()
        patch.write_bytes(b'corrupt patch\n' + original)
        check('tracked patch edit immediately removes verification', snapshot()['status']['progress']['verified'] == 0)
        current, _ = run(['patch-roundtrip'], 'negative-patch')
        check('real packaging check rejects corrupt patch', current['status']['latest']['patch-roundtrip']['outcome'] == 'failed')
        patch.write_bytes(original)
        current, _ = run(['pinned-source', 'patch-roundtrip'], 'restored-patch')
        check('restored packaging re-verifies only after new checks', current['status']['progress']['verified'] == 2)
        manifest = json.loads((project / 'upstream-base/MANIFEST.json').read_text())
        baseline = project / 'upstream-base' / sorted(manifest['files'])[0]
        baseline_original = baseline.read_bytes()
        baseline.write_bytes(baseline_original + b'\ncorrupt baseline\n')
        check('tracked baseline edit immediately removes verification', snapshot()['status']['progress']['verified'] == 0)
        current, _ = run(['pinned-source'], 'negative-baseline')
        check('real Git blob check rejects corrupt baseline', current['status']['latest']['pinned-source']['outcome'] == 'failed')
        baseline.write_bytes(baseline_original)
        current, _ = run(['pinned-source', 'patch-roundtrip'], 'restored-baseline')
        check('restored baseline re-verifies only after new checks', current['status']['progress']['verified'] == 2)
        instance, revision = current['service_instance_id'], current['revision']
        stop(service)
        service = start()
        current = snapshot()
        check('restart has a new service identity', current['service_instance_id'] != instance)
        check('restart restores passing evidence and durable revision', current['revision'] >= revision and current['status']['progress']['verified'] == 2)
        for name in ('warm_snapshot', 'accepted_run_start'):
            check(name + ' p95 <= 250 ms on recorded representative baseline', report['measurements'][name + '_p95_ms'] <= 250)
        report['complete'] = True
        save()
        print(json.dumps({'report': str(output / 'report.json'), 'disposable_project': str(project), 'measurements': report['measurements']}, indent=2))
    except Exception as error:
        report['failure'] = str(error)
        save()
        raise
    finally:
        for process, log in processes:
            if process.poll() is None:
                stop(process)
            log.close()

if __name__ == '__main__':
    main()
