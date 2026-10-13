#!/usr/bin/env python3
"""Exercise the local checker against disposable Git repositories, never this project."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import tempfile
import time


class Harness:
    def __init__(self, binary: Path, output: Path):
        self.binary = binary.resolve(strict=True)
        self.binary_hash = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.output = output.resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.results = []
        self.assertions = []
        self.artifacts = []
        self.state_dir = None
        self.complete = False
        self.environment = {key: value for key, value in os.environ.items()
                            if key in ('PATH', 'LANG', 'LC_ALL', 'TERM')}

    def invoke(self, root: Path, *arguments: str, expected=0, cancel=False):
        command = [str(self.binary), '--root', str(root), '--state-dir', str(self.state_dir), *arguments]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=self.environment, start_new_session=True)
        if cancel:
            # RPM/environment inspection precedes execution. Signal only after
            # the durable running snapshot exists, so this tests a real run.
            deadline = time.monotonic() + 10
            running = False
            while time.monotonic() < deadline and process.poll() is None:
                for snapshot in self.state_dir.rglob('snapshot.json'):
                    try:
                        saved = json.loads(snapshot.read_text())['payload']
                        running = saved.get('latest', {}).get(arguments[-1], {}).get('execution_state') == 'running'
                    except (OSError, ValueError, KeyError):
                        continue
                    if running:
                        break
                if running:
                    time.sleep(0.2)
                    os.killpg(process.pid, signal.SIGINT)
                    break
                time.sleep(0.02)
            if not running:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise AssertionError('Cancellation target never entered durable running state')
        try:
            stdout, stderr = process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            raise AssertionError(f'CLI exceeded harness deadline: {arguments}')
        record = {'arguments': list(arguments), 'exit_code': process.returncode,
                  'stdout': stdout.decode(errors='replace'), 'stderr': stderr.decode(errors='replace')}
        self.results.append(record)
        self.report()
        assert process.returncode == expected, record
        return json.loads(record['stdout']) if record['stdout'].strip() else None

    def approve(self, root: Path, check: str, answer: str, expected=0):
        """Use a real controlling terminal for the human-only synthetic approval."""
        pid, descriptor = pty.fork()
        if pid == 0:
            os.execve(str(self.binary), [str(self.binary), '--root', str(root), '--state-dir', str(self.state_dir), 'approve', check],
                      self.environment)
        captured = bytearray()
        sent = False
        completed = 0
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                if select.select([descriptor], [], [], 0.1)[0]:
                    try:
                        captured.extend(os.read(descriptor, 65536))
                    except OSError:
                        break
                    if not sent:
                        os.write(descriptor, (answer + '\n').encode())
                        sent = True
                completed, status = os.waitpid(pid, os.WNOHANG)
                if completed:
                    break
            else:
                os.kill(pid, signal.SIGKILL)
                raise AssertionError('Approval prompt exceeded harness deadline')
        finally:
            os.close(descriptor)
        if not completed:
            _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        record = {'arguments': ['approve', check], 'exit_code': code,
                  'terminal': captured.decode(errors='replace')}
        self.results.append(record)
        self.report()
        assert code == expected, record

    def assert_that(self, name: str, condition: bool):
        self.assertions.append({'name': name, 'passed': bool(condition)})
        self.report()
        assert condition, name

    def report(self):
        report = {'schema_version': 1, 'complete': self.complete, 'binary': str(self.binary),
                  'binary_sha256': self.binary_hash,
                  'operations': self.results, 'assertions': self.assertions, 'artifacts': self.artifacts}
        (self.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


def fixture(directory: Path):
    root = directory / 'fixture'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    (root / '.progress-checker').mkdir()
    (root / 'source.txt').write_text('original\n')
    (root / 'check.py').write_text(
        'import os,sys,time\n'
        'assert "SMOKE_SECRET" not in os.environ\n'
        'mode=open("mode.txt").read().strip()\n'
        'print("\\x1b[31mcheck output\\x1b[0m",flush=True)\n'
        'if mode=="wait": time.sleep(30)\n'
        'if mode=="mutate":\n'
        ' original=open("source.txt").read()\n'
        ' open("source.txt","w").write("transient change\\n")\n'
        ' time.sleep(0.6)\n'
        ' open("source.txt","w").write(original)\n'
        'sys.exit(1 if mode=="fail" else 0)\n')
    (root / 'mode.txt').write_text('pass\n')
    config = {
        'schema_version': 1, 'project_id': 'synthetic-checker-smoke', 'enabled': True,
        'panel': {'show_on_start': True},
        'execution': {'max_parallel': 1, 'default_timeout_seconds': 2},
        'fingerprint': {'extra_inputs': [], 'exclude_outputs': []},
        'checks': [{'id': 'check', 'argv': ['/usr/bin/python3', 'check.py'],
                    'cwd': '.', 'kind': 'test', 'timeout_seconds': 2}],
        'milestones': [{'id': 'feature', 'title': 'Synthetic feature', 'in_scope': True,
                        'depends_on': [], 'criteria': [{'id': 'passes', 'description': 'Fixture passes',
                                                       'check_id': 'check', 'required': True}]}]}
    config['milestones'].append({
        'id': 'dependent', 'title': 'Dependent feature', 'in_scope': True,
        'depends_on': ['feature'], 'criteria': [{'id': 'dependent-passes',
            'description': 'Same synthetic evidence with explicit dependency',
            'check_id': 'check', 'required': True}]})
    path = root / '.progress-checker/config.json'
    path.write_text(json.dumps(config, indent=2) + '\n')
    subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(root), '-c', 'user.name=Smoke', '-c',
                    'user.email=smoke@example.invalid', 'commit', '-qm', 'fixture'], check=True)
    return root, config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('.local/checker-smoke'))
    options = parser.parse_args()
    harness = Harness(options.binary, options.output)
    with tempfile.TemporaryDirectory(prefix='checker-smoke-') as temporary:
        home = Path(temporary) / 'home'
        home.mkdir()
        harness.state_dir = Path(temporary) / 'state'
        harness.environment.update(HOME=str(home), XDG_CONFIG_HOME=str(home / 'config'),
                                   SMOKE_SECRET='must-not-be-inherited')
        root, config = fixture(Path(temporary))
        config_path = root / '.progress-checker/config.json'
        harness.invoke(root, 'validate')
        hook = Path(temporary) / 'fsmonitor-hook'
        marker = Path(temporary) / 'fsmonitor-marker'
        hook.write_text('#!/bin/sh\n/usr/bin/touch ' + str(marker) + '\n')
        hook.chmod(0o700)
        subprocess.run(['git', '-C', str(root), 'config', 'core.fsmonitor', str(hook)], check=True)
        status = harness.invoke(root, 'status')
        harness.assert_that('status never executes Git fsmonitor hook', not marker.exists())
        subprocess.run(['git', '-C', str(root), 'config', '--unset', 'core.fsmonitor'], check=True)
        harness.assert_that('initial claims cannot verify', status['progress']['verified'] == 0)
        harness.invoke(root, 'run', 'check', expected=1)
        harness.invoke(root, 'approve', 'check', expected=1)
        for milestone in ('feature', 'dependent'):
            status = harness.invoke(root, 'claim', milestone, 'implemented',
                                    '--expected-revision', str(status['revision']))
        harness.assert_that('implemented claims alone cannot verify', status['progress']['verified'] == 0)
        harness.invoke(root, 'claim', 'feature', 'planned', '--expected-revision', '0', expected=1)
        harness.approve(root, 'check', 'approve check')
        status = harness.invoke(root, 'run', 'check')
        harness.assert_that('mapped evidence verifies both dependent milestones', status['progress']['verified'] == 2)
        evidence = status['latest']['check']
        harness.assert_that('passing evidence is current', evidence['outcome'] == 'passed' and evidence['freshness'] == 'current')
        harness.assert_that('evidence identifies command/source/log', all(evidence.get(key) for key in ('run_id', 'source', 'command_hash', 'log_ref', 'log_sha256')))
        logs = [path for path in harness.state_dir.rglob('*.json') if path.parent.name == 'logs']
        log_bytes = [bytes(json.loads(path.read_text())['payload']) for path in logs]
        logged_results = [json.loads(content) for content in log_bytes]
        harness.assert_that('persisted logs strip terminal escape', bool(logged_results) and all('\x1b' not in result[stream]['text'] for result in logged_results for stream in ('stdout', 'stderr')))
        status = harness.invoke(root, 'claim', 'feature', 'planned',
                                '--expected-revision', str(status['revision']))
        harness.assert_that('unverified dependency blocks dependent', status['progress']['verified'] == 0)
        status = harness.invoke(root, 'claim', 'feature', 'implemented',
                                '--expected-revision', str(status['revision']))
        harness.assert_that('restored claim reuses current evidence', status['progress']['verified'] == 2)
        (root / 'source.txt').write_text('changed\n')
        status = harness.invoke(root, 'status')
        harness.assert_that('source mutation removes verification', status['progress']['verified'] == 0)
        harness.assert_that('source evidence marked stale', status['latest']['check']['freshness'] == 'stale')
        status = harness.invoke(root, 'run', 'check')
        harness.assert_that('new attempt restores verification', status['progress']['verified'] == 2)
        config['milestones'][0]['title'] = 'Changed acceptance configuration'
        config_path.write_text(json.dumps(config, indent=2) + '\n')
        status = harness.invoke(root, 'status')
        harness.assert_that('config mutation removes verification', status['progress']['verified'] == 0)
        harness.invoke(root, 'run', 'check', expected=1)
        harness.approve(root, 'check', 'approve check')
        status = harness.invoke(root, 'run', 'check')
        harness.assert_that('exact renewed config approval succeeds', status['progress']['verified'] == 2)
        subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(root), '-c', 'user.name=Smoke', '-c',
                        'user.email=smoke@example.invalid', 'commit', '-qm', 'new HEAD'], check=True)
        status = harness.invoke(root, 'status')
        harness.assert_that('HEAD mutation removes verification', status['progress']['verified'] == 0)
        (root / 'mode.txt').write_text('mutate\n')
        status = harness.invoke(root, 'run', 'check')
        harness.assert_that('edit and revert during run cannot produce current green', status['progress']['verified'] == 0 and status['latest']['check']['freshness'] == 'stale')
        (root / 'mode.txt').write_text('fail\n')
        status = harness.invoke(root, 'run', 'check')
        harness.assert_that('failed latest attempt replaces previous pass', status['latest']['check']['outcome'] == 'failed' and status['progress']['verified'] == 0)
        (root / 'mode.txt').write_text('wait\n')
        status = harness.invoke(root, 'run', 'check')
        harness.assert_that('timeout blocks verification', status['latest']['check']['outcome'] == 'timed_out' and status['progress']['verified'] == 0)
        status = harness.invoke(root, 'run', 'check', cancel=True)
        harness.assert_that('SIGINT cancellation blocks verification', status['latest']['check']['outcome'] == 'cancelled' and status['progress']['verified'] == 0)
        (root / 'mode.txt').write_text('pass\n')
        status = harness.invoke(root, 'run', 'check')
        harness.assert_that('run succeeds after cancellation', status['progress']['verified'] == 2)
        config['checks'][0]['cwd'] = '..'
        config_path.write_text(json.dumps(config) + '\n')
        harness.invoke(root, 'validate', expected=1)
        harness.invoke(root, 'run', 'check', expected=1)
        config['checks'][0]['cwd'] = '.'
        config_path.write_text(json.dumps(config, indent=2) + '\n')
        outside = Path(temporary) / 'outside'
        outside.mkdir()
        (root / 'escape').symlink_to(outside, target_is_directory=True)
        config['checks'][0]['cwd'] = 'escape'
        config_path.write_text(json.dumps(config, indent=2) + '\n')
        harness.approve(root, 'check', 'approve check', expected=1)
        harness.invoke(root, 'run', 'check', expected=1)
        config['checks'][0]['cwd'] = '.'
        config_path.write_text(json.dumps(config, indent=2) + '\n')
        (root / 'escape').unlink()
        harness.invoke(root, 'status')
        snapshots = list(harness.state_dir.rglob('snapshot.json'))
        harness.assert_that('one synthetic project snapshot exists', len(snapshots) == 1)
        attempts = {path: path.read_bytes() for path in (path for path in harness.state_dir.rglob('*.json') if path.parent.name == 'attempts')}
        snapshots[0].write_text('{interrupted write')
        status = harness.invoke(root, 'status')
        harness.assert_that('corrupt snapshot never recovers green', status['progress']['verified'] == 0)
        harness.assert_that('corrupt snapshot reports warning', bool(status['warnings']))
        harness.assert_that('snapshot recovery retains immutable attempts', all(path.read_bytes() == contents for path, contents in attempts.items()))
        for path in harness.state_dir.rglob('*.json'):
            if path.parent.name not in ('attempts', 'logs'):
                continue
            payload = json.loads(path.read_text())['payload']
            harness.artifacts.append({'kind': path.parent.name, 'name': path.name,
                                      'payload': payload})
    harness.complete = True
    harness.report()
    print(f'Checker smoke evidence: {harness.output / "report.json"}')


if __name__ == '__main__':
    main()
