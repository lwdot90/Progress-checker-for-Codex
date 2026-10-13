#!/usr/bin/env python3
"""Verify real two-check batch sequencing in an approved disposable fixture."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ipc = load('batch_ipc', 'smoke-ipc-security.py')
phase1 = load('batch_approvals', 'smoke-checker.py')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / '.local/checker-target/debug/progress-checker')
    parser.add_argument('--output', type=Path, default=ROOT / '.local/batch-smoke')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=True)
    artifact = Path(tempfile.mkdtemp(prefix='run-', dir=args.output)).resolve()
    report = {'status': 'failed', 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'assertions': []}
    process = None
    log = (artifact / 'service.log').open('wb')
    try:
        with tempfile.TemporaryDirectory(prefix='checker-batch-') as temporary:
            base = Path(temporary)
            root, state = base / 'project', base / 'state'
            root.mkdir()
            state.mkdir(mode=0o700)
            (root / '.progress-checker').mkdir()
            (root / 'output').mkdir()
            (root / '.gitignore').write_text('/output/\n')
            (root / 'check.py').write_text('''from pathlib import Path
import os, sys, time
output = Path("output")
try:
    descriptor = os.open(output / "lock", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
except FileExistsError:
    (output / "overlap").write_text("overlapping children")
    raise
try:
    with (output / "events").open("a") as events:
        events.write(sys.argv[1] + " start\\n")
        events.flush()
    time.sleep(.25)
    with (output / "events").open("a") as events:
        events.write(sys.argv[1] + " end\\n")
finally:
    os.close(descriptor)
    (output / "lock").unlink()
''')
            config = {'schema_version': 1, 'project_id': 'batch-smoke', 'enabled': True,
                      'panel': {'show_on_start': True}, 'execution': {'max_parallel': 1, 'default_timeout_seconds': 10},
                      'fingerprint': {'extra_inputs': [], 'exclude_outputs': ['output/**']},
                      'checks': [{'id': name, 'argv': ['/usr/bin/python3', 'check.py', name], 'cwd': '.', 'kind': 'test', 'timeout_seconds': 10} for name in ('first', 'second')],
                      'milestones': [{'id': 'fixture', 'title': 'Both checks', 'in_scope': True, 'depends_on': [],
                                      'criteria': [{'id': name, 'description': name, 'check_id': name, 'required': True} for name in ('first', 'second')]}]}
            (root / '.progress-checker/config.json').write_text(json.dumps(config))
            env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
            for arguments in (['init', '-q'], ['add', '.'], ['-c', 'user.name=Batch fixture', '-c', 'user.email=batch@localhost', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'fixture']):
                subprocess.run(['git', '-C', str(root), *arguments], env=env, check=True)
            approvals = phase1.Harness(binary, artifact / 'approval')
            approvals.state_dir = state
            for name in ('first', 'second'):
                approvals.approve(root, name, 'approve ' + name)
            socket = state / ('ipc-' + hashlib.sha256(os.fsencode(root)).hexdigest()[:24] + '.sock')
            command = [str(binary), '--root', str(root), '--state-dir', str(state), 'serve']
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            before = ipc.wait_socket(process, socket)
            config_hash = before['result']['status']['source']['config_hash']
            operation = {'operation': 'run_checks', 'check_ids': ['first', 'second'], 'idempotency_key': 'two-checks', 'expected_config_hash': config_hash, 'expected_revision': before['revision']}
            accepted = ipc.rpc(socket, operation)
            assert 'error' not in accepted, accepted
            parent = accepted['result']
            assert len(parent['run_ids']) == 2 and len(set(parent['run_ids'])) == 2
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                snapshot = ipc.rpc(socket, {'operation': 'progress'})
                if snapshot.get('error', {}).get('code') == 'FRESHNESS_PENDING':
                    time.sleep(.05)
                    continue
                latest = snapshot['result']['status']['latest']
                if all(latest.get(name, {}).get('execution_state') == 'finished' for name in ('first', 'second')):
                    break
                time.sleep(.05)
            else:
                raise AssertionError('batch children did not terminate within40s')
            assert all(latest[name]['outcome'] == 'passed' for name in ('first', 'second')), latest
            events = (root / 'output/events').read_text().splitlines()
            assert events == ['first start', 'first end', 'second start', 'second end'], events
            assert not (root / 'output/overlap').exists()
            report['assertions'].append('two approved child checks execute sequentially without overlap')
            for name, child_id in zip(('first', 'second'), parent['run_ids']):
                child = ipc.rpc(socket, {'operation': 'get_run', 'run_id': child_id})
                assert 'error' not in child and child['result']['check_id'] == name, child
                assert child['result']['evidence']['outcome'] == 'passed'
            parent_record = ipc.rpc(socket, {'operation': 'get_run', 'run_id': parent['run_id']})
            assert parent_record['result']['run_ids'] == parent['run_ids']
            report['assertions'].append('shared parent acceptance resolves distinct completed child records')
            duplicate = ipc.rpc(socket, operation)
            assert 'error' not in duplicate and duplicate['result']['run_id'] == parent['run_id'], duplicate
            time.sleep(.35)
            assert (root / 'output/events').read_text().splitlines() == events
            report['assertions'].append('same idempotency key returns original batch without reexecution')
            report['acceptance'] = parent
            report['events'] = events
            report['status'] = 'passed'
            ipc.stop(process)
            process = None
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        if process is not None:
            try:
                ipc.stop(process)
            except Exception as error:
                report['shutdown_error'] = str(error)
        log.close()
        (artifact / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(artifact / 'report.json')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
