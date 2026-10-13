#!/usr/bin/env python3
"""Exercise Phase 2 only in disposable repositories; never approve this project."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import select
import signal
import socket
import subprocess
import tempfile
import time

from importlib.util import module_from_spec, spec_from_file_location

_spec = spec_from_file_location('phase1_smoke', Path(__file__).with_name('smoke-checker.py'))
_phase1 = module_from_spec(_spec)
_spec.loader.exec_module(_phase1)


class IPC:
    """The panel's bounded length-prefixed Unix socket transport."""
    def __init__(self, path: Path):
        self.path = path
        self.sequence = 0

    @staticmethod
    def read_exact(connection, count):
        data = bytearray()
        while len(data) < count:
            part = connection.recv(count - len(data))
            if not part:
                raise AssertionError('Service disconnected before answering')
            data.extend(part)
        return bytes(data)

    def request(self, operation, **parameters):
        self.sequence += 1
        request = {'schema_version': 1, 'request_id': f'smoke-{self.sequence}',
                   'operation': {'operation': operation, **parameters}}
        encoded = json.dumps(request).encode()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(15)
            connection.connect(str(self.path))
            connection.sendall(len(encoded).to_bytes(4, 'big') + encoded)
            length = int.from_bytes(self.read_exact(connection, 4), 'big')
            assert 0 < length <= 256 * 1024, 'bounded service response'
            response = json.loads(self.read_exact(connection, length))
        assert response['request_id'] == request['request_id']
        assert response['schema_version'] == 1
        assert bool(response.get('service_instance_id'))
        assert ('result' in response) != ('error' in response)
        return response

    def result(self, operation, **parameters):
        response = self.request(operation, **parameters)
        assert 'error' not in response, response
        return response['result']


class MCP:
    def __init__(self, binary, root, state, environment, stderr):
        self.process = subprocess.Popen([str(binary), '--root', str(root), '--state-dir', str(state)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=stderr, env=environment, start_new_session=True)
        self.sequence = 0
        self.stderr = stderr
        self.call('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                                'clientInfo': {'name': 'synthetic-acceptance', 'version': '1'}})
        self.process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        self.process.stdin.flush()

    def call(self, method, params=None):
        self.sequence += 1
        request = {'jsonrpc': '2.0', 'id': self.sequence, 'method': method, 'params': params or {}}
        self.process.stdin.write(json.dumps(request).encode() + b'\n')
        self.process.stdin.flush()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if not select.select([self.process.stdout], [], [], 0.2)[0]:
                assert self.process.poll() is None, 'MCP process exited'
                continue
            response = json.loads(self.process.stdout.readline())
            if response.get('id') == self.sequence:
                assert 'error' not in response, response
                return response['result']
        raise AssertionError('MCP response deadline exceeded')

    def tool(self, name, arguments=None):
        return self.call('tools/call', {'name': name, 'arguments': arguments or {}})

    def close(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.stderr.close()


def percentile95(samples):
    return sorted(samples)[math.ceil(len(samples) * 0.95) - 1]


class Acceptance:
    def __init__(self, options):
        self.binary = options.binary.resolve(strict=True)
        self.mcp_binary = options.mcp_binary.resolve(strict=True)
        self.output = options.output.resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.report = {'schema_version': 1, 'complete': False,
                       'binary_sha256': hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                       'mcp_binary_sha256': hashlib.sha256(self.mcp_binary.read_bytes()).hexdigest(),
                       'baseline': {'platform': platform.platform(), 'cpu_count': os.cpu_count(),
                                    'samples': options.samples, 'clock': 'time.monotonic_ns',
                                    'cpu_model': next((line.split(':', 1)[1].strip() for line in
                                                       Path('/proc/cpuinfo').read_text().splitlines()
                                                       if line.startswith('model name')), 'unknown'),
                                    'memory_kib': next((line.split()[1] for line in
                                                       Path('/proc/meminfo').read_text().splitlines()
                                                       if line.startswith('MemTotal:')), 'unknown')},
                       'assertions': [], 'operations': [], 'latency_ms': {}}
        self.services = []
        self.mcp = None
        self.samples = options.samples
        self.skip_latency = getattr(options, 'skip_latency', False)
        self.save()
        self.environment = {key: value for key, value in os.environ.items()
                            if key in ('PATH', 'LANG', 'LC_ALL', 'TERM')}

    def save(self):
        (self.output / 'report.json').write_text(json.dumps(self.report, indent=2) + '\n')

    def check(self, name, condition):
        self.report['assertions'].append({'name': name, 'passed': bool(condition)})
        self.save()
        assert condition, name

    def request(self, client, operation, expected_error=None, **parameters):
        started = time.monotonic_ns()
        deadline = time.monotonic() + 15
        while True:
            response = client.request(operation, **parameters)
            if (operation == 'progress' and
                    response.get('error', {}).get('code') == 'FRESHNESS_PENDING' and
                    time.monotonic() < deadline):
                time.sleep(0.03)
                continue
            break
        elapsed = (time.monotonic_ns() - started) / 1000000
        self.report['operations'].append({'operation': operation, 'parameters': parameters,
                                          'elapsed_ms': elapsed, 'response': response})
        self.save()
        if expected_error:
            assert response.get('error', {}).get('code') == expected_error, response
            return response
        assert 'error' not in response, response
        return response['result']

    def start(self):
        log = open(self.output / f'service-{len(self.services)}.log', 'wb')
        process = subprocess.Popen([str(self.binary), '--root', str(self.root),
                                    '--state-dir', str(self.state), 'serve'],
                                   stdout=log, stderr=log, env=self.environment, start_new_session=True)
        self.services.append((process, log))
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            assert process.poll() is None, (self.output / f'service-{len(self.services)-1}.log').read_text()
            if self.socket.exists():
                try:
                    self.request(IPC(self.socket), 'progress')
                    return process
                except (OSError, AssertionError):
                    pass
            time.sleep(0.03)
        raise AssertionError('Service never became ready')

    def stop(self, process, crash=False):
        if process.poll() is None:
            process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def snapshot(self, client):
        snapshot = self.request(client, 'progress')
        return {**snapshot['status'], 'revision': snapshot['revision']}

    def run(self, client, key, status):
        accepted = self.request(client, 'run_checks', check_ids=['check'], idempotency_key=key,
                                expected_config_hash=status['source']['config_hash'],
                                expected_revision=status['revision'])
        return accepted

    def finished(self, client, run_id):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status = self.snapshot(client)
            latest = status['latest'].get('check', {})
            if (latest.get('run_id') == run_id or latest.get('run_id', '').startswith(run_id + '-')) and latest.get('execution_state') == 'finished':
                return status
            time.sleep(0.03)
        raise AssertionError('Accepted run never became terminal')

    def execute(self):
        with tempfile.TemporaryDirectory(prefix='service-smoke-') as temporary:
            directory = Path(temporary)
            self.root, config = _phase1.fixture(directory)
            check_script = self.root / 'check.py'
            check_script.write_text(check_script.read_text().replace('sys.exit(1 if', 'if mode=="flood": print("\\x1b[31m" + "x" * 2000000 + "\\x1b[0m")\nsys.exit(1 if'))
            self.state = directory / 'state'
            self.state.mkdir(mode=0o700)
            home = directory / 'home'
            home.mkdir(mode=0o700)
            self.environment.update(HOME=str(home), XDG_CONFIG_HOME=str(home / 'config'))
            digest = hashlib.sha256(os.fsencode(self.root.resolve())).hexdigest()[:24]
            self.socket = self.state / f'ipc-{digest}.sock'
            service = self.start()
            first, second = IPC(self.socket), IPC(self.socket)
            initial = self.snapshot(first)
            self.check('startup executes no configured command', not initial['latest'])
            self.run_denied(first, initial)
            self.request(first, 'set_claim', milestone_id='feature', claim='implemented',
                         note='Synthetic smoke claim', expected_revision=initial['revision'])
            status = self.snapshot(second)
            self.request(first, 'set_claim', milestone_id='dependent', claim='implemented',
                         note='Synthetic dependent claim', expected_revision=status['revision'])
            status = self.snapshot(second)
            self.check('claims alone never verify', status['progress']['verified'] == 0)
            self.request(first, 'set_claim', expected_error='REVISION_CONFLICT',
                         milestone_id='feature', claim='planned', note='', expected_revision=0)
            self.stop(service)
            approvals = _phase1.Harness(self.binary, self.output / 'approval')
            approvals.state_dir = self.state
            approvals.environment = self.environment
            approvals.approve(self.root, 'check', 'approve check')
            service = self.start()
            first, second = IPC(self.socket), IPC(self.socket)
            status = self.snapshot(first)
            accepted = self.run(first, 'first-run', status)
            duplicate = self.run(second, 'first-run', status)
            self.check('two clients duplicate start resolves one run', accepted['run_id'] == duplicate['run_id'])
            self.request(first, 'run_checks', expected_error='IDEMPOTENCY_CONFLICT',
                         check_ids=['other'], idempotency_key='first-run',
                         expected_config_hash=status['source']['config_hash'], expected_revision=status['revision'])
            status = self.finished(first, accepted['run_id'])
            self.check('passing mapped evidence verifies both milestones', status['progress']['verified'] == 2)
            duplicate_writer = subprocess.run([str(self.binary), '--root', str(self.root),
                                               '--state-dir', str(self.state), 'serve'],
                                              capture_output=True, env=self.environment, timeout=10)
            self.check('second window cannot start a second writer', duplicate_writer.returncode != 0)
            record = self.request(first, 'get_run', run_id=accepted['run_id'])
            self.check('explicit run retrieval keeps matching identity', record['run_id'] == accepted['run_id'])
            log = self.request(first, 'get_log', run_id=accepted['run_ids'][0], check_id='check', offset=0, limit=16)
            self.check('log pagination bounded and sanitized', len(log['text'].encode()) <= 16 and '\x1b' not in log['text'])
            rejected = False
            try:
                response = first.request('get_log', run_id=accepted['run_ids'][0],
                                         check_id='check', offset=0, limit=1000000)
                rejected = response.get('error', {}).get('code') == 'INVALID_REQUEST'
            except AssertionError as error:
                rejected = 'disconnected before answering' in str(error)
            self.check('oversized log request fails closed', rejected)
            self.snapshot(second)
            self.request(first, 'get_run', expected_error='RUN_NOT_FOUND', run_id='absent')
            subscribed = self.request(second, 'subscribe', after_revision=None)
            self.check('subscribe returns authoritative full snapshot', subscribed['revision'] == status['revision'])
            self.mcp = MCP(self.mcp_binary, self.root, self.state, self.environment,
                           open(self.output / 'mcp.log', 'wb'))
            tools = self.mcp.call('tools/list')['tools']
            self.check('eight narrowly scoped MCP tools discovered', len(tools) == 8)
            progress = self.mcp.tool('checker_get_progress')['structuredContent']
            panel = self.snapshot(second)
            self.check('MCP and panel transport agree on revision and progress',
                       progress['revision'] == panel['revision'] and progress['result']['status']['progress'] == panel['progress'])
            denial = self.mcp.tool('checker_set_claim', {'milestone_id': 'feature', 'claim': 'verified',
                                                       'note': '', 'expected_revision': panel['revision']})
            self.check('MCP cannot claim verified', denial.get('isError') is True)
            if not self.skip_latency:
                readings = []
                for _ in range(self.samples):
                    started = time.monotonic_ns()
                    self.snapshot(second)
                    readings.append((time.monotonic_ns() - started) / 1000000)
                acceptances = []
                for index in range(self.samples):
                    status = self.snapshot(first)
                    started = time.monotonic_ns()
                    run = self.run(first, f'benchmark-{index}', status)
                    acceptances.append((time.monotonic_ns() - started) / 1000000)
                    self.finished(first, run['run_id'])
                self.report['latency_ms'] = {
                    'warm_status_samples': readings, 'warm_status_p95': percentile95(readings),
                    'accepted_run_samples': acceptances, 'accepted_run_p95': percentile95(acceptances)}
                self.check('warm snapshot p95 <=250ms', percentile95(readings) <= 250)
                self.check('accepted run p95 <=250ms', percentile95(acceptances) <= 250)
            (self.root / 'source.txt').write_text('modified source\n')
            deadline = time.monotonic() + 5
            while True:
                status = self.snapshot(first)
                if status['latest']['check']['freshness'] == 'stale' or time.monotonic() >= deadline:
                    break
                time.sleep(0.03)
            self.check('live service source refresh removes verification',
                       status['progress']['verified'] == 0 and status['latest']['check']['freshness'] == 'stale')
            (self.root / 'mode.txt').write_text('flood\n')
            status = self.snapshot(first)
            flood = self.run(first, 'large-log', status)
            status = self.finished(first, flood['run_id'])
            record = self.request(first, 'get_run', run_id=flood['run_ids'][0])
            self.check('run metadata never discloses stdout or stderr',
                       'stdout' not in record['result'] and 'stderr' not in record['result'])
            chunks = []
            offset = 0
            for _ in range(6):
                chunk = self.request(first, 'get_log', run_id=flood['run_ids'][0],
                                     check_id='check', offset=offset, limit=32768)
                assert len(chunk['text'].encode()) <= 32768
                chunks.append(chunk['text'])
                offset = chunk['next_offset']
                if not chunk['truncated']:
                    break
            else:
                raise AssertionError('Stored synthetic log exceeds bounded stream retention')
            logged = json.loads(''.join(chunks))
            self.check('explicit large malicious log is bounded sanitized and marked truncated',
                       logged['stdout']['truncated'] is True and
                       len(logged['stdout']['text'].encode()) <= 65536 and
                       '\x1b' not in logged['stdout']['text'])
            (self.root / 'mode.txt').write_text('fail\n')
            status = self.snapshot(first)
            failing = self.run(first, 'failed-run', status)
            status = self.finished(first, failing['run_id'])
            self.check('failed latest run blocks old passing evidence',
                       status['latest']['check']['outcome'] == 'failed' and status['progress']['verified'] == 0)
            (self.root / 'mode.txt').write_text('wait\n')
            status = self.snapshot(first)
            timed = self.run(first, 'timeout-run', status)
            status = self.finished(first, timed['run_id'])
            self.check('timeout blocks verification', status['latest']['check']['outcome'] == 'timed_out')
            status = self.snapshot(first)
            waiting = self.run(first, 'cancel-run', status)
            status = self.snapshot(second)
            self.request(second, 'cancel_run', run_id=waiting['run_id'], expected_revision=status['revision'])
            status = self.finished(first, waiting['run_id'])
            self.check('explicit cross-client cancellation blocks verification',
                       status['latest']['check']['outcome'] == 'cancelled' and status['progress']['verified'] == 0)
            status = self.snapshot(first)
            crashed = self.run(first, 'crash-run', status)
            old_instance = first.request('progress')['service_instance_id']
            self.stop(service, crash=True)
            service = self.start()
            reconnected = IPC(self.socket)
            response = reconnected.request('progress')
            status = {**response['result']['status'], 'revision': response['result']['revision']}
            self.check('reconnect identifies new service instance', response['service_instance_id'] != old_instance)
            self.check('crash cannot restore false green', status['progress']['verified'] == 0 and
                       status['latest']['check']['outcome'] == 'unknown')
            resolved = self.run(reconnected, 'crash-run', status)
            self.check('run idempotency survives crash restart', resolved['run_id'] == crashed['run_id'])
            self.check('crash retains parseable persisted JSON', all(
                json.loads(path.read_text()) is not None for path in self.state.rglob('*.json')))
            self.stop(service)
        self.report['complete'] = True
        self.save()

    def run_denied(self, client, status):
        self.request(client, 'run_checks', expected_error='PERMISSION_REQUIRED', check_ids=['check'],
                     idempotency_key='unapproved', expected_config_hash=status['source']['config_hash'],
                     expected_revision=status['revision'])
        self.check('permission denial executes no command', not self.snapshot(client)['latest'])

    def cleanup(self):
        if self.mcp:
            self.mcp.close()
        for process, log in self.services:
            self.stop(process)
            log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--mcp-binary', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=20)
    parser.add_argument('--skip-latency', action='store_true',
                        help='Functional checks only; leaves latency measurements empty')
    parser.add_argument('--output', type=Path, default=Path('.local/service-smoke'))
    options = parser.parse_args()
    if options.samples < 20:
        parser.error('at least 20 latency samples are required')
    acceptance = Acceptance(options)
    try:
        acceptance.execute()
    except Exception as error:
        acceptance.report['failure'] = {'type': type(error).__name__, 'message': str(error)}
        acceptance.save()
        raise
    finally:
        acceptance.cleanup()
    print(f'Service acceptance evidence: {acceptance.output / "report.json"}')


if __name__ == '__main__':
    main()
