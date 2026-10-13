#!/usr/bin/env python3
"""Adversarial STDIO MCP acceptance in a disposable unapproved fixture."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time

_spec = importlib.util.spec_from_file_location('service_smoke', Path(__file__).with_name('smoke-service.py'))
_service = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_service)

class Wire:
    def __init__(self, binary, root, state, environment):
        self.process = subprocess.Popen([str(binary), '--root', str(root), '--state-dir', str(state)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        self.sequence = 0
        self.transcript = []

    def raw(self, data):
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def receive(self):
        assert select.select([self.process.stdout], [], [], 15)[0], 'response timed out'
        line = self.process.stdout.readline(256 * 1024 + 1)
        assert line.endswith(b'\n') and len(line) <= 256 * 1024, 'bounded newline response'
        response = json.loads(line)
        assert response['jsonrpc'] == '2.0'
        self.transcript.append(response)
        return response

    def call(self, method, params=None):
        self.sequence += 1
        self.raw(json.dumps({'jsonrpc': '2.0', 'id': self.sequence, 'method': method,
                             'params': params or {}}).encode() + b'\n')
        response = self.receive()
        assert response['id'] == self.sequence
        return response

    def tool(self, name, arguments=None):
        response = self.call('tools/call', {'name': name, 'arguments': arguments or {}})
        if 'result' in response:
            response['_tool_name'] = name
            result = response['result']
            assert json.loads(result['content'][0]['text']) == result['structuredContent']
        return response

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.communicate(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--mcp-binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('.local/mcp-boundaries'))
    options = parser.parse_args()
    binary, mcp = options.binary.resolve(strict=True), options.mcp_binary.resolve(strict=True)
    options.output.mkdir(parents=True, exist_ok=True)
    report = {'complete': False, 'assertions': [], 'transcript': [], 'tool_schemas': {},
              'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'mcp_binary_sha256': hashlib.sha256(mcp.read_bytes()).hexdigest()}
    def save():
        (options.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    def check(name, condition):
        report['assertions'].append({'name': name, 'passed': bool(condition)})
        save()
        assert condition, name
    wire = service = None
    try:
        with tempfile.TemporaryDirectory(prefix='mcp-boundaries-') as temporary:
            directory = Path(temporary)
            root, _ = _service._phase1.fixture(directory)
            state = directory / 'state'
            state.mkdir(mode=0o700)
            environment = {key: value for key, value in os.environ.items() if key in ('PATH', 'LANG', 'LC_ALL')}
            environment['HOME'] = str(directory)
            socket_path = state / ('ipc-' + hashlib.sha256(os.fsencode(root.resolve())).hexdigest()[:24] + '.sock')
            service = subprocess.Popen([str(binary), '--root', str(root), '--state-dir', str(state), 'serve'],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=environment, start_new_session=True)
            deadline = time.monotonic() + 45
            while not socket_path.exists():
                assert service.poll() is None, 'service exited before readiness'
                assert time.monotonic() < deadline, 'service readiness deadline'
                time.sleep(.03)
            while True:
                try:
                    _service.IPC(socket_path).result('progress')
                    break
                except (OSError, AssertionError):
                    assert service.poll() is None, 'service exited during readiness'
                    assert time.monotonic() < deadline, 'service cold readiness deadline'
                    time.sleep(.05)
            wire = Wire(mcp, root, state, environment)
            check('tools unavailable before initialize', wire.call('tools/list')['error']['code'] == -32000)
            wire.raw(b'{broken\n')
            check('malformed JSON is parse error', wire.receive()['error']['code'] == -32700)
            wire.raw(b'{"jsonrpc":"2.0","id":{},"method":"ping"}\n')
            check('object request ID rejected', wire.receive()['error']['code'] == -32600)
            wire.raw(b'{"jsonrpc":"2.0","id":7,"method":"ping","injected":true}\n')
            check('unknown envelope fields rejected', wire.receive()['error']['code'] == -32600)
            check('invalid initialization rejected', wire.call('initialize', {'protocolVersion': 1})['error']['code'] == -32602)
            init = wire.call('initialize', {'protocolVersion': '2099-01-01', 'capabilities': {},
                'clientInfo': {'name': 'boundary-smoke', 'version': '1'}})
            check('unsupported protocol falls back explicitly', init['result']['protocolVersion'] == '2025-06-18')
            check('tools await initialized notification', wire.call('tools/list')['error']['code'] == -32000)
            wire.raw(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
            tools = wire.call('tools/list')['result']['tools']
            report['tool_schemas'] = {tool['name']: tool['outputSchema'] for tool in tools}
            check('ten strict tools exclude approval', len(tools) == 10 and all(
                tool['inputSchema']['additionalProperties'] is False for tool in tools) and
                not any('approve' in tool['name'] for tool in tools))
            check('unknown approval tool rejected', wire.tool('checker_approve')['error']['code'] == -32602)
            check('unsupported pagination rejected', wire.call('tools/list', {'cursor': 'fake'})['error']['code'] == -32602)
            progress = wire.tool('checker_get_progress')['result']['structuredContent']
            check('unapproved fixture begins unverified', progress['result']['status']['progress']['verified'] == 0)
            for tool in tools:
                rejected = wire.tool(tool['name'], {'injected': 'unexpected'})
                check(tool['name'] + ' rejects unknown arguments', rejected['result']['structuredContent']['error']['code'] == 'INVALID_ARGUMENT')
            for arguments in (
                {'milestone_id': 'feature', 'claim': 'verified', 'note': '', 'expected_revision': progress['revision']},
                {'milestone_id': 'feature', 'claim': 'implemented', 'note': '', 'expected_revision': -1},
                {'milestone_id': 'feature', 'claim': 'implemented', 'note': '', 'expected_revision': '0'},
            ):
                check('forged verification or revision rejected', wire.tool('checker_set_claim', arguments)['result']['structuredContent']['error']['code'] == 'INVALID_ARGUMENT')
            denied = wire.tool('checker_run_checks', {'check_ids': ['check'], 'idempotency_key': 'unapproved',
                'expected_config_hash': progress['result']['status']['source']['config_hash'], 'expected_revision': progress['revision']})['result']
            check('MCP cannot bypass human approval', denied['isError'] and denied['structuredContent']['error']['code'] == 'PERMISSION_REQUIRED')
            after = wire.tool('checker_get_progress')['result']['structuredContent']
            check('denials execute no configured command', not after['result']['status']['latest'] and after['result']['status']['progress']['verified'] == 0)
            report['transcript'] = wire.transcript
            wire.close()
            wire = None
            for payload, label in ((b'x' * (256 * 1024 + 1), 'oversized frame'), (b'{}', 'unterminated frame')):
                isolated = subprocess.run([str(mcp), '--root', str(root), '--state-dir', str(state)],
                    input=payload, capture_output=True, timeout=15, env=environment)
                check(label + ' fails closed without stdout', isolated.returncode != 0 and isolated.stdout == b'')
            report['complete'] = True
            save()
    finally:
        if wire:
            report['transcript'] = wire.transcript
            save()
            wire.close()
        if service:
            if service.poll() is None:
                os.killpg(service.pid, signal.SIGTERM)
            try:
                service.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(service.pid, signal.SIGKILL)
                service.communicate(timeout=5)
    print(options.output / 'report.json')

if __name__ == '__main__':
    main()
