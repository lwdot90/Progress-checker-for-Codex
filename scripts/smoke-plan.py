#!/usr/bin/env python3
"""Validate plan tools in an existing disposable fixture; restore its config."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', required=True, type=Path, help='Existing disposable Git fixture; config is restored')
args = parser.parse_args()
root = args.root.resolve(strict=True)
config_path = root / '.progress-checker/config.json'
original_bytes = config_path.read_bytes()
original = json.loads(original_bytes)
checker = ROOT / '.local/checker-target/debug/progress-checker'
mcp = ROOT / '.local/checker-target/debug/progress-checker-mcp'
sequence = 0
responses = []
assertions = []
with tempfile.TemporaryDirectory(prefix='checker-plan-') as directory:
    state = Path(directory) / 'state'
    base = [str(checker), '--root', str(root), '--state-dir', str(state)]
    service = subprocess.Popen([*base, 'serve'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    adapter = None
    try:
        deadline = time.monotonic() + 45
        while True:
            status = subprocess.run([*base, 'status'], capture_output=True, text=True)
            if status.returncode == 0: break
            if service.poll() is not None: raise RuntimeError(service.stderr.read().decode())
            if time.monotonic() > deadline: raise RuntimeError('service readiness timeout')
            time.sleep(0.1)
        adapter = subprocess.Popen([str(mcp), '--root', str(root), '--state-dir', str(state)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def call(method, params):
            global sequence
            sequence += 1
            adapter.stdin.write(json.dumps({'jsonrpc':'2.0','id':sequence,'method':method,'params':params})+'\n')
            adapter.stdin.flush()
            response = json.loads(adapter.stdout.readline())
            assert response.get('id') == sequence and 'error' not in response, response
            responses.append(response)
            return response['result']
        def tool(name, arguments=None, read_only=False):
            params = {'name':name,'arguments':arguments or {}}
            if read_only: params['_meta'] = {'openai/readOnly':True}
            return call('tools/call', params)
        def project():
            response = tool('checker_get_project')
            assert not response['isError'], response
            return response['structuredContent']
        def submission(config, current, reason='Smoke: explicit scope update'):
            return {'config':config,'reason':reason,'expected_revision':current['revision'],
                'expected_config_hash':current['result']['status']['source']['config_hash']}
        call('initialize', {'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'plan-smoke','version':'1'}})
        adapter.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n');adapter.stdin.flush()
        definitions = call('tools/list', {})['tools']
        assert len(definitions) == 10
        current = project()
        revised = json.loads(json.dumps(original))
        revised['milestones'][0]['title'] += ' (revised through MCP)'
        read_only = tool('checker_submit_plan', submission(revised, current), True)
        assert read_only['isError'] and read_only['structuredContent']['error']['code'] == 'READ_ONLY_REQUEST'
        assert config_path.read_bytes() == original_bytes
        assertions.append('read-only submission is refused without config writes')
        invalid = json.loads(json.dumps(revised))
        invalid['milestones'][0]['depends_on'] = [invalid['milestones'][0]['id']]
        rejected = tool('checker_submit_plan', submission(invalid, current))
        assert rejected['isError'] and config_path.read_bytes() == original_bytes
        assertions.append('invalid dependency DAG is rejected without config writes')
        accepted = tool('checker_submit_plan', submission(revised, current))
        assert not accepted['isError'], accepted
        change = accepted['structuredContent']['result']['change']
        assert change['changed'] == [original['milestones'][0]['id']]
        assert json.loads(config_path.read_text()) == revised
        assertions.append('MCP submits a validated plan and records changed scope')
        stale = tool('checker_submit_plan', submission(original, current))
        assert stale['isError']
        assert json.loads(config_path.read_text()) == revised
        assertions.append('stale revision cannot overwrite a newer plan')
        history = tool('checker_get_plan_history', {'offset':0,'limit':5})
        assert not history['isError'] and history['structuredContent']['result']['total'] == 1
        current = project()
        denied = tool('checker_run_checks', {'check_ids':[original['checks'][0]['id']],
            'idempotency_key':'plan-grants-no-approval','expected_revision':current['revision'],
            'expected_config_hash':current['result']['status']['source']['config_hash']})
        assert denied['isError'] and denied['structuredContent']['error']['code'] == 'PERMISSION_REQUIRED'
        assertions.append('submitting definitions does not grant execution permission')
        restored = tool('checker_submit_plan', submission(original, project(), 'Smoke: restore original fixture scope'))
        assert not restored['isError'], restored
        history = tool('checker_get_plan_history', {'offset':0,'limit':5})
        assert history['structuredContent']['result']['total'] == 2
        assertions.append('restoring scope is also recorded, not silently erased')
        adapter.stdin.close(); assert adapter.wait(timeout=10) == 0; adapter = None
        service.terminate(); assert service.wait(timeout=10) == 0
        service = subprocess.Popen([*base,'serve'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 45
        while True:
            result = subprocess.run([*base,'status'], capture_output=True)
            if result.returncode == 0: break
            assert time.monotonic() < deadline
            time.sleep(0.1)
        assertions.append('service reopens the restored durable plan successfully')
        report = {'status':'passed','assertions':assertions,'responses':responses,
            'tool_schemas':{tool['name']:tool for tool in definitions},
            'checker_sha256':hashlib.sha256(checker.read_bytes()).hexdigest(),
            'mcp_sha256':hashlib.sha256(mcp.read_bytes()).hexdigest()}
        destination = ROOT / '.local/plugin-validation/plan-report.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps({'status':'passed','assertions':assertions,'receipt':str(destination)}, indent=2))
    finally:
        if adapter and adapter.poll() is None:
            adapter.terminate();adapter.wait(timeout=10)
        if service.poll() is None:
            service.terminate();service.wait(timeout=10)
        config_path.write_bytes(original_bytes)
