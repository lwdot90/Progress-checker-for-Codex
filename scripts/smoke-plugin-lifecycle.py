#!/usr/bin/env python3
import json
import subprocess
import time
from pathlib import Path
import hashlib
import os
import signal
import argparse
import tempfile

parser = argparse.ArgumentParser(description='Check installed launcher lifecycle in an existing disposable Git fixture.')
parser.add_argument('--root', required=True, type=Path)
parser.add_argument('--launcher', required=True, type=Path)
args = parser.parse_args()
root = args.root.resolve(strict=True)
launcher = args.launcher.resolve(strict=True)
private = tempfile.TemporaryDirectory(prefix='checker-lifecycle-')
state = Path(private.name) / 'state'
key = hashlib.sha256(os.fsencode(root)).hexdigest()[:24]
record = state / ('plugin-' + key) / 'service.json'
clients = []
sequence = 0

def call(client, method, params):
    global sequence
    sequence += 1
    request = {'jsonrpc':'2.0','id':sequence,'method':method,'params':params}
    client.stdin.write(json.dumps(request)+'\n'); client.stdin.flush()
    response = json.loads(client.stdout.readline())
    assert response['id'] == sequence and 'error' not in response, response
    return response['result']

def progress(client):
    result = call(client,'tools/call',{'name':'checker_get_progress','arguments':{}})
    assert not result['isError'], result
    return result['structuredContent']

def start():
    client = subprocess.Popen([str(launcher),'--root',str(root),'--state-dir',str(state)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    clients.append(client)
    call(client,'initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'lifecycle-smoke','version':'1'}})
    client.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n');client.stdin.flush()
    assert len(call(client,'tools/list',{})['tools']) == 10
    return client

def finish(client):
    client.stdin.close()
    assert client.wait(timeout=20) == 0, client.stderr.read()

report = {'status':'failed','assertions':[]}
try:
    one,two = start(),start()
    first,second = progress(one),progress(two)
    assert first['service_instance_id'] == second['service_instance_id']
    assert first['result']['status']['latest'] == {}
    assert first['result']['status']['progress']['scoped'] == len(json.loads((root / '.progress-checker/config.json').read_text())['milestones'])
    report['assertions'].append('two installed plugin sessions share one root-bound service without running checks')
    owned = json.loads(record.read_text())
    os.kill(owned['pid'],signal.SIGTERM)
    deadline = time.monotonic()+20
    while time.monotonic()<deadline:
        time.sleep(0.2)
        try:
            current = progress(two)
            if current['service_instance_id'] != first['service_instance_id']:
                break
        except AssertionError:
            pass
    else:
        raise AssertionError('automatic reconnection failed')
    report['assertions'].append('terminated owned service restarts automatically and returns a new instance')
    finish(one)
    assert progress(two)['service_instance_id'] == current['service_instance_id']
    report['assertions'].append('closing first session preserves the second session service')
    finish(two)
    assert not record.exists()
    report['assertions'].append('closing last session stops owned service and removes its runtime ownership record')
    report['status'] = 'passed'
finally:
    for client in clients:
        if client.poll() is None:
            client.terminate();client.wait(timeout=20)
    private.cleanup()
    path = Path(__file__).resolve().parent.parent / '.local/plugin-validation/lifecycle-report.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
