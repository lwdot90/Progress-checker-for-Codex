#!/usr/bin/env python3
"""Packaged negative-only approval test; no human terminal or grant is created.

Uses a fresh Git fixture and public service/MCP responses only. It never reads
private approval/evidence records, sends confirmation text, or uses a PTY.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time

MAX_FRAME = 256 * 1024
BACKEND_TOOLS = {
    'checker_get_project', 'checker_submit_plan', 'checker_get_plan_history',
    'checker_list_milestones', 'checker_set_claim', 'checker_run_checks',
    'checker_get_run', 'checker_get_progress', 'checker_get_log', 'checker_cancel_run',
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_exact(stream, count):
    result = bytearray()
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        require(chunk, 'Service closed a public response early')
        result.extend(chunk)
    return bytes(result)


def ipc(endpoint, operation, sequence):
    request_id = f'negative-{sequence}'
    payload = json.dumps({'schema_version': 1, 'request_id': request_id,
                          'operation': operation}, separators=(',', ':')).encode()
    require(len(payload) <= MAX_FRAME, 'Request exceeds frame bound')
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(str(endpoint))
        stream.sendall(struct.pack('>I', len(payload)) + payload)
        size = struct.unpack('>I', read_exact(stream, 4))[0]
        require(0 < size <= MAX_FRAME, 'Response exceeds frame bound')
        response = json.loads(read_exact(stream, size))
    require(response.get('schema_version') == 1 and response.get('request_id') == request_id,
            'Public response identity differs')
    require(('result' in response) != ('error' in response), 'Ambiguous public response')
    return response


def socket_path(root, state):
    key = hashlib.sha256(os.fsencode(root)).hexdigest()[:24]
    direct = state / f'ipc-{key}.sock'
    if len(os.fsencode(direct)) <= 100:
        return direct
    key = hashlib.sha256(os.fsencode(root) + b'\0' + os.fsencode(state)).hexdigest()[:24]
    return Path('/tmp') / f'progress-checker-ipc-{os.getuid()}' / f'ipc-{key}.sock'


def starttime(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    require(fields[0] not in ('Z', 'X', 'x'), 'Owned service already exited')
    return fields[19]


def run(package, output_dir=None):
    """Return a reusable public negative-only receipt; raise after failed cleanup."""
    package = Path(package).resolve(strict=True)
    if output_dir is None:
        output = Path(tempfile.mkdtemp(prefix='pc-live-approval-negative-')).resolve()
    else:
        output = Path(output_dir).absolute()
        require(not os.path.lexists(output), 'Output must be a fresh directory')
        require(output.parent.resolve(strict=True) == output.parent, 'Output parent must be canonical')
        output.mkdir(mode=0o700)
    root = output / 'project'
    state = output / 'state'
    root.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    (root / '.progress-checker').mkdir()
    marker = root / 'COMMAND_MUST_NOT_RUN'
    (root / 'never-run.py').write_text(
        'from pathlib import Path\nPath("COMMAND_MUST_NOT_RUN").write_text("unexpected")\n')
    config = {'schema_version': 1, 'project_id': 'live-approval-negative', 'enabled': True,
        'panel': {'show_on_start': True},
        'execution': {'max_parallel': 1, 'default_timeout_seconds': 5},
        'fingerprint': {'extra_inputs': [], 'exclude_outputs': []},
        'checks': [{'id': 'never-run', 'argv': ['/usr/bin/python3', 'never-run.py'],
                    'cwd': '.', 'kind': 'test', 'timeout_seconds': 5}],
        'milestones': [{'id': 'fixture', 'title': 'Negative fixture', 'in_scope': True,
            'depends_on': [], 'criteria': [{'id': 'acceptance', 'description': 'Must stay unverified',
                                          'check_id': 'never-run', 'required': True}]}]}
    (root / '.progress-checker/config.json').write_text(json.dumps(config, indent=2) + '\n')
    environment = os.environ.copy()
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
    subprocess.run(['/usr/bin/git', 'init', '-q', str(root)], env=environment,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=True)
    checksums = json.loads((package / 'checksums.json').read_bytes())
    binaries = {}
    hashes = {}
    for name in ('progress-checker', 'progress-checker-mcp'):
        relative = 'plugin/bin/' + name
        path = package / relative
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111
                and info.st_size <= 64 * 1024 * 1024, 'Expected bounded packaged executable')
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        require(checksums.get(relative) == hashes[name], 'Packaged executable checksum differs')
        binaries[name] = path
    cli = [str(binaries['progress-checker']), '--root', str(root), '--state-dir', str(state)]
    endpoint = socket_path(root, state)
    checks = []
    service = None
    pidfd = None
    identity = None
    failure = None
    cleanup_error = None
    report = {'coverage': 'negative-only packaged active-service approval boundary',
        'package': str(package), 'output_directory': str(output), 'runtime_sha256': hashes,
        'assertions': checks, 'approval_created': False, 'confirmation_sent': False,
        'pty_used': False, 'positive_human_approval_qualified': False,
        'private_records_read': False, 'qualification_possible': False, 'complete': False}
    def passed(name):
        checks.append({'name': name, 'passed': True})
    try:
        with (output / 'service.stdout').open('wb') as stdout, (output / 'service.stderr').open('wb') as stderr:
            service = subprocess.Popen(cli + ['serve'], env=environment,
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            pidfd = os.pidfd_open(service.pid)
            identity = starttime(service.pid)
            until = time.monotonic() + 20
            while True:
                require(service.poll() is None, 'Owned packaged service exited during startup')
                try:
                    before = ipc(endpoint, {'operation': 'project'}, 1)
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    require(time.monotonic() < until, 'Packaged service startup deadline')
                    time.sleep(.05)
            require('error' not in before, 'Public project request failed')
            project = before['result']
            require(project['canonical_root'] == str(root)
                    and before['service_instance_id'] == project['service_instance_id'],
                    'Public project root or service instance differs')
            require(not project['status']['latest'] and not project['running'], 'Fresh fixture has attempts')
            report['service_instance_id'] = before['service_instance_id']
            passed('fresh packaged service public project instance')
            denied = ipc(endpoint, {'operation': 'approval_challenge', 'check_id': 'never-run'}, 2)
            require(denied.get('error', {}).get('code') == 'APPROVAL_PEER_REQUIRED'
                    and 'result' not in denied, 'Python raw IPC acquired approval authority')
            passed('Python IPC challenge denied without terminal CLI authority')
            piped = subprocess.run(cli + ['approve', 'never-run'], env=environment,
                stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            require(piped.returncode != 0 and b'interactive human terminal' in piped.stderr,
                    'Packaged CLI approve accepted pipes or failed for an unrelated reason')
            require(b'Type ' not in piped.stdout, 'Piped CLI exposed a confirmation prompt')
            passed('packaged CLI piped approval refused before confirmation')
            messages = [
                {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                    'protocolVersion': '2025-06-18', 'capabilities': {},
                    'clientInfo': {'name': 'approval-negative', 'version': '1'}}},
                {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
            ]
            mcp = subprocess.run([str(binaries['progress-checker-mcp']), '--root', str(root),
                '--state-dir', str(state)], env=environment,
                input=b''.join(json.dumps(value).encode() + b'\n' for value in messages),
                capture_output=True, timeout=10)
            require(mcp.returncode == 0 and len(mcp.stdout) <= MAX_FRAME, 'MCP inventory failed or unbounded')
            responses = [json.loads(line) for line in mcp.stdout.splitlines()]
            inventory = [value for value in responses if value.get('id') == 2]
            require(len(inventory) == 1 and 'error' not in inventory[0], 'MCP tool inventory missing')
            tools = {value['name'] for value in inventory[0]['result']['tools']}
            require(tools == BACKEND_TOOLS and not any('approv' in name for name in tools),
                    'MCP tool inventory exposes approval or differs from ten backend tools')
            report['mcp_tools'] = sorted(tools)
            passed('MCP advertises ten tools and no approval challenge or commit tool')
            denied_run = ipc(endpoint, {'operation': 'run_checks', 'check_ids': ['never-run'],
                'idempotency_key': 'negative-unapproved',
                'expected_config_hash': project['status']['source']['config_hash'],
                'expected_revision': project['revision']}, 3)
            require(denied_run.get('error', {}).get('code') == 'PERMISSION_REQUIRED',
                    'Unapproved check did not refuse exact missing human grant')
            after = ipc(endpoint, {'operation': 'project'}, 4)
            require('error' not in after and after['service_instance_id'] == before['service_instance_id'],
                    'Service identity changed during negative probes')
            require(not marker.exists() and not after['result']['status']['latest']
                    and not after['result']['running']
                    and after['result']['status']['progress']['verified'] == 0,
                    'Unapproved request created an attempt, verification or command marker')
            report['public_project_after'] = after
            passed('unapproved run refused without attempts verification or command execution')
    except BaseException as error:
        failure = error
    finally:
        if service is not None:
            try:
                if service.poll() is None:
                    require(pidfd is not None and identity is not None and starttime(service.pid) == identity,
                            'Owned service identity changed; refusing signal')
                    signal.pidfd_send_signal(pidfd, signal.SIGINT)
                service.wait(timeout=15)
                require(service.returncode == 0 and not endpoint.exists(),
                        'Owned service did not exit cleanly and remove its endpoint')
                report['owned_service_exit'] = service.returncode
                report['owned_service_cleanup_complete'] = True
            except BaseException as error:
                cleanup_error = error
                report['owned_service_cleanup_complete'] = False
            finally:
                if pidfd is not None:
                    os.close(pidfd)
        report['command_marker_absent'] = not marker.exists()
        report['status'] = 'passed-negative-controls' if failure is None and cleanup_error is None else 'failed'
        report['negative_controls_passed'] = failure is None and cleanup_error is None
        report['complete_negative_tests'] = report['negative_controls_passed']
        report['failed_assertions'] = ([str(failure)] if failure is not None else []) + ([str(cleanup_error)] if cleanup_error is not None else [])
        report['error'] = None if failure is None else type(failure).__name__ + ': ' + str(failure)
        report['cleanup_error'] = None if cleanup_error is None else type(cleanup_error).__name__ + ': ' + str(cleanup_error)
        (output / 'negative-approval-report.json').write_text(json.dumps(report, indent=2) + '\n')
    if failure is not None or cleanup_error is not None:
        raise RuntimeError('Negative approval test failed; public receipt: ' + str(output / 'negative-approval-report.json')) from (failure or cleanup_error)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True, help='Extracted package root containing checksums.json and plugin/')
    parser.add_argument('--output-dir', type=Path, help='Fresh disposable public test workspace')
    options = parser.parse_args()
    result = run(options.package, options.output_dir)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
