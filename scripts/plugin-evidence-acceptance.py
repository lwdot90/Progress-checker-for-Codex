#!/usr/bin/env python3
"""Live evidence qualification through an exact extracted plugin runtime.

The caller must supply an existing, explicitly selected human-approved demo
fixture and its retained state. This module never approves a command, imports
private records, or accepts cached qualification reports as evidence.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import time
import uuid

EXPECTED_FEATURE = b'demo implemented\n'
ORIGINAL_FEATURE = b'demo implemented\nchanged\n'
EXPECTED_SCRIPT = (b'from pathlib import Path\n'
                   b'assert Path("feature.txt").read_text() == "demo implemented\\n"\n'
                   b'print("Feature fixture and content checks passed")\n')
FRAME_LIMIT = 256 * 1024


def _bounded_file(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_size > limit):
            raise RuntimeError('Expected a bounded owned regular fixture file: ' + str(path))
        data = os.read(fd, limit + 1)
        after = os.fstat(fd)
        if len(data) > limit or (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError('Fixture file changed during inspection: ' + str(path))
        current = path.lstat()
        if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise RuntimeError('Fixture file was replaced: ' + str(path))
        return data, (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode))
    finally:
        os.close(fd)


class _Fixture:
    def __init__(self, root, state):
        self.root, self.state = Path(root).resolve(strict=True), Path(state).resolve(strict=True)
        if (self.root == self.state or self.root in self.state.parents
                or self.state in self.root.parents):
            raise RuntimeError('Explicit fixture and protected state must not overlap')
        for directory in (self.root, self.state):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise RuntimeError('Fixture/state must be real owned directories')
        if stat.S_IMODE(self.state.stat().st_mode) != 0o700:
            raise RuntimeError('Explicit fixture state must remain private 0700')
        config_directory = self.root / '.progress-checker'
        if not stat.S_ISDIR(config_directory.lstat().st_mode):
            raise RuntimeError('Fixture configuration directory cannot be a symlink')
        self.config_bytes, self.config_identity = _bounded_file(config_directory / 'config.json', 64 * 1024)
        self.script_bytes, self.script_identity = _bounded_file(self.root / 'check.py', 4096)
        self.original, self.feature_identity = _bounded_file(self.root / 'feature.txt', 4096)
        self.config = json.loads(self.config_bytes)
        check = {'id': 'demo-check', 'argv': ['/usr/bin/python3', 'check.py'],
                 'cwd': '.', 'kind': 'test', 'timeout_seconds': 10}
        milestones = self.config.get('milestones', [])
        if (self.config.get('schema_version') != 1
                or self.config.get('project_id') != 'phase1-human-demo'
                or self.config.get('enabled') is not True
                or self.config.get('checks') != [check]
                or self.config.get('fingerprint') != {'extra_inputs': [], 'exclude_outputs': []}
                or self.config.get('execution') != {'max_parallel': 1, 'default_timeout_seconds': 10}
                or len(milestones) != 2
                or [m.get('id') for m in milestones] != ['fixture', 'content']
                or [m.get('depends_on') for m in milestones] != [[], ['fixture']]
                or any(m.get('in_scope') is not True or len(m.get('criteria', [])) != 1
                       or m['criteria'][0].get('check_id') != 'demo-check'
                       or m['criteria'][0].get('required') is not True for m in milestones)
                or self.script_bytes != EXPECTED_SCRIPT or self.original != ORIGINAL_FEATURE):
            raise RuntimeError('Explicit fixture does not match the bounded previously approved demo identity')
        self.feature_owned = self.original

    def guard(self):
        for path, limit, expected, identity in [
                (self.root / '.progress-checker/config.json', 64 * 1024, self.config_bytes, self.config_identity),
                (self.root / 'check.py', 4096, self.script_bytes, self.script_identity),
                (self.root / 'feature.txt', 4096, self.feature_owned, self.feature_identity)]:
            data, current_identity = _bounded_file(path, limit)
            if data != expected or current_identity != identity:
                raise RuntimeError('Concurrent fixture edit detected; refusing mutation: ' + str(path))

    def cas_feature(self, expected, replacement):
        self.guard()
        path = self.root / 'feature.txt'
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode))
            if (not stat.S_ISREG(info.st_mode) or identity != self.feature_identity
                    or os.read(fd, 4097) != expected
                    or (path.lstat().st_dev, path.lstat().st_ino) != identity[:2]):
                raise RuntimeError('Feature compare-and-swap refused a concurrent edit')
            os.lseek(fd, 0, os.SEEK_SET)
            offset = 0
            while offset < len(replacement):
                written = os.write(fd, replacement[offset:])
                if written <= 0:
                    raise RuntimeError('Incomplete bounded feature write')
                offset += written
                # Track exactly our successful prefix writes, including the
                # original trailing bytes until truncate succeeds. Cleanup
                # compares these bytes before restoring; external edits win.
                self.feature_owned = replacement[:offset] + expected[offset:]
            os.ftruncate(fd, len(replacement))
            self.feature_owned = replacement
            os.fsync(fd)
        finally:
            os.close(fd)
        self.guard()


class _MCP:
    def __init__(self, acceptance, directory, plugin, root, state, label):
        self.acceptance, self.directory = acceptance, directory
        self.sequence, self.buffer = 0, bytearray()
        self.log = (directory / (label + '.stderr')).open('wb')
        self.receipts = (directory / (label + '.public-wire.jsonl')).open('w')
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(directory), 'LANG': 'C.UTF-8',
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        self.process = subprocess.Popen([str(plugin / 'bin/checker-plugin'), '--root', str(root),
                                         '--state-dir', str(state)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=self.log, cwd=plugin, env=env)
        try:
            self.rpc('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                                   'clientInfo': {'name': 'live-evidence-acceptance', 'version': '1'}})
            self.process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n')
            self.process.stdin.flush()
            tools = self.rpc('tools/list', {})['tools']
            acceptance.check('evidence runtime advertises ten tools without any approval tool',
                             len(tools) == 10 and not any('approve' in t['name'] for t in tools))
        except BaseException:
            self.close()
            raise

    def rpc(self, method, params):
        self.sequence += 1
        request = {'jsonrpc': '2.0', 'id': self.sequence, 'method': method, 'params': params}
        self.receipts.write(json.dumps({'request': request}) + '\n'); self.receipts.flush()
        self.process.stdin.write(json.dumps(request).encode() + b'\n'); self.process.stdin.flush()
        deadline = time.monotonic() + 55
        while b'\n' not in self.buffer:
            if time.monotonic() > deadline:
                raise RuntimeError('Evidence MCP response deadline exceeded')
            if select.select([self.process.stdout], [], [], .2)[0]:
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if not chunk:
                    raise RuntimeError('Evidence MCP closed')
                self.buffer.extend(chunk)
                if len(self.buffer) > FRAME_LIMIT:
                    raise RuntimeError('Evidence MCP frame exceeds bound')
        line, _, rest = self.buffer.partition(b'\n'); self.buffer[:] = rest
        response = json.loads(line)
        self.receipts.write(json.dumps({'response': response}) + '\n'); self.receipts.flush()
        if response.get('id') != self.sequence or response.get('jsonrpc') != '2.0' or 'error' in response:
            raise RuntimeError('Invalid evidence MCP response')
        return response['result']

    def tool(self, name, arguments=None, read_only=False):
        params = {'name': name, 'arguments': arguments or {}}
        if read_only:
            params['_meta'] = {'openai/readOnly': True}
        reply = self.rpc('tools/call', params)
        if json.loads(reply['content'][0]['text']) != reply['structuredContent']:
            raise RuntimeError('Evidence text and structured results disagree')
        return reply

    def current(self):
        deadline = time.monotonic() + 20
        while True:
            reply = self.tool('checker_get_progress')
            if not reply['isError']:
                return reply['structuredContent']
            if reply['structuredContent']['error']['code'] != 'FRESHNESS_PENDING' or time.monotonic() > deadline:
                raise RuntimeError('Cannot read live evidence: ' + json.dumps(reply['structuredContent']))
            time.sleep(.1)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.terminate(); self.process.wait(timeout=20)
        code = self.process.returncode
        self.process.stdout.close(); self.log.close(); self.receipts.close()
        self.acceptance.check('evidence packaged client shuts down cleanly', code == 0)


def _run(session, fixture, label):
    fixture.guard()
    current = session.current()
    reply = session.tool('checker_run_checks', {
        'check_ids': ['demo-check'], 'idempotency_key': 'evidence-' + label + '-' + uuid.uuid4().hex,
        'expected_config_hash': current['result']['status']['source']['config_hash'],
        'expected_revision': current['revision']})
    if reply['isError']:
        return reply, None
    acceptance = reply['structuredContent']['result']
    run_ids = acceptance['run_ids']
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        fixture.guard()
        current = session.current()
        latest = current['result']['status']['latest'].get('demo-check', {})
        if latest.get('run_id') in run_ids and latest.get('execution_state') == 'finished':
            return reply, current
        time.sleep(.1)
    raise RuntimeError('Bounded demo check did not finish')


def _unapproved(acceptance, directory, plugin):
    directory.mkdir(mode=0o700)
    root, state = directory / 'project', directory / 'state'
    root.mkdir(); state.mkdir(mode=0o700); (root / '.progress-checker').mkdir()
    config = {'schema_version': 1, 'project_id': 'unapproved-evidence-probe', 'enabled': True,
              'panel': {'show_on_start': True}, 'execution': {'max_parallel': 1, 'default_timeout_seconds': 10},
              'fingerprint': {'extra_inputs': [], 'exclude_outputs': []},
              'checks': [{'id': 'sentinel', 'argv': ['/usr/bin/python3', 'sentinel.py'], 'cwd': '.',
                          'kind': 'test', 'timeout_seconds': 10}],
              'milestones': [{'id': 'sentinel', 'title': 'Unapproved sentinel', 'in_scope': True,
                              'depends_on': [], 'criteria': [{'id': 'refusal', 'description': 'No unapproved execution',
                                                             'check_id': 'sentinel', 'required': True}]}]}
    (root / '.progress-checker/config.json').write_text(json.dumps(config) + '\n')
    (root / 'sentinel.py').write_text("from pathlib import Path\nPath('EXECUTED').write_text('unexpected execution')\n")
    for args in [['init', '--quiet'], ['add', '.'], ['-c', 'user.name=Evidence probe', '-c',
                  'user.email=evidence@example.invalid', 'commit', '--quiet', '-m', 'Unapproved fixture']]:
        result = subprocess.run(['/usr/bin/git', '-C', str(root), *args], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=10,
                                env={'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1',
                                     'GIT_CONFIG_GLOBAL': '/dev/null', 'HOME': str(directory)})
        if result.returncode:
            raise RuntimeError('Unable to establish isolated unapproved Git fixture')
    session = _MCP(acceptance, directory, plugin, root, state, 'unapproved')
    try:
        before = session.current()
        reply = session.tool('checker_run_checks', {
            'check_ids': ['sentinel'], 'idempotency_key': 'unapproved-' + uuid.uuid4().hex,
            'expected_revision': before['revision'],
            'expected_config_hash': before['result']['status']['source']['config_hash']})
        acceptance.check('live unapproved command refused without a grant', reply['isError']
                         and reply['structuredContent']['error']['code'] == 'PERMISSION_REQUIRED')
        after = session.current()
        acceptance.check('unapproved refusal creates no attempt or marker',
                         before['revision'] == after['revision']
                         and after['result']['status']['latest'] == {}
                         and after['result']['running'] == [] and not (root / 'EXECUTED').exists())
    finally:
        session.close()


def evidence_integrity(acceptance, directory, fixture_root, fixture_state):
    """Return remaining qualification gates; never obtain a new human grant.

    Required caller integration: exact extract_archive() plugin_directory and
    report['archive']; explicit --evidence-fixture-root/--evidence-fixture-state.
    This changes only the selected demo feature temporarily, with byte/identity
    comparisons and advisory locking, and finally restores only our own bytes.
    Noncooperating concurrent writers cannot be made atomic by a portable file
    API; detected edits abort and are preserved, never overwritten in cleanup.
    """
    if fixture_root is None or fixture_state is None:
        return ['Live evidence qualification requires both explicit previously human-approved demo fixture and state paths.']
    if not acceptance.report.get('archive') or not acceptance.options.archive:
        return ['Live evidence qualification requires the exact checked release archive runtime.']
    directory = Path(directory); directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    plugin = acceptance.options.plugin_directory.resolve(strict=True)
    for name in ['checker-plugin', 'progress-checker', 'progress-checker-mcp']:
        acceptance.artifact('evidence_' + name, plugin / 'bin' / name)
    fixture = _Fixture(fixture_root, fixture_state)
    acceptance.check('explicit approved fixture root is an exact Git worktree',
                     subprocess.check_output(['/usr/bin/git', '-C', str(fixture.root), 'rev-parse',
                                              '--show-toplevel'], timeout=10).decode().strip() == str(fixture.root))
    session = None
    try:
        _unapproved(acceptance, directory / 'unapproved', plugin)
        session = _MCP(acceptance, directory, plugin, fixture.root, fixture.state, 'approved')
        initial = session.current()
        reply, failed = _run(session, fixture, 'fail')
        if failed is None:
            if reply['structuredContent']['error']['code'] == 'PERMISSION_REQUIRED':
                return ['Current backend refused the stored exact demo approval; human grant remains unavailable. No approval was created.']
            raise RuntimeError('Approved demo run refused: ' + json.dumps(reply['structuredContent']))
        status = failed['result']['status']
        acceptance.check('existing backend grant permits actual failing check without verification',
                         status['latest']['demo-check']['outcome'] == 'failed' and status['progress']['verified'] == 0)
        fixture.cas_feature(fixture.original, EXPECTED_FEATURE)
        reply, passed = _run(session, fixture, 'pass')
        acceptance.check('existing exact approval accepts expected fixture', passed is not None)
        status = passed['result']['status']
        acceptance.check('actual current passing evidence verifies both dependent milestones',
                         status['latest']['demo-check']['outcome'] == 'passed'
                         and status['latest']['demo-check']['freshness'] == 'current'
                         and status['progress']['verified'] == status['progress']['scoped'] == 2)
        fixture.cas_feature(EXPECTED_FEATURE, fixture.original)
        deadline = time.monotonic() + 20
        while True:
            stale = session.current()
            if stale['result']['status']['latest']['demo-check']['freshness'] == 'stale':
                break
            if time.monotonic() > deadline:
                raise RuntimeError('Source edit did not become stale')
            time.sleep(.1)
        status = stale['result']['status']
        acceptance.check('restored original source is stale with dependency blocked',
                         status['progress']['verified'] == 0 and any(
                             'dependency fixture is unverified' in blocker
                             for blocker in status['progress']['milestones'][1]['blockers']))
        session.close(); session = None
        session = _MCP(acceptance, directory, plugin, fixture.root, fixture.state, 'restart')
        restored = session.current()
        acceptance.check('restart restores actual claims and latest stale pass',
                         restored['result']['claims'] == initial['result']['claims']
                         and restored['result']['status']['latest']['demo-check']['outcome'] == 'passed'
                         and restored['result']['status']['latest']['demo-check']['freshness'] == 'stale')
        revision = restored['revision']; result = restored['result']
        config_hash = result['status']['source']['config_hash']
        requests = [('checker_run_checks', {'check_ids': ['demo-check'], 'idempotency_key': 'readonly-' + uuid.uuid4().hex,
                                          'expected_revision': revision, 'expected_config_hash': config_hash}),
                    ('checker_set_claim', {'milestone_id': 'fixture', 'claim': 'planned', 'note': 'Read-only rejection probe',
                                          'expected_revision': revision}),
                    ('checker_submit_plan', {'config': result['config'], 'reason': 'Read-only rejection probe',
                                            'expected_revision': revision, 'expected_config_hash': config_hash})]
        for name, args in requests:
            refusal = session.tool(name, args, read_only=True)
            acceptance.check(name + ' live read-only mutation refused', refusal['isError']
                             and refusal['structuredContent']['error']['code'] == 'READ_ONLY_REQUEST')
        after = session.current()
        acceptance.check('read-only refusals preserve revision claims definitions and evidence',
                         after['revision'] == revision and all(after['result'][key] == result[key]
                                                              for key in ['claims', 'config'])
                         and after['result']['status']['latest'] == result['status']['latest'])
        fixture.guard()
        acceptance.report['evidence_fixture'] = {'root': str(fixture.root), 'state': str(fixture.state),
                                                'new_approvals': False, 'fixture_bytes_restored': True,
                                                'check_ids_executed': ['demo-check'],
                                                'fail_run_id': failed['result']['status']['latest']['demo-check']['run_id'],
                                                'pass_run_id': passed['result']['status']['latest']['demo-check']['run_id']}
        return []
    finally:
        try:
            if session:
                session.close()
        finally:
            if fixture.feature_owned != fixture.original:
                fixture.cas_feature(fixture.feature_owned, fixture.original)
            fixture.guard()
