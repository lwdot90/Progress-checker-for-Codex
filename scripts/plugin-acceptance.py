#!/usr/bin/env python3
"""Exercise plugin behaviors in private fixtures; fail unmet full milestones.

This runner never approves a check, runs a configured project command, or edits
the caller's project/evidence. Direct assertions are development validation;
only an approved checker invocation can create evidence for this command.
"""
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import signal
import stat
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_PAYLOAD_BYTES = 128 * 1024 * 1024
MAX_STREAM_BYTES = MAX_PAYLOAD_BYTES + 16 * 1024 * 1024
MAX_MEMBERS = 4096
DEFAULT_CODEX = Path('/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex')
EXPECTED_TOOLS = {
    'checker_submit_plan', 'checker_get_plan_history', 'checker_get_project',
    'checker_list_milestones', 'checker_set_claim', 'checker_run_checks',
    'checker_get_run', 'checker_get_log', 'checker_cancel_run',
    'checker_get_progress',
}
UNQUALIFIED = {
    'plugin-package': [
        'Native standard Codex discovery from an installed archive with its source checkout unavailable.',
        'Qualification of every packaged runtime dependency in a clean recipient environment.',
    ],
    'service-lifecycle': [
        'Packaged root binding, shared writer, automatic reconnect, startup without checks, owned cleanup and independent-service attachment must pass actual probes.',
    ],
    'plan-submission': [
        'Plan changes invalidate previously approved exact commands and previously passing evidence through the installed plugin; this runner grants no approvals.',
        'Installed transaction interruption and restart recovery must leave the original config intact on failure and commit a recovered plan exactly once.',
    ],
    'agent-workflow': [
        'Authenticated standard Codex uses the installed skill to derive accepted scope and report actual evidence independently of claims.',
    ],
    'evidence-integrity': [
        'Installed-plugin passing/failing/stale/dependency/restart evidence scenarios require one exact human-approved command.',
    ],
    'release-distribution': [
        'Qualified versioned archive licenses/checksums, source-free installation, state-preserving upgrade, and evidence-preserving removal.',
    ],
    'standard-codex-pilot': [
        'Authenticated standard Codex planning/approval/verification/staleness/restart and normal prompts in this existing repository.',
        'Clean recipient environment qualification.',
    ],
}


class Acceptance:
    def __init__(self, options):
        self.started_at = time.monotonic()
        self.options = options
        self.report = {
            'milestone': options.milestone, 'status': 'blocked', 'complete': False,
            'coverage': 'Direct isolated-fixture behavioral validation; not checker verification.',
            'assertions': [], 'unqualified': UNQUALIFIED[options.milestone].copy(),
            'artifacts': {},
        }

    def check(self, name, condition, detail=None):
        passed = bool(condition)
        assertion = {'name': name, 'passed': passed}
        if not passed and detail is not None:
            assertion['detail'] = detail
        self.report['assertions'].append(assertion)
        if not passed:
            raise RuntimeError(name)

    def artifact(self, name, path):
        path = path.resolve(strict=True)
        self.report['artifacts'][name] = {
            'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        return path


class UnsupportedRuntime(RuntimeError):
    """A required external host is unavailable, rather than a passing check."""


def behavioral_module(acceptance, name):
    path = acceptance.artifact(name, ROOT / 'scripts' / (name.replace('_', '-') + '.py'))
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != acceptance.report['artifacts'][name]['sha256']:
        raise RuntimeError('Behavioral acceptance module changed before loading: ' + name)
    # Execute the hashed source buffer, not an unrelated timestamp-cached pyc.
    exec(compile(source, str(path), 'exec'), module.__dict__)
    return module


def standard_codex_pilot(acceptance, directory):
    if getattr(acceptance.options, 'primary_attestation', None) is not None:
        module = behavioral_module(acceptance, 'plugin_primary_acceptance')
        acceptance.report['unqualified'] = module.standard_codex_pilot_attested(
            acceptance, directory / 'attested-primary-pilot',
            acceptance.options.primary_attestation, acceptance.options.primary_attestation_sha256,
            acceptance.options.primary_readiness)
        return
    module = behavioral_module(acceptance, 'plugin_pilot_acceptance')
    acceptance.report['unqualified'] = module.standard_codex_pilot(
        acceptance, directory / 'authenticated-pilot',
        acceptance.options.pilot_fixture_root, acceptance.options.pilot_fixture_state,
        acceptance.options.pilot_codex_home, acceptance.options.pilot_accepted_plan,
        acceptance.options.pilot_phase, acceptance.options.pilot_approved_check)


def evidence_integrity(acceptance, directory):
    module = behavioral_module(acceptance, 'plugin_evidence_acceptance')
    acceptance.report['unqualified'] = module.evidence_integrity(
        acceptance, directory / 'evidence-integrity',
        acceptance.options.evidence_fixture_root, acceptance.options.evidence_fixture_state)


def release_distribution(acceptance, directory):
    behavioral_module(acceptance, 'plugin_release_acceptance').release_distribution(acceptance, directory)


def package_recipient(acceptance, directory):
    module = behavioral_module(acceptance, 'plugin_release_acceptance')
    budget = module.Deadline(started_at=acceptance.started_at, work_seconds=210, total_seconds=295)
    report = module.qualify(acceptance.options.archive, directory / 'package-recipient',
                            budget=budget, old_archive=acceptance.options.recipient_old_archive)
    acceptance.report['package_recipient'] = report
    recipient = report.get('recipient', {})
    environment = report.get('environment', {})
    requirements = recipient.get('recipient_requirements', {})
    archive_hash = acceptance.report['archive']['sha256']
    if recipient.get('status') == 'passed':
        acceptance.check('fresh recipient qualification binds the exact extracted archive bytes',
                          report.get('archive_sha256') == archive_hash
                          and recipient.get('upgrade_archive_sha256') == archive_hash)
        nested = report.get('nested_inventory')
        source_unavailable = (requirements.get('host_mounts') is False and environment.get('mounts') == [])
        if nested is not None:
            caps = recipient.get('recipient_capabilities', {})
            source_unavailable = (nested.get('worktree_visible') is False
                and nested.get('host_home_visible') is False
                and environment.get('product_source_visible') is False
                and environment.get('host_home_visible') is False
                and environment.get('invoker_euid') == 1000
                and set(caps) == {'CapEff','CapPrm','CapBnd'}
                and all(int(value,16) == 0 for value in caps.values()))
        acceptance.check('fresh recipient proves packaged dependencies without Rust or product source or host home',
                          requirements.get('toolchain_installed') is False
                          and source_unavailable
                          and environment.get('privileged') is False
                          and 'no Rust Cargo Node' in recipient.get('assertions', []))
        for name in recipient['assertions']:
            acceptance.check('fresh package recipient: ' + name, True)
        # Evidence-preserving release actions have their own gate. Only the
        # clean-recipient dependency requirement closes here.
        acceptance.report['unqualified'] = [gate for gate in acceptance.report['unqualified']
                                            if gate != UNQUALIFIED['plugin-package'][1]]
        acceptance.report['coverage'] = ('Configured package criterion exercised through source-unavailable '
            'standard Codex discovery and fresh Fedora recipient dependency qualification without Rust '
            'or exposed product source or host home; direct development validation, not checker verification.')
        acceptance.report['separate_project_gates'] = [
            'release-distribution: ' + gate for gate in report.get('unqualified', [])]
    else:
        acceptance.report['recipient_missing_prerequisites'] = report.get('unqualified', [])


def environment(directory):
    return {
        'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(directory),
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
    }


def run(command, env, timeout=15):
    return subprocess.run([str(value) for value in command], env=env,
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)


def default_plugin_directory():
    source = ROOT / 'plugins/progress-checker'
    version = json.loads((source / 'plugin.json').read_text())['version']
    packaged = ROOT / '.local/plugin-build' / f'progress-checker-{version}-linux-x86_64/plugin'
    return packaged if packaged.is_dir() else source


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field: ' + key)
        result[key] = value
    return result


def archive_path(name):
    if not isinstance(name, str) or not name or '\\' in name or '\0' in name:
        raise ValueError('Archive paths must be nonempty canonical POSIX paths')
    parts = name.split('/')
    if any(part in ('', '.', '..') for part in parts) or re.match(r'^[A-Za-z]:', name):
        raise ValueError('Unsafe or aliased archive path: ' + name)
    return PurePosixPath(name)


def extract_archive(acceptance, path, destination):
    # Inspect the requested final path before resolve() can hide a symlink.
    path = path.absolute()
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_ARCHIVE_BYTES:
        raise ValueError('Archive must be a bounded nonempty regular file, not a symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as source:
        opened = os.fstat(source.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if not stat.S_ISREG(opened.st_mode) or identity(opened) != identity(info):
            raise ValueError('Archive changed before reading')
        data = source.read(MAX_ARCHIVE_BYTES + 1)
        if len(data) != opened.st_size or len(data) > MAX_ARCHIVE_BYTES:
            raise ValueError('Archive changed size or exceeds the size limit')
        if identity(os.fstat(source.fileno())) != identity(opened) or identity(path.lstat()) != identity(opened):
            raise ValueError('Archive changed while reading')
    digest = hashlib.sha256(data).hexdigest()
    acceptance.report['artifacts']['archive'] = {'path': str(path), 'sha256': digest}
    destination.mkdir(mode=0o700)
    seen, roots, payload = set(), set(), 0
    # Hash and consume this same immutable byte buffer. Never reopen for tar.
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode='rb') as compressed:
        expanded = compressed.read(MAX_STREAM_BYTES + 1)
    if len(expanded) > MAX_STREAM_BYTES:
        raise ValueError('Archive decompressed stream exceeds the size limit')
    # Bound raw TAR before tarfile can process oversized PAX/GNU metadata.
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        for member in archive:
            name = member.name[:-1] if member.isdir() and member.name.endswith('/') else member.name
            relative = archive_path(name)
            if name in seen or len(seen) >= MAX_MEMBERS:
                raise ValueError('Duplicate archive member or member-count limit exceeded: ' + name)
            seen.add(name)
            roots.add(relative.parts[0])
            if len(roots) != 1:
                raise ValueError('Archive must contain one versioned package root')
            if not (member.isdir() or member.isfile()) or member.mode & 0o7000:
                raise ValueError('Archive links, special files, and privileged modes are refused: ' + name)
            if member.size < 0 or member.size > MAX_MEMBER_BYTES or (member.isdir() and member.size):
                raise ValueError('Archive member exceeds the size/type limits: ' + name)
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                if target.exists() and not target.is_dir():
                    raise ValueError('Archive directory collides with a regular file: ' + name)
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            payload += member.size
            if payload > MAX_PAYLOAD_BYTES:
                raise ValueError('Archive total payload exceeds the size limit')
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with archive.extractfile(member) as source:
                content = source.read(MAX_MEMBER_BYTES + 1)
            if len(content) != member.size:
                raise ValueError('Archive member actual size disagrees with its header: ' + name)
            with target.open('xb') as output:
                output.write(content)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
        if expanded[archive.offset:].strip(b'\0'):
            raise ValueError('Archive contains nonzero data after the TAR terminator')
    if not roots:
        raise ValueError('Archive is empty')
    package = destination / next(iter(roots))
    checksums_path = package / 'checksums.json'
    if not checksums_path.is_file() or checksums_path.stat().st_size > 1024 * 1024:
        raise ValueError('Archive requires a bounded checksums.json')
    checksums = json.loads(checksums_path.read_text(), object_pairs_hook=strict_object)
    if not isinstance(checksums, dict):
        raise ValueError('Package checksum inventory must be an object')
    for name, expected in checksums.items():
        archive_path(name)
        if not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{64}', expected):
            raise ValueError('Package checksum must be a lowercase SHA256 digest: ' + name)
    files = {str(file.relative_to(package)): file for file in package.rglob('*') if file.is_file()}
    files.pop('checksums.json', None)
    if files.keys() != checksums.keys():
        raise ValueError('Checksum inventory must match every package regular file exactly')
    for name, file in files.items():
        if hashlib.sha256(file.read_bytes()).hexdigest() != checksums[name]:
            raise ValueError('Package checksum mismatch: ' + name)
    required = {'install.py', 'README.md', 'plugin/plugin.json', 'plugin/bin/checker-plugin',
                'plugin/bin/checker-project', 'plugin/bin/progress-checker',
                'plugin/bin/progress-checker-mcp', 'plugin/skills/progress-checker/SKILL.md'}
    if not required <= files.keys():
        raise ValueError('Archive lacks required self-contained plugin files')
    for name in required:
        if name.startswith('plugin/bin/') and not files[name].stat().st_mode & 0o111:
            raise ValueError('Packaged runtime must be executable: ' + name)
    manifest = json.loads(files['plugin/plugin.json'].read_text(), object_pairs_hook=strict_object)
    version = manifest.get('version')
    if manifest.get('name') != 'progress-checker' or not isinstance(version, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+[-.A-Za-z0-9]*', version):
        raise ValueError('Archive plugin manifest has an invalid name/version')
    if package.name != f'progress-checker-{version}-linux-x86_64':
        raise ValueError('Archive root must match the plugin manifest version/platform')
    acceptance.report['archive'] = {'sha256': digest, 'bytes': len(data), 'members': len(seen),
                                    'payload_bytes': payload, 'version': version,
                                    'checksummed_files': len(files)}
    return package / 'plugin'


def fixture(directory):
    root = directory / 'project'
    (root / '.progress-checker').mkdir(parents=True)
    config = {
        'schema_version': 1, 'project_id': 'plugin-acceptance-fixture', 'enabled': True,
        'panel': {'show_on_start': True},
        'execution': {'max_parallel': 1, 'default_timeout_seconds': 10},
        'fingerprint': {'extra_inputs': [], 'exclude_outputs': []},
        'checks': [{'id': 'sentinel', 'argv': ['/usr/bin/python3', 'sentinel.py'],
                    'cwd': '.', 'kind': 'test', 'timeout_seconds': 10}],
        'milestones': [],
    }
    for name, dependencies in [('alpha', []), ('beta', ['alpha']), ('stable', [])]:
        config['milestones'].append({
            'id': name, 'title': name.title(), 'in_scope': True,
            'depends_on': dependencies,
            'criteria': [{'id': 'acceptance', 'description': 'Sentinel behavior',
                          'check_id': 'sentinel', 'required': True}],
        })
    (root / '.progress-checker/config.json').write_text(json.dumps(config, indent=2) + '\n')
    # This command is deliberately unapproved. Its marker detects any execution.
    (root / 'sentinel.py').write_text("from pathlib import Path\nPath('EXECUTED').write_text('unsafe approval bypass')\n")
    env = environment(directory)
    commands = [
        ['/usr/bin/git', 'init', '--quiet', root],
        ['/usr/bin/git', '-C', root, 'add', '.'],
        ['/usr/bin/git', '-C', root, '-c', 'user.name=Plugin acceptance',
         '-c', 'user.email=acceptance@example.invalid', 'commit', '--quiet', '-m', 'Fixture'],
    ]
    for command in commands:
        result = run(command, env)
        if result.returncode:
            raise RuntimeError('Could not initialize private Git fixture: ' + result.stderr.decode(errors='replace'))
    state = directory / 'state'
    state.mkdir(mode=0o700)
    return root, state, config, env


class Project:
    def __init__(self, acceptance, directory):
        self.acceptance = acceptance
        self.root, self.state, self.config, self.env = fixture(directory)
        self.directory = directory
        self.checker = acceptance.artifact('checker', acceptance.options.binary)
        self.adapter = acceptance.artifact('mcp', acceptance.options.mcp_binary)
        self.service = self.wire = self.log = None
        self.sequence = 0
        self.buffer = bytearray()

    def __enter__(self):
        try:
            self.start()
            return self
        except BaseException:
            self.close()
            raise

    def start(self):
        self.log = (self.directory / 'service.log').open('ab')
        self.service = subprocess.Popen([
            str(self.checker), '--root', str(self.root), '--state-dir', str(self.state), 'serve',
        ], stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log, env=self.env)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                result = run([self.checker, '--root', self.root, '--state-dir', self.state, 'status'], self.env, 5)
                if result.returncode == 0:
                    break
            except subprocess.TimeoutExpired:
                # A cold environment inventory can outlast one readiness probe.
                pass
            if self.service.poll() is not None:
                raise RuntimeError('Private service startup failed: ' + (self.directory / 'service.log').read_text())
            time.sleep(.05)
        else:
            raise RuntimeError('Private service readiness deadline exceeded')
        self.wire = subprocess.Popen([
            str(self.adapter), '--root', str(self.root), '--state-dir', str(self.state),
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, env=self.env)
        self.initialize()

    def initialize(self):
        self.buffer.clear()
        self.call('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                                'clientInfo': {'name': 'plugin-acceptance', 'version': '1'}}, timeout=50)
        self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        tools = self.call('tools/list', {})['tools']
        self.acceptance.check('actual MCP advertises all ten tools and no approval tool',
                              {tool['name'] for tool in tools} == EXPECTED_TOOLS)

    def send(self, value):
        self.wire.stdin.write(json.dumps(value).encode() + b'\n')
        self.wire.stdin.flush()

    def receive(self, timeout=15):
        deadline = time.monotonic() + timeout
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.wire.stdout], [], [], remaining)[0]:
                raise RuntimeError('MCP response deadline exceeded')
            chunk = os.read(self.wire.stdout.fileno(), 65536)
            if not chunk:
                raise RuntimeError('MCP closed before a complete response')
            self.buffer.extend(chunk)
            if len(self.buffer) > 256 * 1024:
                raise RuntimeError('MCP response exceeded the frame bound')
        line, _, rest = self.buffer.partition(b'\n')
        self.buffer[:] = rest
        return json.loads(line)

    def call(self, method, params, timeout=15):
        self.sequence += 1
        self.send({'jsonrpc': '2.0', 'id': self.sequence, 'method': method, 'params': params})
        response = self.receive(timeout)
        if response.get('id') != self.sequence or response.get('jsonrpc') != '2.0' or 'error' in response:
            raise RuntimeError('Unexpected MCP response: ' + json.dumps(response))
        return response['result']

    def tool(self, name, arguments=None, read_only=False):
        params = {'name': name, 'arguments': arguments or {}}
        if read_only:
            params['_meta'] = {'openai/readOnly': True}
        result = self.call('tools/call', params)
        if json.loads(result['content'][0]['text']) != result['structuredContent']:
            raise RuntimeError('Text and structured MCP results disagree')
        return result

    def success(self, name, arguments=None):
        result = self.tool(name, arguments)
        if result['isError']:
            raise RuntimeError(name + ': ' + json.dumps(result['structuredContent']))
        return result['structuredContent']

    def current(self):
        return self.success('checker_get_project')

    def submit(self, config, current=None, reason='Acceptance: explicit isolated-fixture scope revision', read_only=False):
        current = current or self.current()
        return self.tool('checker_submit_plan', {
            'config': config, 'reason': reason, 'expected_revision': current['revision'],
            'expected_config_hash': current['result']['status']['source']['config_hash'],
        }, read_only)

    def history(self):
        return self.success('checker_get_plan_history', {'offset': 0, 'limit': 5})['result']

    def claim(self, name):
        return self.success('checker_set_claim', {
            'milestone_id': name, 'claim': 'implemented', 'note': 'Fixture implementation claim only',
            'expected_revision': self.current()['revision'],
        })

    def refusal(self, key):
        current = self.current()
        result = self.tool('checker_run_checks', {
            'check_ids': ['sentinel'], 'idempotency_key': key,
            'expected_revision': current['revision'],
            'expected_config_hash': current['result']['status']['source']['config_hash'],
        })
        self.acceptance.check('unapproved sentinel is refused: ' + key,
                              result['isError'] and result['structuredContent']['error']['code'] == 'PERMISSION_REQUIRED')
        after = self.current()['result']
        self.acceptance.check('refusal creates no attempts, verification, or command marker: ' + key,
                              after['status']['latest'] == {} and after['running'] == []
                              and after['status']['progress']['verified'] == 0
                              and not (self.root / 'EXECUTED').exists())

    def restart(self):
        self.close()
        self.start()

    def close(self):
        if self.wire:
            if self.wire.poll() is None:
                self.wire.stdin.close()
                try:
                    self.wire.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.wire.terminate()
                    self.wire.wait(timeout=10)
            self.wire = None
        if self.service:
            if self.service.poll() is None:
                self.service.terminate()
                # Never SIGKILL a persisting evidence writer.
                self.service.wait(timeout=15)
            self.service = None
        if self.log:
            self.log.close()
            self.log = None

    def __exit__(self, *_):
        self.close()


class LauncherSession(Project):
    """Use the same bounded wire assertions through the real packaged launcher."""
    def __init__(self, acceptance, launcher, root, state, env, cwd, log):
        self.acceptance, self.root, self.state = acceptance, root.resolve(strict=True), state
        self.sequence, self.buffer = 0, bytearray()
        self.wire = subprocess.Popen([
            str(launcher), '--root', str(root), '--state-dir', str(state),
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, env=env, cwd=cwd)

    def close(self):
        if self.wire:
            if self.wire.poll() is None:
                self.wire.stdin.close()
                try:
                    self.wire.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    self.wire.terminate()
                    self.wire.wait(timeout=20)
            status = self.wire.returncode
            self.wire.stdout.close()
            self.wire = None
            return status
        return None


def process_identity(pid):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        if fields[0] == 'Z' or Path(f'/proc/{pid}').stat().st_uid != os.getuid():
            return None
        return {'pid': pid, 'starttime': fields[19]}
    except (OSError, IndexError):
        return None


def stop_fixture_writer(acceptance, record, checker, root, state):
    """Clean a failed native fixture without signaling any unrelated process."""
    if not record.exists():
        return
    owned = json.loads(record.read_text())
    if process_identity(owned['pid']) != owned:
        return
    command = Path(f"/proc/{owned['pid']}/cmdline").read_bytes().split(b'\0')
    expected = [os.fsencode(checker), b'--root', os.fsencode(root),
                b'--state-dir', os.fsencode(state), b'serve', b'']
    if command != expected:
        raise RuntimeError('Failed fixture writer does not match the exact private command; refusing cleanup')
    os.kill(owned['pid'], signal.SIGTERM)
    deadline = time.monotonic() + 15
    while process_identity(owned['pid']) == owned and time.monotonic() < deadline:
        time.sleep(.05)
    clean = process_identity(owned['pid']) is None
    acceptance.report['fixture_cleanup'] = {'owned_writer_pid': owned['pid'],
        'terminated_after_exact_identity_check': True, 'graceful_exit': clean}
    if not clean:
        raise RuntimeError('Failed private fixture writer did not exit gracefully; no force kill was attempted')


def fixture_process_snapshot(pid):
    path = Path(f'/proc/{pid}')
    try:
        if path.stat().st_uid != os.getuid():
            return {'pid': pid, 'owned': False}
        fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        fds = {}
        for fd in (path / 'fd').iterdir():
            try:
                fds[fd.name] = os.readlink(fd)
            except FileNotFoundError:
                pass
        return {'pid': pid, 'state': fields[0], 'ppid': int(fields[1]),
                'pgrp': int(fields[2]), 'session': int(fields[3]),
                'starttime': fields[19],
                'exit_code': int(fields[49]),
                'command': (path / 'cmdline').read_bytes().decode(errors='replace').split('\0'),
                'children': [int(value) for value in (path / 'task' / str(pid) / 'children').read_text().split()],
                'fds': fds}
    except (OSError, IndexError, ValueError):
        return {'pid': pid, 'absent': True}


def native_runtime_snapshot(runtime, native_pid):
    record = runtime / 'service.json'
    owned = json.loads(record.read_text()) if record.exists() else None
    leases = {path.name: json.loads(path.read_text()) for path in (runtime / 'leases').glob('*.json')}
    pids = {native_pid} | {lease['pid'] for lease in leases.values()}
    if owned:
        pids.add(owned['pid'])
    processes = {pid: fixture_process_snapshot(pid) for pid in pids}
    for snapshot in list(processes.values()):
        for pid in snapshot.get('children', []):
            processes[pid] = fixture_process_snapshot(pid)
    return {'service_record': owned, 'leases': leases,
            'processes': [processes[pid] for pid in sorted(processes)]}


def service_lifecycle(acceptance, directory):
    plugin = acceptance.options.plugin_directory.resolve(strict=True)
    launcher = acceptance.artifact('launcher', plugin / 'bin/checker-plugin')
    checker = acceptance.artifact('checker', plugin / 'bin/progress-checker')
    acceptance.artifact('mcp', plugin / 'bin/progress-checker-mcp')
    acceptance.artifact('plugin_manifest', plugin / 'plugin.json')
    root, state, config, env = fixture(directory)
    alias = directory / 'worktree-alias'
    alias.symlink_to(root, target_is_directory=True)
    unrelated = directory / 'unrelated-plugin-cwd'
    unrelated.mkdir()
    key = hashlib.sha256(os.fsencode(root.resolve())).hexdigest()[:24]
    runtime = state / ('plugin-' + key)
    record = runtime / 'service.json'
    socket_path = state / ('ipc-' + key + '.sock')
    clients, external = [], None
    with (directory / 'launcher.log').open('ab') as log:
        def session(bound_root=root, bound_state=state, cwd=plugin):
            client = LauncherSession(acceptance, launcher, bound_root, bound_state, env, cwd, log)
            clients.append(client)
            return client

        def no_checks(snapshot):
            result = snapshot['result']
            return (result['status']['latest'] == {} and result['running'] == []
                    and result['status']['progress']['verified'] == 0
                    and not (root / 'EXECUTED').exists())

        try:
            # Launch both before either initialization waits: exercise contention.
            one, two = session(), session(alias, cwd=unrelated)
            one.initialize()
            two.initialize()
            first, second = one.current(), two.current()
            acceptance.check('plugin-cache and unrelated cwd bind the same canonical existing worktree',
                              first['result']['canonical_root'] == second['result']['canonical_root'] == str(root.resolve())
                              and first['result']['config'] == second['result']['config'] == config)
            acceptance.check('concurrent packaged launchers share one service instance',
                              first['service_instance_id'] == second['service_instance_id'])
            acceptance.check('automatic startup executes no configured check and grants no verification',
                              no_checks(first) and no_checks(second))
            duplicate = run([checker, '--root', root, '--state-dir', state, 'serve'], env, 10)
            acceptance.check('a competing direct writer cannot acquire the existing service state',
                              duplicate.returncode != 0 and two.current()['service_instance_id'] == first['service_instance_id'])
            one.claim('alpha')
            acceptance.check('both sessions observe the same persisted implementation claim',
                              two.current()['result']['claims'] == {'alpha': 'implemented'})
            one.refusal('launcher-no-approval')
            owned = json.loads(record.read_text())
            acceptance.check('launcher owns a live service with a PID reuse-resistant identity',
                              process_identity(owned['pid']) == owned)
            command = Path(f"/proc/{owned['pid']}/cmdline").read_bytes().split(b'\0')
            acceptance.check('service termination targets only the private fixture command',
                              os.fsencode(root) in command and os.fsencode(state) in command and b'serve' in command)
            os.kill(owned['pid'], signal.SIGTERM)
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                response = two.tool('checker_get_project')
                if not response['isError']:
                    restarted = response['structuredContent']
                    if restarted['service_instance_id'] != first['service_instance_id']:
                        break
                time.sleep(.1)
            else:
                raise RuntimeError('Packaged launcher did not reconnect to a new service within 35 seconds')
            replacement = json.loads(record.read_text())
            acceptance.check('owned termination automatically reconnects both sessions to a new service',
                              replacement != owned and process_identity(replacement['pid']) == replacement
                              and one.current()['service_instance_id'] == restarted['service_instance_id'])
            acceptance.check('reconnection restores durable claims and executes no checks',
                              restarted['result']['claims'] == {'alpha': 'implemented'} and no_checks(restarted))
            acceptance.check('closing one session exits cleanly and preserves the other session writer',
                              one.close() == 0 and two.current()['service_instance_id'] == restarted['service_instance_id']
                              and process_identity(replacement['pid']) == replacement)
            acceptance.check('closing the last owned session removes its service socket ownership and leases',
                              two.close() == 0 and process_identity(replacement['pid']) is None
                              and not record.exists() and not socket_path.exists()
                              and not list((runtime / 'leases').glob('*.json')))

            # A service started independently must never become launcher-owned.
            external_state = directory / 'independent-state'
            external_state.mkdir(mode=0o700)
            external = subprocess.Popen([
                str(checker), '--root', str(root), '--state-dir', str(external_state), 'serve',
            ], stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env)
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                try:
                    status = run([checker, '--root', root, '--state-dir', external_state, 'status'], env, 5)
                    if status.returncode == 0:
                        break
                except subprocess.TimeoutExpired:
                    pass
                if external.poll() is not None:
                    raise RuntimeError('Independent fixture service exited before readiness')
                time.sleep(.05)
            else:
                raise RuntimeError('Independent fixture service readiness deadline exceeded')
            attached = session(bound_state=external_state, cwd=unrelated)
            attached.initialize()
            snapshot = attached.current()
            external_runtime = external_state / ('plugin-' + key)
            acceptance.check('launcher attaches to an independent live writer without claiming ownership',
                              snapshot['result']['canonical_root'] == str(root.resolve()) and no_checks(snapshot)
                              and external.poll() is None and not (external_runtime / 'service.json').exists())
            acceptance.check('last attached session exits without stopping an independently started service',
                              attached.close() == 0 and external.poll() is None)
            status = run([checker, '--root', root, '--state-dir', external_state, 'status'], env, 5)
            acceptance.check('independent writer remains usable without leaked plugin leases or check attempts',
                              status.returncode == 0 and json.loads(status.stdout)['latest'] == {}
                              and not list((external_runtime / 'leases').glob('*.json'))
                              and not (root / 'EXECUTED').exists())
            external.terminate()
            acceptance.check('independently started fixture service shuts down cleanly when its owner stops it',
                              external.wait(timeout=15) == 0)
            acceptance.report['unqualified'] = []
            acceptance.report['coverage'] = 'Configured lifecycle criterion exercised through packaged launchers in isolated existing Git fixtures; not checker verification.'
            acceptance.report['separate_project_gates'] = [
                'standard-codex-pilot still must qualify authenticated normal Codex prompts while the checker is unavailable.',
                'plugin-package still must qualify native installed-plugin discovery and recipient dependencies.',
            ]
        finally:
            for client in clients:
                client.close()
            if external and external.poll() is None:
                external.terminate()
                external.wait(timeout=15)


class NativeCodex(Project):
    """Bounded native app-server RPC, without any model turn or command approval."""
    def __init__(self, binary, root, env, log):
        self.sequence, self.buffer = 0, bytearray()
        self.notifications = []
        self.thread_id = None
        self.shutdown_probe = None
        self.wire = subprocess.Popen([str(binary), 'app-server', '--listen', 'stdio://'],
            cwd=root, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)

    def call(self, method, params, timeout=60):
        self.sequence += 1
        self.send({'id': self.sequence, 'method': method, 'params': params})
        deadline = time.monotonic() + timeout
        while True:
            response = self.receive(max(.001, deadline - time.monotonic()))
            if 'id' not in response:
                if len(self.notifications) >= 4096:
                    raise RuntimeError('Native Codex notification bound exceeded')
                self.notifications.append(response)
                continue
            if response.get('id') != self.sequence or 'error' in response or 'result' not in response:
                raise RuntimeError('Unexpected native Codex response: ' + json.dumps(response))
            return response['result']

    def close(self):
        if self.wire:
            try:
                if self.wire.poll() is None and self.thread_id:
                    self.call('thread/unsubscribe', {'threadId': self.thread_id}, timeout=15)
                    if self.shutdown_probe:
                        self.shutdown_probe('after_thread_unsubscribe')
            finally:
                if self.wire.poll() is None:
                    self.wire.stdin.close()
                    try:
                        self.wire.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        self.wire.terminate()
                        self.wire.wait(timeout=20)
                code = self.wire.returncode
                if self.shutdown_probe:
                    self.shutdown_probe('after_appserver_exit')
                self.wire.stdout.close()
                self.wire = None
            return code


def native_plugin_package(acceptance, directory):
    if not acceptance.options.archive:
        raise UnsupportedRuntime('Native package qualification requires --archive; source-tree probes do not qualify installation.')
    binary = acceptance.options.codex_binary
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise UnsupportedRuntime('Native standard Codex executable is unavailable: ' + str(binary))
    binary = acceptance.artifact('native_codex', binary)
    plugin = acceptance.options.plugin_directory.resolve(strict=True)
    package = plugin.parent
    installer = package / 'install.py'
    checksums = json.loads((package / 'checksums.json').read_text(), object_pairs_hook=strict_object)
    root, _, config, env = fixture(directory)
    profile, data = directory / 'codex-profile', directory / 'data-home'
    profile.mkdir(mode=0o700)
    # No existing authentication/settings are copied. An offline provider also
    # prevents native session prewarming from contacting a hosted provider.
    settings = profile / 'config.toml'
    settings.write_text('model_provider = "acceptance_offline"\n'
        '[model_providers.acceptance_offline]\nname = "Acceptance offline"\n'
        'base_url = "http://127.0.0.1:1/v1"\nwire_api = "responses"\n'
        'requires_openai_auth = false\nsupports_websockets = false\n'
        '\n[projects.' + json.dumps(str(root)) + ']\ntrust_level = "trusted"\n')
    env.update(CODEX_HOME=str(profile), XDG_DATA_HOME=str(data))
    version = run([binary, '--version'], env)
    acceptance.check('native standard Codex identifies its installed version', version.returncode == 0)
    acceptance.report['native_codex_version'] = version.stdout.decode().strip()
    before = (root / '.progress-checker/config.json').read_bytes()
    installed = run(['/usr/bin/python3', installer, 'install', '--project', root,
                     '--codex', binary, '--codex-home', profile, '--data-home', data], env, 60)
    acceptance.check('release installer installs into an isolated native Codex profile',
                      installed.returncode == 0, installed.stderr.decode(errors='replace')[-4096:])
    acceptance.check('installation preserves the existing fixture plan and does not execute checks',
                      (root / '.progress-checker/config.json').read_bytes() == before
                      and not (root / 'EXECUTED').exists())
    key = hashlib.sha256(os.fsencode(root.resolve())).hexdigest()[:12]
    marketplace = 'progress-local-' + key
    selector = 'progress-checker@' + marketplace
    version_name = acceptance.report['archive']['version']
    cache = profile / 'plugins/cache' / marketplace / 'progress-checker' / version_name
    acceptance.check('native installer materializes its plugin cache outside the source package',
                      cache.is_dir() and package not in cache.parents)
    cache_mismatches = []
    cache_files = 0
    for relative, digest in checksums.items():
        if relative.startswith('plugin/') and relative != 'plugin/mcp.json':
            path = cache / relative.removeprefix('plugin/')
            cache_files += 1
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                cache_mismatches.append(relative)
    acceptance.check('native cache preserves every packaged plugin file except its explicit MCP binding',
                      not cache_mismatches, cache_mismatches)
    acceptance.report['native_cache_checked_files'] = cache_files
    mcp = json.loads((cache / 'mcp.json').read_text())['mcpServers']['progress_checker']
    state = data / 'progress-checker'
    runtime_key = hashlib.sha256(os.fsencode(root.resolve())).hexdigest()[:24]
    runtime = state / ('plugin-' + runtime_key)
    acceptance.check('cached MCP definition binds the private fixture without source or Rust paths',
                      mcp['command'] == './bin/checker-plugin'
                      and mcp['args'] == ['--root', str(root.resolve()), '--state-dir', str(state)])
    for label, relative in [('installed_launcher', 'bin/checker-plugin'),
                            ('installed_checker', 'bin/progress-checker'),
                            ('installed_mcp', 'bin/progress-checker-mcp'),
                            ('installed_helper', 'bin/checker-project'),
                            ('installed_skill', 'skills/progress-checker/SKILL.md')]:
        acceptance.artifact(label, cache / relative)
    # The installer/extraction source path no longer exists when a new native
    # process discovers dependencies. Restore only after that process exits.
    hidden = package.with_name(package.name + '-unavailable')
    package.rename(hidden)
    native = None
    try:
        acceptance.check('release source path is unavailable before native plugin discovery', not package.exists())
        with (directory / 'native-codex.log').open('ab') as log:
            native = NativeCodex(binary, root, env, log)
            initialized = native.call('initialize', {
                'clientInfo': {'name': 'plugin-acceptance', 'version': '1'},
                'capabilities': {'experimentalApi': True},
            })
            native.send({'method': 'initialized'})
            acceptance.check('native app-server uses only the isolated Codex profile',
                              initialized['codexHome'] == str(profile))
            listed = native.call('plugin/list', {'cwds': [str(root)], 'marketplaceKinds': ['local'],
                                                'forceRefetch': False})
            matches = [entry for market in listed['marketplaces'] for entry in market['plugins']
                       if entry['id'] == selector]
            acceptance.check('standard Codex natively discovers the installed enabled release',
                              not listed['marketplaceLoadErrors'] and len(matches) == 1
                              and matches[0]['installed'] and matches[0]['enabled']
                              and matches[0]['localVersion'] == version_name)
            started = native.call('thread/start', {'cwd': str(root), 'ephemeral': True,
                'approvalPolicy': 'never', 'sandbox': 'read-only'})
            native.thread_id = started['thread']['id']
            deadline = time.monotonic() + 60
            while True:
                inventory = native.call('mcpServerStatus/list', {'threadId': native.thread_id},
                                        timeout=max(.001, deadline - time.monotonic()))
                servers = [server for server in inventory['data'] if server['name'] == 'progress_checker']
                if len(servers) == 1 and servers[0].get('runtimeStatus') == 'connected':
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(.1)
            acceptance.check('native standard Codex connects the actual installed plugin and all ten tools',
                              len(servers) == 1 and servers[0]['runtimeStatus'] == 'connected'
                              and servers[0]['pluginId'] == selector
                              and set(servers[0]['tools']) == EXPECTED_TOOLS,
                              [{key: value for key, value in server.items() if key != 'tools'}
                               | {'tools': sorted(server.get('tools', {}))} for server in servers])
            acceptance.report['native_discovery'] = {'plugin_id': selector,
                'runtime_status': servers[0]['runtimeStatus'], 'tools': sorted(servers[0]['tools']),
                'profile_isolated': True, 'source_path_unavailable': True, 'model_turns': 0}
            acceptance.report['unqualified'] = [UNQUALIFIED['plugin-package'][1]]
            status = run([cache / 'bin/progress-checker', '--root', root, '--state-dir', state, 'status'], env, 10)
            acceptance.check('native startup produces no configured check attempts or verification',
                              status.returncode == 0 and json.loads(status.stdout)['latest'] == {}
                              and json.loads(status.stdout)['progress']['verified'] == 0
                              and not (root / 'EXECUTED').exists())
            native_pid = native.wire.pid
            snapshots = acceptance.report['native_shutdown_snapshots'] = {}
            native.shutdown_probe = lambda stage: snapshots.update(
                {stage: native_runtime_snapshot(runtime, native_pid)})
            native.shutdown_probe('before_thread_unsubscribe')
            watchdogs = [{'pid': process['pid'], 'starttime': process['starttime']}
                         for process in snapshots['before_thread_unsubscribe']['processes']
                         if '--watch-service' in process.get('command', [])]
            acceptance.report['native_owned_watchdogs'] = watchdogs
            acceptance.check('native package discovery session closes cleanly', native.close() == 0)
            native = None
        # Native thread unload is asynchronous; wait only for fixture leases.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and ((runtime / 'service.json').exists()
                or list((runtime / 'leases').glob('*.json'))
                or any(process_identity(watchdog['pid']) == watchdog for watchdog in watchdogs)):
            time.sleep(.05)
        snapshots['after_cleanup_deadline'] = native_runtime_snapshot(runtime, native_pid)
        acceptance.report['native_shutdown_logs'] = {
            'native_stderr_tail': (directory / 'native-codex.log').read_text(errors='replace')[-4096:],
            'service_log_tail': (runtime / 'service.log').read_text(errors='replace')[-4096:]
                               if (runtime / 'service.log').exists() else '',
        }
        acceptance.check('native session releases its owned checker and plugin leases',
                          not (runtime / 'service.json').exists()
                          and not list((runtime / 'leases').glob('*.json')),
                          {'service_record_exists': (runtime / 'service.json').exists(),
                           'leases': [path.name for path in (runtime / 'leases').glob('*.json')]})
        acceptance.check('native owned-service watchdogs exit after the last native session closes',
                          all(process_identity(watchdog['pid']) is None for watchdog in watchdogs),
                          [fixture_process_snapshot(watchdog['pid']) for watchdog in watchdogs])
        acceptance.report['unqualified'] = [UNQUALIFIED['plugin-package'][1]]
        acceptance.report['coverage'] = 'Archive installer, installed cache byte fidelity, source-unavailable standard Codex native discovery and all ten MCP tools; clean recipient qualification remains pending.'
    finally:
        try:
            if native:
                try:
                    native.close()
                finally:
                    acceptance.report['native_diagnostics'] = {
                        'startup_events': [event for event in native.notifications
                                           if event.get('method') == 'mcpServer/startupStatus/updated'],
                        'stderr_tail': (directory / 'native-codex.log').read_text(errors='replace')[-4096:],
                    }
        finally:
            try:
                stop_fixture_writer(acceptance, runtime / 'service.json', cache / 'bin/progress-checker', root, state)
            finally:
                hidden.rename(package)


def plugin_package(acceptance, directory):
    native_plugin_package(acceptance, directory)
    package_recipient(acceptance, directory)


def plan_submission(acceptance, directory):
    with Project(acceptance, directory) as project:
        config_path = project.root / '.progress-checker/config.json'
        before_bytes = config_path.read_bytes()
        initial = project.current()
        acceptance.check('project tool binds the exact isolated canonical worktree',
                          initial['result']['canonical_root'] == str(project.root.resolve()))
        project.refusal('before-plan')
        revised = copy.deepcopy(project.config)
        revised['milestones'][0]['title'] = 'Alpha revised explicitly'
        revised['milestones'] = [revised['milestones'][0], revised['milestones'][2]]
        added = copy.deepcopy(revised['milestones'][0])
        added.update(id='gamma', title='Gamma added explicitly', depends_on=['alpha'])
        revised['milestones'].append(added)
        read_only = project.submit(revised, read_only=True)
        acceptance.check('read-only plan submission refuses mutation before IPC',
                          read_only['isError'] and read_only['structuredContent']['error']['code'] == 'READ_ONLY_REQUEST'
                          and config_path.read_bytes() == before_bytes and project.history()['total'] == 0)
        invalid = []
        for label, mutate in [
            ('cycle', lambda c: c['milestones'][0].update(depends_on=['beta'])),
            ('unknown dependency', lambda c: c['milestones'][0].update(depends_on=['missing'])),
            ('unsafe cwd', lambda c: c['checks'][0].update(cwd='../outside')),
            ('unsafe fingerprint path', lambda c: c['fingerprint'].update(extra_inputs=['/etc/passwd'])),
            ('zero timeout', lambda c: c['checks'][0].update(timeout_seconds=0)),
            ('unknown field', lambda c: c.update(approval=True)),
            ('invalid identifier', lambda c: c['milestones'][0].update(id='bad id')),
            ('unknown criterion check', lambda c: c['milestones'][0]['criteria'][0].update(check_id='missing')),
            ('no required criterion', lambda c: c['milestones'][0]['criteria'][0].update(required=False)),
            ('duplicate milestone', lambda c: c['milestones'].append(copy.deepcopy(c['milestones'][0]))),
            ('duplicate check', lambda c: c['checks'].append(copy.deepcopy(c['checks'][0]))),
            ('duplicate criterion', lambda c: c['milestones'][0]['criteria'].append(copy.deepcopy(c['milestones'][0]['criteria'][0]))),
            ('changed bound project identity', lambda c: c.update(project_id='another-project')),
            ('tracked source hidden by output exclusion', lambda c: c['fingerprint'].update(exclude_outputs=['sentinel.py'])),
            ('mandatory config hidden by output exclusion', lambda c: c['fingerprint'].update(exclude_outputs=['.progress-checker/**'])),
            ('explicit cache input overlaps output exclusion', lambda c: c['fingerprint'].update(
                extra_inputs=['.local/cache.json'], exclude_outputs=['.local/**'])),
        ]:
            candidate = copy.deepcopy(project.config)
            mutate(candidate)
            invalid.append((label, candidate))
        (project.root / '.local').mkdir()
        (project.root / '.local/cache.json').write_text('{"input":true}\n')
        for label, candidate in invalid:
            rejected = project.submit(candidate)
            acceptance.check(label + ' rejected without config or history changes',
                              rejected['isError'] and config_path.read_bytes() == before_bytes
                              and project.history()['total'] == 0)
        rejected = project.submit(revised, reason='   ')
        acceptance.check('empty reason rejected without writes', rejected['isError'] and config_path.read_bytes() == before_bytes)
        for name in ('alpha', 'beta', 'stable'):
            project.claim(name)
        current = project.current()
        acceptance.check('implemented claims cannot establish verification',
                          current['result']['claims'] == {'alpha': 'implemented', 'beta': 'implemented', 'stable': 'implemented'}
                          and current['result']['status']['progress']['verified'] == 0)
        accepted = project.submit(revised, current)
        acceptance.check('validated plan replacement matches the entire submitted configuration',
                          not accepted['isError'] and json.loads(config_path.read_bytes()) == revised)
        change = accepted['structuredContent']['result']['change']
        acceptance.check('scope history explicitly records added removed and changed milestones',
                          change['added'] == ['gamma'] and change['removed'] == ['beta'] and change['changed'] == ['alpha']
                          and change['before_hash'] != change['after_hash'])
        after = project.current()
        acceptance.check('changed and removed claims reset while unchanged claims persist',
                          after['result']['claims'] == {'stable': 'implemented'}
                          and after['result']['status']['progress']['verified'] == 0)
        stale = project.submit(project.config, current)
        acceptance.check('stale revision cannot overwrite the new plan',
                          stale['isError'] and stale['structuredContent']['error']['code'] == 'REVISION_CONFLICT'
                          and json.loads(config_path.read_bytes()) == revised, stale['structuredContent'])
        wrong_hash = copy.deepcopy(after)
        wrong_hash['result']['status']['source']['config_hash'] = current['result']['status']['source']['config_hash']
        stale = project.submit(project.config, wrong_hash)
        acceptance.check('stale config hash cannot overwrite the new plan',
                          stale['isError'] and stale['structuredContent']['error']['code'] == 'PLAN_CONFLICT'
                          and stale['structuredContent']['error']['message'].startswith('PLAN_CONFLICT')
                          and json.loads(config_path.read_bytes()) == revised, stale['structuredContent'])
        history = project.history()
        acceptance.check('history returns the accepted durable scope summary',
                          history['total'] == 1 and history['entries'] == [change])
        unchanged = project.submit(revised)
        acceptance.check('unchanged plan is idempotent and creates no extra history',
                          not unchanged['isError'] and unchanged['structuredContent']['result']['change'] is None
                          and project.history()['total'] == 1)
        project.refusal('after-plan')
        instance = project.current()['service_instance_id']
        project.restart()
        reopened = project.current()
        acceptance.check('restart restores submitted config claims and scope history under a new service identity',
                          reopened['service_instance_id'] != instance and reopened['result']['config'] == revised
                          and reopened['result']['claims'] == {'stable': 'implemented'}
                          and project.history()['entries'] == [change])
        project.refusal('after-restart')
    plan_interruption(acceptance, directory / 'interrupted-plan')
    plan_invalidation(acceptance, directory / 'approved-plan-invalidation')


def plan_invalidation(acceptance, directory):
    """Consume only an explicit dedicated fixture's existing human grant."""
    selected_root = acceptance.options.plan_fixture_root
    selected_state = acceptance.options.plan_fixture_state
    if selected_root is None:
        return
    if not acceptance.options.archive:
        raise UnsupportedRuntime('Plan invalidation requires an exact --archive runtime.')
    root, state = selected_root.resolve(strict=True), selected_state.resolve(strict=True)
    config_path = root / '.progress-checker/config.json'
    original = json.loads(config_path.read_bytes(), object_pairs_hook=strict_object)
    expected_script = (b'from pathlib import Path\n'
        b'assert Path("feature.txt").read_text() == "plan acceptance implemented\\n"\n'
        b'print("Dedicated plan invalidation fixture passed")\n')
    expected_feature = b'plan acceptance implemented\n'
    acceptance.check('approved plan probe selects only the dedicated isolated fixture',
        original['project_id'] == 'isolated-plan-invalidation'
        and len(original['checks']) == 1 and original['checks'][0] == {
            'id': 'plan-check', 'argv': ['/usr/bin/python3', 'plan-check.py'],
            'cwd': '.', 'kind': 'test', 'timeout_seconds': 10}
        and {item['id'] for item in original['milestones']} == {'alpha', 'beta', 'stable'}
        and all(criterion['check_id'] == 'plan-check' for item in original['milestones'] for criterion in item['criteria'])
        and (root / 'plan-check.py').is_file() and not (root / 'plan-check.py').is_symlink()
        and (root / 'feature.txt').is_file() and not (root / 'feature.txt').is_symlink()
        and (root / 'plan-check.py').read_bytes() == expected_script
        and (root / 'feature.txt').read_bytes() == expected_feature)
    directory.mkdir(mode=0o700, parents=True)
    env = environment(directory)
    canonical = run(['/usr/bin/git', '-C', root, 'rev-parse', '--show-toplevel'], env)
    acceptance.check('dedicated approved plan fixture is the exact existing Git worktree',
                      canonical.returncode == 0 and Path(canonical.stdout.decode().strip()).resolve() == root)
    plugin = acceptance.options.plugin_directory
    launcher = acceptance.artifact('plan_invalidation_launcher', plugin / 'bin/checker-plugin')
    acceptance.artifact('plan_invalidation_checker', plugin / 'bin/progress-checker')
    acceptance.artifact('plan_invalidation_mcp', plugin / 'bin/progress-checker-mcp')
    session = None
    with (directory / 'launcher.log').open('ab') as log:
        def connect():
            client = LauncherSession(acceptance, launcher, root, state, env, plugin, log)
            try:
                client.initialize()
            except BaseException:
                client.close()
                raise
            return client

        def request(label):
            current = session.current()
            return session.tool('checker_run_checks', {
                'check_ids': ['plan-check'], 'idempotency_key': 'plan-' + label + '-' + str(time.time_ns()),
                'expected_revision': current['revision'],
                'expected_config_hash': current['result']['status']['source']['config_hash']})

        def refused_without_attempt(label, expected_latest):
            refused = request(label)
            acceptance.check('plan revision revokes the existing exact human grant: ' + label,
                              refused['isError'] and refused['structuredContent']['error']['code'] == 'PERMISSION_REQUIRED',
                              refused['structuredContent'])
            current = session.current()
            acceptance.check('revoked plan grant creates no replacement check attempts: ' + label,
                              current['result']['status']['latest'] == expected_latest
                              and current['result']['running'] == [])

        try:
            session = connect()
            initial = session.current()
            acceptance.check('dedicated plan fixture initially has no evidence-derived verification',
                              initial['result']['status']['progress']['verified'] == 0)
            for milestone_id in ('alpha', 'beta', 'stable'):
                session.claim(milestone_id)
            claimed = session.current()
            acceptance.check('dedicated implementation claims remain distinct from current verification',
                              claimed['result']['claims'] == {'alpha': 'implemented', 'beta': 'implemented', 'stable': 'implemented'}
                              and claimed['result']['status']['progress']['verified'] == 0)
            permission = request('prior-grant')
            if permission['isError'] and permission['structuredContent']['error']['code'] == 'PERMISSION_REQUIRED':
                acceptance.report['plan_invalidation_probe'] = {'status': 'blocked',
                    'reason': 'Dedicated fixture has no usable exact human grant; no approval was created.'}
                return
            acceptance.check('dedicated human grant accepts the actual packaged plan check',
                              not permission['isError'], permission['structuredContent'])
            run_ids = permission['structuredContent']['result']['run_ids']
            deadline = time.monotonic() + 25
            while True:
                before = session.current()
                evidence = before['result']['status']['latest'].get('plan-check', {})
                if evidence.get('run_id') in run_ids and evidence.get('execution_state') == 'finished':
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('Dedicated human-approved plan check did not finish')
                time.sleep(.1)
            acceptance.check('actual prior approved check establishes current passing evidence',
                              evidence['outcome'] == 'passed' and evidence['freshness'] == 'current'
                              and before['result']['status']['progress']['verified'] == 3)
            revised = copy.deepcopy(before['result']['config'])
            revised['milestones'][0]['title'] += ' explicit invalidation revision'
            accepted = session.submit(revised, before,
                reason='Acceptance: prove installed plan revision invalidates genuine prior evidence and exact approval')
            acceptance.check('installed revision accepts the explicit dedicated plan change',
                              not accepted['isError'], accepted['structuredContent'])
            after = session.current()
            latest = after['result']['status']['latest']
            acceptance.check('installed plan revision makes actual prior passing evidence stale and unverified',
                              latest['plan-check']['run_id'] == evidence['run_id']
                              and latest['plan-check']['outcome'] == 'passed'
                              and latest['plan-check']['freshness'] == 'stale'
                              and after['result']['status']['progress']['verified'] == 0)
            refused_without_attempt('after-submit', latest)
            total = session.history()['total']
            acceptance.check('dedicated invalidation launcher exits cleanly before restart', session.close() == 0)
            session = connect()
            restored = session.current()
            acceptance.check('packaged restart durably retains changed plan stale evidence and scope history',
                              restored['result']['config'] == revised
                              and restored['result']['status']['latest'] == latest
                              and restored['result']['status']['progress']['verified'] == 0
                              and session.history()['total'] == total)
            refused_without_attempt('after-restart', latest)
            acceptance.check('plan invalidation preserves the dedicated check script and feature bytes',
                              (root / 'plan-check.py').read_bytes() == expected_script
                              and (root / 'feature.txt').read_bytes() == expected_feature)
            acceptance.report['plan_invalidation_probe'] = {'status': 'passed', 'fixture_root': str(root),
                'state_directory': str(state), 'genuine_prior_run_id': evidence['run_id'],
                'approval_created': False, 'retained_demo_selected': False,
                'fixture_plan_left_at_explicit_new_revision': True}
            acceptance.report['unqualified'] = [gate for gate in acceptance.report['unqualified']
                                                if gate != UNQUALIFIED['plan-submission'][0]]
        finally:
            if session:
                acceptance.check('dedicated plan invalidation packaged session closes cleanly', session.close() in (0, None))


def plan_interruption(acceptance, directory):
    """Interrupt a real installed transaction at the public config I/O boundary."""
    with Project(acceptance, directory) as project:
        path = project.root / '.progress-checker/config.json'
        parent = path.parent
        original = path.read_bytes()
        permissions = stat.S_IMODE(parent.stat().st_mode)
        revised = copy.deepcopy(project.config)
        revised['milestones'][0]['title'] = 'Recovered interrupted acceptance plan'
        project.claim('alpha')
        project.claim('stable')
        initial = project.current()
        parent.chmod(permissions & ~0o222)
        try:
            # Confirm actual permission enforcement before calling the backend.
            # Privileged environments cannot exercise this portable fault.
            probe = parent / '.permission-probe'
            try:
                with probe.open('xb'):
                    pass
            except PermissionError:
                enforced = True
            else:
                probe.unlink()
                enforced = False
            if not enforced:
                acceptance.report['interruption_probe'] = {'status': 'unsupported',
                    'reason': 'This effective user bypasses public directory write permissions.'}
                return
            failed = project.submit(revised, initial,
                                    reason='Acceptance: recover an interrupted atomic plan replacement')
            acceptance.check('installed plan replacement interruption returns a genuine storage failure',
                              failed['isError']
                              and 'Permission denied' in failed['structuredContent']['error']['message'],
                              failed['structuredContent'])
            acceptance.check('failed atomic plan replacement preserves exact public configuration bytes',
                              path.read_bytes() == original)
            acceptance.check('failed atomic plan replacement does not prematurely commit history',
                              project.history()['total'] == 0)
        finally:
            parent.chmod(permissions)
        project.restart()
        recovered = project.current()
        history = project.history()
        acceptance.check('installed restart recovers the pending transaction to the entire intended plan',
                          recovered['result']['config'] == revised and json.loads(path.read_bytes()) == revised
                          and recovered['service_instance_id'] != initial['service_instance_id'])
        acceptance.check('recovery commits one explicit scope history entry and resets only changed claims',
                          history['total'] == 1 and history['entries'][0]['changed'] == ['alpha']
                          and recovered['result']['claims'] == {'stable': 'implemented'})
        project.restart()
        acceptance.check('second installed restart never duplicates recovered plan history',
                          project.history()['total'] == 1 and project.current()['result']['config'] == revised)
        project.refusal('after-interruption-recovery')
        acceptance.report['interruption_probe'] = {'status': 'passed',
            'boundary': 'public configuration directory denies replacement; durable pending transaction recovers on restart',
            'private_records_manually_edited': False, 'production_failpoint': False,
            'abrupt_process_kill_injected': False}
        acceptance.report['supplementary_source_test_coverage'] = {
            'location': 'checker-core/src/plan.rs',
            'tests': ['replacing_plan_directory_during_update_is_rejected',
                      'pending_plan_recovers_before_and_after_atomic_config_replace',
                      'plan_records_changes_resets_changed_claims_and_clears_approvals'],
            'qualification': 'Source unit coverage complements installed probes; it does not substitute for installed approval/evidence invalidation.'}
        acceptance.report['unqualified'] = [gate for gate in acceptance.report['unqualified']
                                            if gate != UNQUALIFIED['plan-submission'][1]]


def prepare_plan_invalidation_fixture(directory):
    """Stage a separate public fixture for an exact human-approved check later.

    This helper never starts the service, executes the check, or obtains a grant.
    It refuses to reuse any existing directory or private-state records.
    """
    directory = Path(directory).absolute()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    root, state, config, env = fixture(directory)
    (root / 'sentinel.py').unlink()
    (root / 'feature.txt').write_text('plan acceptance implemented\n')
    (root / 'plan-check.py').write_text('from pathlib import Path\n'
        'assert Path("feature.txt").read_text() == "plan acceptance implemented\\n"\n'
        'print("Dedicated plan invalidation fixture passed")\n')
    config['project_id'] = 'isolated-plan-invalidation'
    config['checks'][0].update(id='plan-check', argv=['/usr/bin/python3', 'plan-check.py'])
    for milestone in config['milestones']:
        milestone['criteria'][0].update(check_id='plan-check', description='Dedicated fixture check passes')
    (root / '.progress-checker/config.json').write_text(json.dumps(config, indent=2) + '\n')
    for command in [
        ['/usr/bin/git', '-C', root, 'add', '.'],
        ['/usr/bin/git', '-C', root, '-c', 'user.name=Plugin acceptance',
         '-c', 'user.email=acceptance@example.invalid', 'commit', '--quiet', '-m', 'Dedicated approval fixture'],
    ]:
        completed = run(command, env)
        if completed.returncode:
            raise RuntimeError('Could not stage dedicated approval fixture: ' + completed.stderr.decode(errors='replace'))
    report = {'root': str(root), 'state': str(state), 'check_id': 'plan-check',
        'argv': config['checks'][0]['argv'], 'cwd': str(root), 'timeout_seconds': 10,
        'public_config_sha256': hashlib.sha256((root / '.progress-checker/config.json').read_bytes()).hexdigest(),
        'approval_created': False, 'configured_check_executed': False,
        'acceptance_sequence_after_human_approval': [
            'Run plan-check through the exact archive launcher and require current passing evidence.',
            'Submit an explicit title change with current revision/config hash through checker_submit_plan.',
            'Require former passing evidence to be stale and verification to return to zero.',
            'Require a new run request to refuse PERMISSION_REQUIRED without adding a check attempt.',
            'Restart the packaged launcher and require durable history, stale evidence, and continued refusal.',
        ]}
    (directory / 'preparation.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def agent_workflow(acceptance, directory):
    helper = acceptance.artifact('checker_project', acceptance.options.plugin_directory / 'bin/checker-project')
    env = environment(directory)
    root = directory / 'instructions'
    root.mkdir()
    agents = root / 'AGENTS.md'
    original = '# Existing instructions\r\nPreserve café and bytes.\r\nNo final newline'.encode()
    agents.write_bytes(original)
    agents.chmod(0o640)
    def action(name):
        return run(['/usr/bin/python3', helper, name, '--root', root], env)
    acceptance.check('managed setup installs into existing instructions', action('install').returncode == 0)
    installed = agents.read_bytes()
    acceptance.check('setup preserves existing bytes and file permissions',
                      installed.startswith(original) and stat.S_IMODE(agents.stat().st_mode) == 0o640
                      and installed.count(b'<!-- progress-checker:begin -->') == 1
                      and installed.count(b'<!-- progress-checker:end -->') == 1)
    acceptance.check('setup is byte-idempotent', action('install').returncode == 0 and agents.read_bytes() == installed)
    suffix = b'\nAdditional user instructions after setup.\n'
    agents.write_bytes(installed + suffix)
    acceptance.check('removal preserves user content before and after the managed block',
                      action('remove').returncode == 0 and agents.read_bytes() == original + suffix
                      and stat.S_IMODE(agents.stat().st_mode) == 0o640)
    acceptance.check('removal is byte-idempotent', action('remove').returncode == 0 and agents.read_bytes() == original + suffix)
    acceptance.check('setup can be reinstalled after removal', action('install').returncode == 0)
    edited = agents.read_bytes().replace(b'## Progress Checker', b'## User edited managed instructions')
    agents.write_bytes(edited)
    for name in ('install', 'remove'):
        acceptance.check('edited managed block refuses ' + name + ' and preserves all bytes',
                          action(name).returncode != 0 and agents.read_bytes() == edited)
    ambiguous = original + b'\n<!-- progress-checker:begin -->\n<!-- progress-checker:begin -->\n<!-- progress-checker:end -->\n'
    agents.write_bytes(ambiguous)
    for name in ('install', 'remove'):
        acceptance.check('ambiguous markers refuse ' + name + ' without changing instructions',
                          action(name).returncode != 0 and agents.read_bytes() == ambiguous)
    agents.unlink()
    target = directory / 'outside-agents'
    target.write_bytes(original)
    agents.symlink_to(target)
    acceptance.check('setup refuses a symlink without modifying its target',
                      action('install').returncode != 0 and agents.is_symlink() and target.read_bytes() == original)
    agents.unlink()
    acceptance.check('explicit setup works without an existing AGENTS.md', action('install').returncode == 0)
    acceptance.check('removal from newly created instructions leaves no managed content',
                      action('remove').returncode == 0 and agents.read_bytes() == b'')
    with Project(acceptance, directory) as project:
        revised = copy.deepcopy(project.config)
        revised['milestones'][0]['title'] = 'Accepted fixture scope'
        accepted = project.submit(revised)
        acceptance.check('workflow submits accepted scope through the actual plan tool',
                          not accepted['isError'] and project.history()['total'] == 1)
        project.claim('alpha')
        result = project.success('checker_get_progress')['result']
        alpha = next(item for item in result['status']['progress']['milestones'] if item['milestone_id'] == 'alpha')
        acceptance.check('progress tool reports implementation separately from missing passing evidence',
                          alpha['implementation_claim'] == 'implemented' and alpha['verified'] is False
                          and result['status']['progress']['verified'] == 0
                          and any('lacks current passing evidence' in blocker for blocker in alpha['blockers']))
        forged = project.tool('checker_set_claim', {'milestone_id': 'alpha', 'claim': 'verified', 'note': '',
                                                   'expected_revision': project.current()['revision']})
        acceptance.check('workflow cannot claim verification directly',
                          forged['isError'] and forged['structuredContent']['error']['code'] == 'INVALID_ARGUMENT')
        project.refusal('workflow-no-approval')


def parse_options(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--milestone', choices=UNQUALIFIED, required=True)
    parser.add_argument('--archive', type=Path, help='Validate and exercise only this checksummed release archive')
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--mcp-binary', type=Path)
    parser.add_argument('--plugin-directory', type=Path)
    parser.add_argument('--codex-binary', type=Path, default=DEFAULT_CODEX,
                        help='Installed standard Codex executable for isolated native package qualification')
    parser.add_argument('--evidence-fixture-root', type=Path,
                        help='Explicit existing demo fixture with a previously human-approved exact check')
    parser.add_argument('--evidence-fixture-state', type=Path,
                        help='Explicit retained state directory paired with --evidence-fixture-root')
    parser.add_argument('--plan-fixture-root', type=Path,
                        help='Explicit dedicated isolated-plan-invalidation fixture with an existing human grant')
    parser.add_argument('--plan-fixture-state', type=Path,
                        help='Explicit dedicated retained state paired with --plan-fixture-root')
    parser.add_argument('--pilot-fixture-root', type=Path, help='Explicit existing isolated Git pilot fixture')
    parser.add_argument('--pilot-fixture-state', type=Path, help='Explicit retained external pilot state')
    parser.add_argument('--pilot-codex-home', type=Path, help='Explicit directly authenticated native Codex home; never copied')
    parser.add_argument('--pilot-accepted-plan', type=Path, help='Explicit bounded public accepted complete config JSON')
    parser.add_argument('--pilot-phase', choices=('prepare', 'verify'), default='prepare')
    parser.add_argument('--pilot-approved-check', help='Exact existing human-granted check selected for verify; never grants approval')
    parser.add_argument('--primary-attestation', type=Path,
                        help='OFF-default public immutable live-producer attestation; standard pilot only')
    parser.add_argument('--primary-attestation-sha256',
                        help='Exact approved immutable attestation SHA256; never creates approval')
    parser.add_argument('--primary-readiness', type=Path,
                        help='Mutable readiness paired with approved immutable attestation; no activation/control')
    parser.add_argument('--native-package-only', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--recipient-old-archive', type=Path,
                        help='Exact pinned older archive input for fresh recipient upgrade qualification')
    parser.add_argument('--test-runtime', choices=('public-namespace',),
                        help='Explicit public-fixture mapped-root test runtime; never accepts retained grants or state')
    parser.add_argument('--output', type=Path, help='Optional development report; not private checker evidence')
    options = parser.parse_args(argv)
    if options.archive and any((options.binary, options.mcp_binary, options.plugin_directory)):
        parser.error('--archive cannot be combined with executable or plugin-directory overrides')
    if (options.evidence_fixture_root is None) != (options.evidence_fixture_state is None):
        parser.error('--evidence-fixture-root and --evidence-fixture-state must be supplied together')
    if options.evidence_fixture_root is not None and options.milestone not in ('evidence-integrity', 'release-distribution'):
        parser.error('explicit evidence fixture paths apply only to evidence-integrity or release-distribution')
    if (options.plan_fixture_root is None) != (options.plan_fixture_state is None):
        parser.error('--plan-fixture-root and --plan-fixture-state must be supplied together')
    if options.plan_fixture_root is not None and options.milestone != 'plan-submission':
        parser.error('explicit dedicated plan fixture paths apply only to --milestone plan-submission')
    if (options.pilot_fixture_root is None) != (options.pilot_fixture_state is None):
        parser.error('--pilot-fixture-root and --pilot-fixture-state must be supplied together')
    if any((options.pilot_fixture_root, options.pilot_codex_home, options.pilot_accepted_plan,
            options.pilot_approved_check, options.pilot_phase != 'prepare')) and options.milestone != 'standard-codex-pilot':
        parser.error('explicit pilot options apply only to --milestone standard-codex-pilot')
    if options.pilot_approved_check and options.pilot_phase != 'verify':
        parser.error('--pilot-approved-check requires --pilot-phase verify; it never grants approval')
    primary = any((options.primary_attestation, options.primary_attestation_sha256, options.primary_readiness))
    if primary:
        if not all((options.primary_attestation, options.primary_attestation_sha256, options.primary_readiness)):
            parser.error('--primary-attestation, --primary-attestation-sha256 and --primary-readiness must be paired')
        if options.milestone != 'standard-codex-pilot':
            parser.error('primary live attestation applies only to --milestone standard-codex-pilot')
        if not re.fullmatch(r'[0-9a-f]{64}', options.primary_attestation_sha256):
            parser.error('--primary-attestation-sha256 must be exactly 64 lower-case hexadecimal characters')
        if options.archive is None or options.recipient_old_archive is None:
            parser.error('primary live attestation requires exact current and recipient older archive inputs')
        if any((options.pilot_fixture_root, options.pilot_fixture_state, options.pilot_codex_home,
                options.pilot_accepted_plan, options.pilot_approved_check, options.pilot_phase != 'prepare')):
            parser.error('primary live observation cannot be mixed with direct authenticated fixture pilot options')
        for path in (options.primary_attestation, options.primary_readiness):
            if not path.is_absolute() or '..' in path.parts or not path.is_relative_to(ROOT / '.local'):
                parser.error('primary registration paths must be absolute excluded-worktree public paths')
        if options.primary_attestation == options.primary_readiness:
            parser.error('immutable primary attestation and mutable readiness must use different files')
        if options.output is not None:
            if not options.output.is_absolute() or '..' in options.output.parts or not options.output.is_relative_to(ROOT / '.local'):
                parser.error('primary report path must be a new absolute excluded-worktree public path')
            if os.path.lexists(options.output):
                parser.error('primary report path must be new; existing reports cannot be overwritten or imported')
    if options.test_runtime:
        if options.milestone not in ('service-lifecycle', 'agent-workflow', 'plan-submission', 'plugin-package'):
            parser.error('public-namespace runtime supports only public lifecycle, workflow, plan and package behavior')
        if options.archive is None:
            parser.error('public-namespace runtime requires the exact --archive')
        if any((options.evidence_fixture_root, options.evidence_fixture_state,
                options.plan_fixture_root, options.plan_fixture_state,
                options.pilot_fixture_root, options.pilot_fixture_state,
                options.pilot_codex_home, options.pilot_accepted_plan, options.pilot_approved_check)):
            parser.error('public-namespace runtime refuses retained fixture, approval and authentication paths')
    if options.native_package_only and (options.milestone != 'plugin-package' or options.archive is None or options.test_runtime):
        parser.error('internal native package phase requires plugin-package and an exact archive, without runtime recursion')
    if options.recipient_old_archive is not None and options.milestone not in ('plugin-package', 'release-distribution') and not primary:
        parser.error('recipient older archive applies only to package and release qualification')
    return options


def write_new_primary_report(path, payload):
    """Create one private public receipt, never replacing an existing path/alias."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or not path.is_relative_to(ROOT / '.local'):
        raise RuntimeError('Primary report must be an absolute excluded-worktree public path')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    descriptor = None
    try:
        for component in path.parts[1:-1]:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=parent)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent); parent = child
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(descriptor, 'w') as stream:
            descriptor = None
            stream.write(payload)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def main():
    options = parse_options()
    acceptance = Acceptance(options)
    exit_code = 2
    try:
        if options.test_runtime:
            runtime = behavioral_module(acceptance, 'plugin_acceptance_runtime')
            with tempfile.TemporaryDirectory(prefix='plugin-public-runtime-report-') as temporary:
                remaining = (210 if options.milestone == 'plugin-package' else 260) - (time.monotonic()-acceptance.started_at)
                report, exit_code = runtime.run_acceptance(
                    options.archive, options.milestone, Path(temporary)/'runtime', timeout=remaining)
                acceptance.report = report
                if options.milestone == 'plugin-package' and report['status'] == 'partial':
                    package_recipient(acceptance, Path(temporary)/'recipient')
                    complete = not acceptance.report['unqualified']
                    acceptance.report.update(status='passed' if complete else 'partial', complete=complete)
                    exit_code = 0 if complete else 2
        else:
            behavior = {'plan-submission': plan_submission, 'agent-workflow': agent_workflow,
                        'service-lifecycle': service_lifecycle, 'plugin-package': plugin_package,
                        'evidence-integrity': evidence_integrity,
                        'release-distribution': release_distribution,
                        'standard-codex-pilot': standard_codex_pilot}.get(options.milestone)
            if options.native_package_only:
                behavior = native_plugin_package
            # Extraction, all behavior, and artifact rehashing share one lifetime.
            with tempfile.TemporaryDirectory(prefix='plugin-acceptance-') as temporary:
                directory = Path(temporary)
                if options.archive:
                    options.plugin_directory = extract_archive(acceptance, options.archive, directory / 'release')
                    options.binary = options.plugin_directory / 'bin/progress-checker'
                    options.mcp_binary = options.plugin_directory / 'bin/progress-checker-mcp'
                    acceptance.check('release archive has an exact validated checksum inventory', True)
                else:
                    options.plugin_directory = options.plugin_directory or default_plugin_directory()
                    options.binary = options.binary or options.plugin_directory / 'bin/progress-checker'
                    options.mcp_binary = options.mcp_binary or options.plugin_directory / 'bin/progress-checker-mcp'
                if behavior:
                    behavior(acceptance, directory)
                    acceptance.check('tested executable artifacts remained unchanged during assertions', all(
                        hashlib.sha256(Path(record['path']).read_bytes()).hexdigest() == record['sha256']
                        for record in acceptance.report['artifacts'].values()))
                    complete = not acceptance.report['unqualified']
                    acceptance.report.update(status='passed' if complete else 'partial', complete=complete)
                    if complete:
                        exit_code = 0
                else:
                    acceptance.report['reason'] = 'No complete behavioral acceptance implementation for this milestone yet.'
    except UnsupportedRuntime as error:
        acceptance.report['status'] = 'unsupported'
        acceptance.report['reason'] = str(error)
    except Exception as error:
        acceptance.report['status'] = 'failed'
        acceptance.report['error'] = str(error)
        exit_code = 1
    payload = json.dumps(acceptance.report, indent=2) + '\n'
    if options.output:
        if options.primary_attestation is not None:
            write_new_primary_report(options.output, payload)
        else:
            options.output.parent.mkdir(parents=True, exist_ok=True)
            if options.output.exists():
                previous = options.output.with_name(
                    options.output.stem + '.previous-' + str(time.time_ns()) + options.output.suffix)
                options.output.replace(previous)
            options.output.write_text(payload)
    print(payload, end='')
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
