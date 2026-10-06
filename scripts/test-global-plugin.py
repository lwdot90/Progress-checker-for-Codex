#!/usr/bin/env python3
"""Exercise the installed global plugin in isolated synthetic Git repositories.

This test never approves a command or executes a configured check. The only
run request must refuse a missing human grant. State is inspected through the
packaged public MCP tools; private evidence, keys, and approvals are not read.
"""
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import select
import stat
import subprocess
import tarfile
import tempfile
import time
import tomllib
import uuid

DEFAULT_CODEX = Path('/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex')
BACKEND_TOOLS = {
    'checker_submit_plan', 'checker_get_plan_history', 'checker_get_project',
    'checker_list_milestones', 'checker_set_claim', 'checker_run_checks',
    'checker_get_run', 'checker_get_log', 'checker_cancel_run', 'checker_get_progress',
}
TRACK = 'checker_track_project'
FRAME_LIMIT = 256 * 1024


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


def load_package(options, directory):
    if options.package is not None:
        return options.package.resolve(strict=True), None
    archive = options.archive
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
            raise ValueError('Archive must be a bounded regular file')
        data = source.read(64 * 1024 * 1024 + 1)
    digest = hashlib.sha256(data).hexdigest()
    if digest != options.sha256.lower():
        raise ValueError('Supplied archive does not match --sha256')
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        expanded = compressed.read(144 * 1024 * 1024 + 1)
    if len(expanded) > 144 * 1024 * 1024:
        raise ValueError('Archive expansion exceeds its bound')
    destination = directory / 'extracted-package'
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive_file:
        members = archive_file.getmembers()
        names, roots, payload = set(), set(), 0
        if len(members) > 4096:
            raise ValueError('Archive contains too many members')
        for member in members:
            name = member.name.rstrip('/') if member.isdir() else member.name
            parts = name.split('/')
            if (not name or name.startswith('/') or '\\' in name or '\0' in name
                    or any(part in ('', '.', '..') for part in parts) or name in names
                    or not (member.isfile() or member.isdir())):
                raise ValueError('Archive contains unsafe, duplicated, or special members')
            if member.size > 64 * 1024 * 1024:
                raise ValueError('Archive member exceeds its bound')
            names.add(name); roots.add(parts[0]); payload += member.size
        if len(roots) != 1 or payload > 128 * 1024 * 1024:
            raise ValueError('Archive must have one bounded package root')
        archive_file.extractall(destination, filter='data')
    return destination / roots.pop(), digest


class MCP:
    def __init__(self, arguments, cwd, environment, logs, label):
        self.buffer = bytearray()
        self.sequence = 0
        self.stderr = (logs / (label + '.stderr')).open('wb')
        self.receipts = (logs / (label + '.public-wire.jsonl')).open('w')
        self.process = subprocess.Popen([str(value) for value in arguments], cwd=cwd,
            env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr)
        try:
            self.rpc('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                'clientInfo': {'name': 'global-plugin-integration', 'version': '1'}})
            self.process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
            self.process.stdin.flush()
        except BaseException:
            self.close(require_success=False)
            raise

    def rpc(self, method, params):
        self.sequence += 1
        request = {'jsonrpc': '2.0', 'id': self.sequence, 'method': method, 'params': params}
        self.receipts.write(json.dumps({'request': request}) + '\n'); self.receipts.flush()
        self.process.stdin.write(json.dumps(request).encode() + b'\n'); self.process.stdin.flush()
        deadline = time.monotonic() + 60
        while True:
            if b'\n' in self.buffer:
                line, _, rest = self.buffer.partition(b'\n'); self.buffer[:] = rest
                response = json.loads(line, object_pairs_hook=strict_object)
                self.receipts.write(json.dumps({'response': response}) + '\n'); self.receipts.flush()
                if 'id' not in response:
                    continue
                if response.get('jsonrpc') != '2.0' or response.get('id') != self.sequence or 'error' in response:
                    raise RuntimeError('Invalid MCP response: ' + json.dumps(response))
                return response['result']
            if time.monotonic() >= deadline:
                raise TimeoutError('Global-plugin MCP response deadline exceeded')
            if select.select([self.process.stdout], [], [], .1)[0]:
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if not chunk:
                    raise RuntimeError('Global-plugin MCP closed unexpectedly')
                self.buffer.extend(chunk)
                if len(self.buffer) > FRAME_LIMIT:
                    raise RuntimeError('Global-plugin MCP response exceeds frame limit')

    def tool(self, name, arguments=None, *, read_only=False):
        params = {'name': name, 'arguments': arguments or {}}
        if read_only:
            params['_meta'] = {'openai/readOnly': True}
        reply = self.rpc('tools/call', params)
        if (type(reply.get('isError')) is not bool
                or json.loads(reply['content'][0]['text']) != reply['structuredContent']):
            raise RuntimeError('MCP text and structured results disagree')
        return reply

    def success(self, name, arguments=None, *, read_only=False):
        deadline = time.monotonic() + 30
        while True:
            reply = self.tool(name, arguments, read_only=read_only)
            if not reply['isError']:
                return reply['structuredContent']
            error = reply['structuredContent']['error']
            if error['code'] != 'FRESHNESS_PENDING' or time.monotonic() >= deadline:
                raise AssertionError(name + ' failed: ' + json.dumps(error))
            time.sleep(.1)

    def close(self, *, require_success=True):
        try:
            if self.process.poll() is None:
                self.process.stdin.close()
                try:
                    self.process.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
                    try:self.process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        self.process.kill(); self.process.wait(timeout=5)
        finally:
            self.process.stdout.close(); self.stderr.close(); self.receipts.close()
        if require_success and self.process.returncode != 0:
            raise AssertionError('Packaged MCP connection did not shut down cleanly')


def synthetic_config(project_id):
    return {'schema_version': 1, 'project_id': project_id, 'enabled': True,
        'panel': {'show_on_start': True}, 'execution': {'max_parallel': 1, 'default_timeout_seconds': 5},
        'fingerprint': {'extra_inputs': [], 'exclude_outputs': []}, 'checks': [], 'milestones': []}


def public_files(root):
    """Only the project configuration and user instructions, never state files."""
    return {name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
        for name in ('.progress-checker/config.json', 'AGENTS.md') if (path := root/name).exists()}


def public_snapshot(session):
    current = session.success('checker_get_project')
    history = session.success('checker_get_plan_history', {'offset': 0, 'limit': 5})
    return {'config': current['result']['config'], 'claims': current['result']['claims'],
        'latest': current['result']['status']['latest'], 'history': history['result']}


def descendants_have_writer(parent):
    """Inspect process identity only; no private service files are inspected."""
    processes = {}
    for directory in Path('/proc').glob('[0-9]*'):
        try:
            values = (directory/'stat').read_text().rsplit(')', 1)[1].split()
            if values[0] == 'Z':continue
            processes[int(directory.name)] = int(values[1])
        except (FileNotFoundError, PermissionError, ProcessLookupError):pass
    selected = {parent}
    while True:
        found = {pid for pid, ppid in processes.items() if ppid in selected}
        if found <= selected:break
        selected |= found
    for pid in selected - {parent}:
        try:
            if b'serve' in (Path('/proc')/str(pid)/'cmdline').read_bytes().split(b'\0'):
                return True
        except (FileNotFoundError, PermissionError, ProcessLookupError):pass
    return False


def exercise(options, workspace, logs, report):
    def check(name, condition):
        report['assertions'].append({'name': name, 'passed': bool(condition)})
        if not condition:raise AssertionError(name)

    package, archive_hash = load_package(options, workspace)
    installer, plugin = package/'install.py', package/'plugin'
    check('package contains the global launcher and installer',
        installer.is_file() and (plugin/'bin/checker-global').is_file())
    inventory = json.loads((package/'checksums.json').read_text(), object_pairs_hook=strict_object)
    actual_files = {str(path.relative_to(package)) for path in package.rglob('*') if path.is_file() and path.name != 'checksums.json'}
    check('self-contained package checksums cover every payload file', set(inventory) == actual_files)
    check('self-contained package payload bytes match their checksums', all(
        re.fullmatch(r'[a-f0-9]{64}', digest) and hashlib.sha256((package/name).read_bytes()).hexdigest() == digest
        for name, digest in inventory.items()))
    report['archive_sha256'] = archive_hash
    report['package_version'] = json.loads((plugin/'plugin.json').read_text())['version']
    profile, data, state = workspace/'profile', workspace/'data', workspace/'retained-state'
    profile.mkdir(mode=0o700); data.mkdir(mode=0o700)
    unrelated_settings = '# Unrelated global integration fixture\nmodel = "gpt-6.1-sol"\n'
    (profile/'config.toml').write_text(unrelated_settings)
    environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(workspace), 'LANG': 'C.UTF-8',
        'CODEX_HOME': str(profile), 'XDG_DATA_HOME': str(data), 'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_GLOBAL': '/dev/null', 'PYTHONDONTWRITEBYTECODE': '1'}

    def command(label, arguments, *, success=True):
        result = subprocess.run([str(value) for value in arguments], env=environment,
            stdin=subprocess.DEVNULL, capture_output=True, timeout=90)
        (logs/(label+'.stdout')).write_bytes(result.stdout)
        (logs/(label+'.stderr')).write_bytes(result.stderr)
        check(label + (' succeeds' if success else ' is refused'), (result.returncode == 0) == success)
        return result

    roots = [workspace/'repo-a', workspace/'repo-b']
    originals = []
    for index, root in enumerate(roots):
        root.mkdir()
        agents = ('# Existing instructions ' + str(index) + '\nPreserve café and original bytes.\n').encode()
        (root/'AGENTS.md').write_bytes(agents); (root/'AGENTS.md').chmod(0o640)
        (root/'sentinel.py').write_text("from pathlib import Path\nPath('EXECUTED').write_text('unapproved execution')\n")
        (root/'nested').mkdir(); (root/'nested/readme.txt').write_text('Synthetic subdirectory\n')
        if index == 0:
            (root/'.progress-checker').mkdir()
            (root/'.progress-checker/config.json').write_text(json.dumps(synthetic_config('global-existing-plan'), indent=2)+'\n')
        for label, args in [('init', ['init', '--quiet']), ('add', ['add', '.']),
                ('commit', ['-c', 'user.name=Global integration', '-c', 'user.email=fixture@example.invalid',
                            'commit', '--quiet', '-m', 'Synthetic global plugin fixture'])]:
            command(str(index)+'-git-'+label, ['/usr/bin/git', '-C', root, *args])
        originals.append(public_files(root))
    not_git = workspace/'not-git'; not_git.mkdir(); (not_git/'keep.txt').write_text('Preserve this file\n')
    common = ['--codex', options.codex, '--codex-home', profile, '--data-home', data]

    def install(action, *extra, success=True):
        return command('global-'+action+('-refused' if not success else ''),
            ['/usr/bin/python3', installer, action, *common, *extra], success=success)

    install('install', '--state-dir', state)
    check('global install without --project changes no repository files',
        all(public_files(root) == before for root, before in zip(roots, originals)))

    def cache():
        manifests = list((profile/'plugins/cache').rglob('plugin.json'))
        check('native profile has exactly one installed global plugin', len(manifests) == 1)
        cached = manifests[0].parent
        check('native installed cache has the exact packaged version',
            json.loads(manifests[0].read_text())['version'] == report['package_version'])
        definition = json.loads((cached/'mcp.json').read_text())['mcpServers']['progress_checker']
        check('global native MCP definition binds only retained state, never a project',
            definition['command'] == './bin/checker-global' and definition['args'] == ['--state-dir', str(state)])
        settings = tomllib.loads((profile/'config.toml').read_text())
        check('global plugin is enabled and unrelated global settings survive',
            settings['plugins']['progress-checker@progress-global']['enabled'] is True
            and unrelated_settings in (profile/'config.toml').read_text())
        return cached

    cached = cache()
    connections = []
    def gateway(label, path=cached):
        session = MCP([path/'bin/checker-global', '--state-dir', state], path, environment, logs, label)
        connections.append(session)
        return session

    def error(name, reply, code):
        check(name, reply['isError'] is True and reply['structuredContent']['error']['code'] == code)

    def track(session, root):
        result = session.success(TRACK, {'project_root': str(root)})
        check('tracking confirms the exact selected canonical worktree', result['canonical_root'] == str(root))
        return result

    def close_all():
        while connections:connections.pop().close()

    try:
        first, second, invalid = gateway('first'), gateway('second'), gateway('invalid')
        tools = first.rpc('tools/list', {})['tools']
        check('global gateway discovers ten backend tools plus explicit tracking',
            {tool['name'] for tool in tools} == BACKEND_TOOLS | {TRACK} and len(tools) == 11)
        readonly_tools = first.rpc('tools/list', {'_meta': {'openai/readOnly': True}})['tools']
        check('read-only discovery excludes tracking and every mutation',
            TRACK not in {tool['name'] for tool in readonly_tools}
            and readonly_tools and all(tool['annotations']['readOnlyHint'] is True for tool in readonly_tools))
        error('unbound gateway refuses backend tools', first.tool('checker_get_project'), 'PROJECT_NOT_TRACKED')
        error('unknown tool refuses before project selection', first.tool('invented_tool'), 'INVALID_ARGUMENT')
        error('read-only tracking is refused before any setup', invalid.tool(TRACK,
            {'project_root': str(roots[1])}, read_only=True), 'READ_ONLY_REQUEST')
        for label, metadata in [('false', False), ('zero', 0), ('empty-list', []), ('empty-string', '')]:
            error('malformed '+label+' metadata is refused before tracking', invalid.rpc('tools/call',
                {'name': TRACK, 'arguments': {'project_root': str(roots[1])}, '_meta': metadata}),
                'INVALID_ARGUMENT')
        check('unbound discovery and refusals start no writer or project setup',
            not any(descendants_have_writer(session.process.pid) for session in connections)
            and all(public_files(root) == before for root, before in zip(roots, originals)))
        for label, supplied in [('relative', 'repo-a'), ('subdirectory', str(roots[0]/'nested')),
                                ('not-git', str(not_git)), ('cache', str(cached))]:
            reply = invalid.tool(TRACK, {'project_root': supplied})
            check(label+' project selection is refused', reply['isError'] is True)
        check('invalid roots leave no accidental checker configuration or instructions',
            not (not_git/'.progress-checker').exists() and not (not_git/'AGENTS.md').exists()
            and not (roots[0]/'nested/.progress-checker').exists()
            and not (cached/'.progress-checker').exists() and not (cached/'AGENTS.md').exists())
        managed_block = runpy.run_path(str(plugin/'bin/checker-project'))['BLOCK']
        prefix = b'# Existing user instructions\n'
        refused_agents = [('edited', prefix + managed_block.replace(b'## Progress Checker\n', b'## Edited Checker\n', 1)),
                          ('duplicate', prefix + managed_block + managed_block),
                          ('near-limit', b'x' * (1024 * 1024 - 1))]
        for label, content in refused_agents:
            root = workspace/('unsafe-agents-'+label)
            root.mkdir()
            agents = root/'AGENTS.md'; agents.write_bytes(content); agents.chmod(0o640)
            command(label+'-agents-git-init', ['/usr/bin/git', '-C', root, 'init', '--quiet'])
            before = public_files(root)
            names = {path.name for path in root.iterdir()}
            error(label+' instructions refuse tracking', invalid.tool(TRACK,
                {'project_root': str(root)}), 'INVALID_ARGUMENT')
            check(label+' refusal preserves instructions and creates no project files',
                public_files(root) == before and {path.name for path in root.iterdir()} == names
                and not (root/'.progress-checker').exists())
        check('instruction refusals keep the gateway unbound without a writer',
            not descendants_have_writer(invalid.process.pid))
        tracked = track(first, roots[0])
        check('tracking preserves the exact existing project configuration',
            public_files(roots[0])['.progress-checker/config.json'] == originals[0]['.progress-checker/config.json'])
        error('one connection cannot switch projects', first.tool(TRACK,
            {'project_root': str(roots[1])}), 'PROJECT_ALREADY_BOUND')
        check('refused switch leaves the other project untouched', public_files(roots[1]) == originals[1])
        track(invalid, roots[0])
        first_instance = first.success('checker_get_project')['service_instance_id']
        second_instance = invalid.success('checker_get_project')['service_instance_id']
        check('simultaneous same-root connections share the existing service instance',
            isinstance(first_instance, str) and bool(first_instance) and first_instance == second_instance)
        track(second, roots[1])
        created = json.loads((roots[1]/'.progress-checker/config.json').read_text())
        check('first tracking creates an empty plan without invented checks or milestones',
            created['checks'] == [] and created['milestones'] == [])
        for index, root in enumerate(roots):
            agents = public_files(root)['AGENTS.md']
            check('tracking preserves user instructions and adds one managed block '+str(index),
                agents[0].startswith(originals[index]['AGENTS.md'][0]) and agents[1] == 0o640
                and agents[0].count(b'<!-- progress-checker:begin -->') == 1
                and agents[0].count(b'<!-- progress-checker:end -->') == 1)
        before_idempotent = public_files(roots[0])
        check('same-root tracking is idempotent', track(first, roots[0])['already_tracking'] is True
            and public_files(roots[0]) == before_idempotent)
        current = first.success('checker_get_project')
        config = copy.deepcopy(current['result']['config'])
        config['checks'] = [{'id': 'sentinel', 'argv': ['/usr/bin/python3', 'sentinel.py'],
                            'cwd': '.', 'kind': 'test', 'timeout_seconds': 5}]
        config['milestones'] = [{'id': 'feature', 'title': 'Synthetic feature', 'in_scope': True,
            'depends_on': [], 'criteria': [{'id': 'execution', 'description': 'Unapproved synthetic sentinel',
                                          'check_id': 'sentinel', 'required': True}]}]
        first.success('checker_submit_plan', {'config': config, 'reason': 'Explicit synthetic global-plugin plan',
            'expected_revision': current['revision'],
            'expected_config_hash': current['result']['status']['source']['config_hash']})
        current = first.success('checker_get_project')
        first.success('checker_set_claim', {'milestone_id': 'feature', 'claim': 'implemented',
            'note': 'Synthetic implementation claim only', 'expected_revision': current['revision']})
        progress = first.success('checker_get_progress')['result']
        milestone = next(item for item in progress['status']['progress']['milestones'] if item['milestone_id'] == 'feature')
        check('global workflow keeps implemented claims separate from verification',
            progress['claims']['feature'] == 'implemented' and milestone['verified'] is False
            and progress['status']['progress']['verified'] == 0)
        current = first.success('checker_get_project')
        error('read-only metadata reaches the backend mutation guard', first.tool('checker_set_claim',
            {'milestone_id': 'feature', 'claim': 'planned', 'note': 'Must not change',
             'expected_revision': current['revision']}, read_only=True), 'READ_ONLY_REQUEST')
        current = first.success('checker_get_project')
        error('global gateway preserves exact missing-grant refusal', first.tool('checker_run_checks',
            {'check_ids': ['sentinel'], 'idempotency_key': 'global-unapproved-'+uuid.uuid4().hex,
             'expected_revision': current['revision'],
             'expected_config_hash': current['result']['status']['source']['config_hash']}), 'PERMISSION_REQUIRED')
        first_snapshot, second_snapshot = public_snapshot(first), public_snapshot(second)
        check('simultaneous global connections isolate plans claims and evidence by root',
            first_snapshot['config']['project_id'] != second_snapshot['config']['project_id']
            and first_snapshot['claims']['feature'] == 'implemented' and second_snapshot['claims'] == {}
            and second_snapshot['config']['checks'] == [] and second_snapshot['config']['milestones'] == [])
        check('no unapproved configured command executes or creates evidence',
            all(not (root/'EXECUTED').exists() for root in roots)
            and first_snapshot['latest'] == {} and second_snapshot['latest'] == {})
        project_before = [public_files(root) for root in roots]
        close_all()
        install('list')
        install('update', '--state-dir', workspace/'conflicting-state', success=False)
        install('update')
        updated_cache = cache()
        check('global update preserves public project config and instruction bytes',
            [public_files(root) for root in roots] == project_before)
        for index, expected in enumerate([first_snapshot, second_snapshot]):
            session = gateway('updated-'+str(index), updated_cache); track(session, roots[index])
            check('global update retains public plan claims evidence and history '+str(index),
                public_snapshot(session) == expected)
        close_all()
        install('remove')
        check('global removal preserves project files without repairing them',
            [public_files(root) for root in roots] == project_before)
        check('global removal removes native cache and preserves unrelated profile settings',
            not list((profile/'plugins/cache').rglob('plugin.json'))
            and unrelated_settings in (profile/'config.toml').read_text()
            and 'progress-checker@progress-global' not in tomllib.loads((profile/'config.toml').read_text()).get('plugins', {}))
        # Use the frozen packaged launcher, without tracking/setup, to inspect
        # retained state after uninstall. Never read private records directly.
        for index, expected in enumerate([first_snapshot, second_snapshot]):
            session = MCP([plugin/'bin/checker-plugin', '--root', roots[index], '--state-dir', state],
                          plugin, environment, logs, 'removed-'+str(index))
            connections.append(session)
            check('global removal retains public plan claims evidence and history '+str(index),
                public_snapshot(session) == expected)
        check('installation update and removal never execute the unapproved sentinel',
            all(not (root/'EXECUTED').exists() for root in roots))
        report['coverage'] = ('Actual global native installation and simultaneous explicit-root MCP routing; '
            'plan/claim persistence, empty evidence preservation, and missing-grant refusal. '
            'No approved configured command or authenticated model prompt was executed.')
    finally:
        close_all()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--package', type=Path, help='Extracted self-contained release directory')
    source.add_argument('--archive', type=Path, help='Exact release tar.gz, safely extracted for this test')
    parser.add_argument('--sha256', help='Required exact SHA-256 with --archive')
    parser.add_argument('--codex', type=Path, default=DEFAULT_CODEX)
    parser.add_argument('--output', type=Path, help='Fresh directory for public test receipts')
    options = parser.parse_args()
    if options.archive is not None and (not options.sha256 or not re.fullmatch(r'[A-Fa-f0-9]{64}', options.sha256)):
        parser.error('--archive requires a 64-character --sha256')
    if options.package is not None and options.sha256 is not None:
        parser.error('--sha256 applies only to --archive')
    report = {'status': 'failed', 'assertions': [], 'approvals_created': False,
              'configured_commands_executed': False, 'private_records_read': False}
    code = 1
    with tempfile.TemporaryDirectory(prefix='pc-global-plugin-') as temporary:
        workspace = Path(temporary).resolve()
        logs = options.output.resolve() if options.output else workspace/'public-receipts'
        logs.mkdir(parents=True, exist_ok=True)
        if any(logs.iterdir()):
            raise ValueError('--output must be an empty dedicated report directory')
        try:
            exercise(options, workspace, logs, report)
            report['status'] = 'passed'; code = 0
        except Exception as error:
            report['error'] = str(error)
        (logs/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
