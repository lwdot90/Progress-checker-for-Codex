#!/usr/bin/env python3
"""Qualify native marketplace installation in an unauthenticated private profile.

The native CLI/browser backend installs a pinned Git payload. No installer,
Rust tool, model request, approval, or configured check is executed. Same-pin
refresh and native removal preserve fixture configuration and claims; this is
not a changed-version upgrade or an authenticated end-to-end pilot.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import select
import shutil
import stat
import subprocess
import tempfile
import time
import tomllib
import urllib.parse

_helpers = runpy.run_path(str(Path(__file__).with_name('test-global-plugin.py')))
MCP, BACKEND_TOOLS, TRACK = (_helpers[name] for name in ('MCP', 'BACKEND_TOOLS', 'TRACK'))
strict_object, public_snapshot = (_helpers[name] for name in ('strict_object', 'public_snapshot'))
DEFAULT_CODEX = _helpers['DEFAULT_CODEX']
PAYLOAD_PATH = 'native/linux-x86_64/progress-checker'
PLUGIN = 'progress-checker'
MARKETPLACE = 'progress-global'
FULL_SHA = re.compile(r'^[a-fA-F0-9]{40}$')


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=strict_object)


def inventory(root):
    result = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
            raise ValueError('Installed payload contains a special or oversized file')
        result[path.relative_to(root).as_posix()] = {
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'mode': oct(stat.S_IMODE(info.st_mode)),
        }
        if len(result) > 4096:
            raise ValueError('Installed payload exceeds its file-count limit')
    return result


class AppServer:
    """Only initialize/plugin/skill RPCs from the pinned public app-server API."""
    def __init__(self, codex, cwd, environment, logs, label):
        self.sequence, self.buffer = 0, bytearray()
        self.stderr = (logs / (label + '.stderr')).open('wb')
        self.wire = (logs / (label + '.public-wire.jsonl')).open('w')
        self.process = subprocess.Popen([str(codex), 'app-server'], cwd=cwd,
            env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr)
        try:
            self.rpc('initialize', {'clientInfo': {'name': 'native-marketplace-test', 'version': '1'},
                                   'capabilities': {'experimentalApi': True, 'requestAttestation': False}})
            self.send({'method': 'initialized'})
        except BaseException:
            self.close()
            raise

    def send(self, value):
        self.wire.write(json.dumps({'request': value}) + '\n'); self.wire.flush()
        self.process.stdin.write(json.dumps(value).encode() + b'\n'); self.process.stdin.flush()

    def rpc(self, method, params):
        if method not in {'initialize', 'plugin/list', 'plugin/install', 'plugin/uninstall', 'skills/list'}:
            raise ValueError('Test app-server client does not permit this method')
        self.sequence += 1
        self.send({'id': self.sequence, 'method': method, 'params': params})
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if b'\n' in self.buffer:
                line, _, rest = self.buffer.partition(b'\n'); self.buffer[:] = rest
                response = json.loads(line, object_pairs_hook=strict_object)
                self.wire.write(json.dumps({'response': response}) + '\n'); self.wire.flush()
                if 'id' not in response:
                    continue
                if response.get('id') != self.sequence or 'method' in response or 'error' in response:
                    raise RuntimeError('Unexpected app-server response: ' + json.dumps(response))
                return response['result']
            if select.select([self.process.stdout], [], [], .1)[0]:
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if not chunk:
                    raise RuntimeError('Native app-server closed before its response')
                self.buffer.extend(chunk)
                if len(self.buffer) > 2 * 1024 * 1024:
                    raise RuntimeError('Native app-server response exceeds the test frame bound')
        raise TimeoutError('Native app-server response deadline exceeded')

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.stdin.close()
                try:
                    self.process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.process.terminate(); self.process.wait(timeout=10)
        finally:
            self.process.stdout.close(); self.stderr.close(); self.wire.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def exercise(options, workspace, logs, report):
    def check(name, condition):
        report['assertions'].append({'name': name, 'passed': bool(condition)})
        if not condition:
            raise AssertionError(name)

    home, profile, data = (workspace / name for name in ('home', 'profile', 'data'))
    for path in (home, profile, data):
        path.mkdir(mode=0o700)
    environment = {
        'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(home), 'CODEX_HOME': str(profile),
        'XDG_DATA_HOME': str(data), 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
    }
    unrelated = '# Native marketplace integration: preserve this setting\nmodel = "gpt-6.1-sol"\n'
    (profile / 'config.toml').write_text(unrelated + '\n[features]\nremote_plugin = false\nplugin_sharing = false\n')
    codex = options.codex.resolve(strict=True)
    report['codex_path'] = str(codex)
    report['codex_sha256'] = hashlib.sha256(codex.read_bytes()).hexdigest()

    def command(label, arguments, *, required=True, cwd=workspace, timeout=60):
        result = subprocess.run([str(value) for value in arguments], cwd=cwd, env=environment,
            stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        (logs / (label + '.stdout')).write_bytes(result.stdout)
        (logs / (label + '.stderr')).write_bytes(result.stderr)
        if required:
            check(label + ' succeeds', result.returncode == 0)
        return result

    version = command('codex-version', [codex, '--version']).stdout.decode().strip()
    report['codex_version'] = version
    check('test uses standard Codex 0.160 or 0.161', bool(re.fullmatch(r'codex-cli 0\.(160|161)\.\d+(?:[-.][^\s]+)?', version)))
    report['rust_available_on_runtime_path'] = shutil.which('rustc', path=environment['PATH']) is not None

    # A local Git catalog is pinned by our private detached clone: native add
    # deliberately treats absolute directory inputs as local, refusing --ref.
    supplied = Path(options.marketplace).expanduser()
    local = supplied.is_dir()
    report['source_mode'] = 'local-git' if local else 'remote-git'
    if local:
        source = supplied.resolve(strict=True)
        commit = options.catalog_commit or command('local-catalog-head', ['/usr/bin/git', '-C', source, 'rev-parse', 'HEAD']).stdout.decode().strip()
        if not FULL_SHA.fullmatch(commit):
            raise ValueError('Local marketplace requires a full commit identity')
        catalog_root = workspace / 'pinned-catalog'
        command('clone-local-catalog', ['/usr/bin/git', 'clone', '--quiet', '--no-hardlinks', '--no-checkout', source, catalog_root])
        command('pin-local-catalog', ['/usr/bin/git', '-C', catalog_root, 'checkout', '--quiet', '--detach', commit])
        native_source, ref_args = str(catalog_root), []
        report['marketplace_transport'] = 'local Git catalog, private detached snapshot, native local marketplace add'
    else:
        if not options.catalog_commit:
            raise ValueError('A remote marketplace requires --catalog-commit FULL40')
        commit, native_source, ref_args = options.catalog_commit, options.marketplace, ['--ref', options.catalog_commit]
        report['marketplace_transport'] = 'native Git marketplace add at exact catalog commit'
    added = json.loads(command('marketplace-add', [codex, 'plugin', 'marketplace', 'add', native_source, *ref_args, '--json']).stdout)
    check('native marketplace registration names Progress Checker', added['marketplaceName'] == MARKETPLACE)
    catalog_root = Path(added['installedRoot']).resolve(strict=True)
    catalog_path = catalog_root / '.agents/plugins/marketplace.json'
    actual_commit = command('native-catalog-head', ['/usr/bin/git', '-C', catalog_root, 'rev-parse', 'HEAD']).stdout.decode().strip()
    check('native catalog is the exact full pinned Git commit', actual_commit.lower() == commit.lower())
    report['catalog_commit'] = commit.lower()
    report['catalog_sha256'] = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
    report['marketplace_root'] = str(catalog_root)
    catalog = read_json(catalog_path)
    report['catalog'] = catalog
    entries = [entry for entry in catalog['plugins'] if entry['name'] == PLUGIN]
    check('catalog declares one Progress Checker plugin', catalog['name'] == MARKETPLACE and len(entries) == 1)
    source = entries[0]['source']
    check('catalog pins the fixed native Git subdirectory to a full commit',
        source.get('source') == 'git-subdir' and source.get('path') == './' + PAYLOAD_PATH
        and isinstance(source.get('sha'), str) and FULL_SHA.fullmatch(source['sha']) is not None)
    payload_commit = source['sha'].lower()
    check('payload pin agrees with the requested identity', options.payload_commit is None or payload_commit == options.payload_commit.lower())
    report['payload_commit'] = payload_commit
    marketplaces = json.loads(command('marketplace-list', [codex, 'plugin', 'marketplace', 'list', '--json']).stdout)
    check('native marketplace list returns the registered marketplace',
          any(entry['name'] == MARKETPLACE for entry in marketplaces['marketplaces']))

    # Read public metadata at the same exact payload commit, without checking out
    # or executing its source. This proves what native installation must copy.
    payload_url = source['url']
    if payload_url.startswith('./'):
        payload_url = str(catalog_root / payload_url)
    metadata = workspace / 'payload-metadata.git'
    command('payload-metadata-init', ['/usr/bin/git', 'init', '--quiet', '--bare', metadata])
    command('payload-metadata-fetch', ['/usr/bin/git', '-C', metadata, '-c', 'protocol.file.allow=always',
        'fetch', '--quiet', '--depth=1', '--no-tags', payload_url, payload_commit])
    receipt_bytes = command('payload-metadata-read', ['/usr/bin/git', '-C', metadata, 'show', payload_commit + ':NATIVE_PAYLOAD.json']).stdout
    receipt = json.loads(receipt_bytes, object_pairs_hook=strict_object)
    report['payload_receipt_sha256'] = hashlib.sha256(receipt_bytes).hexdigest()
    report['payload_receipt'] = receipt
    check('public payload receipt identifies the fixed native plugin and 0.4 release',
          receipt['plugin_path'] == PAYLOAD_PATH and re.fullmatch(r'0\.4\.\d+(?:[-.][A-Za-z0-9]+)*', receipt['plugin_version']) is not None)
    expected = {}
    for item in receipt['files']:
        name = item['path']
        if (not isinstance(name, str) or not name or name.startswith('/') or '\\' in name
                or any(part in ('', '.', '..') for part in name.split('/')) or name in expected
                or not re.fullmatch(r'[a-f0-9]{64}', item['sha256']) or item['mode'] not in ('0o644', '0o755')):
            raise ValueError('Public payload receipt contains an invalid file identity')
        expected[name] = {'sha256': item['sha256'], 'mode': item['mode']}

    add_help = command('native-install-help', [codex, 'plugin', 'add', '--help'], required=False)
    selector = PLUGIN + '@' + MARKETPLACE
    def install(label):
        if add_help.returncode == 0:
            report['install_transport'] = 'native codex plugin add'
            command(label, [codex, 'plugin', 'add', selector, '--json'])
        else:
            report['install_transport'] = 'native browser backend plugin/install'
            with AppServer(codex, workspace, environment, logs, label) as server:
                result = server.rpc('plugin/install', {'marketplacePath': str(catalog_path), 'pluginName': PLUGIN})
                check(label + ' needs no authenticated app', result.get('appsNeedingAuth') == [])
    install('native-plugin-install')

    def cache(label):
        manifests = list((profile / 'plugins/cache').rglob('plugin.json'))
        own = [path for path in manifests if read_json(path).get('name') == PLUGIN]
        check(label + ' has one native installed cache', len(own) == 1)
        cached = own[0].parent.resolve(strict=True)
        check(label + ' lives only in the isolated native cache', profile in cached.parents)
        manifest = read_json(cached / 'plugin.json')
        check(label + ' has the exact frozen 0.4 payload version', manifest['version'] == receipt['plugin_version'])
        observed = inventory(cached)
        check(label + ' exact file bytes and modes match the pinned public receipt', observed == expected)
        report['cache_inventory'] = observed
        report['installed_cache'] = str(cached)
        report['package_version'] = manifest['version']
        for name in ('checker-global', 'checker-plugin', 'checker-project', 'progress-checker', 'progress-checker-mcp'):
            check(label + ' runtime is a regular executable: ' + name,
                  stat.S_ISREG((cached / 'bin' / name).lstat().st_mode) and os.access(cached / 'bin' / name, os.X_OK))
        definition = read_json(cached / 'mcp.json')['mcpServers']['progress_checker']
        check(label + ' MCP command is portable and has no project/source/toolchain binding',
              definition.get('type') == 'stdio' and definition['command'] == './bin/checker-global'
              and definition.get('args') == [] and not definition.get('env'))
        return cached, definition

    root = workspace / 'current-project'; root.mkdir()
    user_agents = '# Native recipient project\nPreserve café and existing instructions.\n'.encode()
    (root / 'AGENTS.md').write_bytes(user_agents); (root / 'AGENTS.md').chmod(0o640)
    for label, args in [('init', ['init', '--quiet']), ('add', ['add', '.']), ('commit',
            ['-c', 'user.name=Native integration', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'Recipient fixture'])]:
        command('project-git-' + label, ['/usr/bin/git', '-C', root, *args])
    cached, definition = cache('installed')
    with AppServer(codex, workspace, environment, logs, 'native-discovery') as server:
        listing = server.rpc('plugin/list', {'cwds': [str(root)], 'marketplaceKinds': ['local']})
        own = [plugin for market in listing['marketplaces'] if market['name'] == MARKETPLACE
               for plugin in market['plugins'] if plugin['name'] == PLUGIN]
        check('native browser backend discovers the installed enabled plugin',
              len(own) == 1 and own[0]['installed'] is True and own[0]['enabled'] is True)
        report['native_plugin_id'] = own[0]['id']
        skills = server.rpc('skills/list', {'cwds': [str(root)], 'forceReload': True})
        matching = [skill for entry in skills['data'] for skill in entry['skills']
                    if skill.get('pluginId') == own[0]['id'] and skill['name'] in (PLUGIN, PLUGIN + ':' + PLUGIN)]
        check('standard Codex discovers the installed planning skill',
              len(matching) == 1 and matching[0]['enabled'] is True
              and Path(matching[0]['path']).resolve().is_relative_to(cached))
        report['native_skill'] = matching[0]

    def gateway(label, selected=cached):
        return MCP([selected / 'bin/checker-global'], selected, environment, logs, label)
    session = None
    try:
        session = gateway('installed-mcp')
        tools = session.rpc('tools/list', {})['tools']
        report['tool_names'] = sorted(tool['name'] for tool in tools)
        check('portable installed MCP discovers ten backend tools plus Track this project',
              set(report['tool_names']) == BACKEND_TOOLS | {TRACK} and len(tools) == 11)
        refused = session.tool('checker_get_project')
        check('portable gateway stays unbound before explicit tracking',
              refused['isError'] and refused['structuredContent']['error']['code'] == 'PROJECT_NOT_TRACKED'
              and not (root / '.progress-checker').exists())
        tracked = session.success(TRACK, {'project_root': str(root)})
        check('Track this project confirms the exact current disposable canonical Git root',
              tracked['canonical_root'] == str(root.resolve()))
        current = session.success('checker_get_project')
        check('tracking starts an empty project with no checks approvals or fabricated evidence',
              current['result']['config']['checks'] == [] and current['result']['config']['milestones'] == []
              and current['result']['status']['latest'] == {} and current['result']['running'] == [])
        check('tracking preserves original project instructions and adds one managed section',
              (root / 'AGENTS.md').read_bytes().startswith(user_agents)
              and (root / 'AGENTS.md').read_bytes().count(b'<!-- progress-checker:begin -->') == 1
              and stat.S_IMODE((root / 'AGENTS.md').stat().st_mode) == 0o640)
        config = current['result']['config']
        config['checks'] = [{'id': 'sentinel', 'argv': ['/usr/bin/true'], 'cwd': '.', 'kind': 'test', 'timeout_seconds': 5}]
        config['milestones'] = [{'id': 'native-fixture', 'title': 'Native fixture claim', 'in_scope': True,
            'depends_on': [], 'criteria': [{'id': 'acceptance', 'description': 'No execution requested', 'check_id': 'sentinel', 'required': True}]}]
        session.success('checker_submit_plan', {'config': config, 'reason': 'Native installation retention fixture only',
            'expected_revision': current['revision'], 'expected_config_hash': current['result']['status']['source']['config_hash']})
        current = session.success('checker_get_project')
        session.success('checker_set_claim', {'milestone_id': 'native-fixture', 'claim': 'implemented',
            'note': 'Claim only; no configured check requested', 'expected_revision': current['revision']})
        snapshot = public_snapshot(session)
        check('fixture implementation claim remains unverified with no attempts',
              snapshot['claims'] == {'native-fixture': 'implemented'} and snapshot['latest'] == {}
              and session.success('checker_get_progress')['result']['status']['progress']['verified'] == 0)
        public_files = {name: (root / name).read_bytes() for name in ('AGENTS.md', '.progress-checker/config.json')}
        session.close(); session = None
        if local:
            # Native local-directory catalogs intentionally have no Git upgrade
            # operation. Re-register them, then refresh the pinned plugin.
            command('native-same-pin-marketplace-refresh', [codex, 'plugin', 'marketplace', 'add', str(catalog_root), '--json'])
            report['refresh_transport'] = 'native local catalog re-registration and same-pin plugin add'
        else:
            command('native-same-pin-marketplace-refresh', [codex, 'plugin', 'marketplace', 'upgrade', MARKETPLACE, '--json'])
            report['refresh_transport'] = 'native pinned Git marketplace upgrade and same-pin plugin add'
        install('native-same-pin-plugin-refresh')
        refreshed, _ = cache('refreshed')
        session = gateway('refreshed-mcp', refreshed)
        session.success(TRACK, {'project_root': str(root)})
        check('same-pin native refresh preserves fixture plan claims history and empty evidence', public_snapshot(session) == snapshot)
        session.close(); session = None
        retained = workspace / 'retained-native-payload'; shutil.copytree(refreshed, retained)
        remove_help = command('native-remove-help', [codex, 'plugin', 'remove', '--help'], required=False)
        if remove_help.returncode == 0:
            command('native-plugin-remove', [codex, 'plugin', 'remove', selector, '--json'])
        else:
            with AppServer(codex, workspace, environment, logs, 'native-plugin-remove') as server:
                server.rpc('plugin/uninstall', {'pluginId': report['native_plugin_id']})
        check('native removal deletes only its installed cache and preserves unrelated profile settings',
              not list((profile / 'plugins/cache').rglob('plugin.json'))
              and unrelated in (profile / 'config.toml').read_text()
              and selector not in tomllib.loads((profile / 'config.toml').read_text()).get('plugins', {}))
        check('native refresh and removal leave project config and instruction bytes intact',
              all((root / name).read_bytes() == content for name, content in public_files.items()))
        session = gateway('removed-public-state', retained)
        session.success(TRACK, {'project_root': str(root)})
        check('native removal preserves durable plan claims history and empty evidence through public tools',
              public_snapshot(session) == snapshot)
        check('test remains unauthenticated without creating or copying a profile credential file',
              not (profile / 'auth.json').exists())
        report['coverage'] = ('Native marketplace registration, pinned Git installation, browser backend plugin/skill discovery, '
            'installed-cache portable MCP discovery and explicit fixture tracking; same-pin native refresh and removal '
            'preserve public fixture plans/claims/empty evidence. No changed-version upgrade, authenticated prompt, '
            'approval or configured-check execution was performed.')
    finally:
        if session:
            session.close(require_success=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--marketplace', required=True, help='Local Git marketplace root or native HTTPS/SSH Git URL')
    parser.add_argument('--catalog-commit', help='Full catalog commit; required for remote marketplaces')
    parser.add_argument('--payload-commit', help='Expected full payload commit from the catalog')
    parser.add_argument('--codex', type=Path, default=DEFAULT_CODEX)
    parser.add_argument('--output', type=Path, required=True, help='Fresh nonexistent directory for public receipts')
    options = parser.parse_args()
    for value in (options.catalog_commit, options.payload_commit):
        if value is not None and not FULL_SHA.fullmatch(value):
            parser.error('Commit identities must contain exactly 40 hexadecimal characters')
    if options.output.exists() or options.output.is_symlink():
        parser.error('--output must be a fresh nonexistent path')
    logs = options.output.absolute(); logs.mkdir(parents=True)
    report = {'status': 'failed', 'complete': False, 'assertions': [], 'approvals_created': False,
              'configured_commands_executed': False, 'model_requests_executed': False,
              'private_records_read': False, 'marketplace_source': options.marketplace}
    with tempfile.TemporaryDirectory(prefix='pc-native-marketplace-') as temporary:
        try:
            exercise(options, Path(temporary).resolve(), logs, report)
            report['status'], report['complete'] = 'passed', True
        except Exception as error:
            report['error'] = str(error)
        (logs / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
