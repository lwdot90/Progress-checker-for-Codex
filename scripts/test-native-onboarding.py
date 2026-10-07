#!/usr/bin/env python3
"""Qualify frozen native onboarding bytes, without granting command approval.

Missing release pins or a missing live human trial fail closed. The separate
--negative-only development mode can prove refusal, but cannot pass acceptance.
"""
import argparse
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
VERSION = '0.4.0-dev'
PLUGIN_PATH = 'native/linux-x86_64/progress-checker'
MANIFEST_FIELDS = {'schema_version', 'status', 'version', 'archive_path', 'sha256',
                   'codex', 'marketplace', 'documents', 'positive_fixture'}


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON field: ' + key)
        value[key] = item
    return value


def regular_bytes(path, limit=1024 * 1024):
    """Read one bounded regular inode without following its final symlink."""
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError('Expected a bounded regular file: ' + str(path))
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                             item.st_mtime_ns, item.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if identity(before) != identity(opened):
            raise ValueError('Input changed before reading: ' + str(path))
        data = stream.read(limit + 1)
        if (len(data) != opened.st_size or len(data) > limit
                or identity(opened) != identity(os.fstat(stream.fileno()))
                or identity(opened) != identity(path.lstat())):
            raise ValueError('Input changed while reading: ' + str(path))
    return data


def load_json(path):
    return json.loads(regular_bytes(path), object_pairs_hook=strict_object)


def digest(value, length=64):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{' + str(length) + '}', value)


def exact_fields(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError(label + ' has missing or unknown fields')


def project_path(value):
    if (not isinstance(value, str) or not value or '\\' in value or '\0' in value
            or Path(value).is_absolute() or any(part in ('', '.', '..') for part in value.split('/'))):
        raise ValueError('Release inputs must use canonical project-relative paths')
    path = ROOT / value
    resolved = path.resolve(strict=True)
    if ROOT not in resolved.parents or path != resolved:
        raise ValueError('Release input escapes the project or follows a symlink: ' + value)
    return path


def check(report, name, condition):
    passed = bool(condition)
    report['assertions'].append({'name': name, 'passed': passed})
    if not passed:
        raise ValueError(name)


def validate_manifest(path, report):
    manifest = load_json(path)
    exact_fields(manifest, MANIFEST_FIELDS, 'Release manifest')
    if manifest['schema_version'] != 1 or isinstance(manifest['schema_version'], bool):
        raise ValueError('Unsupported release manifest schema')
    if manifest['version'] != VERSION:
        raise ValueError('Only the separately frozen ' + VERSION + ' onboarding release qualifies')
    if manifest['status'] == 'pending':
        if (any(manifest[name] is not None for name in
                ('archive_path', 'sha256', 'codex', 'marketplace', 'positive_fixture'))
                or manifest['documents'] != []):
            raise ValueError('Pending release must not contain qualifying pins')
        raise ValueError('Native onboarding release is pending; no frozen pins qualify acceptance')
    if manifest['status'] != 'frozen' or not digest(manifest['sha256']):
        raise ValueError('Release must be frozen with an exact archive SHA256')
    manifest['_archive'] = project_path(manifest['archive_path'])
    codex = manifest['codex']
    exact_fields(codex, ('path', 'sha256', 'version'), 'Codex pin')
    if (not isinstance(codex['path'], str) or not Path(codex['path']).is_absolute()
            or not digest(codex['sha256']) or not isinstance(codex['version'], str)
            or not codex['version'].strip()):
        raise ValueError('Installed native Codex needs exact executable and version pins')
    binary = Path(codex['path'])
    check(report, 'installed native Codex executable matches release pin',
          hashlib.sha256(regular_bytes(binary, 256 * 1024 * 1024)).hexdigest() == codex['sha256']
          and os.access(binary, os.X_OK))
    market = manifest['marketplace']
    exact_fields(market, ('source_url', 'catalog_commit', 'payload_commit',
                         'catalog_sha256', 'payload_receipt_sha256'), 'Marketplace pins')
    from urllib.parse import urlsplit
    url = urlsplit(market['source_url'])
    if (url.scheme != 'https' or not url.hostname or not url.path.strip('/')
            or url.username is not None or url.password is not None or url.query or url.fragment
            or not digest(market['catalog_commit'], 40) or not digest(market['payload_commit'], 40)
            or not digest(market['catalog_sha256']) or not digest(market['payload_receipt_sha256'])):
        raise ValueError('Marketplace must pin public HTTPS Git commits and exact catalog/payload bytes')
    if not isinstance(manifest['documents'], list) or not manifest['documents']:
        raise ValueError('Frozen release requires a checksummed onboarding guide')
    seen = set()
    for item in manifest['documents']:
        exact_fields(item, ('path', 'sha256'), 'Document pin')
        if not digest(item['sha256']) or item['path'] in seen:
            raise ValueError('Invalid or duplicate document pin')
        seen.add(item['path'])
        actual = hashlib.sha256(regular_bytes(project_path(item['path']))).hexdigest()
        check(report, 'onboarding document matches pin: ' + item['path'], actual == item['sha256'])
    fixture = manifest['positive_fixture']
    if fixture is not None:
        fields = {'root', 'state_dir', 'check_id', 'service_instance_id', 'config_hash', 'command_hash'}
        if isinstance(fixture, dict) and 'transport' in fixture:
            fields.add('transport')
            transport = fixture['transport']
            exact_fields(transport, ('kind', 'container_id', 'checker_path'), 'Positive fixture transport')
            if (transport['kind'] != 'podman' or not digest(transport['container_id'])
                    or not isinstance(transport['checker_path'], str)
                    or not Path(transport['checker_path']).is_absolute()
                    or any(part in ('', '.', '..') for part in transport['checker_path'].split('/')[1:])):
                raise ValueError('Container transport needs full immutable container ID and exact checker path')
        exact_fields(fixture, fields, 'Positive fixture descriptor')
        for name in ('root', 'state_dir'):
            value = fixture[name]
            if (not isinstance(value, str) or not Path(value).is_absolute()
                    or '\\' in value or '\0' in value
                    or any(part in ('', '.', '..') for part in value.split('/')[1:])
                    or ('transport' not in fixture and str(Path(value).resolve(strict=True)) != value)):
                raise ValueError('Positive fixture paths must be absolute canonical paths')
        if (not isinstance(fixture['check_id'], str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', fixture['check_id'])
                or not isinstance(fixture['service_instance_id'], str)
                or not 1 <= len(fixture['service_instance_id']) <= 128
                or any(not isinstance(fixture[key], str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', fixture[key])
                       for key in ('config_hash', 'command_hash'))):
            raise ValueError('Positive fixture requires exact public service/check/config/command identities')
    return manifest


def isolated_environment(directory):
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(directory),
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_TERMINAL_PROMPT': '0'}


def command(argv, env, timeout=210):
    """Run only a named development helper, never a configured checker command."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen([str(item) for item in argv], env=env,
                                   stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                   start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
            raise
        out.seek(0); err.seek(0)
        stdout, stderr = out.read(8 * 1024 * 1024 + 1), err.read(1024 * 1024 + 1)
        if len(stdout) > 8 * 1024 * 1024 or len(stderr) > 1024 * 1024:
            raise ValueError('Development helper exceeded output bounds')
        if code:
            raise ValueError('Development helper failed (' + str(code) + '): '
                             + stderr.decode(errors='replace')[-2000:]
                             + stdout.decode(errors='replace')[-4000:])
        return stdout


def module(path):
    specification = importlib.util.spec_from_file_location('native_onboarding_archive', path)
    result = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(result)
    return result


def prepare_package(manifest, directory, report):
    # Reuse the hardened bounded, no-link, exact-inventory archive reader. Its
    # input buffer is the same buffer whose SHA is recorded in its report.
    reader = module(ROOT / 'scripts/plugin-acceptance.py')
    class ArchiveReceipt:
        def __init__(self):
            self.report = {'artifacts': {}}
    receipt = ArchiveReceipt()
    plugin = reader.extract_archive(receipt, manifest['_archive'], directory / 'extracted')
    check(report, 'frozen archive bytes match release SHA256',
          receipt.report['archive']['sha256'] == manifest['sha256'])
    check(report, 'frozen archive has the new onboarding version',
          receipt.report['archive']['version'] == VERSION)
    report['archive'] = receipt.report['archive']
    package = plugin.parent
    staged = directory / 'expected-native'
    command([sys.executable, ROOT / 'scripts/prepare-native-marketplace.py',
             '--package', package, '--output', staged], isolated_environment(directory), 30)
    payload = load_json(staged / 'NATIVE_PAYLOAD.json')
    check(report, 'native payload is derived from the exact frozen archive',
          hashlib.sha256(regular_bytes(staged / 'NATIVE_PAYLOAD.json')).hexdigest()
          == manifest['marketplace']['payload_receipt_sha256'])
    report['expected_native_inventory'] = payload
    catalog = directory / 'expected-public-catalog'
    command([sys.executable, ROOT / 'scripts/prepare-native-marketplace.py',
             '--sha', manifest['marketplace']['payload_commit'],
             '--source-url', manifest['marketplace']['source_url'], '--output', catalog],
            isolated_environment(directory), 30)
    check(report, 'published catalog pin describes the frozen native payload commit',
          hashlib.sha256(regular_bytes(catalog / '.agents/plugins/marketplace.json')).hexdigest()
          == manifest['marketplace']['catalog_sha256'])
    return package, payload


def native_browser(manifest, directory, payload, report):
    market = manifest['marketplace']
    # The configured sandbox has no network/home. Exercise native installation
    # against a fresh local Git snapshot, with bytes derived only from the
    # frozen archive. Published HTTPS reachability is a separate developer trial.
    repository = directory / 'expected-native'
    environment = isolated_environment(directory)
    environment.update(GIT_AUTHOR_DATE='2000-01-01T00:00:00Z',
                       GIT_COMMITTER_DATE='2000-01-01T00:00:00Z')
    def git(*arguments):
        return command(['/usr/bin/git', '-C', repository, *arguments], environment, 30).decode().strip()
    git('init', '--quiet')
    git('add', '.')
    git('-c', 'user.name=Native onboarding fixture', '-c', 'user.email=fixture@example.invalid',
        'commit', '--quiet', '-m', 'Frozen archive native payload')
    payload_commit = git('rev-parse', 'HEAD')
    catalog = {
        'name': 'progress-global', 'interface': {'displayName': 'Progress Checker'},
        'plugins': [{'name': 'progress-checker',
                     'description': 'Track project milestones with current local check evidence.',
                     'source': {'source': 'git-subdir', 'url': str(repository),
                                'path': './' + PLUGIN_PATH, 'sha': payload_commit},
                     'policy': {'installation': 'AVAILABLE', 'authentication': 'ON_INSTALL'},
                     'category': 'Productivity'}],
    }
    catalog_path = repository / '.agents/plugins/marketplace.json'
    catalog_path.parent.mkdir(parents=True)
    catalog_path.write_text(json.dumps(catalog, indent=2) + '\n')
    catalog_sha256 = hashlib.sha256(regular_bytes(catalog_path)).hexdigest()
    git('add', '.')
    git('-c', 'user.name=Native onboarding fixture', '-c', 'user.email=fixture@example.invalid',
        'commit', '--quiet', '-m', 'Pinned disposable native catalog')
    catalog_commit = git('rev-parse', 'HEAD')
    output = command([sys.executable, ROOT / 'scripts/test-native-marketplace.py',
        '--marketplace', repository, '--catalog-commit', catalog_commit,
        '--payload-commit', payload_commit, '--codex', manifest['codex']['path'],
        '--output', directory / 'native-trial'], isolated_environment(directory))
    result = json.loads(output, object_pairs_hook=strict_object)
    report['native_trial'] = result
    assertions = result.get('assertions')
    check(report, 'actual native browser backend install/discovery/activation/removal qualified',
          result.get('complete') is True and result.get('status') == 'passed'
          and isinstance(assertions, list) and assertions
          and all(item.get('passed') is True for item in assertions))
    for key, expected_pin in {'catalog_commit': catalog_commit, 'payload_commit': payload_commit,
                              'catalog_sha256': catalog_sha256,
                              'payload_receipt_sha256': market['payload_receipt_sha256']}.items():
        check(report, 'native materialization matches exact local trial ' + key, result.get(key) == expected_pin)
    check(report, 'actual native Codex version matches release pin',
          result.get('codex_version', '').strip() == manifest['codex']['version'].strip()
          and result.get('codex_sha256') == manifest['codex']['sha256'])
    expected = {item['path']: {'sha256': item['sha256'], 'mode': item['mode']}
                for item in payload['files']}
    check(report, 'native installed cache exactly matches archive-derived bytes and modes',
          result.get('cache_inventory') == expected)
    report['published_marketplace_pins'] = market
    report['coverage'] = ('Actual native browser backend discovery and native CLI installation from '
                          'a disposable local Git catalog/synthetic payload commit derived from the '
                          'frozen archive, in an isolated profile. Published HTTPS Git transport '
                          'requires a separate developer trial; these synthetic pins are distinct. '
                          'No visual keyboard automation, model turn, command approval or configured '
                          'check execution. Same-pin refresh is not a changed-version upgrade.')


def public_snapshot(fixture, checker_sha256):
    root, state = Path(fixture['root']), Path(fixture['state_dir'])
    if root.resolve(strict=True) != root or state.resolve(strict=True) != state:
        raise ValueError('Positive fixture paths changed or follow symlinks')
    info = state.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or root == state
            or root in state.parents or state in root.parents):
        raise ValueError('Positive fixture needs separate private runtime directory')
    short = hashlib.sha256(os.fsencode(root)).hexdigest()[:24]
    endpoint = state / ('ipc-' + short + '.sock')
    if len(os.fsencode(endpoint)) > 100:
        context = hashlib.sha256(os.fsencode(root) + b'\0' + os.fsencode(state)).hexdigest()[:24]
        endpoint = Path('/tmp') / ('progress-checker-ipc-' + str(os.geteuid())) / ('ipc-' + context + '.sock')
    parent = endpoint.parent.lstat()
    metadata = endpoint.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700 or not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise ValueError('Positive fixture public endpoint is not a private owned service socket')
    request_id = 'onboarding-public-' + str(os.getpid()) + '-' + str(time.monotonic_ns())
    request = json.dumps({'schema_version': 1, 'request_id': request_id,
                          'operation': {'operation': 'progress'}}).encode()
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(15)
        connection.connect(str(endpoint))
        pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.geteuid():
            raise ValueError('Positive fixture service peer is not the current user')
        # Public process image identity prevents an editable JSON or replacement
        # Python socket from standing in for the release's authentic service.
        with open('/proc/' + str(pid) + '/exe', 'rb') as executable:
            actual = hashlib.file_digest(executable, 'sha256').hexdigest()
        if actual != checker_sha256:
            raise ValueError('Positive fixture peer is not the frozen packaged checker')
        checker_path = fixture.get('transport', {}).get('checker_path')
        if checker_path is not None and not os.path.samefile('/proc/' + str(pid) + '/exe', checker_path):
            raise ValueError('Positive fixture peer is not the exact pinned container checker path')
        connection.sendall(struct.pack('!I', len(request)) + request)
        def receive(length):
            data = b''
            while len(data) < length:
                chunk = connection.recv(length - len(data))
                if not chunk:
                    raise ValueError('Public service closed an incomplete frame')
                data += chunk
            return data
        length = struct.unpack('!I', receive(4))[0]
        if not 0 < length <= 256 * 1024:
            raise ValueError('Public service frame exceeds protocol bound')
        response = json.loads(receive(length), object_pairs_hook=strict_object)
    if (response.get('schema_version') != 1 or response.get('request_id') != request_id
            or response.get('error') is not None or not isinstance(response.get('result'), dict)):
        raise ValueError('Public service returned an invalid/error response')
    if (response.get('service_instance_id') != response['result'].get('service_instance_id')
            or response.get('revision') != response['result'].get('revision')):
        raise ValueError('Public service envelope and snapshot identities disagree')
    return response['result']


def query_positive(fixture, checker_sha256, directory):
    if 'transport' not in fixture:
        return public_snapshot(fixture, checker_sha256)
    # The descriptor supplies identities, never executable query code/argv.
    # Only this fixed read-only IPC probe crosses the pinned container boundary.
    probe = ('import hashlib,json,os,socket,stat,struct,sys,time\nfrom pathlib import Path\n'
             + inspect.getsource(strict_object) + '\n' + inspect.getsource(public_snapshot)
             + '\nprint(json.dumps(public_snapshot(json.loads(sys.argv[1]),sys.argv[2])))\n')
    env = isolated_environment(directory)
    for key in ('HOME', 'USER', 'LOGNAME', 'XDG_RUNTIME_DIR'):
        if key in os.environ:
            env[key] = os.environ[key]
    response = command(['/usr/bin/podman', 'exec', fixture['transport']['container_id'],
                        '/usr/bin/python3', '-c', probe, json.dumps(fixture), checker_sha256], env, 25)
    return json.loads(response, object_pairs_hook=strict_object)


def positive_trial(manifest, package, directory, report):
    fixture = manifest['positive_fixture']
    if fixture is None:
        raise ValueError('Pending: a real separate human approval and successful live fixture run are required')
    checker = package / 'plugin/bin/progress-checker'
    checker_sha256 = hashlib.sha256(regular_bytes(checker, 128 * 1024 * 1024)).hexdigest()
    for number in range(2):
        snapshot = query_positive(fixture, checker_sha256, directory)
        status = snapshot.get('status', {})
        evidence = status.get('latest', {}).get(fixture['check_id'], {})
        check(report, 'live human trial remains on the originally started service instance (' + str(number + 1) + ')',
              snapshot.get('canonical_root') == fixture['root']
              and snapshot.get('service_instance_id') == fixture['service_instance_id']
              and snapshot.get('health') == 'ready' and snapshot.get('running') == [])
        check(report, 'live public service authenticates fresh passing exact fixture command (' + str(number + 1) + ')',
              status.get('source', {}).get('config_hash') == fixture['config_hash']
              and evidence.get('check_id') == fixture['check_id']
              and evidence.get('command_hash') == fixture['command_hash']
              and evidence.get('execution_state') == 'finished' and evidence.get('outcome') == 'passed'
              and evidence.get('freshness') == 'current' and evidence.get('source') == status.get('source')
              and isinstance(evidence.get('run_id'), str) and evidence['run_id']
              and not status.get('warnings'))
        report['positive_trial'] = {'service_instance_id': snapshot['service_instance_id'],
                                    'canonical_root': snapshot['canonical_root'],
                                    'evidence': evidence, 'revision': snapshot.get('revision'),
                                    'approval_step': 'Human approval performed externally; never automated by this runner.'}


def live_approval(manifest, directory, package, report, negative_only):
    output = command([sys.executable, ROOT / 'scripts/test-live-approval-negative.py',
                      '--package', package, '--output-dir', directory / 'negative-trial'],
                     isolated_environment(directory))
    result = json.loads(output, object_pairs_hook=strict_object)
    report['negative_trial'] = result
    check(report, 'actual active-service refusal controls pass without any grant',
          result.get('complete_negative_tests') is True
          and result.get('negative_controls_passed') is True
          and result.get('complete') is False and result.get('qualification_possible') is False
          and result.get('positive_human_approval_qualified') is False
          and result.get('failed_assertions') == [])
    if negative_only:
        raise ValueError('Development negative-only controls passed; real human approval trial is still required')
    positive_trial(manifest, package, directory, report)
    report['coverage'] = ('Actual disposable active-service refusal controls plus read-only public '
                          'evidence from the exact original live human-trial service. '
                          'This runner grants no approval and executes no configured check.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', required=True, choices=(
        'native-browser-install', 'live-service-approval', 'onboarding-release'))
    parser.add_argument('--release-manifest', type=Path,
                        default=Path('.progress-checker/native-onboarding-release.json'))
    parser.add_argument('--negative-only', action='store_true')
    args = parser.parse_args()
    report = {'schema_version': 1, 'case': args.case, 'complete': False,
              'status': 'pending', 'assertions': [],
              'coverage': 'Frozen release and actual public-runtime qualification; no approval grants.'}
    try:
        if args.negative_only and args.case != 'live-service-approval':
            raise ValueError('--negative-only applies only to live-service-approval')
        manifest = validate_manifest(args.release_manifest, report)
        with tempfile.TemporaryDirectory(prefix='pc-native-onboarding-') as temporary:
            directory = Path(temporary)
            package, payload = prepare_package(manifest, directory, report)
            if args.case == 'native-browser-install':
                native_browser(manifest, directory, payload, report)
            elif args.case == 'live-service-approval':
                live_approval(manifest, directory, package, report, args.negative_only)
            else:
                report['coverage'] = ('Exact frozen archive checksums/legal/native payload derivation and '
                                      'pinned onboarding documents. Native install and human live approval '
                                      'are separately required dependency checks, not inferred from documents.')
                check(report, 'release contains self-contained runtime and native payload inventory',
                      payload.get('plugin_version') == VERSION and payload.get('plugin_path') == PLUGIN_PATH
                      and payload.get('generated_files') == ['mcp.json'] and bool(payload.get('files')))
        report.update(status='passed', complete=True)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.TimeoutExpired) as error:
        report['reason'] = str(error)
    print(json.dumps(report, indent=2))
    return 0 if report['complete'] else 2


if __name__ == '__main__':
    sys.exit(main())
