#!/usr/bin/env python3
"""Bind delivery checks to a frozen package through the running plan tool.

This updates definitions, never approvals or evidence. The caller supplies the
reviewed archive; all eight delivery requirements remain unchanged.
"""
import argparse
import copy
import hashlib
import json
import os
import re
import secrets
import select
import signal
import stat
import time
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
PRIMARY_FLAGS = ('--primary-attestation', '--primary-attestation-sha256', '--primary-readiness')
PRIMARY_TRUST = 'explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime'
PRIMARY_ARCHIVE_SHA = '404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
PRIMARY_MCP = Path('/home/luis/.codex/plugins/cache/progress-local-8b5742430514/progress-checker/0.2.1-dev/bin/progress-checker-mcp')
PRIMARY_MCP_SHA = '6be43b4c12d46555d6443d2619bd15e1dd1754f297781f0fa5c0059bf5c79e7a'


def primary_arguments(values, old, rewrites):
    if any(value is not None for value in values) and not all(value is not None for value in values):
        raise RuntimeError('Primary binding requires the complete attestation/SHA/readiness triplet')
    enabled = all(value is not None for value in values)
    if enabled and (old is None or any(rewrites)):
        raise RuntimeError('Primary-only binding requires the prior archive and forbids runtime/fixture rewrites')
    if enabled and not re.fullmatch('[0-9a-f]{64}', values[1]):
        raise RuntimeError('Primary immutable SHA must be 64 lowercase hex characters')
    return enabled


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError('Duplicate primary JSON field')
        result[key] = value
    return result


def primary_bytes(path, private=False):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise RuntimeError('Primary input must be canonical and absolute')
    if private and (not path.is_relative_to(ROOT / '.local') or path.parent.stat().st_uid != os.getuid() or stat.S_IMODE(path.parent.stat().st_mode) != 0o700):
        raise RuntimeError('Primary registration requires an owned private public.local directory')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent); parent = next_fd
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            limit = 32 * 1024 * 1024 if not private else 1024 * 1024
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size > limit or (private and stat.S_IMODE(before.st_mode) != 0o600):
                raise RuntimeError('Unsafe bounded primary input')
            data = stream.read(limit + 1); after = os.fstat(stream.fileno()); current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if len(data) != before.st_size or len(data) > limit or identity(before) != identity(after) or identity(before) != identity(current):
                raise RuntimeError('Primary input changed during anchored read')
            return data
    finally:
        os.close(parent)


def primary_registration(attestation, sha256, readiness):
    attestation, readiness = Path(attestation), Path(readiness)
    if attestation == readiness or attestation.parent != readiness.parent:
        raise RuntimeError('Primary immutable/readiness files must be separate in one private directory')
    raw = primary_bytes(attestation, True)
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise RuntimeError('Primary immutable digest differs')
    immutable = json.loads(raw, object_pairs_hook=strict_object)
    live = json.loads(primary_bytes(readiness, True), object_pairs_hook=strict_object)
    if immutable['root'] != str(ROOT) or immutable['state'] != '/home/luis/.local/share/progress-checker' or immutable['trust_policy'] != PRIMARY_TRUST or immutable['archive_sha256'] != PRIMARY_ARCHIVE_SHA:
        raise RuntimeError('Primary registration root/state/archive/policy differs')
    if 'config_hash' in immutable or 'accepted_config_hash' in immutable:
        raise RuntimeError('Pre-registration must omit final accepted config hash')
    if immutable['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip() or not (immutable['prepared_monotonic_ns'] <= time.monotonic_ns() < immutable['activation_expires_monotonic_ns']) or immutable['activation_expires_monotonic_ns'] - immutable['prepared_monotonic_ns'] > 1800_000_000_000:
        raise RuntimeError('Primary registration expired or from another boot')
    if live.get('attestation_path') != str(attestation) or live.get('attestation_sha256') != sha256 or not live.get('awaiting_root_activation') or live.get('ready') or live.get('terminal') or live.get('consumed'):
        raise RuntimeError('Primary producer is not awaiting activation')
    for key in ('schema_version','producer','producer_argv','producer_source_sha256','source_file_identity','uid','boot_id','python_exe_sha256','nonce','endpoint','root','state','archive_sha256','native_cli_sha256','skill_path','runtime_hashes','module_hashes','socket'):
        if live[key] != immutable[key]:
            raise RuntimeError('Primary immutable/readiness crosspin differs: ' + key)
    expected_modules = {str(ROOT/'scripts'/name) for name in ('plugin-primary-upgrade.py','plugin-acceptance.py','plugin-primary-pilot-activate.py','plugin-pilot-acceptance.py','plugin-primary-pilot-producer.py')}
    if set(immutable['module_hashes']) != expected_modules or set(immutable['runtime_hashes']) != {'checker-plugin','progress-checker','progress-checker-mcp'}:
        raise RuntimeError('Primary module/runtime inventory differs')
    for path, digest in immutable['module_hashes'].items():
        if hashlib.sha256(primary_bytes(Path(path))).hexdigest() != digest:
            raise RuntimeError('Primary source changed after registration')
    endpoint = Path(immutable['endpoint'])
    if endpoint.parent != attestation.parent or endpoint.resolve(strict=True) != endpoint:
        raise RuntimeError('Primary endpoint path differs')
    info = endpoint.lstat()
    socket_identity = {'dev':info.st_dev,'ino':info.st_ino,'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or socket_identity != immutable['socket']:
        raise RuntimeError('Primary endpoint identity differs')
    return {'attestation_path':str(attestation), 'sha256':sha256, 'readiness_path':str(readiness), 'trust_policy':PRIMARY_TRUST}


def primary_transform(config, plan, binding, relative, archive_hash, old_relative, old_hash):
    if plan.get('acceptance_archive') != {'path':relative,'sha256':archive_hash} or archive_hash != PRIMARY_ARCHIVE_SHA or plan.get('acceptance_old_archive') != {'path':old_relative,'sha256':old_hash}:
        raise RuntimeError('Primary mode requires already accepted pinned current/prior archive metadata')
    if relative not in config['fingerprint']['extra_inputs'] or old_relative not in config['fingerprint']['extra_inputs']:
        raise RuntimeError('Primary archives must already be fingerprinted')
    if len(plan['milestones']) != 8 or len(config['milestones']) != 8 or old_hash != 'fbf12375255af78ff30b042a9f9938ecccec5e03d7e8504042dac1872b0f646a':
        raise RuntimeError('Primary binding requires all eight requirements and the pinned genuine prior archive')
    for current_check in config['checks']:
        if current_check['id'] != 'plan-definition':
            argv = current_check['argv']
            if argv.count('--archive') != 1 or argv[argv.index('--archive')+1] != relative:
                raise RuntimeError('Live accepted archive binding differs')
    updated = copy.deepcopy(config)
    matches = [check for check in updated['checks'] if check['id'] == 'standard-codex-pilot']
    if len(matches) != 1:
        raise RuntimeError('Exactly one standard pilot definition required')
    check = matches[0]
    if check['argv'][:4] != ['/usr/bin/python3','scripts/plugin-acceptance.py','--milestone','standard-codex-pilot'] or (check['cwd'],check['kind'],check['timeout_seconds']) != ('.','test',300) or config['execution']['max_parallel'] != 1:
        raise RuntimeError('Primary observer command or execution shape differs')
    allowed = {'--archive','--recipient-old-archive',*PRIMARY_FLAGS}
    remaining = check['argv'][4:]
    seen = set()
    while remaining:
        if len(remaining)<2 or remaining[0] not in allowed or remaining[0] in seen:
            raise RuntimeError('Unexpected or duplicate existing primary command option')
        seen.add(remaining[0]);remaining=remaining[2:]
    check['argv'] = ['/usr/bin/python3','scripts/plugin-acceptance.py','--milestone','standard-codex-pilot','--archive',relative,'--recipient-old-archive',old_relative,PRIMARY_FLAGS[0],binding['attestation_path'],PRIMARY_FLAGS[1],binding['sha256'],PRIMARY_FLAGS[2],binding['readiness_path']]
    return updated


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--archive', required=True, type=Path)
parser.add_argument('--recipient-old-archive', type=Path,
                    help='Frozen genuine prior version used by package and release upgrade checks')
parser.add_argument('--public-test-runtime', action='store_true',
                    help='Use the explicitly attested public namespace for package, lifecycle and workflow checks')
parser.add_argument('--state-dir', required=True, type=Path,
                    help='Private state directory used by the running project checker')
parser.add_argument('--evidence-fixture-root', type=Path)
parser.add_argument('--evidence-fixture-state', type=Path)
parser.add_argument('--plan-fixture-root', type=Path)
parser.add_argument('--plan-fixture-state', type=Path)
parser.add_argument('--primary-attestation', type=Path)
parser.add_argument('--primary-attestation-sha256')
parser.add_argument('--primary-readiness', type=Path)
args = parser.parse_args()


class WorkBudget:
    """200s work and <=10s EOF cleanup, never extending an earlier caller timer."""
    def __init__(self):
        self.started = time.monotonic()
        self.previous_handler = signal.getsignal(signal.SIGALRM)
        self.previous_timer = signal.getitimer(signal.ITIMER_REAL)
        self.armed = False
    def expired(self, _signum, _frame):
        raise TimeoutError('Binding absolute deadline expired; reconcile any submission')
    def cleanup_deadline(self):
        return min(self.started+210, self.started+self.previous_timer[0]) if self.previous_timer[0] else self.started+210
    def arm(self, seconds):
        remaining = self.previous_timer[0]-(time.monotonic()-self.started) if self.previous_timer[0] else seconds
        remaining = min(remaining, self.cleanup_deadline()-time.monotonic())
        # Record responsibility BEFORE changing either global signal resource.
        self.armed = True
        try:
            signal.signal(signal.SIGALRM, self.expired)
            signal.setitimer(signal.ITIMER_REAL, max(.000001,min(seconds,remaining)))
        except BaseException as original:
            try:self.restore()
            except BaseException as cleanup:
                raise RuntimeError('Timer transition failed: '+str(original)+'; restoration uncertain: '+str(cleanup)) from original
            raise
    def restore(self):
        if self.armed:
            errors = []
            try:signal.setitimer(signal.ITIMER_REAL, 0)
            except BaseException as error:errors.append('disarm: '+str(error))
            try:signal.signal(signal.SIGALRM, self.previous_handler)
            except BaseException as error:errors.append('handler: '+str(error))
            if self.previous_timer[0]:
                try:signal.setitimer(signal.ITIMER_REAL,max(.000001,self.previous_timer[0]-(time.monotonic()-self.started)),self.previous_timer[1])
                except BaseException as error:errors.append('earlier timer: '+str(error))
            if errors:raise RuntimeError('Caller timer restoration uncertain: '+'; '.join(errors))
            self.armed = False


def close_reader(process, deadline=None):
    """Only EOF/owned handle close and finite wait; no process/group signal."""
    errors = []
    try:
        process.stdin.close()
    except BaseException as error:
        errors.append('stdin EOF: '+type(error).__name__+': '+str(error))
    try:
        remaining = min(10, deadline-time.monotonic()) if deadline is not None else 10
        if remaining <= 0:raise TimeoutError('Common cleanup deadline exhausted; reader unresolved')
        if process.wait(timeout=remaining) != 0:
            errors.append('returned native reader exited nonzero')
    except BaseException as error:
        errors.append('reader lifetime unresolved: '+type(error).__name__+': '+str(error))
    finally:
        for stream in (process.stdin,process.stdout,process.stderr):
            if stream is not None:
                try:stream.close()
                except BaseException as error:errors.append('pipe handle: '+str(error))
    if errors:
        raise RuntimeError('; '.join(errors))


def spawn_reader(argv, cleanup_deadline=None):
    process = None
    try:
        process = subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
        os.set_blocking(process.stdin.fileno(),False)
        return process
    except BaseException as original:
        cleanup = None
        if process is not None:
            try:close_reader(process,cleanup_deadline)
            except BaseException as error:cleanup = str(error)
        raise RuntimeError('Reader startup failed before RPC: '+type(original).__name__+': '+str(original)
                           + ('; returned reader cleanup uncertain: '+cleanup if cleanup else '; EOF/reaped returned reader or no returned child handle')) from original


def send_bytes(process,data,deadline):
    if type(data) is not bytes or not 0 < len(data) <= 512*1024:
        raise RuntimeError('Bounded exact RPC bytes required')
    offset = 0
    while offset < len(data):
        remaining = deadline-time.monotonic()
        if remaining <= 0 or not select.select([],[process.stdin],[],remaining)[1]:
            raise TimeoutError('MCP write deadline expired')
        if time.monotonic() >= deadline:
            raise TimeoutError('MCP write deadline expired after readiness')
        try:count = os.write(process.stdin.fileno(),data[offset:])
        except BlockingIOError:continue
        if count <= 0:raise RuntimeError('MCP write closed')
        offset += count


def outcome_failure(original,cleanup,observed_commit,attempted):
    if original is None and cleanup is None:return None
    prefix = ('Backend commitment observed; explicitly reconcile accepted config and machine plan before approval/retry. '
              if observed_commit else 'Submission outcome unknown; explicitly reconcile backend/machine plan before approval/retry. '
              if attempted else 'No submission attempted by this binder. ')
    messages = []
    if original is not None:messages.append('Original '+type(original).__name__+': '+str(original))
    if cleanup is not None:messages.append('Owned EOF/FD cleanup uncertain: '+str(cleanup))
    return RuntimeError(prefix+'; '.join(messages))


def run_binding(args):
    adapter = None; directory_fd = None
    submit_attempted = False; backend_committed = False
    original_error = None; cleanup_error = None
    budget = WorkBudget()
    try:
        budget.arm(200)
        try:
            primary_mode = primary_arguments((args.primary_attestation,args.primary_attestation_sha256,args.primary_readiness),args.recipient_old_archive,(args.public_test_runtime,args.evidence_fixture_root,args.evidence_fixture_state,args.plan_fixture_root,args.plan_fixture_state))
        except RuntimeError as error:
            parser.error(str(error))
        primary_binding = primary_registration(args.primary_attestation,args.primary_attestation_sha256,args.primary_readiness) if primary_mode else None
        if bool(args.evidence_fixture_root) != bool(args.evidence_fixture_state):
            parser.error('Evidence qualification requires both explicit fixture and state paths')
        if bool(args.plan_fixture_root) != bool(args.plan_fixture_state):
            parser.error('Plan qualification requires both explicit fixture and state paths')
        evidence_fixture = None
        if args.evidence_fixture_root:
            evidence_fixture = {
                'root': str(args.evidence_fixture_root.resolve(strict=True)),
                'state': str(args.evidence_fixture_state.resolve(strict=True)),
            }
        plan_fixture = None
        if args.plan_fixture_root:
            plan_fixture = {'root': str(args.plan_fixture_root.resolve(strict=True)),
                            'state': str(args.plan_fixture_state.resolve(strict=True))}
        archive = args.archive.resolve(strict=True)
        relative = archive.relative_to(ROOT).as_posix()
        if not archive.is_file() or args.archive.is_symlink() or not relative.startswith('.progress-checker/acceptance-inputs/'):
            raise SystemExit('Use a regular frozen archive under .progress-checker/acceptance-inputs')
        def artifact_digest(path=archive):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
                    raise RuntimeError('Frozen package must be a bounded regular archive')
                digest = hashlib.sha256()
                remaining = 64 * 1024 * 1024 + 1
                while chunk := source.read(min(1024 * 1024, remaining)):
                    digest.update(chunk)
                    remaining -= len(chunk)
                    if remaining == 0:
                        raise RuntimeError('Frozen archive grew beyond its limit')
                return digest.hexdigest()

        archive_hash = artifact_digest()
        old_archive = None
        old_relative = None
        old_hash = None
        if args.recipient_old_archive:
            if args.recipient_old_archive.is_symlink():
                raise SystemExit('Use a regular frozen prior-version archive')
            old_archive = args.recipient_old_archive.resolve(strict=True)
            old_relative = old_archive.relative_to(ROOT).as_posix()
            if not old_relative.startswith('.progress-checker/acceptance-inputs/'):
                raise SystemExit('Freeze the prior-version archive under .progress-checker/acceptance-inputs')
            old_hash = artifact_digest(old_archive)
            if old_hash != 'fbf12375255af78ff30b042a9f9938ecccec5e03d7e8504042dac1872b0f646a':
                raise SystemExit('Prior-version archive does not match the genuine pinned 0.2.0-dev package')

        def ensure_artifacts():
            if artifact_digest() != archive_hash or (old_archive and artifact_digest(old_archive) != old_hash):
                raise RuntimeError('Frozen acceptance inputs changed during plan binding')
        directory_path = ROOT / '.progress-checker'
        directory_fd = os.open(directory_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory_info = os.fstat(directory_fd)

        def ensure_directory():
            current = directory_path.lstat()
            if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (directory_info.st_dev, directory_info.st_ino):
                raise RuntimeError('Plan directory changed during acceptance binding')

        def read_plan():
            ensure_directory()
            fd = os.open('plugin-plan.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            with os.fdopen(fd, 'rb') as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                    raise RuntimeError('Machine plan must be a bounded regular file')
                data = source.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise RuntimeError('Machine plan exceeds the setup limit')
            return data

        def write_plan(plan, before):
            ensure_directory()
            name = '.plugin-plan-' + secrets.token_hex(16) + '.tmp'
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=directory_fd)
            try:
                with os.fdopen(fd, 'w') as output:
                    output.write(json.dumps(plan, indent=2) + '\n')
                    output.flush()
                    os.fsync(output.fileno())
                if read_plan() != before:
                    raise RuntimeError('Machine plan changed; preserve the edit and review acceptance metadata')
                ensure_directory()
                os.replace(name, 'plugin-plan.json', src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                os.fsync(directory_fd)
                ensure_directory()
            finally:
                try:
                    os.unlink(name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
        adapter_path = ROOT / '.local/checker-target/debug/progress-checker-mcp'
        if primary_mode:
            if archive_hash != PRIMARY_ARCHIVE_SHA or hashlib.sha256(primary_bytes(PRIMARY_MCP)).hexdigest() != PRIMARY_MCP_SHA or args.state_dir.resolve(strict=True) != Path('/home/luis/.local/share/progress-checker'):
                raise RuntimeError('Primary binding requires the exact installed404 MCP/root state')
            adapter_path = PRIMARY_MCP
        adapter = spawn_reader([str(adapter_path), '--root', str(ROOT), '--state-dir', str(args.state_dir.resolve(strict=True))],budget.cleanup_deadline())
        sequence = 0
        rpc_buffer = b''

        def call(method, params):
            nonlocal sequence, rpc_buffer, submit_attempted
            sequence += 1
            deadline = time.monotonic() + 30
            data = (json.dumps({'jsonrpc': '2.0', 'id': sequence,
                               'method': method, 'params': params}) + '\n').encode('utf-8')
            if method == 'tools/call' and params.get('name') == 'checker_submit_plan':
                # Once any submission bytes could be sent, a missing response is not a
                # safe retry: the backend may have committed the accepted definition.
                submit_attempted = True
            send_bytes(adapter, data, deadline)
            while b'\n' not in rpc_buffer:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([adapter.stdout], [], [], remaining)[0]:
                    raise RuntimeError('MCP response timed out')
                chunk = os.read(adapter.stdout.fileno(), 16384)
                if not chunk:
                    raise RuntimeError('MCP adapter closed before responding')
                rpc_buffer += chunk
                if len(rpc_buffer) > 512 * 1024:
                    raise RuntimeError('MCP response exceeds the binding limit')
            line, rpc_buffer = rpc_buffer.split(b'\n', 1)
            reply = json.loads(line)
            if not isinstance(reply, dict) or reply.get('jsonrpc') != '2.0' or reply.get('id') != sequence:
                raise RuntimeError('MCP response identity mismatch')
            if 'error' in reply:
                raise RuntimeError(reply['error'])
            if not isinstance(reply.get('result'), dict):
                raise RuntimeError('MCP response result is invalid')
            return reply['result']

        def tool(name, arguments=None):
            return call('tools/call', {'name': name, 'arguments': arguments or {}})

        try:
            call('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                                'clientInfo': {'name': 'acceptance-binding', 'version': '1'}})
            send_bytes(adapter, b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n', time.monotonic()+30)
            for attempt in range(5):
                current = tool('checker_get_project')
                if current['isError']:
                    raise RuntimeError(current)
                snapshot = current['structuredContent']
                if snapshot['result']['canonical_root'] != str(ROOT.resolve(strict=True)):
                    raise RuntimeError('Checker is bound to a different repository')
                config = snapshot['result']['config']
                plan_before = read_plan()
                plan = json.loads(plan_before)
                expected_checks = {item['check_id'] for item in plan['milestones']}
                if config['project_id'] != plan['project_id'] or {check['id'] for check in config['checks']} != expected_checks:
                    raise RuntimeError('Delivery configuration differs from the accepted machine plan')
                updated = copy.deepcopy(config)
                if primary_mode:
                    primary_binding = primary_registration(args.primary_attestation,args.primary_attestation_sha256,args.primary_readiness)
                    updated = primary_transform(config,plan,primary_binding,relative,archive_hash,old_relative,old_hash)
                else:
                    inputs = updated['fingerprint']['extra_inputs']
                    retained_old = plan.get('acceptance_old_archive', {}).get('path') if not old_relative else None
                    inputs[:] = [entry for entry in inputs if not entry.startswith('.progress-checker/acceptance-inputs/') or entry == retained_old]
                    inputs.append(relative)
                    if old_relative:
                        inputs.append(old_relative)
                    for check in updated['checks']:
                        if check['id'] == 'plan-definition':
                            continue
                        argv = check['argv']
                        if argv[:4] != ['/usr/bin/python3', 'scripts/plugin-acceptance.py', '--milestone', check['id']]:
                            raise RuntimeError('Review the changed acceptance command before binding its archive')
                        if '--archive' in argv:
                            index = argv.index('--archive')
                            del argv[index:index + 2]
                        argv.extend(['--archive', relative])
                        if old_relative and check['id'] in ('plugin-package', 'release-distribution'):
                            if '--recipient-old-archive' in argv:
                                index = argv.index('--recipient-old-archive')
                                del argv[index:index + 2]
                            argv.extend(['--recipient-old-archive', old_relative])
                        if args.public_test_runtime and check['id'] in ('plugin-package', 'service-lifecycle', 'agent-workflow'):
                            if '--test-runtime' in argv:
                                index = argv.index('--test-runtime')
                                del argv[index:index + 2]
                            argv.extend(['--test-runtime', 'public-namespace'])
                        if check['id'] in ('evidence-integrity', 'release-distribution') and evidence_fixture:
                            for flag in ('--evidence-fixture-root', '--evidence-fixture-state'):
                                if flag in argv:
                                    index = argv.index(flag)
                                    del argv[index:index + 2]
                            argv.extend(['--evidence-fixture-root', evidence_fixture['root'],
                                         '--evidence-fixture-state', evidence_fixture['state']])
                        if check['id'] == 'plan-submission' and plan_fixture:
                            for flag in ('--plan-fixture-root', '--plan-fixture-state'):
                                if flag in argv:
                                    index = argv.index(flag)
                                    del argv[index:index + 2]
                            argv.extend(['--plan-fixture-root', plan_fixture['root'],
                                         '--plan-fixture-state', plan_fixture['state']])
                ensure_artifacts()
                result = tool('checker_submit_plan', {
                    'config': updated,
                    'reason': ('Change ONLY standard-codex-pilot command to the explicit immutable primary attestation SHA/path, mutable readiness path, and already pinned current/prior archive. Preserve all eight requirements, scope, dependencies, other check definitions, and retained fixture selectors. No execution approval is granted.' if primary_mode else 'Bind the same eight delivery requirements to frozen fingerprinted package inputs and explicitly selected public test runtime. Original criteria and dependencies are retained; partial workflow and plan gates remain incomplete. Retained fixtures use only genuine human approval; this change grants no execution approval.'),
                    'expected_revision': snapshot['revision'],
                    'expected_config_hash': snapshot['result']['status']['source']['config_hash'],
                })
                if not result['isError']:
                    backend_committed = True
                    print(json.dumps(result['structuredContent'], indent=2))
                    break
                if result['structuredContent']['error']['code'] != 'REVISION_CONFLICT':
                    raise RuntimeError(result)
                # A correlated revision refusal establishes that this attempt did not commit.
                submit_attempted = False
            else:
                raise RuntimeError('Project kept changing; read current revision before retrying')
            ensure_artifacts()
            if primary_mode:
                primary_registration(args.primary_attestation,args.primary_attestation_sha256,args.primary_readiness)
                final = tool('checker_get_project')
                if final['isError'] or final['structuredContent']['result']['config'] != updated:
                    raise RuntimeError('Live accepted primary config changed; do not grant or activate')
                if updated != config:
                    change = result['structuredContent']['result']['change']
                    if change['added'] or change['removed'] or change['changed'] != ['standard-codex-pilot']:
                        raise RuntimeError('Unexpected accepted scope change; stop before grants')
                history = tool('checker_get_plan_history', {'offset':0,'limit':5})
                if history['isError']:
                    raise RuntimeError('Cannot reconcile accepted scope history; stop before grants')
                print(json.dumps({'primary_binding_history':history['structuredContent']},indent=2))
                plan['primary_observer'] = primary_binding
            plan['acceptance_archive'] = {'path': relative, 'sha256': archive_hash}
            if old_relative:
                plan['acceptance_old_archive'] = {'path': old_relative, 'sha256': old_hash}
            if args.public_test_runtime:
                plan['public_test_runtime'] = {'mode': 'public-namespace',
                                             'checks': ['plugin-package', 'service-lifecycle', 'agent-workflow'],
                                             'limitation': 'Namespace-local SETFCAP is retained; partial product outcomes remain partial.'}
            if evidence_fixture:
                plan['evidence_fixture'] = evidence_fixture
            if plan_fixture:
                plan['plan_fixture'] = plan_fixture
            write_plan(plan, plan_before)
        except BaseException:
            raise
    except BaseException as error:
        original_error = error
    finally:
        try:
            budget.arm(10)
        except BaseException as error:
            cleanup_error = error
        try:
            if adapter is not None:
                close_reader(adapter,budget.cleanup_deadline())
        except BaseException as error:
            cleanup_error = RuntimeError(str(cleanup_error or '')+'; EOF cleanup: '+str(error))
        finally:
            try:
                if directory_fd is not None:os.close(directory_fd)
            except BaseException as error:
                cleanup_error = RuntimeError(str(cleanup_error or '')+'; public directory FD: '+str(error))
            finally:
                try:budget.restore()
                except BaseException as error:
                    cleanup_error = RuntimeError(str(cleanup_error or '')+'; caller timer restoration uncertain: '+str(error))
    failure = outcome_failure(original_error,cleanup_error,backend_committed,submit_attempted)
    if failure is not None:raise failure


run_binding(args)
