#!/usr/bin/env python3
"""One-way live observer. Never starts a workflow, approves or runs checks.

The fixed checker PID namespace hides host exporter PID/start/executable identity.
Strict mode fails closed there. Kernel SO_PEERPIDFD verifies the connected peer's
lifetime, not its hidden identity. Optional trusted-registration mode is expressly
unqualified development only. Register before final command binding/human approval,
or review a static source-pinned attestor; never invalidate grants mid-workflow.
No saved PASS/report can qualify this module. Combined acceptance additionally
requires current worker reconciliation, fresh recipient proof and artifact checks.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import time

MAX_BYTES = 8 * 1024 * 1024
MAX_FRAME_BYTES = 1024 * 1024
MAX_FRAMES = 4096
SO_PEERPIDFD = 77  # Linux asm-generic/socket.h, independently probed under exact outer profile.
ZERO_HASH = '0' * 64


class ObservationError(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def process_identity(pid):
    try:
        path = Path('/proc') / str(pid)
        fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        if fields[0] == 'Z':
            raise ObservationError('Producer is terminated')
        return {'pid': pid, 'starttime': fields[19], 'uid': path.stat().st_uid}
    except FileNotFoundError as exc:
        raise ObservationError('Producer PID is not visible in observer namespace') from exc


def pinned_registration(registration, expected):
    """Expected pins must come from reviewed registration, never stream assertions."""
    required = {'schema_version', 'nonce', 'root', 'state', 'accepted_config_hash',
                'check_definition', 'producer', 'uid', 'producer_source_sha256',
                'native_cli_sha256', 'runtime_hashes', 'archive_sha256', 'module_hashes',
                'boot_id', 'started_monotonic_ns', 'workflow_expires_monotonic_ns', 'hard_expires_monotonic_ns',
                'observer_ready_monotonic_ns', 'observer_expires_monotonic_ns', 'socket', 'endpoint', 'skill_path'}
    if not required <= registration.keys() or registration['schema_version'] != 1:
        raise ObservationError('Incomplete registration')
    nonce = registration['nonce']
    if not isinstance(nonce, str) or len(nonce) != 64 or any(c not in '0123456789abcdef' for c in nonce):
        raise ObservationError('Nonce must be a fresh 256-bit hexadecimal value')
    for field in required:
        if field not in expected or registration[field] != expected[field]:
            raise ObservationError('Registration pin differs: ' + field)
    start, end = registration['started_monotonic_ns'], registration['hard_expires_monotonic_ns']
    now = time.monotonic_ns()
    if not isinstance(start, int) or not isinstance(end, int) or not start <= now < end or end - start > 600_000_000_000:
        raise ObservationError('Registration expired or exceeds reviewed external workflow interval')
    ready, expires = registration['observer_ready_monotonic_ns'], registration['observer_expires_monotonic_ns']
    if not start <= ready <= now < expires <= end or expires-ready > 90_000_000_000:
        raise ObservationError('Observer handoff window expired or exceeds90 seconds')
    if registration['workflow_expires_monotonic_ns']-start > 480_000_000_000:
        raise ObservationError('External workflow interval exceeds reviewed480 seconds')
    if registration['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        raise ObservationError('Registration is from another boot')
    if not registration.get('ready') or registration.get('consumed') or registration.get('terminal'):
        raise ObservationError('Registration is not a live one-use ready workflow')
    for name, digest in registration['module_hashes'].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest:
            raise ObservationError('Visible producer module source changed: ' + name)
    return registration


def socket_snapshot(path):
    """Anchor every pathname component; never follow endpoint/ancestor links."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ObservationError('Socket path must be an absolute anchored path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISSOCK(info.st_mode):
            raise ObservationError('Registered endpoint is not a socket')
        return {'dev': info.st_dev, 'ino': info.st_ino, 'uid': info.st_uid, 'mode': stat.S_IMODE(info.st_mode), 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
    finally:
        os.close(fd)


def peer_attestation(sock, registration, *, development_trusted_registration=False):
    """Kernel peer lifetime plus strict visible identity or unqualified attestation."""
    pid, uid, gid = struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != registration['uid']:
        raise ObservationError('Live reporter peer UID differs')
    if not development_trusted_registration:
        if pid <= 0:
            raise ObservationError('Peer PID hidden by fixed sandbox; strict host identity unavailable')
        visible = process_identity(pid)
        expected = dict(registration['producer'], uid=registration['uid'])
        if visible != expected:
            raise ObservationError('Direct producer PID/start/UID differs')
    try:
        fd = sock.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD)
    except OSError as exc:
        raise ObservationError('Kernel peer PIDfd unavailable') from exc
    try:
        assert_peer_live(fd)
    except BaseException:
        os.close(fd)
        raise
    return fd, {'kernel_peer_lifetime': True, 'peer_pid': pid, 'peer_uid': uid, 'peer_gid': gid,
                'hidden_host_identity_independently_verified': pid > 0 and not development_trusted_registration,
                'policy': 'unqualified trusted host registration development' if development_trusted_registration else 'direct visible PID/start/UID',
                'accepted_gate': False}


def assert_peer_live(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    if poll.poll(0):
        raise ObservationError('Kernel-bound exporter is no longer live')


def recv_exact(sock, length, deadline):
    data = bytearray()
    while len(data) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ObservationError('Observer shared deadline exceeded')
        sock.settimeout(min(remaining, 1))
        try:
            chunk = sock.recv(min(65536, length-len(data)))
        except socket.timeout:
            continue
        if not chunk:
            raise ObservationError('Truncated live stream')
        data.extend(chunk)
    return bytes(data)


def parse_snapshot(raw, registration):
    """Actual producer Buffer schema: seq1, previous hash over exact newline bytes."""
    if not raw or len(raw) > MAX_BYTES or not raw.endswith(b'\n'):
        raise ObservationError('Snapshot bounds/truncation')
    previous = ZERO_HASH
    timestamp = registration['started_monotonic_ns']
    frames = []
    for line in raw.splitlines(keepends=True):
        if len(line) > MAX_FRAME_BYTES or len(frames) >= MAX_FRAMES:
            raise ObservationError('Raw frame bound exceeded')
        try:
            frame = json.loads(line)
        except (ValueError, UnicodeError) as exc:
            raise ObservationError('Invalid raw JSON frame') from exc
        if not isinstance(frame, dict) or set(frame) != {'schema_version', 'nonce', 'seq', 'phase', 'collected_monotonic_ns', 'type', 'data', 'previous_sha256', 'sha256'}:
            raise ObservationError('Unexpected producer frame schema')
        collected = frame['collected_monotonic_ns']
        if frame['schema_version'] != 1 or frame['nonce'] != registration['nonce']:
            raise ObservationError('Raw frame session pin differs')
        if frame['seq'] != len(frames)+1 or not isinstance(collected, int) or not timestamp <= collected <= time.monotonic_ns() or collected >= registration['hard_expires_monotonic_ns']:
            raise ObservationError('Producer frame order/time mismatch')
        value = dict(frame); claimed = value.pop('sha256')
        if frame['previous_sha256'] != previous or hashlib.sha256(json.dumps(value, separators=(',', ':')).encode()).hexdigest() != claimed:
            raise ObservationError('Raw hash-chain/selfhash mismatch')
        if frame['type'] in {'native_jsonl', 'core_mcp_request', 'core_mcp_response'}:
            value = frame['data']
            if not isinstance(value, dict) or set(value) != {'raw_line', 'event'} or json.loads(value['raw_line']) != value['event']:
                raise ObservationError('Raw native/core bytes differ from parsed event')
        previous, timestamp = hashlib.sha256(line).hexdigest(), collected
        frames.append(frame)
    return frames


def read_snapshots(sock, registration, *, deadline):
    first_size = struct.unpack('!I', recv_exact(sock, 4, deadline))[0]
    if first_size > MAX_BYTES:
        raise ObservationError('Snapshot exceeds 8MiB')
    first = recv_exact(sock, first_size, deadline)
    first_frames = parse_snapshot(first, registration)
    second_size = struct.unpack('!I', recv_exact(sock, 4, deadline))[0]
    if second_size > MAX_BYTES:
        raise ObservationError('Snapshot exceeds 8MiB')
    second = recv_exact(sock, second_size, deadline)
    if not second.startswith(first) or len(second) <= len(first):
        raise ObservationError('Second raw snapshot is not a strict append-only extension')
    frames = parse_snapshot(second, registration)
    if frames[-1]['type'] != 'stream_terminal':
        raise ObservationError('Missing live stream terminal frame')
    return frames, len(first_frames), hashlib.sha256(second).hexdigest()


def successful(call):
    structured = (call.get('result') or {}).get('structured_content') or {}
    if call.get('status') != 'completed' or call.get('error') is not None or 'error' in structured or 'result' not in structured:
        raise ObservationError('Actual backend tool receipt failed')
    return structured


def validate_delivery_progress(value, *, verified):
    milestones = [m for m in value['progress']['milestones'] if m.get('milestone_id') == 'delivery-plan']
    if len(milestones) != 1 or milestones[0].get('verified') is not verified:
        raise ObservationError('Delivery-plan evidence-derived progress differs')
    if value['claims'].get('delivery-plan') != 'implemented':
        raise ObservationError('Delivery-plan implementation claim differs')


def validate_finished_run(value, child, *, freshness='current'):
    runs = value.get('runs')
    if value.get('execution_state') != 'finished' or not isinstance(runs, list) or len(runs) != 1:
        raise ObservationError('Fresh backend batch is not exact finished single child')
    record = runs[0]
    evidence = record.get('evidence', {})
    if (record.get('run_id') != child or record.get('check_id') != 'plan-definition'
            or evidence.get('run_id') != child or evidence.get('check_id') != 'plan-definition'
            or evidence.get('outcome') != 'passed' or record.get('current_freshness') != freshness
            or record.get('changed_during_run') is not False):
        raise ObservationError('Fresh backend RunRecord proof differs')


def validate_check_definition(config, definition):
    expected = {'id': 'plan-definition', 'argv': ['/usr/bin/python3', 'scripts/check-plugin-plan.py'],
                'cwd': '.', 'kind': 'test', 'timeout_seconds': 300}
    if definition != expected or [c for c in config['checks'] if c['id'] == 'plan-definition'] != [definition]:
        raise ObservationError('Immutable concrete check differs from accepted exact definition')


def validate_phase_chronology(frames):
    def single(kind, phase=None):
        matched = [f for f in frames if f['type'] == kind and (phase is None or f['phase'] == phase)]
        if len(matched) != 1:
            raise ObservationError('Exact phase boundary required: ' + kind + '/' + str(phase))
        return matched[0]['seq']
    timeline = [('public_frame', 'verified'), ('source_cas', None), ('public_frame', 'stale'),
                ('gentle_restart', None), ('public_frame', 'restart-stale'), ('source_restored', None)]
    sequence = [single(*item) for item in timeline]
    if sequence != sorted(sequence) or len(set(sequence)) != len(sequence):
        raise ObservationError('Public verification/stale/restart/restore order differs')
    intervals = {'accepted-and-verify': (0, sequence[0]), 'source-stale': (sequence[1], sequence[2]),
                 'native-restart': (sequence[3], sequence[4]), 'unavailable': (sequence[4], sequence[5])}
    for phase, (lower, upper) in intervals.items():
        start, finish = single('phase_start', phase), single('phase_finish', phase)
        raw = [f['seq'] for f in frames if f['type'] == 'native_jsonl' and f['phase'] == phase]
        if not raw or not lower < start < min(raw) <= max(raw) < finish < upper:
            raise ObservationError('Native phase lies outside matching public interval: ' + phase)


def validate_native_bindings(calls, registration, *, phase):
    child, batch = registration['child_run_id'], registration['run_id']
    freshness = 'current' if phase == 'accepted-and-verify' else 'stale'
    completed_run = progress_seen = log_seen = False
    previous = None
    for call in calls:
        tool, arguments = call['tool'], call['arguments']
        receipt = successful(call); value = receipt['result']
        if tool in {'checker_get_project', 'checker_get_progress'}:
            if arguments != {} or value['canonical_root'] != registration['root'] or value['status']['source']['config_hash'] != registration['accepted_config_hash']:
                raise ObservationError('Native project/progress binding differs')
            if tool == 'checker_get_progress':
                milestones = [m for m in value['status']['progress']['milestones'] if m['milestone_id'] == 'delivery-plan']
                if len(milestones) == 1 and milestones[0]['verified'] is (freshness == 'current'):
                    progress_seen = True
        elif tool == 'checker_get_run':
            if arguments != {'run_id': batch} or value.get('run_id') != batch:
                raise ObservationError('Native run read differs from recorded batch')
            if value.get('execution_state') == 'finished':
                validate_finished_run(value, child, freshness=freshness); completed_run = True
        elif tool == 'checker_get_log':
            if arguments != {'run_id': child, 'check_id': 'plan-definition', 'offset': 0, 'limit': 4096} or value.get('run_id') != child or value.get('check_id') != 'plan-definition' or value.get('offset') != 0:
                raise ObservationError('Native log read differs from recorded exact child')
            log_seen = True
        elif tool in {'checker_submit_plan', 'checker_set_claim', 'checker_run_checks'}:
            if previous is None or previous['tool'] != 'checker_get_project':
                raise ObservationError('Native mutation lacks immediately preceding fresh project read')
            project = successful(previous)
            if arguments.get('expected_revision') != project['revision']:
                raise ObservationError('Native mutation revision differs from preceding read')
            if tool != 'checker_set_claim' and arguments.get('expected_config_hash') != project['result']['status']['source']['config_hash']:
                raise ObservationError('Native mutation config hash differs from preceding read')
        previous = call
    if not completed_run or not progress_seen or (phase == 'accepted-and-verify' and not log_seen):
        raise ObservationError('Native exact finished run/progress/log evidence missing')


def semantic_receipt(frames, registration, *, connected_monotonic_ns):
    """Validate raw actual phase evidence; combined pilot gates remain required."""
    baselines = [f['data'] for f in frames if f['type'] == 'protected_baseline']
    ready_audits = [f['data'] for f in frames if f['type'] == 'protected_audit' and f['phase'] == 'ready']
    terminal = frames[-1]
    if len(baselines) != 1 or len(ready_audits) != 1 or terminal['type'] != 'stream_terminal' or 'audit' not in terminal['data']:
        raise ObservationError('Initial/prestream/terminal protected audits missing')
    baseline = baselines[0]
    for audit in [ready_audits[0], terminal['data']['audit']]:
        if audit['protected_hashes'] != baseline['protected_hashes'] or audit['legacy_leases'] != baseline['legacy_leases']:
            raise ObservationError('Raw protected bytes/legacy lease baseline differs')
        if audit.get('modules_unchanged') is not True or audit.get('package_inventories_unchanged') is not True or audit.get('readme_bytes_mode_restored') is not True:
            raise ObservationError('Producer prestream audit is incomplete')
        if audit['writer'] != registration['phase_writer_ids']['restarted']:
            raise ObservationError('Prestream audit successor writer differs')
    if terminal['data']['restored_readme_sha256'] != baseline['readme_sha256'] or terminal['data']['current_writer'] != registration['phase_writer_ids']['restarted']:
        raise ObservationError('Terminal source restore/writer differs')
    edits = [f for f in frames if f['type'] == 'source_cas']
    restores = [f for f in frames if f['type'] == 'source_restored']
    restarts = [f for f in frames if f['type'] == 'gentle_restart']
    if len(edits) != 1 or len(restores) != 1 or len(restarts) != 1 or not edits[0]['seq'] < restarts[0]['seq'] < restores[0]['seq']:
        raise ObservationError('Source-stale/restart/restore chronological proof differs')
    if edits[0]['data']['original_sha256'] != baseline['readme_sha256'] or edits[0]['data']['edited_sha256'] == baseline['readme_sha256'] or restores[0]['data']['sha256'] != baseline['readme_sha256']:
        raise ObservationError('Source CAS restore proof differs')
    restart = restarts[0]['data']
    if restart['old'] == restart['new'] or restart['new'] != registration['phase_writer_ids']['restarted'] or restart['old'] != registration['phase_writer_ids']['initial'] or restart['signal'] != 'SIGTERM PIDfd':
        raise ObservationError('Actual gentle writer replacement proof differs')
    public = {f['phase']: f['data'] for f in frames if f['type'] == 'public_frame'}
    if not {'verified', 'stale', 'restart-stale'} <= public.keys():
        raise ObservationError('Required current/stale/restart public frames missing')
    verified, stale, restarted = (public[k] for k in ['verified', 'stale', 'restart-stale'])
    validate_check_definition(verified['config'], registration['check_definition'])
    validate_phase_chronology(frames)
    child = registration['child_run_id']
    for value, freshness in [(verified, 'current'), (stale, 'stale'), (restarted, 'stale')]:
        latest = value['latest'].get('plan-definition', {})
        if latest.get('run_id') != child or latest.get('outcome') != 'passed' or latest.get('freshness') != freshness or value['running']:
            raise ObservationError('Passing/current/stale/restart evidence differs')
        if value['config_hash'] != registration['accepted_config_hash'] or value['canonical_root'] != registration['root']:
            raise ObservationError('Observed primary root/config differs')
        validate_delivery_progress(value, verified=freshness == 'current')
    if verified['service_instance_id'] != stale['service_instance_id'] or restarted['service_instance_id'] == stale['service_instance_id']:
        raise ObservationError('Backend identity did not span actual verified/stale/restart phases')
    for field in ['config', 'claims', 'claim_notes', 'history']:
        if verified[field] != stale[field] or verified[field] != restarted[field]:
            raise ObservationError('Public durable field changed: ' + field)
    groups = {}
    for f in frames:
        if f['type'] == 'native_jsonl':
            groups.setdefault(f['phase'], []).append(f['data']['event'])
    phases = ['accepted-and-verify', 'source-stale', 'native-restart']
    if set(groups) != set(phases+['unavailable']):
        raise ObservationError('Unexpected or missing raw native phase')
    for phase in phases:
        events = groups.get(phase, [])
        if not any(e.get('type') == 'turn.completed' for e in events) or any(e.get('type') in {'turn.failed', 'error'} for e in events):
            raise ObservationError('Native phase incomplete: ' + phase)
        items = [e['item'] for e in events if e.get('type') == 'item.completed']
        calls = [i for i in items if i.get('type') == 'mcp_tool_call']
        allowed = {'checker_get_project', 'checker_get_progress', 'checker_get_run'}
        if phase == phases[0]:
            allowed |= {'checker_submit_plan', 'checker_set_claim', 'checker_get_plan_history', 'checker_run_checks', 'checker_get_log'}
        answer = '\n'.join(i.get('text', '') for i in items if i.get('type') == 'agent_message')
        if not re.search(r'\b5\b', answer):
            raise ObservationError('Actual normal arithmetic answer missing: ' + phase)
        if not calls or any(c.get('server') != 'progress_checker' or c.get('tool') not in allowed for c in calls):
            raise ObservationError('Unexpected actual native operation')
        image_frames = [f for f in frames if f['type'] == 'native_images' and f['phase'] == phase]
        finishes = [f for f in frames if f['type'] == 'phase_finish' and f['phase'] == phase]
        if len(image_frames) != 1 or len(finishes) != 1 or image_frames[0]['data'].get('required') is not True or len(image_frames[0]['data'].get('images', [])) != 1:
            raise ObservationError('Available native phase current process images missing')
        image = image_frames[0]['data']['images'][0]
        cache = Path(registration['skill_path']).parents[2]
        arguments = ['--root', registration['root'], '--state-dir', registration['state'], '']
        if image.get('launcher_argv') != ['/usr/bin/python3', str(cache/'bin/checker-plugin')]+arguments or image.get('adapter_argv') != [str(cache/'bin/progress-checker-mcp')]+arguments:
            raise ObservationError('Available native child command/root/state differs')
        if image.get('launcher_source_sha256') != registration['runtime_hashes']['checker-plugin'] or image.get('adapter_exe_sha256') != registration['runtime_hashes']['progress-checker-mcp'] or image.get('native_pid') != finishes[0]['data']['native_pid']:
            raise ObservationError('Available native current hashes/phase PID differ')
        expected_service = verified['service_instance_id'] if phase != 'native-restart' else restarted['service_instance_id']
        for c in calls:
            if successful(c).get('service_instance_id') != expected_service:
                raise ObservationError('Actual native phase backend identity differs')
        if not {'checker_get_project', 'checker_get_progress', 'checker_get_run'} <= {c['tool'] for c in calls}:
            raise ObservationError('Native evidence reads missing')
        validate_native_bindings(calls, registration, phase=phase)
        skill = registration['skill_path']
        allowed_commands = {f'/usr/bin/cat {skill}', f"/bin/bash -lc '/usr/bin/cat {skill}'", f"/bin/bash -lc '/usr/bin/cat -- {skill}'"}
        for item in items:
            if item.get('type') == 'command_execution' and (item.get('command') not in allowed_commands or item.get('exit_code') != 0):
                raise ObservationError('Native shell command differs from exact skill read')
            if item.get('type') == 'file_change':
                raise ObservationError('Native file mutation forbidden')
        if phase == phases[0]:
            submits = [c for c in calls if c['tool'] == 'checker_submit_plan']
            claims = [c for c in calls if c['tool'] == 'checker_set_claim']
            runs = [c for c in calls if c['tool'] == 'checker_run_checks']
            if len(submits) != 1 or submits[0]['arguments']['config'] != verified['config']:
                raise ObservationError('Accepted identical plan proof missing')
            if len(claims) != 1 or claims[0]['arguments'] != dict(claims[0]['arguments'], milestone_id='delivery-plan', claim=verified['claims']['delivery-plan'], note=verified['claim_notes'].get('delivery-plan', '')):
                raise ObservationError('Existing exact claim proof missing')
            if len(runs) != 1 or runs[0]['arguments']['check_ids'] != ['plan-definition'] or runs[0]['arguments']['idempotency_key'] != 'primary-'+registration['nonce']:
                raise ObservationError('Single exact approved native check proof missing')
            if successful(runs[0])['result']['run_id'] != registration['run_id'] or successful(runs[0])['result']['run_ids'] != [child]:
                raise ObservationError('Native/backend run identity differs')
    failures = [f for f in frames if f['type'] == 'unavailable_discovery' and f['phase'] == 'unavailable']
    failure_starts = [f for f in frames if f['type'] == 'phase_start' and f['phase'] == 'unavailable']
    if len(failures) != 1 or len(failure_starts) != 1:
        raise ObservationError('Actual ephemeral failed-startup discovery/ordinary phase missing')
    restarted_frame = next(f for f in frames if f['type'] == 'public_frame' and f['phase'] == 'restart-stale')
    if not restarted_frame['seq'] < failures[0]['seq'] < failure_starts[0]['seq'] < restores[0]['seq']:
        raise ObservationError('Unavailable native phase is not in the reviewed interval')
    unavailable_images = [f for f in frames if f['type'] == 'native_images' and f['phase'] == 'unavailable']
    if len(unavailable_images) != 1 or unavailable_images[0]['data'] != {'required': False, 'images': []}:
        raise ObservationError('Failed startup must not claim a connected checker adapter')
    unavailable_proof = validate_unavailable_phase(
        failures[0]['data'], groups.get('unavailable', []), failure_starts[0]['data']['argv'],
        selector='progress-checker@progress-local-8b5742430514', skill_path=registration['skill_path'])
    requests = {}
    fresh = []
    for f in frames:
        if f['type'] == 'core_mcp_request':
            event = f['data']['event']
            if event.get('method') != 'tools/call' or event.get('params', {}).get('name') not in {'checker_get_project', 'checker_get_progress', 'checker_get_run', 'checker_get_log', 'checker_get_plan_history'}:
                raise ObservationError('Unexpected producer-side backend operation')
            if event['id'] in requests:
                raise ObservationError('Duplicate autonomous backend request identity')
            requests[event['id']] = event['params']
        if f['type'] == 'core_mcp_response':
            event = f['data']['event']; request = requests.pop(event.get('id'), None)
            if not request:
                raise ObservationError('Unpaired autonomous backend response')
            if f['phase'] == 'current-poll' and f['collected_monotonic_ns'] >= connected_monotonic_ns:
                if 'error' in event or 'result' not in event:
                    raise ObservationError('Fresh autonomous backend RPC failed')
                result = event['result']
                structured = result.get('structuredContent') or {}
                if result.get('isError') is not False or 'error' in structured or 'result' not in structured:
                    raise ObservationError('Fresh autonomous backend tool failed')
                content = result.get('content', [])
                if not content or content[0].get('type') != 'text' or json.loads(content[0]['text']) != structured:
                    raise ObservationError('Core raw text/structured results disagree')
                expected_arguments = {'checker_get_project': {}, 'checker_get_progress': {},
                    'checker_get_run': {'run_id': registration['run_id']},
                    'checker_get_log': {'run_id': child, 'check_id': 'plan-definition', 'offset': 0, 'limit': 4096}}
                if request.get('name') not in expected_arguments or request.get('arguments') != expected_arguments[request['name']]:
                    raise ObservationError('Autonomous poll differs from fixed read-only arguments')
                if structured.get('service_instance_id') != restarted['service_instance_id']:
                    raise ObservationError('Fresh autonomous backend service identity differs')
                fresh.append((request, structured))
    if requests:
        raise ObservationError('Incomplete autonomous backend request/response pairs')
    if {x[0]['name'] for x in fresh} != {'checker_get_project', 'checker_get_progress', 'checker_get_run', 'checker_get_log'}:
        raise ObservationError('Fresh independently scheduled final backend reads missing')
    for request, structured in fresh:
        value = structured['result']
        if request['name'] == 'checker_get_run':
            if value.get('run_id') != registration['run_id']:
                raise ObservationError('Fresh backend batch response identity differs')
            validate_finished_run(value, child)
        if request['name'] == 'checker_get_log' and (value.get('run_id') != child or value.get('check_id') != 'plan-definition' or value.get('offset') != 0):
            raise ObservationError('Fresh backend log identity differs')
    return {'complete': False, 'semantic_validation_passed': True,
            'native_phase_count': len(phases)+1, 'raw_frame_count': len(frames),
            'unqualified': ['Hidden host producer identity still relies on separately reviewed trusted registration.',
                            'Final active-observer run reconciliation and complete semantic audit remain staged.'],
            'coverage': 'Fresh raw native planning/check/current-stale-restart/unavailable semantics validated; combined pilot gates still required.',
            '_live_validation_context': {'semantic_validation_passed': True, 'verified': verified,
                'fresh_projects': [structured['result'] for request, structured in fresh if request['name'] == 'checker_get_project'],
                'native_phases': phases+['unavailable'], 'unavailable_proof': unavailable_proof}}


def consume(socket_path, registration, expected, *, deadline=None, development_trusted_registration=False):
    pinned_registration(registration, expected)
    path = Path(socket_path)
    if str(path) != registration['endpoint']:
        raise ObservationError('Endpoint differs from registration')
    info = socket_snapshot(path)
    if info != registration['socket'] or info['uid'] != registration['uid'] or info['mode'] & 0o077:
        raise ObservationError('Observation endpoint differs from pinned private socket')
    limit = min(deadline or time.monotonic()+210, registration['observer_expires_monotonic_ns']/1e9)
    fd = None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(max(.001, min(5, limit-time.monotonic())))
            sock.connect(str(path))
            if socket_snapshot(path) != info:
                raise ObservationError('Socket changed during connect')
            fd, identity = peer_attestation(sock, registration, development_trusted_registration=development_trusted_registration)
            connected = time.monotonic_ns()
            sock.sendall(canonical({'schema_version': 1, 'nonce': registration['nonce'], 'request': 'read-events'}) + b'\n')
            frames, first_count, digest = read_snapshots(sock, registration, deadline=limit)
            assert_peer_live(fd)
            result = semantic_receipt(frames, registration, connected_monotonic_ns=connected)
            if socket_snapshot(path) != info:
                raise ObservationError('Socket changed during one-use observation')
            result.update(identity=identity, first_snapshot_frames=first_count, raw_buffer_sha256=digest)
            return result
    finally:
        if fd is not None:
            os.close(fd)


def owned_json(path, *, expected_sha256=None):
    """Read only an excluded-worktree public registration, anchored and bounded."""
    path = Path(path)
    root = Path(__file__).resolve().parent.parent
    if not path.is_absolute() or '..' in path.parts or not path.is_relative_to(root / '.local'):
        raise ObservationError('Registration must be a public excluded-worktree path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    file_fd = None
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_mode & 0o077 or before.st_size > 256*1024:
            raise ObservationError('Registration must be an owned private bounded regular file')
        raw = bytearray()
        while True:
            chunk = os.read(file_fd, min(65536, 256*1024+1-len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > 256*1024:
                raise ObservationError('Registration exceeds256KiB')
        after = os.fstat(file_fd)
        current = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        stamp = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns, x.st_mode, x.st_uid)
        if stamp(before) != stamp(after) or stamp(after) != stamp(current):
            raise ObservationError('Registration changed while reading')
        digest = hashlib.sha256(raw).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            raise ObservationError('Approved immutable attestation SHA differs')
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ObservationError('Registration JSON must be an object')
        return value, digest
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(fd)


def consume_attested(attestation_path, expected_attestation_sha256, readiness_path,
                     *, deadline=None, expected_observer_run_id=None):
    """Approved public immutable digest; explicitly trusted hidden host identity.

    The observed producer is independently activated by its external owner. This
    method cannot activate it, send signals, execute host commands, read credentials
    or invoke backend RPCs. The reader's only bytes are the fixed read-events request.
    """
    if not isinstance(expected_attestation_sha256, str) or not re.fullmatch('[0-9a-f]{64}', expected_attestation_sha256):
        raise ObservationError('Explicit approved immutable registration SHA required')
    attestation, digest = owned_json(attestation_path, expected_sha256=expected_attestation_sha256)
    readiness, _ = owned_json(readiness_path)
    static = {'schema_version', 'nonce', 'root', 'state', 'producer', 'uid', 'producer_source_sha256',
              'native_cli_sha256', 'runtime_hashes', 'archive_sha256', 'module_hashes',
              'boot_id', 'socket', 'endpoint', 'skill_path', 'check_definition',
              'producer_argv', 'source_file_identity', 'python_exe_sha256'}
    if not static <= attestation.keys() or not static <= readiness.keys():
        raise ObservationError('Staged producer attestation contract incomplete')
    if attestation.get('trust_policy') != 'explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime':
        raise ObservationError('Explicit reviewed host identity attestation policy required')
    prepared = attestation.get('prepared_monotonic_ns')
    activation_deadline = attestation.get('activation_expires_monotonic_ns')
    activated = readiness.get('activated_monotonic_ns')
    if not all(isinstance(v, int) for v in [prepared, activation_deadline, activated]) or not prepared <= activated <= activation_deadline or activation_deadline-prepared > 1800_000_000_000:
        raise ObservationError('Independent activation outside reviewed preregistration interval')
    if readiness.get('awaiting_root_activation') is not False or activated != readiness.get('started_monotonic_ns'):
        raise ObservationError('Workflow not independently activated')
    producer_path = Path(__file__).resolve().parent / 'plugin-primary-pilot-producer.py'
    info = producer_path.stat()
    if attestation['source_file_identity'] != {'device': info.st_dev, 'inode': info.st_ino} or hashlib.sha256(producer_path.read_bytes()).hexdigest() != attestation['producer_source_sha256']:
        raise ObservationError('Visible source identity/hash differs from approved host registration')
    if 'accepted_config_hash' in attestation or 'config_hash' in attestation:
        raise ObservationError('Final config hash in pre-registration creates a binding cycle')
    for field in static:
        if readiness[field] != attestation[field]:
            raise ObservationError('Immutable/mutable registration crosspin differs: ' + field)
    if readiness.get('attestation_sha256') != digest:
        raise ObservationError('Ready stream does not bind approved immutable attestation')
    result = consume(readiness['endpoint'], readiness, readiness, deadline=deadline,
                     development_trusted_registration=True)
    # Trusted immutable input strengthens identity provenance without claiming that
    # the sandbox independently sees the hidden host PID/executable.
    result['identity']['policy'] = 'explicit approved immutable host identity attestation plus kernel peer lifetime'
    result['identity']['trusted_attestation_sha256'] = digest
    result['identity']['hidden_host_identity_independently_verified'] = False
    result['expected_observer_run_id'] = expected_observer_run_id
    result['complete'] = False
    result['unqualified'].append('Fresh source-free recipient and exact active-observer reconciliation not yet integrated.')
    return result


def reconcile_current_project(project, verified, registration, expected_definition,
                              *, expected_observer_run_id=None):
    """Allow only the worker's exact sole observational child as a known difference.

    Called with a fresh raw fixed-poll GetProject result, not a saved summary.
    Caller supplies the reviewed configured observer definition; no argv guessing
    or environment injection occurs. Lack of that definition cannot qualify.
    """
    if expected_definition.get('id') != 'standard-codex-pilot' or not isinstance(expected_definition.get('argv'), list):
        raise ObservationError('Exact approved observational check definition required')
    definitions = [c for c in project['config']['checks'] if c['id'] == 'standard-codex-pilot']
    if definitions != [expected_definition] or project['config']['execution']['max_parallel'] != 1:
        raise ObservationError('Observer approved definition/sole-worker configuration differs')
    if project['canonical_root'] != registration['root'] or project['config'] != verified['config'] or project['claims'] != verified['claims'] or project['claim_notes'] != verified['claim_notes']:
        raise ObservationError('Fresh current root/config/claims/notes differs')
    status = project['status']
    if status['source']['config_hash'] != registration['accepted_config_hash']:
        raise ObservationError('Current accepted configuration binding differs')
    running = project['running']
    if len(running) != 1 or running[0].get('check_id') != 'standard-codex-pilot' or running[0].get('execution_state') != 'running':
        raise ObservationError('Only the actual sole active observer child is allowed')
    child = running[0]['run_id']
    if expected_observer_run_id is not None and child != expected_observer_run_id:
        raise ObservationError('Explicit observer child identity differs')
    evidence = status['latest'].get('standard-codex-pilot')
    if evidence != running[0] or project['run_metadata'].get('standard-codex-pilot', {}).get('run_id') != child:
        raise ObservationError('Current observer run/latest/metadata identity differs')
    if evidence['source']['config_hash'] != registration['accepted_config_hash'] or not evidence.get('command_hash'):
        raise ObservationError('Active observer command/config proof missing')
    others = {k: v for k, v in status['latest'].items() if k != 'standard-codex-pilot'}
    baseline = {k: v for k, v in verified['latest'].items() if k != 'standard-codex-pilot'}
    if others != baseline:
        raise ObservationError('Unexpected non-observer latest evidence changed')
    if evidence['source']['fingerprint'] != baseline['plan-definition']['source']['fingerprint']:
        raise ObservationError('Observer did not start against restored verified source')
    return {'observer_child_run_id': child, 'derivation': 'exact sole approved observer evidence/latest/run_metadata',
            'explicit_expected_id_checked': expected_observer_run_id is not None,
            'complete': False}


def unavailable_overrides(argv, selector):
    """Exactly reviewed ephemeral config-source shadowing, never persisted disable."""
    values = {}
    for index, token in enumerate(argv):
        if token != '-c':
            continue
        if index+1 >= len(argv) or '=' not in argv[index+1]:
            raise ObservationError('Malformed unavailable config override')
        key, value = argv[index+1].split('=', 1)
        if key in values:
            raise ObservationError('Duplicate ephemeral unavailable override')
        values[key] = value
    required = {
        'plugins.'+selector+'.enabled': 'true',
        'mcp_servers.progress_checker.command': '"/usr/bin/false"',
        'mcp_servers.progress_checker.args': '[]',
        'mcp_servers.progress_checker.enabled': 'true',
    }
    if any(values.get(key) != value for key, value in required.items()):
        raise ObservationError('Exact false-start enabled-checker shadowing not present')
    return required


def validate_unavailable_phase(discovery, events, model_argv, *, selector, skill_path):
    """Actual failed startup + enabled skill + normal turn, not disable-only proof.

    Discovery contains original native RPC results under initialize/skills/thread/
    server_status keys. Producer's source-backed collector supplies these frames;
    this validator neither changes config nor calls an external native server.
    """
    unavailable_overrides(discovery['argv'], selector)
    unavailable_overrides(model_argv, selector)
    skills = [s for group in discovery['skills'].get('data', []) for s in group.get('skills', [])
              if s.get('pluginId') == selector and s.get('path') == skill_path and s.get('enabled') is True]
    if len(skills) != 1:
        raise ObservationError('Installed skill must remain enabled during failed checker startup')
    servers = [s for s in discovery['server_status'].get('data', []) if s.get('name') == 'progress_checker']
    if len(servers) != 1 or servers[0].get('runtimeStatus') != 'failed' or servers[0].get('tools') not in ({}, []):
        raise ObservationError('Actual enabled checker failed startup/empty tools not observed')
    if not discovery['thread'].get('thread', {}).get('id'):
        raise ObservationError('Failed checker discovery did not use an actual native thread')
    if not any(e.get('type') == 'turn.completed' for e in events) or any(e.get('type') in {'turn.failed', 'error'} for e in events):
        raise ObservationError('Ordinary native unavailable-checker turn did not complete')
    items = [e['item'] for e in events if e.get('type') == 'item.completed']
    if any(i.get('type') in {'mcp_tool_call', 'file_change'} for i in items):
        raise ObservationError('Unavailable phase unexpectedly called a tool or changed files')
    commands = {f'/usr/bin/cat {skill_path}', f"/bin/bash -lc '/usr/bin/cat {skill_path}'", f"/bin/bash -lc '/usr/bin/cat -- {skill_path}'"}
    if any(i.get('type') == 'command_execution' and (i.get('command') not in commands or i.get('exit_code') != 0) for i in items):
        raise ObservationError('Unavailable phase ran an unrequested shell command')
    answer = '\n'.join(i.get('text', '') for i in items if i.get('type') == 'agent_message')
    if not re.search(r'\b5\b', answer):
        raise ObservationError('Unavailable checker prevented ordinary arithmetic answer')
    return {'failed_startup_observed': True, 'installed_skill_enabled': True,
            'ordinary_turn_completed': True, 'normal_answer': answer, 'complete': False,
            'coverage': 'Actual ephemeral failed startup and ordinary prompt only; no persisted configuration mutation.'}
