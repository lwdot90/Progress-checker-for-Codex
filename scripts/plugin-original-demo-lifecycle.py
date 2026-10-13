#!/usr/bin/env python3
"""OFF-default PURE captured lifecycle semantics; no I/O/actions/live attestation.

Inputs must ultimately come from the separately strict raw-stream decoder and
reviewed live collector. Supplied poll/process facts do not prove host provenance.
No producer passed/drained/cleanup_complete flags can qualify this evaluator.
"""
from pathlib import PurePosixPath

ROOT = '/home/luis/progress-checker/.local/checker-demo/session-c5c6vsyz/project'
STATE = '/home/luis/progress-checker/.local/checker-demo/session-c5c6vsyz/state'
ARCHIVE = '404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
HASHES = {'checker-plugin': '82fb1e7cef3172e465f33fec54d4d7be4f799c66193b5dd8f9b989689009fcaa',
          'progress-checker': '9ece1092eba4232a3c66c745d90c7d62df5aaa25a3587a9363c6fe142c830d99',
          'progress-checker-mcp': '6be43b4c12d46555d6443d2619bd15e1dd1754f297781f0fa5c0059bf5c79e7a'}
PENDING = ['Strict serialized frames, live fixed-host registration/source provenance and actual pidfd ownership are not qualified by supplied facts.',
           'Independent activation, one-use peer lifetime and fresh observation remain required.',
           'Full original body/CAS/API predicates and actual human-granted execution remain required.']


class LifecycleError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise LifecycleError(message)


def process_identity(value):
    require(type(value) is dict and set(value) == {'pid','starttime','uid','state','ppid','argv'}, 'Complete captured process schema required')
    require(type(value['pid']) is int and value['pid'] > 0
            and type(value['ppid']) is int and value['ppid'] >= 0
            and type(value['uid']) is int and value['uid'] >= 0
            and type(value['starttime']) is str and value['starttime'].isascii() and value['starttime'].isdigit()
            and type(value['state']) is str and value['state'] in {'R','S','D','Z','T','t','X','x','K','W','P','I'}
            and type(value['argv']) is list and all(type(arg) is str for arg in value['argv']), 'Typed captured process identity required')
    return value


def runtime_identity(value):
    require(type(value) is dict and set(value) == {'pid','starttime'}
            and type(value['pid']) is int and value['pid'] > 0
            and type(value['starttime']) is str and value['starttime'].isascii() and value['starttime'].isdigit(), 'Typed public runtime record/lease required')
    return value


def evaluate_lifecycle(frames, registration):
    """Recompute supplied identity/drain facts; full qualification always false."""
    require(registration.get('root') == ROOT and registration.get('state') == STATE and registration.get('archive_sha256') == ARCHIVE, 'Fixed original-demo registration required')
    producer = process_identity(registration['producer'])
    require(producer['uid'] == 1000 and producer['state'] != 'Z', 'Exact normal host producer identity required')
    runtime = registration['runtime_files']
    bins = {name: [path for path in runtime if PurePosixPath(path).name == name] for name in HASHES}
    require(all(len(paths) == 1 for paths in bins.values()) and len(runtime) == 3, 'Exact three runtime files required')
    paths = {name: values[0] for name, values in bins.items()}
    require(all(runtime[paths[name]] == value for name, value in HASHES.items()), 'Runtime hashes differ')
    base = str(PurePosixPath(registration['endpoint']).parent)
    require(str(PurePosixPath(paths['checker-plugin']).parent) == base+'/extracted/progress-checker-0.2.1-dev-linux-x86_64/plugin/bin', 'Fixed extracted runtime location differs')
    require(all(PurePosixPath(p).parent == PurePosixPath(paths['checker-plugin']).parent for p in paths.values()), 'Mixed runtime directory')
    require(type(frames) is list and 0 < len(frames) <= 4096, 'Bounded captured frames required')
    process = []
    previous_time = -1
    for index, frame in enumerate(frames, 1):
        require(frame['sequence'] == index and type(frame['sequence']) is int and type(frame['monotonic_ns']) is int and frame['monotonic_ns'] >= previous_time, 'Captured frame ordering differs')
        require(frame['schema_version'] == 1 and type(frame['schema_version']) is int and frame['job_id'] == registration['job_id'] and frame['nonce'] == registration['nonce'], 'Captured job pins differ')
        previous_time = frame['monotonic_ns']
        if frame['kind'] == 'process':
            require(type(frame['payload']) is dict, 'Process payload must be object')
            process.append(frame)
    results = {}
    backends = {}
    last_drains = {}
    for session in ('unapproved', 'approved', 'restart'):
        selected = [f for f in process if f['payload'].get('session') == session]
        if not selected:
            results[session] = {'semantic_passed': False, 'missing': 'No captured application session'}
            continue
        root, state = (base+'/body/unapproved/project', base+'/body/unapproved/state') if session == 'unapproved' else (ROOT, STATE)
        starts = {}; drains = {}; exits = []; eofs = []; terms = []
        for frame in selected:
            payload = frame['payload']; role, operation = payload['role'], payload['operation']
            require(role in {'client', 'adapter', 'backend', 'watchdog', 'health-probe'} and operation in {'start', 'EOF', 'TERM', 'exit', 'drain'}, 'Unexpected process operation/role')
            require(payload['root'] == root and payload['state'] == state, 'Session literal root/state differs')
            info = process_identity(payload['pid_identity'])
            require(type(info['pid']) is int and info['pid'] > 0 and type(info['starttime']) is str and info['starttime'].isdigit() and info['uid'] == 1000 and type(info['uid']) is int and payload['argv'] == info['argv'], 'Process identity differs')
            key = (info['pid'], info['starttime'])
            if operation == 'start':
                require(key not in starts and info['state'] != 'Z', 'Duplicate or already-dead startup identity')
                starts[key] = frame
            else:
                require(key in starts and frame['sequence'] > starts[key]['sequence'], 'Operation without its actual startup')
                baseline = starts[key]['payload']
                require(payload['pid_identity'] == baseline['pid_identity'] and payload['executable_sha256'] == baseline['executable_sha256'] and role == baseline['role'], 'Captured process identity changed')
            if operation == 'drain':
                require(key not in drains, 'Duplicate drain fact')
                mask = payload.get('pidfd_poll_revents')
                # Reaping adds POLLHUP to the readable pidfd; both 1 and 17
                # are valid dead-child observations. All other bits fail closed.
                require(type(mask) is int and mask & 1 and not mask & ~17, 'Actual bound-pidfd readable death fact required')
                current = payload.get('current_identity', 'missing')
                if current is not None:
                    current = process_identity(current)
                    require(current['pid'] == info['pid'] and (current['starttime'] != info['starttime'] or current['state'] == 'Z'), 'Current original process remains live')
                require(payload.get('fixture_processes') == [] and payload['service_record'] is None and payload['lease_snapshot'] == {} and payload['endpoint_identity'] is None, 'Actual process/record/lease/socket drain facts required')
                drains[key] = frame
            elif operation == 'exit':
                require(role == 'client' and type(payload.get('returncode')) is int and payload['returncode'] == 0, 'Original launcher must exit zero')
                exits.append(frame)
            elif operation == 'EOF':
                require(role == 'client', 'Only owned client EOF allowed'); eofs.append(frame)
            elif operation == 'TERM':
                require(role == 'client', 'No backend/group forced signals'); terms.append(frame)
        primary = {role: [f for f in starts.values() if f['payload']['role'] == role] for role in ('client','adapter','backend','watchdog')}
        require(all(len(values) == 1 for values in primary.values()), 'Exactly one original startup per required role')
        client = primary['client'][0]['payload']['pid_identity']; backend = primary['backend'][0]['payload']['pid_identity']
        args = ['--root', root, '--state-dir', state]
        for frame in selected:
            payload = frame['payload']
            require(type(payload['lease_snapshot']) is dict and all(type(name) is str and runtime_identity(value) == {'pid':client['pid'],'starttime':client['starttime']} for name,value in payload['lease_snapshot'].items()), 'Foreign captured launcher lease')
            require(payload['service_record'] is None or runtime_identity(payload['service_record']) == {'pid':backend['pid'],'starttime':backend['starttime']}, 'Foreign captured backend record')
            endpoint = payload['endpoint_identity']
            require(endpoint is None or (type(endpoint) is dict and endpoint.get('uid') == 1000 and endpoint.get('mode') == 0o600), 'Captured endpoint owner/mode differs')
        for startup in starts.values():
            payload = startup['payload']; info = payload['pid_identity']
            if payload['role'] == 'health-probe':
                require(info['argv'] == [paths['progress-checker']]+args+['status'] and info['ppid'] == client['pid'] and payload['executable_sha256'] == HASHES['progress-checker'], 'Health-probe identity differs')
        for role, values in primary.items():
            payload = values[0]['payload']; info = payload['pid_identity']
            expected = {'client': ['/usr/bin/python3', paths['checker-plugin']]+args,
                        'adapter': [paths['progress-checker-mcp']]+args,
                        'backend': [paths['progress-checker']]+args+['serve'],
                        'watchdog': ['/usr/bin/python3', paths['checker-plugin']]+args+['--watch-service', str(backend['pid']), backend['starttime']]}[role]
            require(info['argv'] == expected, 'Captured role executable argv differs')
            require(info['ppid'] == (registration['producer']['pid'] if role == 'client' else client['pid']), 'Actual initial child ancestry differs')
            expected_hash = registration['python_exe_sha256'] if role in {'client','watchdog'} else HASHES['progress-checker-mcp' if role == 'adapter' else 'progress-checker']
            require(payload['executable_sha256'] == expected_hash, 'Captured executable hash differs')
            if role == 'backend':
                require(payload['service_record'] == {'pid':backend['pid'],'starttime':backend['starttime']}, 'Backend startup service-record binding differs')
        require(len(exits) == len(eofs) == 1 and eofs[0]['sequence'] < exits[0]['sequence'] and len(terms) <= 1, 'Original EOF/exit chronology differs')
        if terms:
            require(eofs[0]['sequence'] < terms[0]['sequence'] < exits[0]['sequence'], 'Owned TERM chronology differs')
        require(set(drains) == set(starts) and all(f['sequence'] > exits[0]['sequence'] for f in drains.values()), 'Every captured child must drain after original zero exit')
        require(all(f['sequence'] < eofs[0]['sequence'] for f in starts.values()), 'Startup after close began')
        backends[session] = (backend['pid'], backend['starttime'])
        last_drains[session] = max(f['sequence'] for f in drains.values())
        results[session] = {'semantic_passed': True, 'captured_process_count': len(starts), 'drain_facts_recomputed': True}
    if all(session in backends for session in ('approved','restart')):
        require(backends['approved'] != backends['restart'], 'Restart must use a different actual backend identity')
        restart_first = min(f['sequence'] for f in process if f['payload'].get('session') == 'restart' and f['payload']['operation'] == 'start')
        require(last_drains['approved'] < restart_first, 'Restart before approved application fully drained')
    require(all(f['payload'].get('session') in {'unapproved','approved','restart'} for f in process), 'Unknown captured session')
    return {'status': 'captured-semantic-only', 'complete': False, 'qualification_possible': False,
            'captured_lifecycle_semantics_passed': all(v['semantic_passed'] for v in results.values()),
            'sessions': results, 'remaining_unqualified': list(PENDING)}
