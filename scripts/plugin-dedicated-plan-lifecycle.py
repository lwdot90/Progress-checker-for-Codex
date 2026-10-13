#!/usr/bin/python3
"""OFF-default pure dedicated lifecycle semantics; never establishes live proof.

All process/PIDfd/runtime facts are supplied captured development inputs. No
process, filesystem, socket, service, approval or check operation exists here.
"""
import hashlib
from pathlib import PurePosixPath
import types

ROOT = '/home/luis/progress-checker/.local/plugin-acceptance/plan-invalidation-human-fixture-v2/project'
STATE = '/home/luis/progress-checker/.local/plugin-acceptance/plan-invalidation-human-fixture-v2/state'
ARCHIVE = '404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
CAPTURE_SHA = 'a19413a48ca9f6fcd6b91344d21e66f0f6679aacad01cfc5d7359dcffc5d122c'
HASHES = {'checker-plugin':'82fb1e7cef3172e465f33fec54d4d7be4f799c66193b5dd8f9b989689009fcaa',
          'progress-checker':'9ece1092eba4232a3c66c745d90c7d62df5aaa25a3587a9363c6fe142c830d99',
          'progress-checker-mcp':'6be43b4c12d46555d6443d2619bd15e1dd1754f297781f0fa5c0059bf5c79e7a'}
IDENTITY_KEYS = {'pid','starttime','uid','state','ppid','argv'}
PROCESS_KEYS = {'session','role','operation','pid_identity','executable_sha256','argv',
                'root','state','endpoint_identity','lease_snapshot','service_record','returncode'}
DRAIN_KEYS = {'pidfd_poll_revents','current_identity','fixture_processes'}
SOCKET_KEYS = {'dev','ino','uid','mode','mtime_ns','ctime_ns'}


class LifecycleError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise LifecycleError(message)


def sha(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def record(value):
    require(type(value) is dict and set(value) == {'pid','starttime'}
            and type(value['pid']) is int and value['pid'] > 0
            and type(value['starttime']) is str and value['starttime'].isascii()
            and value['starttime'].isdecimal(), 'Typed PID/starttime record required')
    return value


def identity(value):
    require(type(value) is dict and set(value) == IDENTITY_KEYS, 'Exact process identity required')
    record({'pid':value['pid'],'starttime':value['starttime']})
    require(type(value['uid']) is int and value['uid'] == 1000
            and type(value['ppid']) is int and value['ppid'] >= 0
            and type(value['state']) is str and len(value['state']) == 1
            and value['state'] in 'RSDZTtXxKWPI'
            and type(value['argv']) is list and (value['argv'] or value['state'] in {'Z','X','x'})
            and all(type(arg) is str and '\0' not in arg for arg in value['argv']),
            'Typed process UID/parent/state/argv required')
    return value


def socket_identity(value):
    if value is None:
        return None
    require(type(value) is dict and set(value) == SOCKET_KEYS
            and all(type(item) is int for item in value.values())
            and value['dev'] >= 0 and value['ino'] > 0 and value['uid'] == 1000
            and value['mode'] == 0o600 and value['mtime_ns'] >= 0 and value['ctime_ns'] >= 0,
            'Typed owned socket facts required')
    return value


def registration(meta):
    require(type(meta) is dict and meta.get('root') == ROOT and meta.get('state') == STATE
            and meta.get('archive_sha256') == ARCHIVE, 'Literal dedicated registration required')
    producer = identity(meta.get('producer'))
    require(producer['state'] not in {'Z','X','x'} and sha(meta.get('python_exe_sha256')),
            'Live producer identity and executable hash required')
    endpoint = meta.get('endpoint')
    require(type(endpoint) is str and endpoint.startswith('/')
            and str(PurePosixPath(endpoint)) == endpoint and PurePosixPath(endpoint).name == 'observe.sock'
            and '..' not in PurePosixPath(endpoint).parts, 'Canonical fixed observation endpoint required')
    prefix = str(PurePosixPath(endpoint).parent)+'/extracted/progress-checker-0.2.1-dev-linux-x86_64/plugin/bin'
    runtime = meta.get('runtime_files')
    expected = {prefix+'/'+name: value for name,value in HASHES.items()}
    require(type(runtime) is dict and runtime == expected, 'Literal extracted archive runtime hashes required')
    return producer, {name:prefix+'/'+name for name in HASHES}


def evaluate(lines, meta, capture_source):
    """Recompute all supplied lifecycle records; no serialized PASS flag consumed."""
    producer, paths = registration(meta)
    require(type(capture_source) is bytes and len(capture_source) <= 8*1024*1024
            and hashlib.sha256(capture_source).hexdigest() == CAPTURE_SHA,
            'Exact pure capture source buffer required')
    capture = types.ModuleType('reviewed_dedicated_capture')
    exec(compile(capture_source,'reviewed_dedicated_capture','exec'),capture.__dict__)
    classified = capture.classify_serialized(lines,meta['job_id'],meta['nonce'])
    frames = [item['frame'] for item in classified['classified_frames']]
    process = [frame for frame in frames if frame['kind'] == 'process']
    require(process, 'Actual supplied process records required')
    require(all(type(f['payload'].get('session')) is str
                and f['payload']['session'] in {'initial','restart'} for f in process),
            'Fixed process session required')
    sessions, backends, drains = {}, {}, {}
    for session in ('initial','restart'):
        selected = [f for f in process if f['payload']['session'] == session]
        if not selected:
            require(session == 'restart' and classified['body_phase'] != 'restart-done',
                    'Full workflow lacks actual restart processes')
            continue
        starts, drained, exits, eofs, terms, pids = {}, {}, [], [], [], {}
        socket_before = None
        for frame in selected:
            payload = frame['payload']
            role, operation = payload.get('role'), payload.get('operation')
            require(type(role) is str and role in {'client','adapter','backend','watchdog','health-probe'}
                    and type(operation) is str and operation in {'start','EOF','TERM','exit','drain'},
                    'Fixed owned role/operation required')
            require(set(payload) == PROCESS_KEYS | (DRAIN_KEYS if operation == 'drain' else set()),
                    'Exact lifecycle payload schema required')
            require(payload['root'] == ROOT and payload['state'] == STATE, 'Literal process scope differs')
            info = identity(payload['pid_identity'])
            require(payload['argv'] == info['argv'] and sha(payload['executable_sha256']),
                    'Process executable/argv identity differs')
            key = (info['pid'],info['starttime'])
            require(info['pid'] not in pids or pids[info['pid']] == info['starttime'],
                    'PID reuse within owned session forbidden')
            pids[info['pid']] = info['starttime']
            endpoint = socket_identity(payload['endpoint_identity'])
            if endpoint is not None:
                require(socket_before is None or socket_before == endpoint, 'Owned socket identity changed')
                socket_before = endpoint
            leases = payload['lease_snapshot']
            require(type(leases) is dict and all(type(name) is str and name and '/' not in name
                    for name in leases), 'Typed public lease snapshot required')
            for value in leases.values(): record(value)
            if payload['service_record'] is not None: record(payload['service_record'])
            if operation == 'start':
                require(key not in starts and info['state'] not in {'Z','X','x'}
                        and payload['returncode'] is None, 'Unique live owned startup required')
                starts[key] = frame
            else:
                require(key in starts and frame['sequence'] > starts[key]['sequence'],
                        'Owned operation without prior actual startup')
                baseline = starts[key]['payload']
                require(info == baseline['pid_identity'] and role == baseline['role']
                        and payload['executable_sha256'] == baseline['executable_sha256'],
                        'Owned captured identity changed')
            if operation == 'drain':
                mask = payload['pidfd_poll_revents']
                require(key not in drained and type(mask) is int and mask & 1 and not mask & ~17,
                        'Actual PIDfd death readiness required (1 or reaped17)')
                current = payload['current_identity']
                if current is not None:
                    current = identity(current)
                    require(current['pid'] == info['pid'] and
                            (current['starttime'] != info['starttime'] or current['state'] in {'Z','X','x'}),
                            'Original owned process remains live')
                    if current['starttime'] != info['starttime'] and current['state'] not in {'Z','X','x'}:
                        argv = current['argv']
                        bound = '--root' in argv and '--state-dir' in argv
                        if bound:
                            root_index, state_index = argv.index('--root'), argv.index('--state-dir')
                            bound = (root_index+1 < len(argv) and state_index+1 < len(argv)
                                     and argv[root_index+1] == ROOT and argv[state_index+1] == STATE)
                        require(not bound, 'Reused PID has a foreign live fixture process')
                require(payload['fixture_processes'] == [] and payload['service_record'] is None
                        and leases == {} and endpoint is None, 'Actual public process/runtime drain facts required')
                require(payload['returncode'] is None or (role == 'client'
                        and type(payload['returncode']) is int and payload['returncode'] == 0),
                        'Drain cannot manufacture successful child exits')
                drained[key] = frame
            elif operation == 'exit':
                require(role == 'client' and type(payload['returncode']) is int
                        and payload['returncode'] == 0, 'Original owned launcher zero wait status required')
                exits.append(frame)
            elif operation in {'EOF','TERM'}:
                require(role == 'client' and payload['returncode'] is None, 'Only owned launcher close/signaling allowed')
                (eofs if operation == 'EOF' else terms).append(frame)
        primary = {role:[f for f in starts.values() if f['payload']['role'] == role]
                   for role in ('client','adapter','backend','watchdog')}
        require(all(len(values) == 1 for values in primary.values()), 'All four actual owned startup roles required')
        client = primary['client'][0]['payload']['pid_identity']
        backend = primary['backend'][0]['payload']['pid_identity']
        require(producer['pid'] not in pids
                and all(f['sequence'] > primary['client'][0]['sequence'] for f in starts.values()
                        if f['payload']['role'] != 'client')
                and primary['backend'][0]['sequence'] < primary['watchdog'][0]['sequence'],
                'Owned parent startup chronology differs')
        args = ['--root',ROOT,'--state-dir',STATE]
        expected_argv = {'client':['/usr/bin/python3',paths['checker-plugin']]+args,
                         'adapter':[paths['progress-checker-mcp']]+args,
                         'backend':[paths['progress-checker']]+args+['serve'],
                         'watchdog':['/usr/bin/python3',paths['checker-plugin']]+args+
                                     ['--watch-service',str(backend['pid']),backend['starttime']],
                         'health-probe':[paths['progress-checker']]+args+['status']}
        client_record = {'pid':client['pid'],'starttime':client['starttime']}
        backend_record = {'pid':backend['pid'],'starttime':backend['starttime']}
        for frame in selected:
            payload = frame['payload']; info = payload['pid_identity']; role = payload['role']
            require(info['argv'] == expected_argv[role]
                    and info['ppid'] == (producer['pid'] if role == 'client' else client['pid']),
                    'Actual original ancestry/command differs')
            expected_hash = meta['python_exe_sha256'] if role in {'client','watchdog'} else HASHES[
                'progress-checker-mcp' if role == 'adapter' else 'progress-checker']
            require(payload['executable_sha256'] == expected_hash, 'Original executable bytes differ')
            require(all(value == client_record for value in payload['lease_snapshot'].values())
                    and (payload['service_record'] is None or payload['service_record'] == backend_record),
                    'Foreign/reused launcher lease or backend record')
        require(primary['backend'][0]['payload']['service_record'] == backend_record,
                'Backend startup record binding required')
        require(socket_before is not None, 'Actual owned service socket startup required')
        require(len(eofs) == len(exits) == 1 and len(terms) <= 1
                and eofs[0]['sequence'] < exits[0]['sequence'], 'Actual original EOF/wait chronology required')
        if terms:
            require(eofs[0]['sequence'] < terms[0]['sequence'] < exits[0]['sequence'], 'Owned close TERM chronology differs')
        require(set(drained) == set(starts) and all(f['sequence'] > exits[0]['sequence'] for f in drained.values())
                and all(f['sequence'] < eofs[0]['sequence'] for f in starts.values()),
                'Every owned role must actually drain after original wait')
        sessions[session] = {'captured_semantics_passed':True,'owned_process_count':len(starts)}
        backends[session] = (backend['pid'],backend['starttime'])
        drains[session] = max(f['sequence'] for f in drained.values())
    if 'restart' in backends:
        require(backends['restart'] != backends['initial'], 'Restart must use different actual backend identity')
        restart_first = min(f['sequence'] for f in process if f['payload']['session'] == 'restart')
        require(drains['initial'] < restart_first, 'Restart before all owned initial roles/runtime drained')
    return {'status':'dedicated-captured-lifecycle-only','complete':False,'qualification_possible':False,
            'captured_lifecycle_semantics_passed':True,'body_phase':classified['body_phase'],
            'sessions':sessions,'full_transcript_frame_count':len(frames),'approval_created':False,
            'unqualified':['Supplied PIDfd/process/runtime facts establish no independent live host proof.',
                           'Genuine human-granted trial and independent transport registration remain required.',
                           'Separate installed plan-interruption recovery coverage remains required.']}


if __name__ == '__main__':
    print('OFF: pure dedicated lifecycle source staging only; no host/backend operation.')
