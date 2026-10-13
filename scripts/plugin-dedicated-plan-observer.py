#!/usr/bin/python3
"""OFF-default read-only dedicated three-packet observer source stage.

Only an explicitly reviewed immutable registration can select a fixed stream.
No activation, subprocess, fixture mutation, grant, Store or backend interface.
Hidden-host source execution remains a reviewed trust assumption. Even a fully
validated handoff is not full-plan qualification; fresh public integration and
exact human approved checker evidence remain required.
"""
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import select
import socket
import stat
import struct
import time
import types

ROOT = Path('/home/luis/progress-checker')
FIXTURE = ROOT/'.local/plugin-acceptance/plan-invalidation-human-fixture-v2/project'
STATE = FIXTURE.parent/'state'
RESERVATION = FIXTURE.parent/'.dedicated-plan-capture-reservation'
ARCHIVE = ROOT/'.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz'
ARCHIVE_SHA = '404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
PINS = {
    'plugin-acceptance.py':'ad1fc66caa841211d6f485832be4a602ac5c1a00743b5c42aefdbdd6f6ff1d99',
    'plugin-dedicated-plan-capture.py':'a19413a48ca9f6fcd6b91344d21e66f0f6679aacad01cfc5d7359dcffc5d122c',
    'plugin-dedicated-plan-public.py':'977ce1b54f9b73386d0db90e59b7ae0a3b9189ff7ee95967ca884d32c98531b2',
    'plugin-dedicated-plan-lifecycle.py':'1a52ba75e8b230dff8bf548b302084c759899de90a0a2bc8fc599ec90028d30e',
    'plugin-dedicated-plan-adapter.py':'d8b02f2b3cb6ac45d0daf0d9753479ed7001a9dea1433f8b3a428b5a791fd646',
    'plugin-acceptance-runtime.py':'a001a978a55d305993b9d55375fe7f65c2c6b2509973e20135ac86e2bd3d4f51',
    'plugin-sandbox-recipient.py':'7408c56f0b9aa39d8ed97bb238be960bec7a2ee07053ba372f574b744aef1a96'}
HOST_SHA = 'c1440e86162097cd3a7d7f65c478a57c42b5817f627f0d91e4802e05ed0a0b38'
NAMES = tuple(PINS)+('plugin-dedicated-plan-host.py','plugin-dedicated-plan-activate.py',
                     'plugin-dedicated-plan-observer.py','plugin-dedicated-plan-acceptance.py')
RUNTIME = {'checker-plugin':'82fb1e7cef3172e465f33fec54d4d7be4f799c66193b5dd8f9b989689009fcaa',
           'progress-checker':'9ece1092eba4232a3c66c745d90c7d62df5aaa25a3587a9363c6fe142c830d99',
           'progress-checker-mcp':'6be43b4c12d46555d6443d2619bd15e1dd1754f297781f0fa5c0059bf5c79e7a'}
BUDGETS = {'preparation':1800,'start':5,'work':120,'cleanup':120,'observation':90,'final_margin':30,'hard':365}
TRUST = 'explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime'
MAX_STREAM, MAX_PACKET = 8*1024*1024, 1024*1024
META_KEYS = {'schema_version','mode','trust_policy','job_id','nonce','root','state','producer',
             'producer_argv','python_exe_sha256','boot_id','body_sha256','archive_sha256',
             'module_hashes','runtime_files','fixture_files','initial_public_snapshot',
             'check_definition','endpoint','socket','prepared_ns','activation_expires_ns','budget_seconds'}
READY_KEYS = {'schema_version','attestation_path','attestation_sha256','job_id','nonce','producer',
              'endpoint','socket','awaiting_activation','ready','consumed','activated_ns','hard_deadline_ns',
              'body_started_ns','body_work_deadline_ns','body_cleanup_deadline_ns','cleanup_complete',
              'body_exit','body_status','observer_expires_ns'}


def require(condition, message):
    if not condition: raise RuntimeError(message)


def digest(data): return hashlib.sha256(data).hexdigest()
def hextext(value, length): return type(value) is str and len(value)==length and all(c in '0123456789abcdef' for c in value)


def strict(data):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result, 'Duplicate JSON key'); result[key]=value
        return result
    def floating(value):
        result=float(value); require(math.isfinite(result), 'Nonfinite JSON'); return result
    return json.loads(data,object_pairs_hook=pairs,parse_float=floating,
                      parse_constant=lambda _:require(False,'Nonfinite JSON'))


def bounded(path, limit, private=False):
    """No-follow component traversal and before/after/path identity check."""
    require(type(path) is Path or isinstance(path,Path), 'Path required')
    require(path.is_absolute() and '..' not in path.parts, 'Canonical input required')
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            os.close(parent); parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid==1000 and before.st_nlink==1
                    and not before.st_mode&0o022 and before.st_size<=limit, 'Unsafe bounded input')
            if private:
                info=os.fstat(parent)
                require(stat.S_IMODE(before.st_mode)==0o600 and info.st_uid==1000
                        and stat.S_IMODE(info.st_mode)==0o700, 'Unsafe coordination directory/mode')
            data=stream.read(limit+1); after=os.fstat(stream.fileno())
            current=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            facts=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            require(len(data)==before.st_size<=limit and facts(before)==facts(after)==facts(current),
                    'Bounded input changed while read')
            return data
    finally: os.close(parent)


def endpoint_identity(path):
    require(path.resolve(strict=True)==path, 'Endpoint alias')
    info=path.lstat(); require(stat.S_ISSOCK(info.st_mode), 'Socket required')
    return {'dev':info.st_dev,'ino':info.st_ino,'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),
            'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}


def load(name,data):
    require(name in {'plugin-dedicated-plan-capture.py','plugin-dedicated-plan-public.py',
                     'plugin-dedicated-plan-lifecycle.py'} and digest(data)==PINS[name], 'Pure frozen evaluator required')
    module=types.ModuleType(name.replace('-','_')); module.__file__=str(ROOT/'scripts'/name)
    exec(compile(data,module.__file__,'exec'),module.__dict__); return module


def validate_registration(meta,ready,path,sha,now,boot):
    require(type(meta) is dict and set(meta)==META_KEYS and type(ready) is dict and set(ready)==READY_KEYS,
            'Exact registration/readiness schema required')
    require(type(meta['schema_version']) is int and meta['schema_version']==1 and meta['mode']=='dedicated-plan'
            and meta['trust_policy']==TRUST and meta['root']==str(FIXTURE) and meta['state']==str(STATE),
            'Fixed dedicated registration required')
    require(hextext(meta['job_id'],32) and hextext(meta['nonce'],64) and hextext(sha,64)
            and hextext(meta['python_exe_sha256'],64), 'Registration identifiers malformed')
    producer=meta['producer']
    require(type(producer) is dict and set(producer)=={'pid','starttime','uid','state','ppid','argv'}
            and type(producer['pid']) is int and producer['pid']>0 and type(producer['uid']) is int
            and producer['uid']==1000 and type(producer['ppid']) is int and producer['ppid']>=0
            and type(producer['starttime']) is str and producer['starttime'].isascii() and producer['starttime'].isdecimal()
            and type(producer['state']) is str and len(producer['state'])==1 and producer['state'] not in {'Z','X','x'}
            and type(producer['argv']) is list and all(type(v) is str for v in producer['argv'])
            and type(meta['producer_argv']) is list and all(type(v) is str for v in meta['producer_argv']),
            'Complete typed producer identity required')
    require(meta['body_sha256']==PINS['plugin-acceptance.py'] and meta['archive_sha256']==ARCHIVE_SHA
            and meta['budget_seconds']==BUDGETS and all(type(v) is int for v in meta['budget_seconds'].values())
            and meta['boot_id']==boot, 'Source/archive/boot/budget pins differ')
    require(type(meta['module_hashes']) is dict and set(meta['module_hashes'])=={str(ROOT/'scripts'/n) for n in NAMES}
            and all(hextext(v,64) for v in meta['module_hashes'].values())
            and all(meta['module_hashes'][str(ROOT/'scripts'/n)]==v for n,v in PINS.items())
            and meta['module_hashes'][str(ROOT/'scripts/plugin-dedicated-plan-host.py')]==HOST_SHA, 'Exact eleven reviewed sources required')
    prefix=path.parent/'extracted/progress-checker-0.2.1-dev-linux-x86_64/plugin/bin'
    require(meta['runtime_files']=={str(prefix/n):v for n,v in RUNTIME.items()}, 'Fixed runtime inventory required')
    require(meta['endpoint']==str(path.parent/'observe.sock') and type(meta['socket']) is dict
            and set(meta['socket'])=={'dev','ino','uid','mode','mtime_ns','ctime_ns'}
            and all(type(v) is int for v in meta['socket'].values()) and meta['socket']['uid']==1000
            and meta['socket']['mode']==0o600 and meta['socket']['ino']>0, 'Fixed endpoint pin required')
    for key in ('schema_version','job_id','nonce','producer','endpoint','socket'):
        require(type(ready[key]) is type(meta[key]) and ready[key]==meta[key], 'Static readiness crosspin differs')
    require(ready['attestation_path']==str(path) and ready['attestation_sha256']==sha
            and ready['ready'] is True and ready['consumed'] is False and ready['awaiting_activation'] is False
            and ready['cleanup_complete'] is True and type(ready['body_exit']) is int and ready['body_exit']==0
            and ready['body_status'] in {'full-public-captured-semantics','blocked-missing-grant-captured-semantics'},
            'No clean unconsumed ready stream')
    clocks=('prepared_ns','activation_expires_ns')
    require(all(type(meta[k]) is int and meta[k]>=0 for k in clocks)
            and all(type(ready[k]) is int and ready[k]>=0 for k in ('activated_ns','hard_deadline_ns',
                'body_started_ns','body_work_deadline_ns','body_cleanup_deadline_ns','observer_expires_ns')), 'Integer clocks required')
    p,a,s=meta['prepared_ns'],ready['activated_ns'],ready['body_started_ns']
    require(meta['activation_expires_ns']==p+1800_000_000_000 and p<=a<meta['activation_expires_ns']
            and a<=s<=a+5_000_000_000 and abs(ready['body_work_deadline_ns']-s-120_000_000_000)<=1000
            and abs(ready['body_cleanup_deadline_ns']-s-240_000_000_000)<=1000
            and ready['hard_deadline_ns']==a+365_000_000_000
            and s<=now<ready['observer_expires_ns']<=min(now+90_000_000_000,ready['hard_deadline_ns']-30_000_000_000),
            'Expired/different cumulative clocks')


def verify_audit(audit,meta,ready,ready_bytes,payload,frames,connected,now):
    keys={'schema_version','job_id','nonce','connected_ns','audited_ns','raw_exact_bytes_sha256',
          'module_hashes','runtime_files','final_public_pins','fixture_census','ready_sha256'}
    require(type(audit) is dict and set(audit)==keys and type(audit['schema_version']) is int
            and audit['schema_version']==1 and audit['job_id']==meta['job_id'] and audit['nonce']==meta['nonce'], 'Exact fresh audit schema required')
    # Producer records connected_ns after it reads the request, which is after our connect.
    require(type(audit['connected_ns']) is int and type(audit['audited_ns']) is int
            and connected<=audit['connected_ns']<=audit['audited_ns']<=now
            and frames[-1]['monotonic_ns']<=audit['audited_ns']<ready['observer_expires_ns'], 'Fresh postconnect audit clock required')
    require(audit['raw_exact_bytes_sha256']==digest(payload) and audit['ready_sha256']==digest(ready_bytes)
            and audit['module_hashes']==meta['module_hashes'] and audit['runtime_files']==meta['runtime_files'], 'Fresh audit hash pins differ')
    final=[f['payload'] for f in frames if f['kind']=='public-files' and f['payload'].get('role')=='final']
    require(len(final)==1, 'Original final public snapshot required')
    pins={v['role']:{'sha256':digest(base64.b64decode(v['bytes_base64'],validate=True))} for v in final[0]['files']}
    require(audit['final_public_pins']==pins, 'Audit final public bytes differ')
    require(audit['fixture_census']=={'service_record':None,'lease_snapshot':{},'endpoint_identity':None,'fixture_processes':[]}, 'Fresh fixed fixture drain absent')
    return final[0]


def verify_completion(ack,meta,ready,committed,payload,audit_bytes,halfclosed,now):
    keys={'schema_version','job_id','nonce','completed_ns','raw_exact_bytes_sha256','transfer_audit_sha256',
          'readiness_sha256','module_hashes','runtime_files','endpoint_identity','reservation_identity'}
    require(type(ack) is dict and set(ack)==keys and type(ack['schema_version']) is int and ack['schema_version']==1
            and ack['job_id']==meta['job_id'] and ack['nonce']==meta['nonce'], 'Exact completion schema/identity required')
    require(type(ack['completed_ns']) is int and halfclosed<=ack['completed_ns']<=now
            and ack['completed_ns']<min(ready['observer_expires_ns'],ready['hard_deadline_ns']-30_000_000_000), 'Completion clock expired/not post-EOF')
    require(ack['raw_exact_bytes_sha256']==digest(payload) and ack['transfer_audit_sha256']==digest(audit_bytes)
            and ack['readiness_sha256']==digest(committed) and ack['module_hashes']==meta['module_hashes']
            and ack['runtime_files']==meta['runtime_files'] and ack['endpoint_identity'] is None
            and ack['reservation_identity'] is None, 'Completion hash/source/cleanup pins differ')
    expected=dict(ready,ready=False,consumed=True)
    require(strict(committed)==expected, 'Exact committed consumed readiness required')


def read_exact(wire,count,deadline):
    result=bytearray()
    while len(result)<count:
        wait=min(15,deadline-time.monotonic())
        require(wait>0 and select.select([wire],[],[],wait)[0], 'Finite packet wait expired')
        chunk=wire.recv(count-len(result)); require(chunk, 'Truncated packet'); result.extend(chunk)
    return bytes(result)


def packet(wire,limit,deadline):
    count=struct.unpack('!I',read_exact(wire,4,deadline))[0]
    require(0<count<=limit, 'Packet size bound'); return read_exact(wire,count,deadline)


def source_runtime_guard(meta):
    buffers={}
    for name in NAMES:
        data=bounded(ROOT/'scripts'/name,MAX_STREAM)
        require(digest(data)==meta['module_hashes'][str(ROOT/'scripts'/name)], 'Reviewed source buffer changed'); buffers[name]=data
    require(digest(bounded(ARCHIVE,64*1024*1024))==ARCHIVE_SHA, 'Reviewed archive changed')
    for path,pin in meta['runtime_files'].items():
        require(digest(bounded(Path(path),32*1024*1024))==pin, 'Reviewed runtime changed')
    return buffers


def final_guard(meta,path,original,ready_path,committed,endpoint,poll,deadline):
    # Reconcile latest failure/readiness after ACK: duplicate activation may
    # invalidate a producer after it sent ACK. No saved ACK alone qualifies.
    require(time.monotonic()<deadline and not poll.poll(0) and not os.path.lexists(endpoint)
            and not os.path.lexists(RESERVATION) and not os.path.lexists(path.parent/'failure.json')
            and bounded(path,MAX_PACKET,True)==original and bounded(ready_path,MAX_PACKET,True)==committed,
            'Final peer/deadline/failure/immutable/consumed/cleanup guard failed')


def consume(attestation,sha,readiness):
    path,ready_path=Path(attestation),Path(readiness)
    require(path.is_absolute() and path.is_relative_to(ROOT/'.local') and '..' not in path.parts
            and path.name=='attestation.json' and ready_path==path.parent/'readiness.json', 'Fixed public coordination paths required')
    original=bounded(path,MAX_PACKET,True); require(digest(original)==sha, 'Reviewed immutable SHA differs')
    ready_bytes=bounded(ready_path,MAX_PACKET,True); meta,ready=strict(original),strict(ready_bytes)
    validate_registration(meta,ready,path,sha,time.monotonic_ns(),Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    buffers=source_runtime_guard(meta)
    raw=load('plugin-dedicated-plan-capture.py',buffers['plugin-dedicated-plan-capture.py'])
    public=load('plugin-dedicated-plan-public.py',buffers['plugin-dedicated-plan-public.py'])
    lifecycle=load('plugin-dedicated-plan-lifecycle.py',buffers['plugin-dedicated-plan-lifecycle.py'])
    require(meta['check_definition']==raw.CHECK, 'Literal dedicated check required')
    initial=meta['initial_public_snapshot']
    config=raw.strict(base64.b64decode(initial['files'][0]['bytes_base64'],validate=True))
    public.file_snapshot(initial,raw,config)
    require(meta['fixture_files']=={v['role']:{'sha256':digest(base64.b64decode(v['bytes_base64'],validate=True))} for v in initial['files']}, 'Initial public pins differ')
    endpoint=Path(meta['endpoint']); require(endpoint_identity(endpoint)==meta['socket'], 'Endpoint changed')
    require(not os.path.lexists(path.parent/'failure.json'), 'Failed registration')
    deadline=min(time.monotonic()+90,ready['observer_expires_ns']/1e9,ready['hard_deadline_ns']/1e9-30)
    with socket.socket(socket.AF_UNIX) as wire:
        wire.settimeout(max(.001,min(15,deadline-time.monotonic()))); wire.connect(str(endpoint)); connected=time.monotonic_ns()
        require(endpoint_identity(endpoint)==meta['socket'], 'Endpoint changed during connect')
        peer_pid,peer_uid,_=struct.unpack('3i',wire.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        require(peer_uid==1000==meta['producer']['uid'], 'Kernel peer UID differs')
        require(peer_pid==meta['producer']['pid'] or (peer_pid==0 and meta['trust_policy']==TRUST),
                'Visible kernel peer PID differs from reviewed producer')
        peerfd=struct.unpack('i',wire.getsockopt(socket.SOL_SOCKET,77,4))[0]  # Linux SO_PEERPIDFD; fail closed if unsupported.
        require(peerfd>=0, 'Kernel peer PIDfd unavailable')
        try:
            poll=select.poll(); poll.register(peerfd,select.POLLIN|select.POLLHUP|select.POLLERR)
            require(not poll.poll(0), 'Connected producer exited')
            request={'schema_version':1,'job_id':meta['job_id'],'nonce':meta['nonce'],'request':'read-events'}
            wire.sendall(json.dumps(request,separators=(',',':')).encode()+b'\n')
            payload=packet(wire,MAX_STREAM,deadline); require(payload.endswith(b'\n'), 'Unterminated raw JSONL')
            audit_bytes=packet(wire,MAX_PACKET,deadline)
            lines=payload.splitlines(keepends=True); classified=raw.classify_serialized(lines,meta['job_id'],meta['nonce'])
            frames=[v['frame'] for v in classified['classified_frames']]
            result=public.evaluate(lines,meta['job_id'],meta['nonce'],buffers['plugin-acceptance.py'],buffers['plugin-dedicated-plan-capture.py'])
            life=lifecycle.evaluate(lines,meta,buffers['plugin-dedicated-plan-capture.py'])
            require(initial==next(f['payload'] for f in frames if f['kind']=='public-files' and f['payload']['role']=='initial'), 'Original initial snapshot differs')
            for frame in frames:
                bound=ready['body_work_deadline_ns'] if frame['kind'] in {'request','response'} else ready['body_cleanup_deadline_ns']
                require(ready['activated_ns']<=frame['monotonic_ns']<=bound, 'Actual raw event budget differs')
            verify_audit(strict(audit_bytes),meta,ready,ready_bytes,payload,frames,connected,time.monotonic_ns())
            require(time.monotonic()<deadline and not poll.poll(0) and endpoint_identity(endpoint)==meta['socket']
                    and bounded(path,MAX_PACKET,True)==original and bounded(ready_path,MAX_PACKET,True)==ready_bytes
                    and not os.path.lexists(path.parent/'failure.json'), 'Pre-EOF live stability failed')
            source_runtime_guard(meta)
            halfclosed=time.monotonic_ns(); wire.shutdown(socket.SHUT_WR)
            ack=strict(packet(wire,MAX_PACKET,deadline)); committed=bounded(ready_path,MAX_PACKET,True)
            verify_completion(ack,meta,ready,committed,payload,audit_bytes,halfclosed,time.monotonic_ns())
            final_guard(meta,path,original,ready_path,committed,endpoint,poll,deadline)
            source_runtime_guard(meta)
            final_guard(meta,path,original,ready_path,committed,endpoint,poll,deadline)
            terminal=frames[-1]['payload']
            handoff=(result['semantic_validation_passed'] is True and result['original_assertion_count']==18
                     and life['captured_lifecycle_semantics_passed'] is True and not classified['pending_rpc']
                     and terminal['body_exit']==0 and terminal['cleanup_complete'] is True
                     and terminal.get('error') is None and terminal.get('error_type') is None)
            # Final guard remains directly adjacent to deriving the finite handoff.
            final_guard(meta,path,original,ready_path,committed,endpoint,poll,deadline)
            result.update(dedicated_handoff_passed=handoff,captured_lifecycle=life,complete=False,
                          qualification_possible=False,approval_created=False,retained_execution=True,
                          handoff_policy=TRUST,hidden_host_source_independently_verified=False,
                          kernel_peer_pid=peer_pid,kernel_peer_uid=peer_uid,kernel_peer_lifetime_live=True,
                          immutable_registration_sha256=sha,completion_committed=True,
                          full_plan_integration_required=True)
        finally: os.close(peerfd)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attestation',type=Path); parser.add_argument('--sha256'); parser.add_argument('--readiness',type=Path)
    args=parser.parse_args()
    if not any((args.attestation,args.sha256,args.readiness)):
        print('OFF: no socket, host, fixture, service, grant or check operation.'); return 0
    if not all((args.attestation,args.sha256,args.readiness)): parser.error('Complete reviewed attestation/SHA/readiness required')
    result=consume(args.attestation,args.sha256,args.readiness); print(json.dumps(result,indent=2)); return 2


if __name__=='__main__': raise SystemExit(main())
