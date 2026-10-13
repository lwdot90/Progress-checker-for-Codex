#!/usr/bin/python3
"""Read one fresh fixed demo stream; no activation, process, file mutation or RPC.

Staged consumer: explicit reviewed host registration plus kernel peer lifetime.
No claim of independently seeing hidden host PID/source inside a sandbox. The
finite local composite requires raw, lifecycle, fresh audit and committed ACK.
"""
import argparse,base64,hashlib,importlib.util,json,math,os,select,socket,stat,struct,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
MAX_STREAM=8*1024*1024
NAMES=('plugin-original-demo-collector.py','plugin-original-demo-activate.py','plugin-original-demo-observer.py','plugin-original-demo-raw.py','plugin-original-demo-lifecycle.py','plugin-evidence-acceptance.py','plugin-acceptance.py')
RAW_SHA='e61a08643d6c3cb37941c3a328f6d460277d2df23e8ab682d2ca4188dad9dac8'
LIFECYCLE_SHA='1aa5036b06bb3c2cf54afccbc3065c67b51ca830b1d3e45ccc83e3129da3631d'
HOST_GATES=('OFF-default staged: independent host provenance verifier not integrated','Owned backend/watchdog/lease/socket drain verifier not integrated','Immutable registration and independent activation verifier not integrated')

def pairs(values):
    result={}
    for key,value in values:
        if key in result:raise RuntimeError('Duplicate observer JSON key')
        result[key]=value
    return result

def strict(data):
    def floating(value):
        result=float(value)
        if not math.isfinite(result):raise RuntimeError('Nonfinite observer number')
        return result
    return json.loads(data,object_pairs_hook=pairs,parse_float=floating,parse_constant=lambda _:(_ for _ in ()).throw(RuntimeError('Nonfinite observer JSON')))

def producer_identity(value):
    return type(value) is dict and set(value)=={'pid','starttime','uid','state','ppid','argv'} and type(value['pid']) is int and value['pid']>0 and type(value['starttime']) is str and value['starttime'].isascii() and value['starttime'].isdecimal() and type(value['uid']) is int and value['uid']==1000 and type(value['ppid']) is int and value['ppid']>=0 and type(value['state']) is str and len(value['state'])==1 and type(value['argv']) is list and all(type(arg) is str for arg in value['argv'])

def source_buffer(path):
    if path.resolve(strict=True)!=path or path.parent!=ROOT/'scripts':raise RuntimeError('Canonical reviewed source required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or before.st_mode&0o022 or before.st_size>8*1024*1024:raise RuntimeError('Bounded regular reviewed source required')
        data=stream.read(8*1024*1024+1);after=os.fstat(stream.fileno());now=path.lstat()
        key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if len(data)!=before.st_size or key(before)!=key(after) or key(before)!=key(now):raise RuntimeError('Reviewed source changed while captured')
        return data

def verify_transfer_audit(audit,meta,ready,payload,frames,connected_ns,now_ns):
    if type(audit) is not dict or set(audit)!={'schema_version','job_id','nonce','observed_ns','raw_exact_bytes_sha256','module_hashes','runtime_files','public_files','layout_censuses'}:raise RuntimeError('Exact audit schema required')
    if type(audit['schema_version']) is not int or audit['schema_version']!=1 or audit['job_id']!=meta['job_id'] or audit['nonce']!=meta['nonce']:raise RuntimeError('Audit registration pins differ')
    observed=audit['observed_ns']
    if type(observed) is not int or not connected_ns<=observed<=now_ns or observed>=min(ready['observer_expires_ns'],ready['hard_deadline_ns']-30_000_000_000) or observed<frames[-1]['monotonic_ns']:raise RuntimeError('Fresh postconnect audit clock differs')
    if audit['raw_exact_bytes_sha256']!=hashlib.sha256(payload).hexdigest() or audit['module_hashes']!=meta['module_hashes'] or audit['runtime_files']!=meta['runtime_files']:raise RuntimeError('Audit exact bytes/source/runtime pins differ')
    terminal=frames[-1]['payload'];final=terminal.get('registered_input_hashes_after',{})
    if final.get('module_hashes')!=meta['module_hashes'] or final.get('runtime_files')!=meta['runtime_files']:raise RuntimeError('Original terminal input audit absent/different')
    public=audit['public_files']
    if type(public) is not dict or set(public)!={'role','files','directory_stats','capture_process'} or public['role']!='transfer' or not producer_identity(public['capture_process']):raise RuntimeError('Audit public snapshot schema differs')
    if any(public['capture_process'][key]!=meta['producer'][key] for key in ('pid','starttime','uid','ppid','argv')):raise RuntimeError('Audit collector identity differs')
    paths={'config':meta['root']+'/.progress-checker/config.json','script':meta['root']+'/check.py','feature':meta['root']+'/feature.txt'}
    if type(public['files']) is not list or len(public['files'])!=3:raise RuntimeError('Exact three public files required')
    files={item.get('relative_role'):item for item in public['files']}
    if set(files)!=set(paths):raise RuntimeError('Public roles differ/duplicate')
    for role,path in paths.items():
        item=files[role]
        if set(item)!={'relative_role','bytes_base64','before_stat','after_stat','path_lstat'}:raise RuntimeError('Public file schema differs')
        content=base64.b64decode(item['bytes_base64'],validate=True)
        if len(content)>(65536 if role=='config' else 4096) or hashlib.sha256(content).hexdigest()!=meta['fixture_files'][path]['sha256']:raise RuntimeError('Public bytes changed/unrestored')
        current=item['before_stat']
        if current!=item['after_stat'] or current!=item['path_lstat']:raise RuntimeError('Public capture identity changed')
        expected=meta['fixture_files'][path]['stat']
        keys=('device','inode','mode','uid','nlink','size','regular') if role=='feature' else tuple(expected)
        if set(current)!=set(expected) or any(type(current[key]) is not type(expected[key]) or current[key]!=expected[key] for key in keys):raise RuntimeError('Public pinned identity changed')
        if final.get('fixture_files',{}).get(path,{}).get('sha256')!=meta['fixture_files'][path]['sha256']:raise RuntimeError('Terminal public bytes differ')
    dirs=public['directory_stats']
    if type(dirs) is not dict or set(dirs)!={'root','state','config'} or any(dirs[key]!=meta['fixture_directories'][key] for key in ('root','state')):raise RuntimeError('Public directory pins differ')
    baseline=next((f['payload'] for f in frames if f['kind']=='public-files' and f['payload'].get('role')=='fixture'),None)
    if baseline is None or dirs['config']!=baseline['directory_stats']['config']:raise RuntimeError('Config directory identity differs')
    base=str(Path(meta['endpoint']).parent)
    expected_layouts=[(meta['root'],meta['state']),(base+'/body/unapproved/project',base+'/body/unapproved/state')]
    censuses=audit['layout_censuses']
    if type(censuses) is not list or len(censuses)!=2:raise RuntimeError('Exact two layout censuses required')
    for census,(root,state) in zip(censuses,expected_layouts):
        if type(census) is not dict or set(census)!={'root','state','service_record','leases','endpoint_identity','processes'} or census['root']!=root or census['state']!=state or census['service_record'] is not None or type(census['leases']) is not dict or census['leases'] or census['endpoint_identity'] is not None or type(census['processes']) is not list or census['processes']:raise RuntimeError('Fresh fixed layout not fully drained')
    return {'status':'fresh-captured-audit-only','postconnect_audit_recomputed':True,'qualification_possible':False,'observed_ns':observed}

def verify_completion(completion,meta,ready,committed_bytes,payload,audit_bytes,after_halfclose_ns,now_ns):
    keys={'schema_version','job_id','nonce','completed_ns','raw_exact_bytes_sha256','transfer_audit_sha256','readiness_sha256','module_hashes','runtime_files','endpoint_identity','reservation_identity'}
    if type(completion) is not dict or set(completion)!=keys or type(completion['schema_version']) is not int or completion['schema_version']!=1 or completion['job_id']!=meta['job_id'] or completion['nonce']!=meta['nonce']:raise RuntimeError('Exact completion identity/schema required')
    stamp=completion['completed_ns']
    if type(stamp) is not int or not after_halfclose_ns<=stamp<=now_ns or stamp>=min(ready['observer_expires_ns'],ready['hard_deadline_ns']-30_000_000_000):raise RuntimeError('Completion clock expired/not post-EOF')
    hashes=(hashlib.sha256(payload).hexdigest(),hashlib.sha256(audit_bytes).hexdigest(),hashlib.sha256(committed_bytes).hexdigest())
    if tuple(completion[key] for key in ('raw_exact_bytes_sha256','transfer_audit_sha256','readiness_sha256'))!=hashes:raise RuntimeError('Completion exact packet/readiness digests differ')
    if completion['module_hashes']!=meta['module_hashes'] or completion['runtime_files']!=meta['runtime_files'] or completion['endpoint_identity'] is not None or completion['reservation_identity'] is not None:raise RuntimeError('Completion source/runtime/teardown facts differ')
    committed=strict(committed_bytes);expected=dict(ready);expected.update(ready=False,consumed=True)
    if committed!=expected or committed.get('ready') is not False or committed.get('consumed') is not True:raise RuntimeError('Exact consumed readiness transition required')
    return committed

def qualify_local(result,captured_lifecycle,context):
    """Finite composite over freshly recomputed local results, never saved PASS.

    context is constructed only by consume after kernel peer, immutable, packet,
    clock, source-buffer and completion checks. Hidden host provenance remains
    the explicitly reviewed registration trust policy, not direct sandbox proof.
    """
    complete_context=type(context) is dict and set(context)=={'reviewed_host_registration','kernel_peer_live','fresh_audit','completion_committed','source_buffers_pinned','activation_clocks'} and all(value is True for value in context.values())
    lifecycle_ok=captured_lifecycle.get('captured_lifecycle_semantics_passed') is True
    raw_ok=result.get('assertion_count')==18 and type(result.get('assertion_count')) is int and len(result.get('assertions',[]))==18 and all(item.get('passed') is True for item in result['assertions']) and result.get('raw_serialized_gate') is True and result.get('absolute_deadline_gate') is True and all(type(result.get(group)) is dict and result[group] and all(value is True for value in result[group].values()) for group in ('fixture_cas_gates','session_binding_gates','run_association_gates'))
    body=result.get('body_remaining_unqualified',[])
    remaining=list(body)
    # Remove only known stage-added entries, preserving even identical strings
    # if they originated in the actual body. Unknown strings always survive.
    extras=result.get('remaining_unqualified',[])[len(body):]
    discharged=complete_context and lifecycle_ok
    remaining.extend(value for value in extras if not(discharged and value in HOST_GATES))
    passed=discharged and raw_ok and type(result.get('body_exit')) is int and result['body_exit']==0 and not result.get('body_error') and result.get('cleanup_complete') is True and not remaining and result.get('status')!='failed'
    result.update(remaining_unqualified=remaining,qualification_possible=passed,complete=passed,status='passed' if passed else 'failed' if result.get('status')=='failed' or result.get('body_error') or result.get('body_exit') not in (0,None) else 'partial',retained_execution=True)
    result['qualification_policy']='Explicit reviewed hidden-host registration plus fresh kernel peer lifetime and locally recomputed raw/lifecycle/audit/completion; hidden PID/source not independently visible.'
    return result

def bounded(path,limit):
    path=Path(path)
    if not path.is_absolute() or path.resolve(strict=True)!=path or not path.is_relative_to(ROOT/'.local'):raise RuntimeError('Canonical public.local observer input required')
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);os.close(parent);parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600 or stat.S_IMODE(os.fstat(parent).st_mode)!=0o700 or before.st_size>limit:
                raise RuntimeError('Unsafe bounded observer input before read')
            data=stream.read(limit+1);after=os.fstat(stream.fileno());now=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600 or stat.S_IMODE(os.fstat(parent).st_mode)!=0o700 or before.st_size>limit or len(data)!=before.st_size or key(before)!=key(after) or key(before)!=key(now):raise RuntimeError('Unsafe or changed observer input')
            return data
    finally:os.close(parent)

def endpoint_identity(path):
    if path.resolve(strict=True)!=path:raise RuntimeError('Endpoint alias')
    info=path.lstat()
    if not stat.S_ISSOCK(info.st_mode):raise RuntimeError('Endpoint is not a socket')
    return {'dev':info.st_dev,'ino':info.st_ino,'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}

def read_exact(wire,count,deadline):
    result=bytearray()
    while len(result)<count:
        remaining=deadline-time.monotonic()
        if remaining<=0 or not select.select([wire],[],[],remaining)[0]:raise RuntimeError('Bounded one-use stream deadline')
        chunk=wire.recv(count-len(result))
        if not chunk:raise RuntimeError('Truncated fixed stream')
        result.extend(chunk)
    return bytes(result)

def consume(attestation_path,sha256,readiness_path):
    path,ready_path=Path(attestation_path),Path(readiness_path)
    if path.parent!=ready_path.parent or path.name!='attestation.json' or ready_path.name!='readiness.json':raise RuntimeError('Exact separate registration filenames required')
    original=bounded(path,1024*1024)
    if hashlib.sha256(original).hexdigest()!=sha256:raise RuntimeError('Approved immutable SHA differs')
    ready_bytes=bounded(ready_path,1024*1024)
    meta=strict(original);ready=strict(ready_bytes)
    if not producer_identity(meta.get('producer')):raise RuntimeError('Complete typed producer identity required')
    if set(meta['module_hashes'])!={str(ROOT/'scripts'/name) for name in NAMES}:raise RuntimeError('Exact seven source modules required')
    if meta['module_hashes'][str(ROOT/'scripts/plugin-original-demo-raw.py')]!=RAW_SHA or meta['module_hashes'][str(ROOT/'scripts/plugin-original-demo-lifecycle.py')]!=LIFECYCLE_SHA:raise RuntimeError('Reviewed evaluator pins differ')
    if type(meta.get('schema_version')) is not int or meta.get('schema_version')!=1 or meta.get('mode')!='original-demo' or meta.get('trust_policy')!='explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime' or meta.get('root')!='/home/luis/progress-checker/.local/checker-demo/session-c5c6vsyz/project' or meta.get('state')!='/home/luis/progress-checker/.local/checker-demo/session-c5c6vsyz/state':raise RuntimeError('Unexpected fixed registration')
    if type(ready.get('schema_version')) is not int or ready.get('attestation_sha256')!=sha256 or ready.get('attestation_path')!=str(path) or ready.get('ready') is not True or ready.get('awaiting_activation') is not False or ready.get('consumed') is not False or ready.get('cleanup_complete') is not True:raise RuntimeError('No fresh clean ready job')
    for key in ('schema_version','job_id','nonce','producer','endpoint','socket'):
        if ready[key]!=meta[key]:raise RuntimeError('Static readiness crosspin differs')
    if any(type(ready.get(key)) is not int for key in ('activated_ns','workflow_deadline_ns','hard_deadline_ns','observer_expires_ns')) or type(meta.get('prepared_ns')) is not int:raise RuntimeError('Exact integer registration clocks required')
    if meta['boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip() or time.monotonic_ns()>=ready['observer_expires_ns']:raise RuntimeError('Expired registration')
    endpoint=Path(meta['endpoint'])
    if endpoint!=path.parent/'observe.sock' or endpoint_identity(endpoint)!=meta['socket'] or meta['socket']['mode']!=0o600:raise RuntimeError('Owned endpoint identity differs')
    source=ROOT/'scripts/plugin-original-demo-raw.py';data=source_buffer(source)
    if hashlib.sha256(data).hexdigest()!=meta['module_hashes'][str(source)]:raise RuntimeError('Raw evaluator buffer differs')
    spec=importlib.util.spec_from_file_location('original_demo_raw',source);raw=importlib.util.module_from_spec(spec);exec(compile(data,str(source),'exec'),raw.__dict__)
    lifecycle_source=ROOT/'scripts/plugin-original-demo-lifecycle.py';lifecycle_data=source_buffer(lifecycle_source)
    if hashlib.sha256(lifecycle_data).hexdigest()!=LIFECYCLE_SHA:raise RuntimeError('Lifecycle buffer differs before exec')
    lifecycle_spec=importlib.util.spec_from_file_location('original_demo_lifecycle',lifecycle_source);lifecycle=importlib.util.module_from_spec(lifecycle_spec);exec(compile(lifecycle_data,str(lifecycle_source),'exec'),lifecycle.__dict__)
    runtime_prefix=path.parent/'extracted/progress-checker-0.2.1-dev-linux-x86_64/plugin/bin'
    if meta.get('archive_sha256')!=lifecycle.ARCHIVE or meta['runtime_files']!={str(runtime_prefix/name):value for name,value in lifecycle.HASHES.items()}:raise RuntimeError('Exact archive/runtime inventory required')
    deadline=min(time.monotonic()+90,ready['observer_expires_ns']/1e9,ready['hard_deadline_ns']/1e9-30)
    with socket.socket(socket.AF_UNIX) as wire:
        wire.settimeout(max(.01,deadline-time.monotonic()));wire.connect(str(endpoint));connected_ns=time.monotonic_ns()
        if endpoint_identity(endpoint)!=meta['socket']:raise RuntimeError('Endpoint changed during connect')
        peer_pid,peer_uid,peer_gid=struct.unpack('3i',wire.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if peer_uid!=meta['producer']['uid']:raise RuntimeError('Kernel peer UID differs')
        # Kernel bound peer lifetime, not hidden host source/PID proof.
        peerfd=struct.unpack('i',wire.getsockopt(socket.SOL_SOCKET,77,4))[0]
        try:
            poll=select.poll();poll.register(peerfd,select.POLLIN)
            if poll.poll(0):raise RuntimeError('Collector already exited')
            wire.sendall(json.dumps({'schema_version':1,'job_id':meta['job_id'],'nonce':meta['nonce'],'request':'read-events'}).encode()+b'\n')
            count=struct.unpack('!I',read_exact(wire,4,deadline))[0]
            if not 0<count<=MAX_STREAM:raise RuntimeError('Original serialized stream length bound')
            payload=read_exact(wire,count,deadline)
            if not payload.endswith(b'\n'):raise RuntimeError('Truncated original serialized frame')
            audit_count=struct.unpack('!I',read_exact(wire,4,deadline))[0]
            if not 0<audit_count<=1024*1024:raise RuntimeError('Fresh audit packet bound')
            audit_bytes=read_exact(wire,audit_count,deadline);audit=strict(audit_bytes)
            frames=raw.decode_frames(payload.splitlines(keepends=True));raw.validate(frames,meta['job_id'],meta['nonce'])
            result=raw.evaluate_raw(payload.splitlines(keepends=True),meta['job_id'],meta['nonce'],{'prepared_ns':meta['prepared_ns'],'activated_ns':ready['activated_ns'],'workflow_deadline_ns':ready['workflow_deadline_ns'],'hard_deadline_ns':ready['hard_deadline_ns'],'observer_now_ns':time.monotonic_ns()})
            result['transfer_audit']=verify_transfer_audit(audit,meta,ready,payload,frames,connected_ns,time.monotonic_ns())
            try:result['captured_lifecycle']=lifecycle.evaluate_lifecycle(frames,meta)
            except (ValueError,KeyError,TypeError) as exc:result['captured_lifecycle']={'status':'failed-captured-semantics','error':str(exc),'qualification_possible':False}
            if time.monotonic()>=deadline or poll.poll(0) or endpoint_identity(endpoint)!=meta['socket'] or bounded(path,1024*1024)!=original or bounded(ready_path,1024*1024)!=ready_bytes:raise RuntimeError('Collector/endpoint/immutable/readiness changed during stream')
            after_halfclose_ns=time.monotonic_ns();wire.shutdown(socket.SHUT_WR)
            completion_count=struct.unpack('!I',read_exact(wire,4,deadline))[0]
            if not 0<completion_count<=1024*1024:raise RuntimeError('Completion packet bound')
            completion=strict(read_exact(wire,completion_count,deadline));committed_bytes=bounded(ready_path,1024*1024)
            verify_completion(completion,meta,ready,committed_bytes,payload,audit_bytes,after_halfclose_ns,time.monotonic_ns())
            if time.monotonic()>=deadline or poll.poll(0) or os.path.lexists(endpoint) or bounded(path,1024*1024)!=original:raise RuntimeError('Completion peer/endpoint/immutable stability failed')
            for source_path,source_sha in meta['module_hashes'].items():
                if hashlib.sha256(source_buffer(Path(source_path))).hexdigest()!=source_sha:raise RuntimeError('Reviewed source changed by completion')
            reservation=Path(meta['root']).parent/'.original-demo-observation-reservation'
            if time.monotonic()>=deadline or poll.poll(0) or os.path.lexists(endpoint) or os.path.lexists(reservation) or os.path.lexists(ready_path.parent/'failure.json') or bounded(path,1024*1024)!=original or bounded(ready_path,1024*1024)!=committed_bytes:raise RuntimeError('Final completion peer/clock/immutable/readiness/cleanup stability failed')
            activation_ok=all(type(meta.get(key)) is int for key in ('prepared_ns','activation_expires_ns')) and meta['activation_expires_ns']-meta['prepared_ns']==1800_000_000_000 and meta['prepared_ns']<=ready['activated_ns']<meta['activation_expires_ns']
            result=qualify_local(result,result['captured_lifecycle'],{'reviewed_host_registration':True,'kernel_peer_live':True,'fresh_audit':True,'completion_committed':True,'source_buffers_pinned':True,'activation_clocks':activation_ok})
        finally:os.close(peerfd)
    result['live_identity']={'policy':meta['trust_policy'],'hidden_pid_source_independently_verified':False,'kernel_peer_pid':peer_pid,'kernel_peer_uid':peer_uid,'kernel_peer_lifetime_live':True,'approved_attestation_sha256':sha256}
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--attestation',type=Path);parser.add_argument('--sha256');parser.add_argument('--readiness',type=Path);args=parser.parse_args()
    if not any((args.attestation,args.sha256,args.readiness)):print('OFF: no stream or workflow operation.')
    elif not all((args.attestation,args.sha256,args.readiness)):parser.error('Complete explicit one-use attestation/SHA/readiness required')
    else:
        result=consume(args.attestation,args.sha256,args.readiness);print(json.dumps(result,indent=2));raise SystemExit(0 if result.get('complete') is True else 2)
