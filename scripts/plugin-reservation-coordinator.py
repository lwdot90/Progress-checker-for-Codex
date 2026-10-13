#!/usr/bin/python3
"""Stage a public-only two-lock reservation handoff.

Accepts no retained fixture/state/command paths and grants no check execution.
Outer cancellation is destructive and cannot prove gentle signed-writer safety.
"""
import argparse,array,fcntl,hashlib,json,os,re,signal,socket,stat,struct,subprocess,tempfile,time,traceback
from pathlib import Path
SELF=Path(__file__).resolve();ROOT=SELF.parent.parent;OUT=ROOT/'.local/plugin-validation/reservation-coordinator'
BASE=ROOT/'.local/rs'
COMMON=['/usr/bin/bwrap','--unshare-all','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--clearenv','--setenv','PATH','/usr/bin:/bin']

def identity(pid):
    try:
        fields=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
        status=Path(f'/proc/{pid}/status').read_text()
        return {'pid':pid,'starttime':fields[19],'state':fields[0],'uid':Path(f'/proc/{pid}').stat().st_uid,'nspid':next(x for x in status.splitlines() if x.startswith('NSpid:')).split()[1:]}
    except (FileNotFoundError,ProcessLookupError):return None

def descendants(pid):
    result=[]
    try:children=Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
    except FileNotFoundError:return result
    for child in map(int,children):result.append(child);result.extend(descendants(child))
    return result

def namespace_members(anchor_fd):
    anchor=os.fstat(anchor_fd);anchor_key=(anchor.st_dev,anchor.st_ino)
    initial=Path('/proc/self/ns/pid').stat();initial_key=(initial.st_dev,initial.st_ino)
    members=[];unknown=[];caller_depth=len(identity(os.getpid())['nspid'])
    entries=[p for p in Path('/proc').iterdir() if p.name.isdigit()]
    if len(entries)>8192:raise RuntimeError('Owned process census exceeds bound')
    for p in entries:
        pid=int(p.name);info=identity(pid)
        if info is None or info['uid']!=1000 or info['state']=='Z':continue
        # Host /proc exposes the complete NSpid hierarchy. A depth-one
        # process is in this host initial PID namespace, never our descendant.
        if len(info['nspid'])<=caller_depth:continue
        fd=None
        try:
            fd=os.open(p/'ns/pid',os.O_RDONLY|os.O_CLOEXEC)
            for depth in range(32):
                meta=os.fstat(fd);key=(meta.st_dev,meta.st_ino)
                if key==anchor_key:members.append(info);break
                if key==initial_key:break
                parent=fcntl.ioctl(fd,0xb702);os.close(fd);fd=parent # Linux NS_GET_PARENT
            else:unknown.append({'pid':pid,'reason':'namespace ancestry depth exceeded'})
        except (FileNotFoundError,ProcessLookupError):pass
        except OSError as error:unknown.append({'pid':pid,'reason':str(error)})
        finally:
            if fd is not None:os.close(fd)
    return members,unknown

def safe_namespace_members(anchor_fd,*,inject_failure=False):
    try:
        if inject_failure:raise RuntimeError('Injected public census exception')
        return namespace_members(anchor_fd)
    except Exception as error:return [],[{'reason':'namespace census failed: '+type(error).__name__+': '+str(error)}]

def held(path):
    fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);return False
        except BlockingIOError:return True
    finally:os.close(fd)

def file_metadata(fd):
    info=os.fstat(fd)
    return {'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),'links':info.st_nlink,'regular':stat.S_ISREG(info.st_mode)}

def bounded(path,limit=16384):
    with path.open('rb') as f:data=f.read(limit+1)
    if len(data)>limit:raise RuntimeError('Oversized process public metadata')
    return data

def source_inventory():
    commands=[['/usr/bin/git','ls-files','-z','--cached'],['/usr/bin/git','ls-files','-z','--others','--exclude-standard']]
    paths=set()
    for cmd in commands:paths.update(x.decode() for x in subprocess.check_output(cmd,cwd=ROOT).split(b'\0') if x)
    config=json.loads((ROOT/'.progress-checker/config.json').read_text())
    paths.update(config['fingerprint']['extra_inputs'])
    entries={}
    for name in sorted(paths):
        p=ROOT/name
        if p.is_symlink():entries[name]={'symlink':os.readlink(p)}
        elif p.is_file():entries[name]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'mode':stat.S_IMODE(p.stat().st_mode)}
        elif not p.exists():entries[name]={'deleted':True}
        else:entries[name]={'special':stat.S_IFMT(p.stat().st_mode)}
    head=subprocess.run(['/usr/bin/git','rev-parse','--verify','--quiet','HEAD'],cwd=ROOT,text=True,capture_output=True)
    return {'inventory_sha256':hashlib.sha256(json.dumps(entries,sort_keys=True).encode()).hexdigest(),'entries':len(entries),'head':head.stdout.strip() if head.returncode==0 else None,'method':'public tracked/nonignored Git paths plus literal config extra inputs; not a checker signed evidence record'}

def job_dir(job):
    if not re.fullmatch('[a-z0-9]{8}',job):raise ValueError('Invalid hardcoded disposable job token')
    return BASE/job

ROLES=['launcher-mutex','canonical-worktree-writer']
CASES=['normal','exact-bound','wrong-nonce','wrong-type','wrong-source','oversized-prefix','extra-fd','census-error']
FRAME_MAX=4096
REFUSAL_CASES={'wrong-nonce','wrong-type','wrong-source','oversized-prefix','extra-fd'}

def owned_directory(path):
    if path.resolve(strict=True)!=path:raise RuntimeError('Symlink coordination path')
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=1000 or stat.S_IMODE(info.st_mode)!=0o700:raise RuntimeError('Expected private owned public coordination directory')

def source_hash():
    fd=os.open(SELF,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>256*1024:raise RuntimeError('Invalid bounded coordinator source')
        data=source.read(256*1024+1)
        after=os.fstat(source.fileno())
        if len(data)>256*1024 or (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise RuntimeError('Coordinator source changed')
        return hashlib.sha256(data).hexdigest()

def client(job,case):
    d=job_dir(job);owned_directory(BASE);owned_directory(d);sock=d/'s'
    nonce_path=d/'nonce';info=nonce_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=1000 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:raise RuntimeError('Invalid public one-use nonce')
    nonce_fd=os.open(nonce_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(nonce_fd,'rb') as nonce_source:
        actual=os.fstat(nonce_source.fileno())
        if (actual.st_dev,actual.st_ino,actual.st_mode,actual.st_size)!=(info.st_dev,info.st_ino,info.st_mode,info.st_size):raise RuntimeError('Nonce identity changed')
        nonce=nonce_source.read(65).decode()
    if not re.fullmatch('[a-f0-9]{64}',nonce):raise RuntimeError('Invalid bounded nonce')
    st=sock.lstat()
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600:raise RuntimeError('Unexpected public socket identity')
    s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.settimeout(5);s.connect(str(sock))
    server_peer=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    if server_peer[1:]!=(os.getuid(),os.getgid()):raise RuntimeError('Unexpected translated server UID/GID')
    request={'type':'receive-two-disposable-locks','version':1,'job':job,'nonce':nonce,'source_sha256':source_hash()}
    if case=='wrong-nonce':request['nonce']='0'*64
    elif case=='wrong-type':request['type']='forbidden-host-rpc'
    elif case=='wrong-source':request['source_sha256']='0'*64
    packet=json.dumps(request).encode()
    if case=='exact-bound':packet+=b' '*(FRAME_MAX-len(packet))
    elif case=='oversized-prefix':packet+=b' '*(FRAME_MAX-len(packet))+b'FORBIDDEN_TRAILING_DATA'
    if case=='extra-fd':
        extra=os.open(nonce_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:s.sendmsg([packet],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[extra]))])
        finally:os.close(extra)
    else:s.send(packet)
    data,ancillary,flags,_=s.recvmsg(FRAME_MAX,socket.CMSG_SPACE(8),socket.MSG_CMSG_CLOEXEC)
    fds=[]
    try:
        unexpected_ancillary=False
        for level,kind,value in ancillary:
            if (level,kind)==(socket.SOL_SOCKET,socket.SCM_RIGHTS):
                descriptors=array.array('i');descriptors.frombytes(value[:len(value)-len(value)%descriptors.itemsize]);fds.extend(descriptors)
                if len(value)%descriptors.itemsize:unexpected_ancillary=True
            else:unexpected_ancillary=True
        if unexpected_ancillary:raise RuntimeError('Unexpected ancillary type')
        if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or len(fds)!=2:raise RuntimeError('Exact two descriptors required')
        report=json.loads(data)
        if report.get('roles')!=ROLES or report['type']!='two-disposable-locks' or report['job']!=job or report['nonce']!=nonce:raise RuntimeError('Envelope binding mismatch')
        if [file_metadata(fd) for fd in fds]!=report['locks']:raise RuntimeError('Received descriptor metadata mismatch')
        if time.monotonic()>report['deadline']:raise RuntimeError('Shared job deadline expired')
        code="import os,time;fds="+repr(fds)+";assert all(not os.path.exists('/proc/self/fd/'+str(fd)) for fd in fds);print('PAYLOAD_READY',flush=True);pid=os.fork();os.setsid() if pid==0 else None;time.sleep(30)"
        inner=COMMON+['--sync-fd',str(fds[1]),'--','/usr/bin/python3','-c',code]
        argv=COMMON+['--sync-fd',str(fds[0]),'--',*inner]
        process=subprocess.Popen(argv,pass_fds=tuple(fds))
        (d/'client.json').write_text(json.dumps({'server_peer':server_peer,'received_locks':report['locks'],'guardian_monitor':process.pid,'argv':argv,'received_fds_cloexec':[not os.get_inheritable(fd) for fd in fds]}))
        # Close local copies only; HOST keeps original shared descriptions.
        for fd in fds:os.close(fd)
        fds=[];s.close();process.wait()
    finally:
        for fd in fds:os.close(fd)
        s.close()

def host(case):
    if os.getuid()!=1000 or os.geteuid()!=1000:raise RuntimeError('Public coordinator requires actual unprivileged UID1000')
    BASE.mkdir(parents=True,exist_ok=True);owned_directory(BASE);OUT.mkdir(parents=True,exist_ok=True)
    token=os.urandom(4).hex();d=job_dir(token);d.mkdir(mode=0o700)
    lockpaths=[d/'launcher-mutex.lock',d/'canonical-worktree-writer.lock'];fds=[];process=None;peerfd=None;scopefd=None;server=None;conn=None;tracked=set();result={'case':case,'roles':ROLES,'reservation_mode':'public-disposable-only','status':'failed','scope':'public disposable descriptor-only handoff; no retained state, grants, check execution or generic host RPC','unqualified':['Forced fixed-outer teardown kills every nested namespace, so this cannot establish gentle signed-writer shutdown.'],'guardian_signals_sent':[]}
    before=source_inventory();started=time.monotonic();deadline=started+10
    try:
        if '.local/**' not in json.loads((ROOT/'.progress-checker/config.json').read_text())['fingerprint']['exclude_outputs']:raise RuntimeError('Public socket directory not excluded')
        subprocess.run(['/usr/bin/git','check-ignore','--quiet',str(d/'s')],cwd=ROOT,check=True)
        for p in lockpaths:
            p.write_text('Disposable public coordination lock.\n');p.chmod(0o600)
            fd=os.open(p,os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);fds.append(fd)
        nonce=os.urandom(32).hex();(d/'nonce').write_text(nonce);(d/'nonce').chmod(0o600)
        server=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);server.settimeout(5);server.bind(str(d/'s'));(d/'s').chmod(0o600);server.listen(1)
        # Exact production security.rs mount/env/argv prefix: no FD additions.
        command=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--bind',str(ROOT),str(ROOT),'--chdir',str(ROOT),'--','/usr/bin/python3',str(SELF),'--public-client',token,'--case',case]
        output=(d/'outer.stdout').open('wb');process=subprocess.Popen(command,stdout=output,stderr=subprocess.STDOUT,close_fds=True,env={'HOME':'/tmp','LANG':'C.UTF-8','PATH':'/usr/bin:/bin'});output.close();result['exact_outer_argv']=command
        conn,_=server.accept();conn.settimeout(5)
        peer=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));initial=identity(peer[0]);peerfd=os.pidfd_open(peer[0]);after=identity(peer[0])
        if peer[1:]!=(os.getuid(),os.getgid()) or initial is None or after is None or (initial['pid'],initial['starttime'],initial['uid'])!=(after['pid'],after['starttime'],after['uid']):raise RuntimeError('Kernel peer identity invalid')
        ancestry=[process.pid,*descendants(process.pid)]
        if peer[0] not in ancestry:raise RuntimeError('Peer outside exact controlled job ancestry')
        expected=b'/usr/bin/python3\0'+os.fsencode(SELF)+b'\0--public-client\0'+token.encode()+b'\0--case\0'+case.encode()+b'\0'
        if bounded(Path(f'/proc/{peer[0]}/cmdline'))!=expected:raise RuntimeError('Unexpected exact client argv')
        packet,ancillary,packet_flags,_=conn.recvmsg(FRAME_MAX,socket.CMSG_SPACE(8),socket.MSG_CMSG_CLOEXEC)
        unsolicited_fds=[]
        for level,kind,value in ancillary:
            if (level,kind)==(socket.SOL_SOCKET,socket.SCM_RIGHTS):
                received=array.array('i');received.frombytes(value[:len(value)-len(value)%received.itemsize]);unsolicited_fds.extend(received)
        for unsolicited in unsolicited_fds:os.close(unsolicited)
        result['request_packet_bytes']=len(packet);result['request_packet_flags']=packet_flags;result['unsolicited_descriptors_closed']=len(unsolicited_fds)
        if packet_flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or ancillary:
            result['refusal_before_descriptor_transfer']=True
            raise RuntimeError('Request packet truncated or contained unexpected ancillary data')
        request=json.loads(packet);expected_request={'type':'receive-two-disposable-locks','version':1,'job':token,'nonce':nonce,'source_sha256':source_hash()}
        if request!=expected_request:
            result['refusal_before_descriptor_transfer']=True
            raise RuntimeError('Single job request mismatch')
        security=(ROOT/'checker-core/src/security.rs').read_text()
        array_text=security.split('command.args([\n',1)[1].split(']);',1)[0]
        expected_static=re.findall(r'"([^"]*)"',array_text)
        if command[1:1+len(expected_static)]!=expected_static:raise RuntimeError('Production static sandbox args mismatch')
        result['production_static_args']=expected_static;result['production_security_source_sha256']=hashlib.sha256(security.encode()).hexdigest();result['outer_environment']={'HOME':'/tmp','LANG':'C.UTF-8','PATH':'/usr/bin:/bin'};result['environment_applied_via_process_api']=True
        result['kernel_peer']=peer;result['peer_identity_before_pidfd']=initial;result['peer_identity_after_pidfd']=after;result['verified_job_ancestry']=ancestry
        envelope={'roles':ROLES,'type':'two-disposable-locks','job':token,'nonce':nonce,'deadline':deadline,'locks':[file_metadata(fd) for fd in fds]}
        conn.sendmsg([json.dumps(envelope).encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))]);conn.close();conn=None;server.close();server=None;(d/'s').unlink()
        while time.monotonic()<deadline:
            tracked.update([process.pid,*descendants(process.pid)])
            if (d/'client.json').exists() and b'PAYLOAD_READY' in bounded(d/'outer.stdout'):break
            if process.poll() is not None:raise RuntimeError('Controlled outer failed before payload readiness')
            time.sleep(.01)
        else:raise TimeoutError('Payload startup shared deadline exceeded')
        time.sleep(.05);tracked.update([process.pid,*descendants(process.pid)])
        result['client']=json.loads((d/'client.json').read_text());guardians=[]
        for pid in sorted(tracked):
            info=identity(pid)
            if not info:continue
            info['role']='namespace-init' if len(info['nspid'])>1 and info['nspid'][-1]=='1' else 'monitor-or-payload';info['lock_fds']=[]
            for path in Path(f'/proc/{pid}/fd').iterdir():
                try:
                    meta=path.stat()
                    if not any((meta.st_dev,meta.st_ino)==(entry['device'],entry['inode']) for entry in envelope['locks']):continue
                    info['lock_fds'].append({'fd':int(path.name),'target':os.readlink(path),'device':meta.st_dev,'inode':meta.st_ino,'uid':meta.st_uid,'fdinfo':bounded(Path(f'/proc/{pid}/fdinfo/{path.name}')).decode()})
                except (FileNotFoundError,ProcessLookupError):pass
            guardians.append(info)
        outer_inits=[info for info in guardians if info['role']=='namespace-init' and len(info['nspid'])==2]
        if len(outer_inits)!=1:raise RuntimeError('Exact enclosing PID1 scope missing')
        scopefd=os.open('/proc/'+str(outer_inits[0]['pid'])+'/ns/pid',os.O_RDONLY|os.O_CLOEXEC)
        scope=os.fstat(scopefd);result['enclosing_namespace_identity']={'device':scope.st_dev,'inode':scope.st_ino}
        members,unknown=safe_namespace_members(scopefd)
        if case=='census-error':
            result['injected_census_error_locks_held']=[held(path) for path in lockpaths]
            _,unknown=safe_namespace_members(scopefd,inject_failure=True)
        result['namespace_census_before_cancel']=members;result['namespace_census_unknown']=unknown
        if unknown:raise RuntimeError('Cannot establish full owned namespace membership')
        result['namespace_tree']=guardians
        result['source_bound_peer_revalidated']=identity(peer[0])['starttime']==initial['starttime'] and source_hash()==expected_request['source_sha256']
        if not result['source_bound_peer_revalidated']:raise RuntimeError('Peer/source identity changed before handoff proof')
        proof=[fd for item in guardians if item['role']=='namespace-init' for fd in item['lock_fds']]
        if {fd['inode'] for fd in proof}!={entry['inode'] for entry in envelope['locks']} or not all('FLOCK' in fd['fdinfo'] for fd in proof):raise RuntimeError('Actual guardian FD/FLOCK proof failed')
        result['host_originals_before_cancel']=[file_metadata(fd) for fd in fds]
        result['locks_before_outer_kill']=[held(p) for p in lockpaths]
        # Disposable topology test: killing exact outer monitor invokes its
        # PDEATHSIG namespace kill cascade. This is NOT a gentle writer stop.
        process.kill();process.wait(timeout=3)
        drain=time.monotonic()+3
        while time.monotonic()<drain:
            alive=[item for pid in tracked if (item:=identity(pid)) is not None and item['state']!='Z']
            if scopefd is not None:
                scoped,unknown=safe_namespace_members(scopefd)
                alive+=scoped
                if unknown:result['namespace_census_unknown']=unknown;raise RuntimeError('Cannot prove namespace drain')
            if not alive:break
            time.sleep(.01)
        result['live_namespace_after_outer_kill']=alive;result['locks_held_by_host_after_namespace_drain']=[held(p) for p in lockpaths]
        if alive or not all(result['locks_held_by_host_after_namespace_drain']):raise RuntimeError('Host reservation or namespace drain failed')
        for fd in fds:os.close(fd)
        fds=[];result['locks_after_host_close']=[held(p) for p in lockpaths]
        if any(result['locks_after_host_close']):raise RuntimeError('Unexpected lingering public descriptor')
        result['status']='passed'
    except BaseException as error:
        result.update(error=str(error),traceback=traceback.format_exc())
        if case=='census-error' and str(error)=='Cannot establish full owned namespace membership':result['status']='passed_expected_census_failure'
        if case in REFUSAL_CASES and result.get('refusal_before_descriptor_transfer') and str(error) in ('Single job request mismatch','Request packet truncated or contained unexpected ancillary data'):result['status']='passed_expected_refusal'
    finally:
        if conn:conn.close()
        if server:server.close()
        if process and process.poll() is None:
            tracked.update([process.pid,*descendants(process.pid)]);process.kill()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:result['cleanup_error']='Outer monitor cleanup incomplete'
        cleanup=time.monotonic()+3
        while time.monotonic()<cleanup:
            alive=[item for pid in tracked if (item:=identity(pid)) is not None and item['state']!='Z']
            if not alive:break
            time.sleep(.01)
        if scopefd is not None:
            scoped,unknown=safe_namespace_members(scopefd);alive+=scoped
            result['cleanup_namespace_census_unknown']=unknown
        else:unknown=[]
        result['cleanup_live_namespace']=alive if tracked else []
        if alive or unknown:
            result['status']='failed';result['reservation_teardown_pending']=True
            (OUT/('public-'+case+'-report.json')).write_text(json.dumps(result,indent=2)+'\n')
            print('Public reservation teardown pending; host FD copies remain genuinely held.',flush=True)
            while alive or unknown:
                time.sleep(.1)
                if scopefd is not None:alive,unknown=safe_namespace_members(scopefd)
                else:alive=[item for pid in tracked if (item:=identity(pid)) is not None and item['state']!='Z'];unknown=[]
            result['pending_reservation_eventually_drained']=True
            result['cleanup_live_namespace']=[]
        if result['cleanup_live_namespace']:
            result['status']='failed';result['unqualified'].append('Namespace drain unresolved; public host reservation retained until process exit.')
        # Public only: never LOCK_UN; descriptors close after observed drain.
        if not result['cleanup_live_namespace']:
            for fd in fds:os.close(fd)
            fds=[]
        if peerfd is not None:os.close(peerfd)
        if scopefd is not None:os.close(scopefd)
        result['stdout']=bounded(d/'outer.stdout').decode(errors='replace') if (d/'outer.stdout').exists() else ''
        if not result['cleanup_live_namespace']:
            for path in d.iterdir():path.unlink()
            d.rmdir();result['socket_directory_removed']=not d.exists()
        result['elapsed_seconds']=time.monotonic()-started
    result['source_inventory_before']=before;result['source_inventory_after']=source_inventory();result['source_inventory_unchanged']=before==result['source_inventory_after']
    if not result['source_inventory_unchanged']:result['status']='failed';result['unqualified'].append('Concurrent source inventory change prevents noninterference qualification.')
    result['source_sha256']=source_hash();result['bwrap_sha256']=hashlib.sha256(Path('/usr/bin/bwrap').read_bytes()).hexdigest()
    (OUT/('public-'+case+'-report.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'error':result.get('error'),'source_inventory_unchanged':result['source_inventory_unchanged'],'elapsed_seconds':result['elapsed_seconds']}))
    return result['status'] in ('passed','passed_expected_refusal','passed_expected_census_failure')
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);mode=parser.add_mutually_exclusive_group(required=True);mode.add_argument('--public-self-test',action='store_true');mode.add_argument('--public-client');parser.add_argument('--case',choices=CASES,default='normal')
    args=parser.parse_args()
    if args.public_client:client(args.public_client,args.case)
    else:raise SystemExit(0 if host(args.case) else 1)
