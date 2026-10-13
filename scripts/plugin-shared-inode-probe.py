#!/usr/bin/python3
"""PUBLIC disposable-only same-core-inode protocol-v2 rehearsal; never grants checks."""
import argparse,fcntl,hashlib,importlib.util,json,os,pwd,signal,stat,subprocess,sys,tarfile,tempfile,time,traceback
from pathlib import Path
ROOT=Path('/home/luis/progress-checker')
ARCHIVE=ROOT/'.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz'
SHA='404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
ENV={'HOME':'/tmp','LANG':'C.UTF-8','PATH':'/usr/bin:/bin'}

def sha(p):
    if p.stat().st_size>64*1024*1024:raise ValueError('Bounded input required')
    return hashlib.sha256(p.read_bytes()).hexdigest()

def wait_file(p,timeout=30,process=None):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if p.exists():return json.loads(p.read_text())
        if process is not None and process.poll() is not None:raise RuntimeError('Public namespace exited before coordination: '+str(process.returncode))
        time.sleep(.05)
    raise TimeoutError('Public coordination deadline: '+str(p))

def core_path(root):
    key=hashlib.sha256(json.dumps(str(root),ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    r=Path('/run/user')/str(os.getuid())
    valid=r.is_dir() and r.stat().st_uid==os.getuid() and stat.S_IMODE(r.stat().st_mode)==0o700
    base=r if valid else Path(pwd.getpwuid(os.getuid()).pw_dir)/'.local/state'
    return base/'progress-checker-locks'/(key+'.lock')

def extract(binary):
    if sha(ARCHIVE)!=SHA:raise ValueError('Archive pin mismatch')
    with tarfile.open(ARCHIVE) as t:
        m=[x for x in t.getmembers() if x.name.endswith('/bin/progress-checker')]
        if len(m)!=1 or not m[0].isfile() or m[0].size>32*1024*1024:raise ValueError('ELF inventory')
        binary.write_bytes(t.extractfile(m[0]).read());binary.chmod(0o755)

def gentle(p):
    if p and p.poll() is None:p.terminate();p.wait(timeout=10)

def guest():
    parser=argparse.ArgumentParser();parser.add_argument('--fixture-root',type=Path);parser.add_argument('--fixture-state',type=Path)
    a,_=parser.parse_known_args();out=Path('/results');root=a.fixture_root;state=a.fixture_state
    extract_guest=Path('/r/checker')
    with tarfile.open('/inputs/new.tar.gz') as t:
        m=[x for x in t.getmembers() if x.name.endswith('/bin/progress-checker')][0]
        extract_guest.write_bytes(t.extractfile(m).read());extract_guest.chmod(0o755)
    key=hashlib.sha256(json.dumps(str(root),ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    lock=Path('/r/.local/state/progress-checker-locks')/(key+'.lock');info=lock.stat()
    r={'upgrade_archive_sha256':SHA,'status':'failed','guest_uid':os.getuid(),'uid_map':Path('/proc/self/uid_map').read_text(),
       'passwd_home':pwd.getpwuid(os.getuid()).pw_dir,'run_user0_present':Path('/run/user/0').exists(),
       'stable_parent_mode':stat.S_IMODE(lock.parent.stat().st_mode),'stable_parent_owner':lock.parent.stat().st_uid,
       'mount_inode':[info.st_dev,info.st_ino],'mount_owner':info.st_uid,'mount_mode':stat.S_IMODE(info.st_mode),
       'limitations':['Test mapped-root namespace sole CAP_SETFCAP; not normal nonroot equivalence','Abrupt outer teardown cannot guarantee gentle writer stop']}
    if r['guest_uid']!=0 or r['passwd_home']!='/r' or r['run_user0_present'] or r['stable_parent_mode']!=0o700 or r['mount_owner']!=0 or r['mount_mode']!=0o600 or r['stable_parent_owner']!=0:raise RuntimeError('Stable selector attestation rejected')
    (out/'mount-ready.json').write_text(json.dumps(r))
    go=wait_file(out/'go.json');p=None
    try:
        with (out/'service.log').open('wb') as log:p=subprocess.Popen([str(extract_guest),'--root',str(root),'--state-dir',str(state),'serve'],stdout=log,stderr=log)
        if go['case']=='race':
            p.wait(timeout=10);r['race_exit']=p.returncode;r['race_refusal']=(p.returncode!=0 and 'another checker' in (out/'service.log').read_text().lower())
            if not r['race_refusal']:raise RuntimeError('Host winner did not cause real Store refusal')
        else:
            end=time.monotonic()+20
            while time.monotonic()<end:
                cp=subprocess.run([str(extract_guest),'--root',str(root),'--state-dir',str(state),'status'],capture_output=True,timeout=5)
                if cp.returncode==0:
                    v=json.loads(cp.stdout);break
                if p.poll() is not None:raise RuntimeError('Guest Store startup failed')
                time.sleep(.05)
            else:raise TimeoutError('Guest status API startup')
            if v['latest'] or v['progress']['verified']:raise RuntimeError('Unexpected fresh evidence')
            fds=[]
            for fd in (Path('/proc')/str(p.pid)/'fd').iterdir():
                try:
                    st=fd.stat();fi=(Path('/proc')/str(p.pid)/'fdinfo'/fd.name).read_text()
                    if (st.st_dev,st.st_ino)==tuple(r['mount_inode']):fds.append({'fd':fd.name,'inode':[st.st_dev,st.st_ino],'fdinfo':fi})
                except FileNotFoundError:continue
            r['actual_core_fds']=fds
            if not any('FLOCK' in x['fdinfo'] for x in fds):raise RuntimeError('Actual core locked FD absent')
            r['status_snapshot']=v
            (out/'writer-ready.json').write_text(json.dumps(r))
            wait_file(out/'stop.json');gentle(p);r['service_exit']=p.returncode
            if p.returncode:raise RuntimeError('Gentle Store exit failed')
        r['status']='passed'
    except BaseException as e:r['error']=str(e);r['traceback']=traceback.format_exc()
    finally:
        if p and p.poll() is None:
            try:gentle(p)
            except BaseException as e:r['cleanup_error']=str(e);r['status']='failed'
        (out/'report.json').write_text(json.dumps(r,indent=2))
    return 0 if r['status']=='passed' else 2


def client(args):
    spec=importlib.util.spec_from_file_location('runtime',ROOT/'scripts/plugin-sandbox-recipient.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    actual=subprocess.Popen
    def mapped(argv,*a,**kw):
        if isinstance(argv,list) and argv[:1]==['/usr/bin/bwrap']:
            key=hashlib.sha256(json.dumps(args.root,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()+'.lock'
            insert=['--dir','/r/.local','--dir','/r/.local/state','--perms','0700','--dir','/r/.local/state/progress-checker-locks','--bind-fd',str(args.mount_fd),'/r/.local/state/progress-checker-locks/'+key]
            argv=argv[:];ix=argv.index('--');argv[ix:ix]=insert;kw['pass_fds']=(args.mount_fd,)
        return actual(argv,*a,**kw)
    m.subprocess.Popen=mapped
    st=os.fstat(args.mount_fd);target=os.readlink('/proc/self/fd/'+str(args.mount_fd))
    (Path(args.output)/'mount-fd-attestation.json').write_text(json.dumps({'device':st.st_dev,'inode':st.st_ino,'mode':stat.S_IMODE(st.st_mode),'fd_flags':fcntl.fcntl(args.mount_fd,fcntl.F_GETFL),'readlink':target,'resolved_target_visible_in_outer':Path(target).exists()}))
    # qualify requires empty output: move this public metadata to sibling parent.
    (Path(args.output)/'mount-fd-attestation.json').rename(Path(args.output).parent/'mount-fd-attestation.json')
    try:m.qualify(ARCHIVE,None,Path(__file__),output=Path(args.output),timeout=150,_public_fixture=(Path(args.root),Path(args.state)))
    finally:os.close(args.mount_fd)


def host(case,output):
    output.mkdir(parents=True,exist_ok=False);r={'status':'failed','case':case,'protocol':'v2 O_PATH mount-only core role; host locked OFD never transferred','source_sha256':sha(Path(__file__)),'archive_sha256':sha(ARCHIVE),'retained_fixture_access':False}
    base=ROOT/'.local/rs';base.mkdir(exist_ok=True)
    d=Path(tempfile.mkdtemp(prefix='inode-',dir=base));root=d/'p';hs=d/'hs';gs=d/'gs';root.mkdir();hs.mkdir(mode=0o700);gs.mkdir(mode=0o700)
    (root/'.public-runtime-fixture').write_text('Public disposable same-inode fixture');(root/'.progress-checker').mkdir()
    config={'schema_version':1,'project_id':'public-same-inode','enabled':True,'panel':{'show_on_start':True},'execution':{'max_parallel':1,'default_timeout_seconds':5},'fingerprint':{'extra_inputs':[],'exclude_outputs':[]},'checks':[{'id':'never-run','argv':['/usr/bin/true'],'cwd':'.','kind':'test','timeout_seconds':5}],'milestones':[{'id':'fixture','title':'Public Store lock only','in_scope':True,'depends_on':[],'criteria':[{'id':'unused','description':'Never approved or requested','check_id':'never-run','required':True}]}]}
    (root/'.progress-checker/config.json').write_text(json.dumps(config));subprocess.run(['/usr/bin/git','init','--quiet',str(root)],check=True)
    binary=d/'checker';extract(binary);p=None;outer=None;lockfd=None;mountfd=None;racefd=None
    try:
        with (output/'host-service.log').open('wb') as log:p=subprocess.Popen([str(binary),'--root',str(root),'--state-dir',str(hs),'serve'],stdout=log,stderr=log)
        end=time.monotonic()+15
        while time.monotonic()<end:
            cp=subprocess.run([str(binary),'--root',str(root),'--state-dir',str(hs),'status'],capture_output=True,timeout=5)
            if cp.returncode==0:break
            if p.poll() is not None:raise RuntimeError('Host actual Store startup failed')
            time.sleep(.05)
        else:raise TimeoutError('Host Store startup')
        gentle(p);r['host_service_exit']=p.returncode
        if p.returncode:raise RuntimeError('Host Store gentle exit failed')
        lock=core_path(root);st=lock.stat();r['host_core_path']=str(lock);r['host_core_inode']=[st.st_dev,st.st_ino]
        if st.st_uid!=1000 or stat.S_IMODE(st.st_mode)!=0o600:raise RuntimeError('Existing actual Store lock metadata')
        lockfd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        mountfd=os.open(lock,os.O_PATH|os.O_NOFOLLOW)
        if (os.fstat(mountfd).st_dev,os.fstat(mountfd).st_ino)!=(st.st_dev,st.st_ino):raise RuntimeError('Mount FD inode changed')
        nested=output/'guest';nested.mkdir()
        argv=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--bind',str(ROOT),str(ROOT),'--chdir',str(ROOT),'--','/usr/bin/python3',str(Path(__file__).resolve()),'--client','--root',str(root),'--state',str(gs),'--output',str(nested),'--mount-fd',str(mountfd)]
        r['outer_argv']=argv;r['outer_environment']=ENV
        with (output/'outer.log').open('wb') as log:outer=subprocess.Popen(argv,env=ENV,pass_fds=(mountfd,),stdout=log,stderr=log)
        mounted=wait_file(nested/'mount-ready.json',100,outer)
        if mounted['mount_inode']!=r['host_core_inode']:raise RuntimeError('Guest mounted different inode')
        os.close(lockfd);lockfd=None;r['old_locked_ofd_closed_before_guest_start']=True
        if case=='race':racefd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(racefd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        (nested/'go.json').write_text(json.dumps({'case':case}))
        if case=='normal':
            writer=wait_file(nested/'writer-ready.json');r['guest_writer']=writer
            contender=os.open(lock,os.O_RDWR|os.O_NOFOLLOW)
            try:
                try:fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB);raise RuntimeError('Host contender acquired guest-owned lock')
                except BlockingIOError:r['host_contender_blocked']=True
            finally:os.close(contender)
            (nested/'stop.json').write_text('{}')
        outer.wait(timeout=40)
        if outer.returncode:raise RuntimeError('Outer public helper failed: '+(output/'outer.log').read_text())
        guest_report=json.loads((nested/'report.json').read_text());r['guest_report']=guest_report
        if guest_report['status']!='passed':raise RuntimeError('Guest report failed')
        if racefd is not None:os.close(racefd);racefd=None
        contender=os.open(lock,os.O_RDWR|os.O_NOFOLLOW)
        try:fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB);r['after_gentle_exit_unlocked']=True
        finally:os.close(contender)
        r['status']='passed'
    except BaseException as e:r['error']=str(e);r['traceback']=traceback.format_exc()
    finally:
        if outer and outer.poll() is None:
            outer.terminate()
            try:outer.wait(timeout=10)
            except subprocess.TimeoutExpired:r['cleanup_error']='Outer still alive; public fixture retained'
        if p and p.poll() is None:
            try:gentle(p)
            except BaseException as e:r['cleanup_error']=str(e);r['status']='failed'
        for fd in (lockfd,mountfd,racefd):
            if fd is not None:os.close(fd)
        r['fixture_retained']=str(d);(output/'report.json').write_text(json.dumps(r,indent=2))
    print(json.dumps({'status':r['status'],'error':r.get('error'),'output':str(output)}))
    return 0 if r['status']=='passed' else 2

if __name__=='__main__':
    if '--fixture-root' in sys.argv:sys.exit(guest())
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--public-self-test',action='store_true');p.add_argument('--case',choices=['normal','race'],default='normal');p.add_argument('--output',type=Path,required=True);p.add_argument('--client',action='store_true');p.add_argument('--root');p.add_argument('--state');p.add_argument('--mount-fd',type=int);a=p.parse_args()
    if a.client:client(a)
    elif a.public_self_test:sys.exit(host(a.case,a.output.resolve()))
    else:p.error('Explicit public-self-test required')
