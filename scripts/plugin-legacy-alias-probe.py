#!/usr/bin/python3
"""Explicit fresh PUBLIC-only kernel MS_BIND feasibility; no retained mode or checks."""
import argparse,ctypes,fcntl,hashlib,importlib.util,json,os,signal,stat,subprocess,tempfile,time,traceback
from pathlib import Path
ROOT=Path('/home/luis/progress-checker');SOURCE=Path(__file__).resolve()
ENV={'HOME':'/tmp','LANG':'C.UTF-8','PATH':'/usr/bin:/bin'}
CLONE_NEWUSER=0x10000000;CLONE_NEWNS=0x20000;MS_BIND=4096;MS_REC=16384;MS_PRIVATE=1<<18

def caps():
    return {line.split(':',1)[0]:line.split(':',1)[1].strip() for line in Path('/proc/self/status').read_text().splitlines() if line.startswith(('CapEff:','CapPrm:','CapBnd:','CapAmb:'))}

def identity(fd):
    s=os.fstat(fd);return {'device':s.st_dev,'inode':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'regular':stat.S_ISREG(s.st_mode),'links':s.st_nlink,'flags':fcntl.fcntl(fd,fcntl.F_GETFL)}

def syscall(lib,name,*args):
    ctypes.set_errno(0);v=getattr(lib,name)(*args)
    if v:raise OSError(ctypes.get_errno(),name+': '+os.strerror(ctypes.get_errno()))

def drop_caps(lib):
    # No product payload is started; still prove setup privileges are discarded.
    for cap in range(41):
        ctypes.set_errno(0)
        if lib.prctl(24,cap,0,0,0) and ctypes.get_errno()!=22:raise OSError(ctypes.get_errno(),'PR_CAPBSET_DROP')
    class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
    class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
    h=Header(0x20080522,0);d=(Data*2)();syscall(lib,'capset',ctypes.byref(h),ctypes.byref(d));syscall(lib,'prctl',47,4,0,0,0)

def child(a):
    report={'status':'failed','scope':'public kernel mount feasibility only; no guest Store/check/grant','source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'outer_uid':os.getuid(),'outer_gid':os.getgid(),'original_fd_before_unshare':identity(a.fd),'source_readlink':os.readlink('/proc/self/fd/'+str(a.fd)),'source_visible_outer':Path(os.readlink('/proc/self/fd/'+str(a.fd))).exists()}
    lib=ctypes.CDLL(None,use_errno=True);parent=None;target=None;alias=None;directory=None
    try:
        if report['outer_uid']!=1000 or report['outer_gid']!=1000:raise RuntimeError('Invoking outer identity mismatch')
        expected=json.loads(a.expected)
        before=report['original_fd_before_unshare']
        if [before['device'],before['inode']]!=expected or before['mode']!=0o600 or before['uid']!=1000 or before['links']!=1 or not before['regular'] or not before['flags']&os.O_PATH:raise RuntimeError('Original public core mount role mismatch')
        oldmnt=Path('/proc/self/ns/mnt').stat().st_ino;olduser=Path('/proc/self/ns/user').stat().st_ino
        syscall(lib,'unshare',CLONE_NEWUSER|CLONE_NEWNS)
        Path('/proc/self/setgroups').write_text('deny\n');Path('/proc/self/uid_map').write_text('0 1000 1\n');Path('/proc/self/gid_map').write_text('0 1000 1\n')
        report.update(uid=os.getuid(),gid=os.getgid(),uid_map=Path('/proc/self/uid_map').read_text(),gid_map=Path('/proc/self/gid_map').read_text(),setup_caps=caps(),original_fd_in_setup=identity(a.fd))
        report['fresh_namespace_identities']={'old_mnt':oldmnt,'new_mnt':Path('/proc/self/ns/mnt').stat().st_ino,'old_user':olduser,'new_user':Path('/proc/self/ns/user').stat().st_ino}
        if os.getuid()!=0 or oldmnt==report['fresh_namespace_identities']['new_mnt'] or olduser==report['fresh_namespace_identities']['new_user']:raise RuntimeError('Fresh namespace identity rejected')
        syscall(lib,'mount',None,b'/',None,ctypes.c_ulong(MS_REC|MS_PRIVATE),None);report['private_propagation_set']=True
        directory=Path(tempfile.mkdtemp(prefix='pc-public-alias-',dir='/tmp'));directory.chmod(0o700)
        parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        target=os.open('core-alias',os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600,dir_fd=parent)
        report['fresh_parent']={'uid':os.fstat(parent).st_uid,'mode':stat.S_IMODE(os.fstat(parent).st_mode)};report['target_before']=identity(target)
        if report['fresh_parent']!={'uid':0,'mode':0o700}:raise RuntimeError('Fresh alias parent rejected')
        src=('/proc/self/fd/'+str(a.fd)).encode();dest=('/proc/self/fd/'+str(target)).encode()
        report['mount_call']={'source':src.decode(),'destination':dest.decode(),'flags':MS_BIND,'filesystem':None,'data':None}
        ctypes.set_errno(0);result=lib.mount(src,dest,None,ctypes.c_ulong(MS_BIND),None);err=ctypes.get_errno()
        report['mount_result']={'return':result,'errno':err,'error':os.strerror(err) if err else None}
        if result:
            report['status']='unqualified';report['conclusion']='Kernel rejected foreign original O_PATH bind; no fallback or later Store phase attempted'
        else:
            alias=os.open('core-alias',os.O_PATH|os.O_NOFOLLOW,dir_fd=parent);info=identity(alias);report['alias_reopened']=info
            if [info['device'],info['inode']]!=expected or not info['regular'] or info['mode']!=0o600 or info['uid']!=0:raise RuntimeError('Alias mount is not exact original core inode')
            report['alias_readlink']=os.readlink('/proc/self/fd/'+str(alias));report['alias_path_visible']=Path(report['alias_readlink']).exists()
            if not report['alias_path_visible']:raise RuntimeError('Reopened alias remains invisible to builder')
            report['status']='mount-gate-passed';report['conclusion']='Exact alias mount feasible; curated guest mount/actual Store normal/race remain unqualified and unexecuted'
    except BaseException as e:report.update(status='failed',error=str(e),traceback=traceback.format_exc())
    finally:
        if report.get('fresh_namespace_identities'):
            try:drop_caps(lib);report['after_setup_caps']=caps()
            except BaseException as e:report.update(status='failed',cap_cleanup_error=str(e))
        for fd in (alias,target,parent,a.fd):
            if fd is not None:
                try:os.close(fd)
                except OSError:pass
        # Namespace teardown discards any alias; no host mount or pathname unlink RPC.
        Path(a.output).write_text(json.dumps(report,indent=2)+'\n')
    return 0 if report['status']=='mount-gate-passed' else 2

def host(a):
    proposed=a.output.absolute();allowed=ROOT/'.local/plugin-validation/shared-inode-v2'
    if '..' in proposed.parts or not proposed.is_relative_to(allowed) or any(p.is_symlink() for p in (proposed,*proposed.parents)):raise ValueError('Output must be a new nonsymlink dedicated shared-inode-v2 report path')
    out=proposed.resolve();out.mkdir(parents=True,exist_ok=False)
    spec=importlib.util.spec_from_file_location('public',ROOT/'scripts/plugin-shared-inode-probe.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    r={'status':'failed','scope':'fresh public actual404 canonical core lock only; original fixtures/state/grants never selected','source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'helper_sha256':m.sha(ROOT/'scripts/plugin-shared-inode-probe.py'),'archive_sha256':m.sha(m.ARCHIVE)}
    d=Path(tempfile.mkdtemp(prefix='alias-',dir=ROOT/'.local/rs'));root=d/'p';state=d/'s';root.mkdir();state.mkdir(mode=0o700);(root/'.progress-checker').mkdir()
    config={'schema_version':1,'project_id':'public-legacy-alias','enabled':True,'panel':{'show_on_start':True},'execution':{'max_parallel':1,'default_timeout_seconds':5},'fingerprint':{'extra_inputs':[],'exclude_outputs':[]},'checks':[{'id':'never-run','argv':['/usr/bin/true'],'cwd':'.','kind':'test','timeout_seconds':5}],'milestones':[{'id':'fixture','title':'Public mount only','in_scope':True,'depends_on':[],'criteria':[{'id':'unused','description':'Never approved or requested','check_id':'never-run','required':True}]}]}
    (root/'.progress-checker/config.json').write_text(json.dumps(config));subprocess.run(['/usr/bin/git','init','--quiet',str(root)],check=True)
    binary=d/'checker';m.extract(binary);p=None;outer=None;held=None;mountfd=None
    try:
        with (out/'host-service.log').open('wb') as log:p=subprocess.Popen([str(binary),'--root',str(root),'--state-dir',str(state),'serve'],stdout=log,stderr=log)
        end=time.monotonic()+15
        while time.monotonic()<end:
            cp=subprocess.run([str(binary),'--root',str(root),'--state-dir',str(state),'status'],capture_output=True,timeout=5)
            if cp.returncode==0:
                v=json.loads(cp.stdout)
                if v['latest'] or v['progress']['verified']:raise RuntimeError('Unexpected fresh evidence')
                r['actual_status_snapshot']=v;break
            if p.poll() is not None:raise RuntimeError('Actual host Store startup failed')
            time.sleep(.05)
        else:raise TimeoutError('Actual host Store startup')
        m.gentle(p);r['host_service_exit']=p.returncode
        if p.returncode:raise RuntimeError('Actual host Store gentle exit failed')
        lock=m.core_path(root);held=os.open(lock,os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB);mountfd=os.open(lock,os.O_PATH|os.O_NOFOLLOW)
        r['host_core_lock']=identity(mountfd);r['host_core_path']=str(lock);expected=[r['host_core_lock']['device'],r['host_core_lock']['inode']]
        argv=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--bind',str(ROOT),str(ROOT),'--chdir',str(ROOT),'--','/usr/bin/python3',str(SOURCE),'--child','--fd',str(mountfd),'--expected',json.dumps(expected),'--output',str(out/'kernel-report.json')]
        r['outer_argv']=argv;r['outer_environment']=ENV;r['descriptor_topology_limitation']='Extra inherited original O_PATH public test role; no production SCM equivalence'
        with (out/'outer.log').open('wb') as log:outer=subprocess.Popen(argv,env=ENV,pass_fds=(mountfd,),stdout=log,stderr=log)
        outer.wait(timeout=25);r['outer_exit']=outer.returncode
        child_report=json.loads((out/'kernel-report.json').read_text());r['kernel_report']=child_report
        r['status']=child_report['status'];r['held_original_core_through_setup_and_exit']=True
        if outer.returncode not in (0,2):r['status']='failed';r['error']='Unexpected outer exit'
    except BaseException as e:r.update(status='failed',error=str(e),traceback=traceback.format_exc())
    finally:
        if outer and outer.poll() is None:
            r['cleanup_actions']=['owned outer Popen.terminate']
            outer.terminate()
            try:outer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                r['status']='failed';r['cleanup_actions'].append('owned outer Popen.kill')
                outer.kill()
                try:outer.wait(timeout=5)
                except subprocess.TimeoutExpired:r['cleanup_error']='Owned public namespace not reaped after kill; no retained reservation claim'
            r['cleanup_terminal_return']=outer.poll()
        if p and p.poll() is None:
            try:m.gentle(p)
            except BaseException as e:r['status']='failed';r['cleanup_error']=str(e)
        for fd in (mountfd,held):
            if fd is not None:os.close(fd)
        r['fixture_retained']=str(d);(out/'report.json').write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({'status':r['status'],'output':str(out),'error':r.get('error')}));return 0 if r['status']=='mount-gate-passed' else 2

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--public-self-test',action='store_true');p.add_argument('--child',action='store_true');p.add_argument('--fd',type=int);p.add_argument('--expected');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.child:raise SystemExit(child(a))
    if not a.public_self_test:p.error('Explicit public-self-test required')
    raise SystemExit(host(a))
