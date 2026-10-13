#!/usr/bin/env python3
"""OFF by default: independently initiated actual-primary native workflow.

A reader can only consume one fresh live raw buffer after workflow completion;
it cannot initiate or control a workflow. No approval frontend, auth copy or
private-state edit exists here. Root must review before --produce execution.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import re
import signal
import socket
import stat
import struct
import threading
import time

ROOT=Path(__file__).resolve().parent.parent
CODEX_PROFILE=Path('/home/luis/.codex')
STATE=Path('/home/luis/.local/share/progress-checker')
CACHE=CODEX_PROFILE/'plugins/cache/progress-local-8b5742430514/progress-checker/0.2.1-dev'
SOURCE=Path('/home/luis/.local/share/progress-checker-plugins/8b5742430514/plugins/progress-checker')
RUNTIME=STATE/'plugin-8b5742430514e5c52baf368b'
SELECTOR='progress-checker@progress-local-8b5742430514'
CODEX=Path('/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex')
LIMIT=8*1024*1024


def load(path):
    import importlib.util
    spec=importlib.util.spec_from_file_location(path.stem.replace('-','_'),path)
    result=importlib.util.module_from_spec(spec);data=path.read_bytes();exec(compile(data,str(path),'exec'),result.__dict__);result.loaded_source_sha256=hashlib.sha256(data).hexdigest();result.loaded_source_path=str(path);return result


class SourceCAS:
    def __init__(self,driver,path):
        self.driver,self.path=driver,path
        self.original=driver.regular(path,1024*1024);self.owned=self.original
        info=path.lstat()
        if info.st_nlink!=1 or info.st_mode&0o022:raise RuntimeError('README CAS needs owned unshared regular source')
        self.identity=(info.st_dev,info.st_ino,stat.S_IMODE(info.st_mode))
    def write(self,expected,replacement):
        if self.driver.regular(self.path,1024*1024)!=expected:raise RuntimeError('README CAS refused concurrent bytes')
        fd=os.open(self.path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);info=os.fstat(fd)
            if (info.st_dev,info.st_ino,stat.S_IMODE(info.st_mode))!=self.identity or os.read(fd,1024*1024+1)!=expected or (self.path.lstat().st_dev,self.path.lstat().st_ino)!=self.identity[:2]:raise RuntimeError('README CAS identity changed')
            os.lseek(fd,0,os.SEEK_SET);offset=0
            while offset<len(replacement):
                count=os.write(fd,replacement[offset:])
                if count<=0:raise RuntimeError('README partial write')
                offset+=count;self.owned=replacement[:offset]+expected[offset:]
            os.ftruncate(fd,len(replacement));self.owned=replacement;os.fsync(fd)
        finally:os.close(fd)
    def restore(self):
        if self.owned!=self.original:self.write(self.owned,self.original)


class Buffer:
    def __init__(self,nonce):self.raw=bytearray();self.sequence=0;self.previous='0'*64;self.nonce=nonce
    def add(self,kind,phase,value):
        self.sequence+=1
        item={'schema_version':1,'nonce':self.nonce,'seq':self.sequence,'collected_monotonic_ns':time.monotonic_ns(),'type':kind.replace('-','_'),'phase':phase,'data':value,'previous_sha256':self.previous}
        item['sha256']=hashlib.sha256(json.dumps(item,separators=(',',':')).encode()).hexdigest()
        line=json.dumps(item,separators=(',',':')).encode()+b'\n'
        if len(self.raw)+len(line)>LIMIT:raise RuntimeError('Live raw buffer exceeds8MiB')
        self.previous=hashlib.sha256(line).hexdigest();self.raw.extend(line)


def successful(call):
    structured=(call.get('result') or {}).get('structured_content') or {}
    return call.get('status')=='completed' and call.get('error') is None and 'error' not in structured and 'result' in structured


def protection_snapshot(driver,protected,packages,report,phase,modules=None):
    """Retain path/hash/mode-only comparisons; no protected contents enter reports."""
    hashes={};inventories={};mismatches=[]
    for path,before in protected.items():
        try:
            after=driver.digest(Path(path));hashes[path]=after
            if after!=before:mismatches.append({'scope':'protected','path':path,'before_sha256':before,'after_sha256':after})
        except Exception as error:
            mismatches.append({'scope':'protected','path':path,'before_sha256':before,'kind':'unavailable','error_type':type(error).__name__})
    for name,path in [('cache',CACHE),('source',SOURCE)]:
        before=packages[name]
        try:
            after=driver.inventory(path);inventories[name]=after
            for relative in sorted(set(before)|set(after)):
                if before.get(relative)!=after.get(relative):
                    mismatches.append({'scope':name,'path':str(path/relative),
                        'kind':'added' if relative not in before else 'removed' if relative not in after else 'changed',
                        'before':before.get(relative),'after':after.get(relative)})
        except Exception as error:
            mismatches.append({'scope':name,'path':str(path),'kind':'unavailable','error_type':type(error).__name__})
    if modules is not None:
        for path,before in modules.items():
            try:
                after=driver.digest(Path(path))
                if after!=before:mismatches.append({'scope':'module','path':path,'before_sha256':before,'after_sha256':after})
            except Exception as error:
                mismatches.append({'scope':'module','path':path,'before_sha256':before,'kind':'unavailable','error_type':type(error).__name__})
    report.setdefault('protection_checks',[]).append({'phase':phase,'protected_hashes':hashes,
        'package_inventory_sha256':{name:hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest() for name,value in inventories.items()},
        'mismatches':mismatches})
    return hashes,mismatches


def final_audit_report(audit,report):
    """An unavailable audit stays partial and cannot replace the original failure."""
    if audit is None:
        report['final_audit']={'status':'unavailable','complete':False,'reason':'Workflow stopped before final audit was defined'}
        report['status']='failed'
        return
    try:report['final_audit']=audit()
    except BaseException as error:
        report['final_audit_error']=repr(error);report['status']='failed'


def actor_image(runner,driver,pid):
    """Capture a stable owned public process image, including its exact command."""
    before=runner.process_identity(pid);snapshot=runner.fixture_process_snapshot(pid)
    if not before or snapshot.get('state') in (None,'Z','X','x') or snapshot.get('starttime')!=before['starttime']:
        raise RuntimeError('Legacy actor absent or identity changed during census')
    argv=snapshot.get('command',[])
    if argv[-1:]==['']:argv=argv[:-1]
    image={'identity':before,'exe_sha256':driver.digest(Path(f'/proc/{pid}/exe')),
           'argv':argv,'ppid':snapshot['ppid']}
    if runner.process_identity(pid)!=before:raise RuntimeError('Legacy actor raced public census')
    return image


def launcher_thread_children(pid):
    """Read every launcher thread's bounded children file with a stable task roster."""
    task_root=Path('/proc')/str(pid)/'task'
    def tasks():
        names=sorted(entry.name for entry in task_root.iterdir())
        if not names or len(names)>128 or any(not re.fullmatch('[1-9][0-9]*',name) for name in names):
            raise RuntimeError('Unknown or oversized launcher task census')
        return names
    before=tasks()
    def read():
        result={}
        for tid in before:
            fd=os.open(task_root/tid/'children',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            try:
                data=bytearray()
                while len(data)<=16384:
                    chunk=os.read(fd,16385-len(data))
                    if not chunk:break
                    data.extend(chunk)
                if len(data)>16384:raise RuntimeError('Launcher thread children exceed bound')
            finally:os.close(fd)
            values=data.decode('ascii').split()
            if any(not re.fullmatch('[1-9][0-9]*',value) for value in values):raise RuntimeError('Malformed launcher thread children')
            children=[int(value) for value in values]
            if len(children)!=len(set(children)):raise RuntimeError('Duplicate launcher thread child')
            result[tid]=children
        return result
    first=read()
    if tasks()!=before:raise RuntimeError('Launcher task roster changed')
    if read()!=first or tasks()!=before:raise RuntimeError('Launcher thread children changed during census')
    children=[child for values in first.values() for child in values]
    if len(children)!=len(set(children)):raise RuntimeError('Launcher child ownership raced between threads')
    return first,children


def actor_children(runner,driver,pid,image):
    """An unavailable parent census is unknown, never an empty child list."""
    snapshot=runner.fixture_process_snapshot(pid)
    argv=snapshot.get('command',[])
    if argv[-1:]==['']:argv=argv[:-1]
    children=snapshot.get('children')
    if snapshot.get('pid')!=pid or snapshot.get('state') in (None,'Z','X','x') or snapshot.get('starttime')!=image['identity']['starttime'] or snapshot.get('ppid')!=image['ppid'] or argv!=image['argv'] or type(children) is not list or any(type(child) is not int or child<=0 for child in children) or len(children)!=len(set(children)):
        raise RuntimeError('Unknown or changed legacy parent child census')
    threads,children=launcher_thread_children(pid)
    if threads.get(str(pid))!=snapshot['children']:raise RuntimeError('Launcher main-thread children changed')
    if actor_image(runner,driver,pid)!=image:raise RuntimeError('Legacy parent changed during child census')
    return children


def restart_actor_drained(runner,pid,image):
    """Only absence or the same captured retired zombie counts as drained."""
    snapshot=runner.fixture_process_snapshot(pid)
    if snapshot.get('absent') is True:
        if os.path.exists(f'/proc/{pid}'):raise RuntimeError('Retired actor census unavailable')
        return True
    if snapshot.get('pid')!=pid or snapshot.get('starttime')!=image['identity']['starttime'] or snapshot.get('ppid')!=image['ppid'] or snapshot.get('state') is None:
        raise RuntimeError('Managed restart actor changed or PID was reused')
    return snapshot['state'] in ('Z','X','x')


def legacy_census(runner,driver,leases,writer,runtime_hashes,python_hash):
    """Separate restart-owned writer/watchers from retained launcher/adapter images."""
    common=['--root',str(ROOT),'--state-dir',str(STATE)]
    python_commands={'/usr/bin/python3',str(Path('/usr/bin/python3').resolve(strict=True))}
    initial=actor_image(runner,driver,writer['pid'])
    if initial['identity']!=writer or initial['argv']!=[str(CACHE/'bin/progress-checker'),*common,'serve'] or initial['exe_sha256']!=runtime_hashes['progress-checker']:
        raise RuntimeError('Initial managed writer image differs')
    retained={};watchers={}
    for lease in leases.values():
        pid=lease['pid'];launcher=actor_image(runner,driver,pid)
        if launcher['identity']!=lease or len(launcher['argv'])!=6 or launcher['argv'][0] not in python_commands or launcher['argv'][1:]!=[str(CACHE/'bin/checker-plugin'),*common] or launcher['exe_sha256']!=python_hash:
            raise RuntimeError('Exact legacy launcher image required')
        retained[pid]=launcher
        children=actor_children(runner,driver,pid,launcher)
        for child in children:
            image=actor_image(runner,driver,child)
            if image['ppid']!=pid:raise RuntimeError('Legacy child parent changed')
            argv=image['argv']
            if child==writer['pid']:
                if image!=initial:raise RuntimeError('Managed initial writer child differs')
            elif argv==[str(CACHE/'bin/progress-checker-mcp'),*common] and image['exe_sha256']==runtime_hashes['progress-checker-mcp']:
                retained[child]=image
            elif len(argv)==9 and argv[0] in python_commands and argv[1:]==[str(CACHE/'bin/checker-plugin'),*common,'--watch-service',str(writer['pid']),writer['starttime']] and image['exe_sha256']==python_hash:
                watchers[child]=image
            else:
                raise RuntimeError('Unknown legacy launcher child; refusing role exclusion')
        if actor_image(runner,driver,pid)!=launcher:raise RuntimeError('Legacy launcher changed during child census')
    return retained,initial,watchers


def audit_legacy(runner,driver,retained,initial,watchers,successor,hard):
    """Require retained images and bounded natural drain of exact restart actors."""
    if successor==initial['identity']:raise RuntimeError('Managed writer was not replaced')
    until=min(hard,time.monotonic()+15)
    while True:
        pending=[]
        for pid,image in {initial['identity']['pid']:initial,**watchers}.items():
            if restart_actor_drained(runner,pid,image):continue
            identity=runner.process_identity(pid)
            if identity!=image['identity'] or actor_image(runner,driver,pid)!=image:
                raise RuntimeError('Managed restart actor changed or PID was reused')
            pending.append(pid)
        if not pending:break
        if time.monotonic()>=until:raise RuntimeError('Managed initial writer/watcher drain incomplete')
        time.sleep(min(.1,max(0,until-time.monotonic())))
    successor_children={}
    for pid,image in retained.items():
        if actor_image(runner,driver,pid)!=image:raise RuntimeError('Final legacy launcher/adapter PID/start/exe changed')
        if image['argv'][1:2]==[str(CACHE/'bin/checker-plugin')]:
            common=['--root',str(ROOT),'--state-dir',str(STATE)]
            for child in actor_children(runner,driver,pid,image):
                retired={initial['identity']['pid']:initial,**watchers}
                if child in retired and restart_actor_drained(runner,child,retired[child]):continue
                current=actor_image(runner,driver,child)
                if current['ppid']!=pid:raise RuntimeError('Final legacy child parent changed')
                if child in retained and current==retained[child]:continue
                if child==successor['pid'] and current['identity']==successor and current['argv']==[str(CACHE/'bin/progress-checker'),*common,'serve'] and current['exe_sha256']==initial['exe_sha256']:
                    successor_children[child]=current;continue
                argv=current['argv']
                python_commands={'/usr/bin/python3',str(Path('/usr/bin/python3').resolve(strict=True))}
                if len(argv)==9 and argv[0] in python_commands and argv[1:]==[str(CACHE/'bin/checker-plugin'),*common,'--watch-service',str(successor['pid']),successor['starttime']] and current['exe_sha256']==image['exe_sha256']:
                    successor_children[child]=current;continue
                raise RuntimeError('Unknown final legacy launcher child')
    if time.monotonic()>=hard:raise RuntimeError('Legacy process audit exceeded hard deadline')
    return {'initial_writer':initial,'initial_watchers':watchers,'initial_writer_drained':True,
            'initial_watchers_drained':True,'successor_writer':successor,'retained_images':retained,
            'successor_children':successor_children}



def immutable_attestation(metadata, fixed_check, prepared, deadline):
    value={key:metadata[key] for key in ['schema_version','producer','producer_argv','producer_source_sha256','source_file_identity','uid','boot_id','python_exe_sha256','nonce','endpoint','root','state','archive_sha256','native_cli_sha256','skill_path','runtime_hashes','module_hashes','socket']}
    value.update(check_definition=fixed_check,prepared_monotonic_ns=int(prepared*1e9),activation_expires_monotonic_ns=int(deadline*1e9),trust_policy='explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime')
    return value


class ActivationGate:
    """Host signal activation only after immutable+readiness publication."""
    def __init__(self):
        self.activated=threading.Event();self.armed=False;self.early=False;self.expired=False;self.deadline=None
    def signal(self,number,frame):
        if number!=signal.SIGUSR1:return
        if not self.armed:self.early=True;return
        if time.monotonic()>=self.deadline:self.expired=True;return
        self.activated.set()
    def arm(self,deadline,published=False):
        if self.armed or self.early or not published or time.monotonic()>=deadline:raise RuntimeError('Invalid/early/expired activation arm')
        self.deadline=deadline;self.armed=True
    def publish_and_arm(self,publish,deadline,previous_mask):
        # Blocked from before setup. Reject signals pending before publication;
        # preserve legitimate post-publication pending delivery without resetting.
        if signal.SIGUSR1 in signal.sigpending():raise RuntimeError('Pre-publication activation signal refused')
        publish()
        if signal.SIGUSR1 in signal.sigpending():raise RuntimeError('Activation signal raced publication; refusing ambiguous early activation')
        self.arm(deadline,published=True)
        signal.pthread_sigmask(signal.SIG_SETMASK,previous_mask)
    def wait(self,listener,deadline):
        if self.early or self.expired or not self.armed or time.monotonic()>=deadline:raise RuntimeError('Early/unarmed/expired activation refused')
        while not self.activated.is_set():
            if self.early or self.expired or time.monotonic()>=deadline:raise RuntimeError('Pre-registration activation deadline expired')
            try:
                reader,_=listener.accept()
                with reader:
                    reader.settimeout(.1)
                    try:reader.sendall(b'NOT_READY: independent root activation required\n')
                    except OSError:pass
            except socket.timeout:pass
        if self.early or self.expired or time.monotonic()>=deadline:raise RuntimeError('Activation event expired before workflow start')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--produce',action='store_true',help='Deprecated; direct workflow start is refused')
    parser.add_argument('--prepare-live',action='store_true',help='Bind preregistration, then await explicit root PIDfdSIGUSR1 activation')
    parser.add_argument('--attestation',type=Path)
    parser.add_argument('--report-dir',type=Path)
    parser.add_argument('--registration',type=Path)
    parser.add_argument('--approved-check',choices=['plan-definition'])
    args=parser.parse_args()
    if not args.prepare_live and not args.produce:
        print('OFF: no native/model/check/source/restart operation. Reviewed explicit --prepare-live inputs plus independent root activation required.');return 0
    if args.produce or not args.prepare_live or not args.report_dir or not args.registration or not args.attestation or args.approved_check!='plan-definition':raise SystemExit('Directproduce refused; reviewed prepare-live/report-dir/registration/attestation and priorhuman plan-definition selection required')
    gate=ActivationGate();previous_signal_mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGUSR1});signal.signal(signal.SIGUSR1,gate.signal)
    driver=load(ROOT/'scripts/plugin-primary-upgrade.py');runner=load(ROOT/'scripts/plugin-acceptance.py')
    from types import SimpleNamespace
    driver.RUNNER=runner;driver.ACCEPTANCE=runner.Acceptance(SimpleNamespace(milestone='service-lifecycle'))
    prepared=time.monotonic();preparation_deadline=prepared+1800
    started=prepared;work=started+480;hard=started+600
    directory=args.report_dir.absolute()
    if not directory.is_relative_to(ROOT/'.local') or directory.parent.resolve(strict=True)!=directory.parent:raise RuntimeError('Producer output must use a nonaliased excluded.local parent')
    directory.mkdir(mode=0o700,exist_ok=False)
    registration=args.registration.absolute()
    attestation=args.attestation.absolute()
    if attestation.parent!=directory or attestation.exists() or attestation==registration:raise RuntimeError('Immutable attestation must be new/separate in producer directory')
    if registration.parent!=directory or registration.exists():raise RuntimeError('Registration must be new and owned in producer report directory')
    endpoint=directory/'observe.sock'
    if len(os.fsencode(endpoint))>100:raise RuntimeError('Use a short protected producer report path')
    nonce=secrets.token_hex(32);buffer=Buffer(nonce);client=None;source=None;server=None
    report={'status':'blocked','approval_created':False,'auth_copied':False,'reader_controls_workflow':False,'configured_check':'plan-definition','nonce_sha256':hashlib.sha256(nonce.encode()).hexdigest()}
    env=os.environ.copy();env['CODEX_HOME']=str(CODEX_PROFILE);env.pop('OPENAI_API_KEY',None);env.pop('CODEX_API_KEY',None)
    phase_state={'phase':'initial'}
    legacy_leases={};legacy_images={};legacy_watchers={};audit=None
    ident=runner.process_identity(os.getpid());ident['uid']=os.getuid()
    metadata={'schema_version':1,'producer':ident,'producer_argv':list(os.sys.argv),'producer_source_sha256':driver.digest(Path(__file__)), 'source_file_identity':{'device':Path(__file__).stat().st_dev,'inode':Path(__file__).stat().st_ino},
              'uid':os.getuid(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'python_exe_sha256':driver.digest(Path('/proc/self/exe')),'nonce':nonce,'endpoint':str(endpoint),'ready':False,'started_monotonic_ns':int(started*1e9),'workflow_expires_monotonic_ns':int(work*1e9),'hard_expires_monotonic_ns':int(hard*1e9),'root':str(ROOT),'state':str(STATE),'phase_writer_ids':{}}
    def publish():
        temporary=registration.with_suffix('.tmp');temporary.write_text(json.dumps(metadata,indent=2)+'\n');os.chmod(temporary,0o600);os.replace(temporary,registration)
    def current_writer():return driver.writer(RUNTIME/'service.json',CACHE/'bin/progress-checker',ROOT,STATE,metadata['runtime_hashes']['progress-checker'])
    def public():
        result=driver.snapshot(client);result['claim_notes']=client.current()['result']['claim_notes'];return result
    try:
        archive=ROOT/'.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz'
        plugin=runner.extract_archive(driver.ACCEPTANCE,archive,directory/'extracted')
        if driver.ACCEPTANCE.report['archive']['sha256']!=driver.ARCHIVE_HASH:raise RuntimeError('Exact404 archive required')
        expected=driver.inventory(plugin);packages={'cache':driver.inventory(CACHE),'source':driver.inventory(SOURCE)}
        for name,base in [('cache',CACHE),('source',SOURCE)]:
            if packages[name].keys()!=expected.keys()|{'mcp.json'} or any(packages[name][p]!=v for p,v in expected.items()):raise RuntimeError('Installed exact404 inventory changed')
            binding=json.loads(driver.regular(base/'mcp.json',65536))['mcpServers']['progress_checker']
            if binding['command']!='./bin/checker-plugin' or binding['args']!=['--root',str(ROOT),'--state-dir',str(STATE)]:raise RuntimeError('Exactprimarybinding required')
        metadata['archive_sha256']=driver.ARCHIVE_HASH;metadata['native_cli_sha256']=driver.digest(CODEX)
        if metadata['native_cli_sha256']!='12eb3e81114588aca3b7998f4f19e8997b056aca08e57a7ca7c8a3ec8c652aad':raise RuntimeError('Reviewed native CLI bytes changed')
        metadata['skill_path']=str(CACHE/'skills/progress-checker/SKILL.md')
        metadata['runtime_hashes']={name:driver.digest(CACHE/'bin'/name) for name in ['checker-plugin','progress-checker','progress-checker-mcp']}
        metadata['module_hashes']={str(path):driver.digest(path) for path in [ROOT/'scripts/plugin-primary-upgrade.py',ROOT/'scripts/plugin-acceptance.py',ROOT/'scripts/plugin-primary-pilot-activate.py',ROOT/'scripts/plugin-pilot-acceptance.py',Path(__file__).resolve()]}

        for loaded in [driver,runner]:
            if loaded.loaded_source_sha256!=metadata['module_hashes'][loaded.loaded_source_path]:raise RuntimeError('Executed module bytes differ from attestation source')
        metadata['budget_seconds']={'preregistration_wait':1800,'workflow_work':480,'hard_with_observer_cleanup':600,'observer_wait_max':90}
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(endpoint));os.chmod(endpoint,0o600);server.listen(1);server.settimeout(.2)
        socket_info=endpoint.lstat()
        metadata['socket']={'dev':socket_info.st_dev,'ino':socket_info.st_ino,'uid':socket_info.st_uid,'mode':stat.S_IMODE(socket_info.st_mode),'mtime_ns':socket_info.st_mtime_ns,'ctime_ns':socket_info.st_ctime_ns}
        fixed_check={'id':'plan-definition','argv':['/usr/bin/python3','scripts/check-plugin-plan.py'],'cwd':'.','kind':'test','timeout_seconds':300}
        immutable=immutable_attestation(metadata,fixed_check,prepared,preparation_deadline)
        immutable_bytes=(json.dumps(immutable,indent=2)+'\n').encode()
        fd=os.open(attestation,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(immutable_bytes);stream.flush();os.fsync(stream.fileno())
        metadata['attestation_sha256']=hashlib.sha256(immutable_bytes).hexdigest();metadata['attestation_path']=str(attestation);metadata['awaiting_root_activation']=True
        gate.publish_and_arm(publish,preparation_deadline,previous_signal_mask);print('Pre-registered immutable attestation: '+str(attestation),flush=True);print('Attestation SHA256: '+metadata['attestation_sha256'],flush=True)
        gate.wait(server,preparation_deadline)
        # Reconcile final accepted root only AFTER independent activation. No cached initial config is used.
        if driver.regular(attestation,1024*1024)!=immutable_bytes or any(driver.digest(Path(path))!=value for path,value in metadata['module_hashes'].items()):raise RuntimeError('Immutable preregistration/source changed before activation')
        if driver.inventory(CACHE)!=packages['cache'] or driver.inventory(SOURCE)!=packages['source'] or driver.digest(CODEX)!=metadata['native_cli_sha256']:raise RuntimeError('Native/package changed before root activation')
        started=time.monotonic();work=started+480;hard=started+600
        metadata.update(awaiting_root_activation=False,activated_monotonic_ns=int(started*1e9),started_monotonic_ns=int(started*1e9),workflow_expires_monotonic_ns=int(work*1e9),hard_expires_monotonic_ns=int(hard*1e9))
        legacy_leases={p.name:json.loads(driver.regular(p,4096)) for p in (RUNTIME/'leases').glob('*.json')}
        initial_writer=current_writer()
        legacy_images,legacy_writer,legacy_watchers=legacy_census(runner,driver,legacy_leases,initial_writer,metadata['runtime_hashes'],metadata['python_exe_sha256'])
        publish()

        driver.capture([CODEX,'--version'],directory,'native-version',min(work,time.monotonic()+10),env,ROOT,report)
        metadata['native_cli_version']=(directory/'native-version.stdout').read_text().strip()
        protected_paths=[ROOT/p for p in ['.progress-checker/config.json','AGENTS.md','PLUGIN_PLAN.md','.progress-checker/plugin-plan.json','.codex/config.toml']]+[CODEX_PROFILE/'config.toml']
        protected={str(p):driver.digest(p) for p in protected_paths}
        report['protected_baseline']=dict(protected);report['package_baseline']=packages
        source=SourceCAS(driver,ROOT/'README.md')
        metadata['original_readme_sha256']=hashlib.sha256(source.original).hexdigest()
        metadata['phase_writer_ids']['initial']=current_writer()
        if metadata['phase_writer_ids']['initial']!=initial_writer:raise RuntimeError('Initial writer changed after legacy census')
        publish();buffer.add('registration','initial',{k:v for k,v in metadata.items() if k!='nonce'})
        buffer.add('protected-baseline','initial',{'protected_hashes':protected,'legacy_leases':legacy_leases,'legacy_images':legacy_images,'managed_initial_writer':legacy_writer,'managed_initial_watchers':legacy_watchers,'writer':metadata['phase_writer_ids']['initial'],'readme_sha256':metadata['original_readme_sha256'],'module_hashes':metadata['module_hashes']})
        with (directory/'observer-mcp.log').open('ab') as log:
            client=driver.wire(CACHE/'bin/progress-checker-mcp',ROOT,STATE,env,log,work)
            original_send=client.send
            def wire_send(value):
                buffer.add('core-mcp-request',phase_state['phase'],{'raw_line':json.dumps(value),'event':value});original_send(value)
            def wire_receive(timeout=15):
                deadline=min(hard,time.monotonic()+timeout)
                while b'\n' not in client.buffer:
                    remaining=deadline-time.monotonic()
                    if remaining<=0 or not select.select([client.wire.stdout],[],[],remaining)[0]:raise RuntimeError('Independent core receipt deadline')
                    data=os.read(client.wire.stdout.fileno(),65536)
                    if not data:raise RuntimeError('Independent core MCP EOF')
                    client.buffer.extend(data)
                    if len(client.buffer)>256*1024:raise RuntimeError('Independent core MCP frame exceeds256KiB')
                line,_,rest=client.buffer.partition(b'\n');client.buffer[:]=rest;value=json.loads(line)
                buffer.add('core-mcp-response',phase_state['phase'],{'raw_line':line.decode(),'event':value});return value
            client.send=wire_send;client.receive=wire_receive
            before=public();report['before']=before
            check=next(c for c in before['config']['checks'] if c['id']=='plan-definition')
            if check!={'id':'plan-definition','argv':['/usr/bin/python3','scripts/check-plugin-plan.py'],'cwd':'.','kind':'test','timeout_seconds':300}:raise RuntimeError('Concrete human check definition changed')
            metadata['check_definition']=check;metadata['accepted_config_hash']=before['config_hash'];metadata['initial_source_fingerprint']=client.current()['result']['status']['source']['fingerprint']
            if before['running']:raise RuntimeError('Workflow must independently start with no running checks')
            if before['claims'].get('delivery-plan')!='implemented':raise RuntimeError('Existing delivery-plan implemented claim required')
            def model(phase,prompt,allowed,permissions=(),failed_startup=False):
                skill=str(CACHE/'skills/progress-checker/SKILL.md')
                prefix='Apply the installed Progress Checker skill. Only /usr/bin/cat '+skill+' is an allowed shell command. '
                suffix=' Never create/feed command approval or invoke unrequested tools. Never edit files through shell. Then answer what is2+3.'
                flags=['-c','plugins.'+SELECTOR+'.enabled=true']
                flags+=['-c','model="gpt-6.1-sol"']
                if failed_startup:
                    for override in ['mcp_servers.progress_checker.command="/usr/bin/false"','mcp_servers.progress_checker.args=[]','mcp_servers.progress_checker.enabled=true']:flags+=['-c',override]
                for tool in permissions:flags+=['-c','plugins.'+SELECTOR+'.mcp_servers.progress_checker.tools.'+tool+'.approval_mode="approve"']
                argv=[str(CODEX),'--no-daemon','-a','never','-s','read-only','-C',str(ROOT)]+flags+['exec','--json','--ephemeral',prefix+prompt+suffix]
                phase_state['phase']=phase
                metadata['phase_writer_ids'][phase]=current_writer()
                buffer.add('phase-start',phase,{'writer':current_writer(),'argv':argv})
                phase_images=[];monitor_stop=threading.Event();monitor_errors=[]
                def sample_native():
                    seen=set()
                    while not monitor_stop.wait(.05):
                        try:
                            commands=report.get('commands',[])
                            if not commands or commands[-1].get('argv')!=argv:continue
                            native_pid=commands[-1]['pid']
                            live={p.name:json.loads(driver.regular(p,4096)) for p in (RUNTIME/'leases').glob('*.json')}
                            for name,owned in live.items():
                                if name in legacy_leases or owned['pid'] in seen:continue
                                launcher=runner.fixture_process_snapshot(owned['pid']);ancestor=owned['pid'];visited=set()
                                while ancestor!=native_pid and ancestor not in visited and len(visited)<32:
                                    visited.add(ancestor);info=runner.fixture_process_snapshot(ancestor)
                                    if info.get('absent'):break
                                    ancestor=info['ppid']
                                if ancestor!=native_pid:raise RuntimeError('Native launcher ancestry changed')
                                if runner.process_identity(owned['pid'])!=owned or launcher['command'][1:-1]!=[str(CACHE/'bin/checker-plugin'),'--root',str(ROOT),'--state-dir',str(STATE)]:raise RuntimeError('Native launcher identity/argv changed')
                                adapters=[runner.fixture_process_snapshot(pid) for pid in launcher['children']]
                                adapters=[a for a in adapters if a.get('command')==[str(CACHE/'bin/progress-checker-mcp'),'--root',str(ROOT),'--state-dir',str(STATE),'']]
                                if not adapters:continue
                                if len(adapters)!=1 or driver.digest(Path(f'/proc/{adapters[0]["pid"]}/exe'))!=metadata['runtime_hashes']['progress-checker-mcp']:raise RuntimeError('Native current adapter image changed')
                                seen.add(owned['pid']);phase_images.append({'launcher':owned,'launcher_argv':launcher['command'],'launcher_source_sha256':metadata['runtime_hashes']['checker-plugin'],'adapter':{'pid':adapters[0]['pid'],'starttime':adapters[0]['starttime']},'adapter_argv':adapters[0]['command'],'adapter_exe_sha256':metadata['runtime_hashes']['progress-checker-mcp'],'native_pid':native_pid})
                        except FileNotFoundError:pass
                        except BaseException as exc:monitor_errors.append(repr(exc));return
                sampler=threading.Thread(target=sample_native,daemon=True)
                if not failed_startup:sampler.start()
                try:driver.capture(argv,directory,phase,min(work,time.monotonic()+(180 if phase=='accepted-and-verify' else (60 if failed_startup else 90))),env,ROOT,report)
                finally:
                    monitor_stop.set()
                    if sampler.is_alive():sampler.join(timeout=1)
                if not failed_startup and (monitor_errors or len(phase_images)!=1):raise RuntimeError('Fresh native process image proof missing: '+repr(monitor_errors))
                buffer.add('native-images',phase,{'required':not failed_startup,'images':phase_images})
                raw=(directory/(phase+'.stdout')).read_text();events=[]
                for line in raw.splitlines():
                    if line.strip():buffer.add('native-jsonl',phase,{'raw_line':line,'event':json.loads(line)});events.append(json.loads(line))
                calls=[event['item'] for event in events if event.get('type')=='item.completed' and event.get('item',{}).get('type')=='mcp_tool_call']
                commands=[event['item'].get('command','') for event in events if event.get('type')=='item.completed' and event.get('item',{}).get('type')=='command_execution']
                shell_allowed=[f'/usr/bin/cat {skill}',f"/bin/bash -lc '/usr/bin/cat {skill}'",f"/bin/bash -lc '/usr/bin/cat -- {skill}'"]
                if any(command not in shell_allowed for command in commands) or any(event.get('item',{}).get('type')=='file_change' for event in events):raise RuntimeError('Unexpected model shell/write')
                if any(call.get('server')!='progress_checker' or call.get('tool') not in allowed for call in calls):raise RuntimeError('Unexpected model MCP call')
                messages=[event['item']['text'] for event in events if event.get('type')=='item.completed' and event.get('item',{}).get('type')=='agent_message']
                if any(event.get('type') in ['turn.failed','error'] for event in events):raise RuntimeError('Native phase reports failed/error event')
                if not any(event.get('type')=='turn.completed' for event in events) or not re.search(r'\b5\b','\n'.join(messages)):raise RuntimeError('Native phase didnotcomplete normal arithmetic turn')
                if (not failed_startup and not calls) or any(not successful(call) for call in calls):raise RuntimeError('Native phase tool failed; stop without source/restart')
                required=set() if failed_startup else ({'checker_get_project','checker_get_progress','checker_get_run'} if phase!='accepted-and-verify' else {'checker_get_project','checker_submit_plan','checker_set_claim','checker_get_plan_history','checker_run_checks','checker_get_run','checker_get_progress','checker_get_log'})
                if not required<={call['tool'] for call in calls}:raise RuntimeError('Required actual native operations missing')
                buffer.add('phase-finish',phase,{'writer':current_writer(),'native_pid':report['commands'][-1]['pid']})
                return calls
            accepted={'config':before['config'],'claim':'implemented','note':before['claim_notes'].get('delivery-plan','')}
            prompt='Read checker_get_project. Submit this IDENTICAL alreadyaccepted configuration once via checker_submit_plan using actualcurrentrevision/hash and reason "Primary fullpilot accepted plan; no scope change": '+json.dumps(accepted['config'])+'. Read currentproject again, reaffirm ONLYexisting delivery-plan implemented claim using actualcurrentrevision and this EXACT current note: '+json.dumps(accepted['note'])+'. If currentconfig/claim/note differs stop. Read history limit5. AFTER checker_set_claim, call checker_get_project again immediately BEFORE checker_run_checks, and use ONLY that fresh response revision/config hash for the run request. Run ONLY the previously HUMANapproved plan-definition via checker_run_checks with idempotency_key '+json.dumps('primary-'+nonce)+', actualcurrentrevision/config hash. If backend refuses approval STOP and report missinggrant; no retry/workaround/approval. If accepted, poll checker_get_run with its returnedrun_id until finished (no extra run request), read checker_get_progress and checker_get_log(offset0,limit4096) for its childrun_id/check_id plan-definition. Explain actualcurrentverification.'
            calls=model('accepted-and-verify',prompt,{'checker_get_project','checker_submit_plan','checker_set_claim','checker_get_plan_history','checker_run_checks','checker_get_run','checker_get_progress','checker_get_log'},['checker_submit_plan','checker_set_claim','checker_run_checks'])
            submits=[c for c in calls if c['tool']=='checker_submit_plan'];claims=[c for c in calls if c['tool']=='checker_set_claim']
            if len(submits)!=1 or submits[0]['arguments']['config']!=before['config'] or len(claims)!=1 or claims[0]['arguments']['milestone_id']!='delivery-plan' or claims[0]['arguments']['claim']!='implemented' or claims[0]['arguments']['note']!=accepted['note']:raise RuntimeError('Actual native accepted plan/existing claim differs')
            runs=[c for c in calls if c['tool']=='checker_run_checks']
            if len(runs)!=1 or runs[0]['arguments']['check_ids']!=['plan-definition'] or not successful(runs[0]):raise RuntimeError('Missing genuine prior human grant or exact check acceptance; no source/restart phase')
            last_project=None
            for call in calls:
                if call['tool']=='checker_get_project':last_project=call['result']['structured_content']
                if call['tool'] in ['checker_submit_plan','checker_set_claim','checker_run_checks']:
                    if last_project is None or call['arguments']['expected_revision']!=last_project['revision']:raise RuntimeError('Native mutation didnotuse actualcurrentrevision')
                    if call['tool']!='checker_set_claim' and call['arguments']['expected_config_hash']!=last_project['result']['status']['source']['config_hash']:raise RuntimeError('Native mutation configbinding differs')
                    last_project=None
            if runs[0]['arguments']['idempotency_key']!='primary-'+nonce:raise RuntimeError('Native run didnotuse freshnonce')
            acceptance=runs[0]['result']['structured_content']['result'];run_id=acceptance['run_id'];child=acceptance['run_ids'][0]
            verified=public();latest=verified['latest'].get('plan-definition',{})
            if not any(m['milestone_id']=='delivery-plan' and m['verified'] for m in verified['progress']['milestones']):raise RuntimeError('Actual current progress didnotverify stated deliverycriterion')
            if verified['running'] or latest.get('run_id')!=child or latest.get('outcome')!='passed' or latest.get('freshness')!='current':raise RuntimeError('Concretecheck didnotfinish currentpassing')
            if not any(c['tool']=='checker_get_run' and successful(c) and c['arguments']['run_id'] in [run_id,child] for c in calls) or not any(c['tool']=='checker_get_log' and successful(c) and c['arguments']['check_id']=='plan-definition' and c['arguments']['run_id']==child for c in calls):raise RuntimeError('Actual native getrun/log proofmissing')
            if verified['config']!=before['config'] or verified['claims']!=before['claims'] or verified['claim_notes']!=before['claim_notes'] or verified['history']!=before['history']:raise RuntimeError('Acceptedplan/claims/notes/history changed')
            core_run=client.success('checker_get_run',{'run_id':run_id});core_log=client.success('checker_get_log',{'run_id':child,'check_id':'plan-definition','offset':0,'limit':4096})
            if core_run['result'].get('execution_state')!='finished' or len(core_run['result'].get('runs',[]))!=1 or not all(item.get('evidence',{}).get('outcome')=='passed' and item.get('current_freshness')=='current' for item in core_run['result'].get('runs',[])):raise RuntimeError('Independent actual core getrun notfinished')
            metadata['run_id']=run_id;metadata['child_run_id']=child;report['run_id']=run_id;report['child_run_id']=child;buffer.add('public-frame','verified',verified)
            phase_state['phase']='source-stale'
            source.write(source.original,source.original+b'\n<!-- primary-fullpilot temporary source '+nonce.encode()+b' -->\n');buffer.add('source-cas','stale',{'original_sha256':metadata['original_readme_sha256'],'edited_sha256':hashlib.sha256(source.owned).hexdigest()})
            model('source-stale','Read checker_get_project/checker_get_progress and checker_get_run for run_id '+json.dumps(run_id)+'. Explain why evidence is stale despite retainedpass/claims. No plan/claim/check operations.',{'checker_get_project','checker_get_progress','checker_get_run'})
            stale=public();client.success('checker_get_run',{'run_id':run_id});client.success('checker_get_log',{'run_id':child,'check_id':'plan-definition','offset':0,'limit':4096});item=stale['latest'].get('plan-definition',{})
            if any(m['milestone_id']=='delivery-plan' and m['verified'] for m in stale['progress']['milestones']):raise RuntimeError('Source stale progress remained verified')
            if stale['running'] or item.get('freshness')!='stale' or item.get('run_id')!=child:raise RuntimeError('Native source edit didnotderive stale')
            buffer.add('public-frame','stale',stale)
            phase_state['phase']='restart'
            with driver.locked(RUNTIME,min(work,time.monotonic()+10)):
                if public()['running']:raise RuntimeError('Refusing restart while anycheckrunning')
                owned=current_writer();fd=os.pidfd_open(owned['pid'],0)
                try:
                    if current_writer()!=owned:raise RuntimeError('Writer changed before PIDfd restart')
                    signal.pidfd_send_signal(fd,signal.SIGTERM,None,0)
                finally:os.close(fd)
            until=min(work,time.monotonic()+35)
            while time.monotonic()<until:
                try:
                    new=current_writer()
                    if new!=owned:break
                except (OSError,ValueError,RuntimeError):pass
                time.sleep(.1)
            else:raise RuntimeError('Gentle writer restart failed; noforcekill')
            metadata['phase_writer_ids']['restarted']=new;buffer.add('gentle-restart','restart',{'old':owned,'new':new,'signal':'SIGTERM PIDfd'})
            model('native-restart','Read checker_get_project/checker_get_progress and checker_get_run for run_id '+json.dumps(run_id)+'. Confirm retainedacceptedplan, existingclaims and stale priorpass after actualwriterrestart. No plan/claim/check operations.',{'checker_get_project','checker_get_progress','checker_get_run'})
            restarted=public();client.success('checker_get_run',{'run_id':run_id});client.success('checker_get_log',{'run_id':child,'check_id':'plan-definition','offset':0,'limit':4096})
            if restarted['latest']['plan-definition'].get('run_id')!=child or restarted['latest']['plan-definition'].get('freshness')!='stale' or restarted['claims']!=before['claims'] or restarted['claim_notes']!=before['claim_notes'] or restarted['config']!=before['config'] or restarted['history']!=before['history']:raise RuntimeError('Restart durability notproven')
            buffer.add('public-frame','restart-stale',restarted)
            # Real invocation-only failed transport: Config catalog wins over Plugin,
            # while installed skill remains enabled. No cache/profile mutation.
            import subprocess,types
            pilot=load(ROOT/'scripts/plugin-pilot-acceptance.py')
            if pilot.loaded_source_sha256!=metadata['module_hashes'][pilot.loaded_source_path]:raise RuntimeError('Failure diagnostic module source changed')
            unavailable=runner.NativeCodex.__new__(runner.NativeCodex)
            unavailable.sequence,unavailable.buffer,unavailable.notifications=0,bytearray(),[]
            unavailable.thread_id=unavailable.shutdown_probe=None;unavailable.pilot_deadline=min(work,time.monotonic()+30)
            unavailable.receive=types.MethodType(pilot._native_receive,unavailable)
            failed_overrides=['plugins.'+SELECTOR+'.enabled=true','mcp_servers.progress_checker.command="/usr/bin/false"','mcp_servers.progress_checker.args=[]','mcp_servers.progress_checker.enabled=true']
            failed_argv=[str(CODEX),'--no-daemon']+[word for value in failed_overrides for word in ['-c',value]]+['app-server','--listen','stdio://']
            with (directory/'unavailable-native.stderr').open('xb') as failed_log:
                unavailable.wire=subprocess.Popen(failed_argv,cwd=ROOT,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=failed_log,start_new_session=True)
                try:
                    initialize=unavailable.call('initialize',{'clientInfo':{'name':'primary-unavailable','version':'1'},'capabilities':{'experimentalApi':True}});unavailable.send({'method':'initialized'})
                    skills=unavailable.call('skills/list',{'cwds':[str(ROOT)],'forceReload':False})
                    enabled_skills=[skill for item in skills.get('data',[]) for skill in item.get('skills',[]) if skill.get('pluginId')==SELECTOR and skill.get('enabled') and skill.get('path')==metadata['skill_path']]
                    thread=unavailable.call('thread/start',{'cwd':str(ROOT),'ephemeral':True,'approvalPolicy':'never','sandbox':'read-only'});unavailable.thread_id=thread['thread']['id']
                    until=min(work,time.monotonic()+20)
                    while time.monotonic()<until:
                        server_status=unavailable.call('mcpServerStatus/list',{'threadId':unavailable.thread_id})
                        matches=[server for server in server_status.get('data',[]) if server.get('name')=='progress_checker']
                        if matches and matches[0].get('runtimeStatus')=='failed':break
                        time.sleep(.1)
                    if initialize.get('codexHome')!=str(CODEX_PROFILE) or len(enabled_skills)!=1 or len(matches)!=1 or matches[0].get('runtimeStatus')!='failed' or matches[0].get('tools'):raise RuntimeError('Actual failed startup/skill availability not proven')
                    buffer.add('unavailable-discovery','unavailable',{'argv':failed_argv,'initialize':initialize,'skills':skills,'thread':thread,'server_status':server_status,'collision_policy':'Config priority2 overrides Plugin priority0/Selected1; plugin skill enabled; pluginId may be absent'})
                    unavailable.call('thread/unsubscribe',{'threadId':unavailable.thread_id},timeout=5)
                finally:driver.close_wire(unavailable)
            model('unavailable','The invocation-only checker transport intentionally runs /usr/bin/false, so its MCP startup fails. Do not call any MCP tools, modify plans/claims/checks/files, or grant approval. Read only the exact installed skill if needed and answer normal arithmetic.',set(),failed_startup=True)
            phase_state['phase']='source-restored'
            source.restore();buffer.add('source-restored','ready',{'sha256':driver.digest(ROOT/'README.md')})
            _,mismatches=protection_snapshot(driver,protected,packages,report,'before-final-audit')
            if mismatches:raise RuntimeError('Protectedroot/profile/package changed')
            def audit():
                final_hashes,mismatches=protection_snapshot(driver,protected,packages,report,'final-audit',metadata['module_hashes'])
                modules_unchanged=not any(item['scope']=='module' for item in mismatches)
                if mismatches:raise RuntimeError('Final protected root/profile/module/package bytes changed')
                final_writer=current_writer()
                if final_writer!=metadata['phase_writer_ids'].get('restarted',metadata['phase_writer_ids']['initial']):raise RuntimeError('Final workflow writer changed')
                until=min(hard,time.monotonic()+15)
                while time.monotonic()<until:
                    final_leases={p.name:json.loads(driver.regular(p,4096)) for p in (RUNTIME/'leases').glob('*.json')}
                    if final_leases==legacy_leases:break
                    time.sleep(.1)
                if final_leases!=legacy_leases:raise RuntimeError('Final native cleanup changed legacy leases')
                legacy_audit=audit_legacy(runner,driver,legacy_images,legacy_writer,legacy_watchers,final_writer,hard)
                if driver.regular(source.path,1024*1024)!=source.original or stat.S_IMODE(source.path.stat().st_mode)!=source.identity[2]:raise RuntimeError('Final README bytes/mode not restored')
                return {'protected_hashes':final_hashes,'modules_unchanged':True,'package_inventories_unchanged':True,'writer':final_writer,'legacy_leases':final_leases,'legacy_process_audit':legacy_audit,'readme_bytes_mode_restored':True}
            buffer.add('protected-audit','ready',audit())
            def fixed_poll():
                phase_state['phase']='current-poll'
                for name,arguments in [('checker_get_project',{}),('checker_get_progress',{}),('checker_get_run',{'run_id':run_id}),('checker_get_log',{'run_id':child,'check_id':'plan-definition','offset':0,'limit':4096})]:
                    client.success(name,arguments)
            # Listener exists before atomic ready registration. Reader has no API control.
            fixed_poll()
            # Reuse pre-bound immutable endpoint; no socket identity change after human approval.
            ready_started=time.monotonic()
            metadata.update(ready=True,observer_ready_monotonic_ns=int(ready_started*1e9),observer_expires_monotonic_ns=int(min(hard-20,ready_started+90)*1e9),current_writer=current_writer(),run_id=run_id,child_run_id=child,buffer_schema={'seq':'integer','phase':'string','collected_monotonic_ns':'integer','type':'string','data':'object-or-array','previous_sha256':'sha256'},stream_snapshots=2);publish()
            ready_until=min(hard-20,time.monotonic()+90);next_poll=time.monotonic()+2
            while time.monotonic()<ready_until:
                if time.monotonic()>=next_poll:fixed_poll();next_poll+=2
                try:connection,_=server.accept();break
                except socket.timeout:pass
            else:raise RuntimeError('No one-use reader arrived within independent deadline')
            with connection:
                connection.settimeout(max(.01,min(10,hard-time.monotonic()-15)))
                request=bytearray()
                while b'\n' not in request and len(request)<=4096:
                    chunk=connection.recv(4096-len(request)+1)
                    if not chunk:break
                    request.extend(chunk)
                expected_request={'schema_version':1,'nonce':nonce,'request':'read-events'}
                if json.loads(request)!=expected_request:raise RuntimeError('Readerrequestinvalid; no workflowcontrolRPC')
                # Two cumulative snapshots: independent fixed schedule, no reader parameters.
                payload=bytes(buffer.raw);connection.sendall(struct.pack('!I',len(payload))+payload)
                while time.monotonic()<next_poll:time.sleep(min(.05,next_poll-time.monotonic()))
                fixed_poll()
                buffer.add('stream-terminal','terminal',{'current_writer':current_writer(),'restored_readme_sha256':driver.digest(ROOT/'README.md'),'audit':audit()})
                payload=bytes(buffer.raw);connection.sendall(struct.pack('!I',len(payload))+payload)
                # Keep producer live until normal reader EOF, never accept a second command.
                connection.settimeout(max(.01,min(15,hard-time.monotonic()-10)))
                if connection.recv(1):raise RuntimeError('Reader sent forbidden follow-upcontrol bytes')
            metadata['ready']=False;metadata['consumed']=True;publish();report['status']='workflow-observed';report['buffer_sha256']=hashlib.sha256(buffer.raw).hexdigest()
    except BaseException as exc:report['status']='failed';report['error']=repr(exc)
    finally:
        if source:
            try:source.restore();report['readme_restored']=driver.regular(source.path,1024*1024)==source.original
            except BaseException as exc:report['readme_restore_error']=repr(exc);report['status']='failed'
        if client:
            try:driver.close_wire(client)
            except BaseException as exc:report['mcp_cleanup_error']=repr(exc);report['status']='failed'
        if 'protected' in locals():
            if audit is None:
                try:protection_snapshot(driver,protected,packages,report,'unavailable-final-audit',metadata['module_hashes'])
                except Exception as exc:report['protection_diagnostic_error_type']=type(exc).__name__
        final_audit_report(audit,report)
        if server:server.close()
        if endpoint.exists():endpoint.unlink()
        metadata['ready']=False;metadata['terminal']=True;publish()
        report['elapsed_seconds']=time.monotonic()-started;report['registration_metadata']={k:v for k,v in metadata.items() if k!='nonce'}
        (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(directory/'report.json')
    return 0 if report['status']=='workflow-observed' else 2


if __name__=='__main__':raise SystemExit(main())
