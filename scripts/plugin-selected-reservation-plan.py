#!/usr/bin/python3
"""OFF-default metadata planner; never reserves, mounts or executes fixtures.

Only the two fixture pairs in the accepted machine plan are selectable. Signed
state, grants and authentication keys are never opened, copied or modified.
"""
from __future__ import annotations
import argparse,contextlib,hashlib,json,os,pwd,stat
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
SELECTORS={'original-demo':('evidence_fixture','evidence-integrity','evidence-fixture'),
           'dedicated-plan':('plan_fixture','plan-submission','plan-fixture')}
EXPECTED={'original-demo':(ROOT/'.local/checker-demo/session-c5c6vsyz/project',ROOT/'.local/checker-demo/session-c5c6vsyz/state'),
          'dedicated-plan':(ROOT/'.local/plugin-acceptance/plan-invalidation-human-fixture-v2/project',ROOT/'.local/plugin-acceptance/plan-invalidation-human-fixture-v2/state')}

def strict_object(items):
    result={}
    for key,value in items:
        if key in result:raise ValueError('Duplicate public metadata key')
        result[key]=value
    return result

@contextlib.contextmanager
def anchored_parent(path):
    relative=path.relative_to(ROOT)
    if not relative.parts or len(relative.parts)>64:raise ValueError('Public metadata path exceeds anchored scope')
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    frames=[];fds=[]
    try:
        current=os.open(ROOT,flags);fds.append(current)
        origin=os.fstat(current);visible=ROOT.lstat()
        if (origin.st_dev,origin.st_ino)!=(visible.st_dev,visible.st_ino):raise RuntimeError('Trusted root identity changed')
        for component in relative.parts[:-1]:
            parent=current;current=os.open(component,flags,dir_fd=parent);fds.append(current)
            opened=os.fstat(current);visible=os.stat(component,dir_fd=parent,follow_symlinks=False)
            if not stat.S_ISDIR(visible.st_mode) or (opened.st_dev,opened.st_ino)!=(visible.st_dev,visible.st_ino):raise RuntimeError('Anchored public directory identity changed')
            frames.append((parent,component,opened))
        yield current,relative.parts[-1]
        for parent,component,opened in frames:
            visible=os.stat(component,dir_fd=parent,follow_symlinks=False)
            if not stat.S_ISDIR(visible.st_mode) or (visible.st_dev,visible.st_ino,visible.st_mode,visible.st_uid)!=(opened.st_dev,opened.st_ino,opened.st_mode,opened.st_uid):raise RuntimeError('Anchored public parent changed during read')
        visible=ROOT.lstat()
        if (visible.st_dev,visible.st_ino)!=(origin.st_dev,origin.st_ino):raise RuntimeError('Trusted root identity changed after read')
    finally:
        for fd in reversed(fds):os.close(fd)

def public_json(path,limit,*,private_runtime=False):
    with anchored_parent(path) as (parent,name):
        if private_runtime:
            parent_info=os.fstat(parent)
            if parent_info.st_uid!=1000 or stat.S_IMODE(parent_info.st_mode)!=0o700:raise ValueError('Launcher PID parent must be private owned0700')
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(fd,'rb') as source:
            before=os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=1000 or before.st_nlink!=1 or before.st_size>limit:raise ValueError('Expected bounded owned public metadata file')
            # atomic() produces 0666&umask insideprivate0700, often0644.
            if private_runtime and before.st_mode&0o111:raise ValueError('Launcher PID metadata unexpectedly executable')
            data=source.read(limit+1);after=os.fstat(source.fileno());current=os.stat(name,dir_fd=parent,follow_symlinks=False)
            if len(data)>limit or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or (current.st_dev,current.st_ino)!=(before.st_dev,before.st_ino):raise RuntimeError('Public metadata changed while reading')
    return json.loads(data,object_pairs_hook=strict_object)

def metadata(path,*,directory=False,private=False,optional=False):
    if optional and not path.exists() and not path.is_symlink():return {'path':str(path),'exists':False}
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode):raise ValueError('Symlink metadata path refused')
    if directory and not stat.S_ISDIR(info.st_mode):raise ValueError('Expected directory metadata')
    if not directory and not stat.S_ISREG(info.st_mode):raise ValueError('Expected regular lock/public path metadata')
    if private and (info.st_uid!=1000 or stat.S_IMODE(info.st_mode)!=(0o700 if directory else 0o600)):raise ValueError('Expected owned private runtime metadata')
    return {'path':str(path),'exists':True,'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),'links':info.st_nlink,'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}

def anchored_directory(path,*,private=False):
    if path.resolve(strict=True)!=path or ROOT not in path.parents:raise ValueError('Fixture must be an exact nonsymlink canonical project-local path')
    relative=path.relative_to(ROOT);cursor=ROOT
    for component in relative.parts:
        cursor/=component
        metadata(cursor,directory=True)
    info=metadata(path,directory=True,private=private)
    if info['uid']!=1000:raise ValueError('Fixture directory must be owned by invoking host user')
    return info

def stable_lock_directory():
    runtime=Path('/run/user/1000')
    try:
        info=runtime.lstat()
        valid=stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid==1000 and info.st_mode&0o077==0
    except FileNotFoundError:valid=False
    if valid:return runtime/'progress-checker-locks','core /run/user/UID selector'
    return Path(pwd.getpwuid(1000).pw_dir)/'.local/state/progress-checker-locks','core passwd stable-home fallback; metadata only, never a guest HOME mount'

def process_identity(record):
    if not isinstance(record,dict) or set(record)!={'pid','starttime'} or not isinstance(record['pid'],int) or isinstance(record['pid'],bool) or record['pid']<=0 or not isinstance(record['starttime'],str) or not record['starttime'].isdigit():raise ValueError('Invalid bounded launcher PID identity record')
    pid=record['pid'];directory=Path(f'/proc/{pid}');fd=None
    try:
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        before=os.fstat(fd)
        def fields():
            statfd=os.open('stat',os.O_RDONLY|os.O_CLOEXEC,dir_fd=fd)
            with os.fdopen(statfd,'rb') as source:data=source.read(4097)
            if len(data)>4096:raise RuntimeError('Oversized public process stat')
            return data.decode().rsplit(')',1)[1].split()
        first=fields();second=fields();after=os.fstat(fd);visible=directory.lstat()
        if first[19]!=second[19] or (before.st_dev,before.st_ino,before.st_uid)!=(after.st_dev,after.st_ino,after.st_uid) or (visible.st_dev,visible.st_ino)!=(before.st_dev,before.st_ino):raise RuntimeError('Process PID/start/owner changed during metadata observation')
        live=second[0]!='Z' and after.st_uid==1000 and second[19]==record['starttime']
        return {'pid':pid,'starttime':record['starttime'],'live':live,'observed_starttime':second[19],'observed_uid':after.st_uid}
    except (FileNotFoundError,ProcessLookupError):return {'pid':pid,'starttime':record['starttime'],'live':False}
    finally:
        if fd is not None:os.close(fd)

def launcher_idle(runtime):
    result={'observation_only':True,'continuous_exclusion_established':False,'live_identities':[],'stale_identities':[],'unknown':[],'records_modified':False}
    if not runtime.exists():result.update(launcher_runtime_exists=False,snapshot_idle=True,missing_launcher_mutex=True);return result
    metadata(runtime,directory=True,private=True);result['launcher_runtime_exists']=True
    records=[]
    service=runtime/'service.json'
    if service.exists() or service.is_symlink():records.append(service)
    leases=runtime/'leases'
    if leases.exists() or leases.is_symlink():
        metadata(leases,directory=True,private=True)
        with anchored_parent(leases/'__inventory__') as (leasefd,_):names=os.listdir(leasefd)
        paths=[leases/name for name in names]
        if len(paths)>128:raise ValueError('Launcher lease inventory exceeds fixed bound')
        for path in paths:
            if not path.name.endswith('.json') or not path.stem.isdigit():raise ValueError('Unexpected launcher lease metadata filename')
            records.append(path)
    for path in records:
        try:
            observed=process_identity(public_json(path,1024,private_runtime=True));observed['metadata_path']=str(path)
            result['live_identities' if observed['live'] else 'stale_identities'].append(observed)
        except (OSError,ValueError,RuntimeError) as error:result['unknown'].append({'metadata_path':str(path),'reason':str(error)})
    result['snapshot_idle']=not result['live_identities'] and not result['unknown']
    return result

def plan(selector):
    if os.getuid()!=1000 or os.geteuid()!=1000:raise ValueError('Planner requires actual unprivileged host UID1000')
    field,milestone,flag=SELECTORS[selector]
    machine=public_json(ROOT/'.progress-checker/plugin-plan.json',128*1024)
    current=public_json(ROOT/'.progress-checker/config.json',256*1024)
    selected=machine[field];root,state=Path(selected['root']),Path(selected['state'])
    if (root,state)!=EXPECTED[selector]:raise ValueError('Accepted machine-plan fixture identity changed; explicit new scope review required')
    if root==state or root in state.parents or state in root.parents:raise ValueError('Fixture/state overlap')
    root_identity=anchored_directory(root);state_identity=anchored_directory(state,private=True)
    checks=[item for item in current['checks'] if item['id']==milestone]
    if len(checks)!=1:raise ValueError('Accepted milestone check definition missing')
    argv=checks[0]['argv']
    if not isinstance(argv,list) or not argv or not all(isinstance(value,str) for value in argv):raise ValueError('Configured argv must be a nonempty list of strings')
    for option in ('--'+flag+'-root','--'+flag+'-state'):
        if argv.count(option)!=1 or argv.index(option)+1>=len(argv):raise ValueError('Missing or repeated configured fixture flag/value')
    if argv.count('--'+flag+'-root')!=1 or argv.count('--'+flag+'-state')!=1 or argv[argv.index('--'+flag+'-root')+1]!=str(root) or argv[argv.index('--'+flag+'-state')+1]!=str(state):raise ValueError('Machine plan and literal configured fixture pair disagree')
    core_key=hashlib.sha256(json.dumps(str(root),ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    launcher_key=hashlib.sha256(os.fsencode(root)).hexdigest()[:24]
    lockdir,selector_reason=stable_lock_directory()
    if lockdir.resolve(strict=False)!=lockdir:raise ValueError('Stable lock selector is not an exact canonical metadata path')
    runtime=state/('plugin-'+launcher_key)
    core_lock=lockdir/(core_key+'.lock');launcher_lock=runtime/'lock'
    observations=launcher_idle(runtime)
    # No state contents are enumerated other than fixed launcher PID metadata.
    anchor_check=anchored_directory(root);state_check=anchored_directory(state,private=True)
    if root_identity!=anchor_check or state_identity!=state_check:raise RuntimeError('Selected directory identity changed during metadata planning')
    short=state/('ipc-'+launcher_key+'.sock')
    socket_key=hashlib.sha256(os.fsencode(root)+b'\0'+os.fsencode(state)).hexdigest()[:24]
    guest_socket=short if len(os.fsencode(short))<=100 else Path('/tmp/progress-checker-ipc-0')/('ipc-'+socket_key+'.sock')
    prerequisites=[]
    if not core_lock.exists():prerequisites.append('Original canonical writer lock does not exist; no creation/acquisition authorized.')
    if not launcher_lock.exists():prerequisites.append('Selected original launcher mutex does not exist; initialization requires separate review, no file was created.')
    return {'missing_prerequisites':prerequisites,'status':'metadata-planned-unqualified','selector':selector,'mode':'OFF-default; metadata only; no execution entry point','archive':machine['acceptance_archive'],'selected_root_identity':root_identity,'selected_state_identity':state_identity,'key_derivation':{'core_json_root_sha256':core_key,'launcher_filesystem_root_sha256_24':launcher_key,'core_source':'checker-core/src/store.rs: serde_json::to_vec(canonical root)','launcher_source':'checker-plugin: sha256(os.fsencode(canonical root))[:24]'},'reservation_roles':[{'role':'canonical-worktree-writer','path':str(core_lock),'selector':selector_reason,'metadata':metadata(core_lock,private=True,optional=True)},{'role':'launcher-mutex','path':str(launcher_lock),'metadata':metadata(launcher_lock,private=True,optional=True)}],'launcher_idle_observation':observations,'proposed_guest_mounts':[{'operation':'bind','source':str(root),'destination':str(root),'scope':'explicit selected fixture only'},{'operation':'bind','source':str(state),'destination':str(state),'scope':'core legitimately reads original state in place; orchestrator does not parse it'},{'operation':'tmpfs','destination':str(runtime),'mode':'0700','guest_owner_uid':0,'scope':'fresh guest-only launcher PID/lease metadata; no original records copied'}],'guest_socket_path':str(guest_socket),'proposed_guest_environment':{'PATH':'/usr/bin:/bin','HOME':'/r','LANG':'C.UTF-8'},'production_check_environment':{'PATH':'/usr/bin:/bin','HOME':'/tmp','LANG':'C.UTF-8'},'capability_difference':'namespace-local sole SETFCAP in guest parent and nested payload; not zero-cap/nonroot equivalence','original_configured_argv':argv,'plan_flags_preserved':{'root_flag':'--'+flag+'-root','state_flag':'--'+flag+'-state','paired_paths':True},'private_records_opened_or_copied':False,'locks_acquired':False,'mounts_created':False,'checks_requested_or_approved':False,'unqualified':['Host/controller abrupt death with all descriptor holders lost remains unresolved.','Retained fixture integration with curated source-free helper is not implemented or qualified.','Idle metadata is a snapshot, not continuous writer/watchdog/launcher exclusion across aliases/state bases.','Full fixture config/script/feature-byte acceptance identity and actual archive payload hashes are not evaluated by this metadata-only planner.','Original core must validate exact human grant in place; no grant was inspected or created.','Fixed outer teardown kills nested writers abruptly; no gentle signed-writer guarantee.','Proposed selected runtime CLI/configured command binding is not implemented or approved.']}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--fixture',choices=SELECTORS,required=True)
    args=parser.parse_args()
    try:result=plan(args.fixture)
    except (OSError,ValueError,RuntimeError,KeyError,IndexError,TypeError) as error:result={'status':'metadata-refused-unqualified','error':str(error),'locks_acquired':False,'mounts_created':False,'checks_requested_or_approved':False}
    print(json.dumps(result,indent=2))
    return 2
if __name__=='__main__':raise SystemExit(main())
