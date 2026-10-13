#!/usr/bin/python3
"""OFF-default source-pinned instrumentation for the fixed preservation body.

This stages private-module wrappers only. No CLI can prepare, activate or invoke
the body. Registration, activation, live ownership and committed observation are
separate pending integration prerequisites. Never read/copy private state files.
"""
import argparse,ast,base64,hashlib,importlib.util,json,os,select,stat,subprocess,threading,time
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parent.parent
FIXTURE=ROOT/'.local/checker-demo/session-c5c6vsyz/project';STATE=FIXTURE.parent/'state'
RELEASE_SHA='f2c996c6f9a49ba3abb2ea38a715f1e3c774e850d3282efb64a95eee8f4cd2d6'
BODY_SHA='44626dc4e60a623939f1e89dfb24ff5d162222b7dc9b888ef9ae18781951e3e2'
EVIDENCE_SHA='bb4b6e9e761836bc33f4c42e70c5a7c7b204558783e5ebdd9b2a56d5077d6aeb'
OWNERSHIP_SHA='54847b3acd43a8a87199d5e1f0793f1c6b8a731e2464d14e42f11352439cdb82'
INSTALLER_SHA='6385f661784e2ecd231920a2cf82738ac9de1fbe7ace9d4a499056a5280a090e'
ARCHIVE_SHA='404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
CODEX=Path('/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex')
class Refusal(RuntimeError):pass
def sha(data):return hashlib.sha256(data).hexdigest()
def validate_request(q):
    if type(q) is not dict or q.get('jsonrpc')!='2.0':raise Refusal('Fixed JSONRPC request required before write')
    method=q.get('method');params=q.get('params')
    if method=='notifications/initialized':
        if q!={'jsonrpc':'2.0','method':method,'params':{}}:raise Refusal('Fixed initialized notification required')
        return
    if set(q)!={'jsonrpc','id','method','params'} or type(q['id']) is not int or q['id']<=0:raise Refusal('Exact request ID/schema required')
    if method=='initialize':
        if params!={'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'live-evidence-acceptance','version':'1'}}:raise Refusal('Fixed initialize parameters required')
        return
    if method=='tools/list':
        if params!={}:raise Refusal('Fixed tools/list parameters required')
        return
    if method!='tools/call' or type(params) is not dict:raise Refusal('Unexpected method before write')
    name=params.get('name');args=params.get('arguments')
    if name=='checker_get_progress':
        if set(params)!={'name','arguments'} or args!={}:raise Refusal('Fixed progress parameters required')
        return
    if name not in ('checker_get_project','checker_get_run','checker_get_log') or set(params)!={'name','arguments','_meta'} or type(params['_meta']) is not dict or set(params['_meta'])!={'openai/readOnly'} or params['_meta']['openai/readOnly'] is not True or type(args) is not dict:raise Refusal('Only strict read-only tools may be written')
    if name=='checker_get_project' and args!={}:raise Refusal('Fixed project arguments required')
    if name=='checker_get_run' and (set(args)!={'run_id'} or type(args['run_id']) is not str or not args['run_id']):raise Refusal('Fixed child run arguments required')
    if name=='checker_get_log' and (set(args)!={'run_id','check_id','offset','limit'} or type(args['run_id']) is not str or not args['run_id'] or args['check_id']!='demo-check' or type(args['offset']) is not int or args['offset']!=0 or type(args['limit']) is not int or args['limit']!=32768):raise Refusal('Fixed bounded child log arguments required')
def bounded(path,limit):
    if path.resolve(strict=True)!=path:raise Refusal('Source/public alias')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or before.st_mode&0o022 or before.st_size>limit:raise Refusal('Bounded owned public file required')
        data=stream.read(limit+1);after=os.fstat(stream.fileno());current=path.lstat()
        key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if len(data)!=before.st_size or key(before)!=key(after) or key(before)!=key(current):raise Refusal('Public input changed while captured')
        return data,before
def module_buffer(path,expected):
    data,_=bounded(path,8*1024*1024)
    if sha(data)!=expected:raise Refusal('Exact source buffer differs before exec')
    return data
def load_buffer(path,data):
    spec=importlib.util.spec_from_file_location(path.stem.replace('-','_'),path);module=importlib.util.module_from_spec(spec);exec(compile(data,str(path),'exec'),module.__dict__);return module
class BudgetAdapter:
    def __init__(self,deadline):self.deadline=deadline;self.cleaning=False
    def remaining(self,cap):return self.deadline.remaining(cap,cleanup=self.cleaning)
    def check(self):self.remaining(1)
class ActionBudget:
    def __init__(self,shared,maximum,cleanup=False):self.shared,self.cleaning=shared,cleanup;self.end=time.monotonic()+shared.remaining(maximum,cleanup=cleanup);self.cleanup_end=shared.cleanup_end
    def remaining(self,maximum=None,*,cleanup=False):
        left=min(self.end-time.monotonic(),self.shared.remaining(maximum,cleanup=cleanup or self.cleaning))
        if left<=0:raise TimeoutError('Installer cumulative action deadline exceeded')
        return left if maximum is None else min(maximum,left)
    def check(self):self.remaining(1)
class Trace:
    def __init__(self,raw,job,nonce,deadline):self.raw=raw;self.capture=raw.Capture(job,nonce);self.budget=BudgetAdapter(deadline);self.phase='preflight';self.lock=threading.RLock();self.operations=[]
    def emit(self,kind,payload,phase=None,stamp=None):
        with self.lock:self.budget.check();return self.capture.event(phase or self.phase,kind,payload,time.monotonic_ns() if stamp is None else stamp)
class PublicInventory:
    def __init__(self,ownership):self.ownership=ownership
    def capture(self):
        files={};directories={};total=0
        for path in FIXTURE.rglob('*'):
            relative=path.relative_to(FIXTURE)
            if '.git' in relative.parts:continue
            if path.is_symlink():raise Refusal('Fixture alias')
            if path.is_dir():directories[str(relative)]=self.ownership.directory_record(path);continue
            data,info=bounded(path,1024*1024);total+=len(data)
            if total>16*1024*1024:raise Refusal('Public fixture inventory bound')
            files[str(relative)]={'bytes_base64':base64.b64encode(data).decode(),'mode':stat.S_IMODE(info.st_mode),'stat':self.ownership.stat_record(info)}
        return {'root':str(FIXTURE),'files':files,'directories':directories}
class PipeInput:
    def __init__(self,stream,session,collector):self.stream,self.session,self.c=stream,session,collector
    def write(self,data):
        with self.c.trace.lock:
            line=bytes(data);q=self.c.raw.raw_line(base64.b64encode(line).decode());validate_request(q)
            if q['method']!='notifications/initialized' and self.session.pending is not None:raise Refusal('Concurrent MCP request before write')
            stamp=time.monotonic_ns();send_until=time.monotonic()+self.c.trace.budget.remaining(55);offset=0
            while offset<len(line):
                remaining=min(send_until-time.monotonic(),self.c.trace.budget.remaining(55))
                if remaining<=0:raise Refusal('Actual MCP cumulative write deadline')
                if not select.select([],[self.stream.fileno()],[],remaining)[1]:raise Refusal('Actual MCP write deadline')
                if time.monotonic()>=send_until:raise Refusal('Actual MCP cumulative write deadline before syscall')
                try:n=os.write(self.stream.fileno(),line[offset:])
                except BlockingIOError:continue
                if n<=0:raise Refusal('Actual MCP incomplete write')
                offset+=n
            if q['method']=='notifications/initialized':self.c.trace.emit('notification',{'session':self.session.label,'request_line_base64':base64.b64encode(line).decode(),'sent_ns':stamp},stamp=stamp)
            else:
                self.session.pending=(line,stamp)
            return offset
    def flush(self):return None
    def close(self):
        self.c.trace.budget.cleaning=True;self.c.trace.emit('process',self.session.owned.payload(self.session.process.pid,'EOF'));return self.stream.close()
    def __getattr__(self,key):return getattr(self.stream,key)
class IOFacade:
    def __init__(self,c):self.c=c
    def __getattr__(self,key):return getattr(os,key)
    def read(self,fd,size):
        data=os.read(fd,min(size,self.c.raw.MAX_LINE));session=self.c.sessions_by_fd.get(fd)
        if session:
            session.raw_buffer.extend(data)
            if len(session.raw_buffer)>self.c.raw.MAX_LINE:raise Refusal('Actual raw response line bound')
            while b'\n' in session.raw_buffer:
                line,_,rest=session.raw_buffer.partition(b'\n');session.raw_buffer[:]=rest
                if session.pending is None:raise Refusal('Unsolicited MCP output')
                request,sent=session.pending;session.pending=None
                with self.c.trace.lock:
                    received=time.monotonic_ns();response=line+b'\n';p={'session':session.label,'request_line_base64':base64.b64encode(request).decode(),'response_line_base64':base64.b64encode(response).decode(),'request':self.c.raw.raw_line(base64.b64encode(request).decode()),'response':self.c.raw.raw_line(base64.b64encode(response).decode()),'sent_ns':sent,'received_ns':received};self.c.trace.emit('rpc',p,stamp=received)
                session.owned.sample()
        return data
class SelectFacade:
    def __init__(self,c):self.c=c
    def __getattr__(self,key):return getattr(select,key)
    def select(self,r,w,e,timeout=None):return select.select(r,w,e,self.c.trace.budget.remaining(timeout or 55))
class ProcessProxy:
    def __init__(self,p,session,c):self.real,self.session,self.c=p,session,c
    def __getattr__(self,key):return getattr(self.real,key)
    def wait(self,timeout=None):return self.real.wait(timeout=self.c.trace.budget.remaining(timeout or 20))
    def terminate(self):return self.session.owned.signal_client()
class InstallerAction:
    def __init__(self,c,argv,stdout,stderr):self.c,self.argv,self.stdout,self.stderr=c,argv,stdout,stderr;self.real=None;self.owner=None;self.returned=None;self.pending_fd=None;self.release_uncertain=False;self.errors=[];self.output=None;self.finished=False;self.qualified=False;self.index=len(c.installers);c.installers.append(self)
    def attach(self,p):
        self.real=p # Reachable before any proxy/descriptor/helper setup.
        self.pending_fd=os.pidfd_open(p.pid,0);self.returned=self.c.installer.ReturnedHandle(p.pid,self.pending_fd);self.pending_fd=None
        self.owner=self.c.installer.OwnedInstaller.__new__(self.c.installer.OwnedInstaller)
        self.owner.__init__(p,self.argv,self.c.directory,self.c.action_budget,lambda kind,payload:self.c.trace.emit(kind,dict(payload,action_index=self.index)),self.c.installer_hashes,self.returned);self.qualified=True
    def capture(self):
        parts=[];stats=[];errors=[]
        try:self.c.action_budget.remaining(1)
        except BaseException as error:errors.append('Action deadline: '+repr(error))
        self.c.deadline.remaining(1,cleanup=True)
        for stream in (self.stdout,self.stderr):
            try:
                before=os.fstat(stream.fileno());data=os.pread(stream.fileno(),8*1024*1024+1,0);after=os.fstat(stream.fileno());parts.append(data);stats.append({'before':self.c.ownership.stat_record(before),'after':self.c.ownership.stat_record(after)})
                if not stat.S_ISREG(before.st_mode) or before.st_size>8*1024*1024 or len(data)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):errors.append('Installer output bound/identity changed')
            except BaseException as error:parts.append(b'');stats.append(None);errors.append(repr(error))
        self.output={'argv':list(self.argv),'action_index':self.index,'pid_identity':None if self.owner is None else getattr(self.owner,'leader',None),'returncode':None if self.real is None else self.real.returncode,'stdout_base64':base64.b64encode(parts[0]).decode(),'stderr_base64':base64.b64encode(parts[1]).decode(),'output_stats':stats,'capture_errors':errors};self.c.last_command=self.output;self.errors.extend(errors)
        try:self.c.action_budget.remaining(1)
        except BaseException as error:errors.append('Action deadline after capture: '+repr(error))
        if errors:raise Refusal('Actual installer output capture unresolved')
    def shutdown(self):
        previous=self.c.trace.budget.cleaning;self.c.trace.budget.cleaning=True;issues=[];released=True
        try:
            fd=self.pending_fd;self.pending_fd=None
            if fd is not None:
                try:os.close(fd)
                except BaseException as error:self.release_uncertain=True;released=False;issues.append(repr(error))
            for owner in (self.owner,self.returned):
                if owner is None:continue
                try:
                    if owner is self.owner and not hasattr(owner,'stop'):continue # Capsule still owns a pre-transfer fd.
                    if not owner.shutdown():released=False;issues.append('Installer handle/monitor cleanup uncertain')
                except BaseException as error:released=False;issues.append(repr(error))
            if self.real is not None:
                try:
                    if self.real.poll() is None:released=False;issues.append('Returned installer still live; quarantine')
                except BaseException as error:released=False;issues.append(repr(error))
            if self.release_uncertain:released=False;issues.append('Prior returned PIDfd release uncertainty')
        finally:self.c.trace.budget.cleaning=previous
        self.errors.extend(issues);self.c.errors.extend(issues);self.finished=released
        if not released:self.c.quarantined=True
        return released
class InstallerProxy:
    def __init__(self,action):self.action=action;self.real=action.real
    def __getattr__(self,key):return getattr(self.real,key)
    def wait(self,timeout=None):
        a=self.action;failure=None;result=None;previous=a.c.trace.budget.cleaning
        try:
            try:result=self.real.wait(timeout=a.c.action_budget.remaining(timeout))
            except BaseException as error:failure=error;a.errors.append('Original wait: '+repr(error))
            try:a.capture()
            except BaseException as error:failure=failure or error
            if failure is None:
                try:a.c.trace.budget.cleaning=True;a.owner.drain(result)
                except BaseException as error:failure=error;a.errors.append('Installer drain: '+repr(error))
        finally:
            try:
                if not a.shutdown() and failure is None:failure=Refusal('Installer resources unresolved')
            finally:a.c.trace.budget.cleaning=previous
        if failure is not None:raise failure
        return result
def private_owned_class(base):
    class PrivateOwned(base):
        def shutdown(self):
            # Stopping/joining is independent of sample/EOF/wait failures.
            # Never close a handle while the monitor could still use it.
            issues=[]
            try:self.stop.set()
            except BaseException as error:issues.append('Monitor stop: '+repr(error))
            try:
                if self.thread.ident is not None:self.thread.join(timeout=self.trace.budget.remaining(1))
            except BaseException as error:issues.append('Monitor join: '+repr(error))
            try:alive=self.thread.is_alive()
            except BaseException as error:issues.append('Monitor liveness: '+repr(error));alive=True
            if alive:
                self.errors.extend(issues+['Monitor remains live; PIDfds retained']);return False
            for item in self.owned.values():
                fd=item.get('pidfd')
                if fd is not None:
                    # Linux close errors can follow release of the number.
                    # Relinquish first; never retry a possibly reused fd.
                    item['pidfd']=None
                    try:os.close(fd)
                    except BaseException as error:issues.append('PIDfd close: '+repr(error))
            self.resource_release_uncertain=getattr(self,'resource_release_uncertain',False) or bool(issues)
            self.errors.extend(issues);return not issues and not self.resource_release_uncertain
        def drain(self):
            failure=None;released=False
            try:self.observe_drain()
            except BaseException as error:failure=error
            finally:released=self.shutdown()
            if failure is not None:raise failure
            if not released:raise Refusal('Owned resource release unresolved; quarantine')
        def observe_drain(self):
            self.trace.budget.cleaning=True;until=time.monotonic()+self.trace.budget.remaining(45)
            while time.monotonic()<until:
                self.sample();record,leases=self.layout.metadata();live=[]
                for pid,item in self.owned.items():
                    poll=select.poll();poll.register(item['pidfd'],select.POLLIN)
                    if not any(mask&select.POLLIN for _,mask in poll.poll(0)):live.append(pid)
                if not live and record is None and not leases and not self.layout.endpoint.exists() and not self.layout.processes():break
                time.sleep(.05)
            else:raise Refusal('Owned application drain unresolved')
            self.stop.set()
            if self.thread.ident is not None:self.thread.join(timeout=self.trace.budget.remaining(1))
            if self.thread.is_alive() or self.errors:raise Refusal('Owned monitor shutdown unresolved')
            if not {'client','adapter','backend','watchdog'}<={item['role'] for item in self.owned.values()}:raise Refusal('Incomplete startup roles')
            for pid,item in self.owned.items():
                poll=select.poll();poll.register(item['pidfd'],select.POLLIN);mask=0
                for _,value in poll.poll(0):mask|=value
                if not mask&select.POLLIN or mask&~(select.POLLIN|select.POLLHUP):raise Refusal('Bound handle drain differs')
                current=self.identity(pid);record,leases=self.layout.metadata();processes=self.layout.processes()
                if record is not None or leases or self.layout.endpoint.exists() or processes:raise Refusal('Runtime reappeared during final drain')
                self.trace.emit('process',self.payload(pid,'drain',self.launcher.returncode if pid==self.launcher.pid else None,{'pidfd_poll_revents':mask,'current_identity':current,'fixture_processes':processes}))
    return PrivateOwned
class ProcessFacade:
    def __init__(self,c):self.c=c
    def __getattr__(self,key):return getattr(subprocess,key)
    def Popen(self,argv,*args,**kwargs):
        c=self.c;values=list(map(str,argv));session=c.creating
        if session is None:
            if c.command_argv is None or values!=c.command_argv:raise Refusal('Unregistered process outside exact fixed installer action')
            if kwargs.get('start_new_session') is not True or kwargs.get('stdin')!=subprocess.DEVNULL:raise Refusal('Owned synchronous installer session required')
            if c.quarantined:raise Refusal('Earlier installer unresolved; no follow-on action')
            action=InstallerAction(c,values,kwargs['stdout'],kwargs['stderr']);c.active_installer=action
            p=subprocess.Popen(argv,*args,**kwargs);action.real=p
            try:action.attach(p);return InstallerProxy(action)
            except BaseException as error:
                action.errors.append('Original setup: '+repr(error))
                try:action.capture()
                except BaseException as capture_error:action.errors.append('Setup output: '+repr(capture_error))
                finally:
                    try:action.shutdown()
                    except BaseException as cleanup_error:action.errors.append('Setup resource cleanup: '+repr(cleanup_error));c.errors.append(repr(cleanup_error));c.quarantined=True
                raise
        expected=[str(session.plugin/'bin/checker-plugin'),'--root',str(FIXTURE),'--state-dir',str(STATE)]
        if values!=expected:raise Refusal('Only fixed retained launcher argv allowed')
        session.layout.require_absent();p=subprocess.Popen(argv,*args,**kwargs);session.process=p
        try:
            session.process=ProcessProxy(p,session,c);session.stdout_fd=p.stdout.fileno();session.pending=None;session.raw_buffer=bytearray();session.owned=c.OwnedProcesses(c.trace,session.layout,session.plugin,session.label)
            session.owned.start(p);c.sessions_by_fd[session.stdout_fd]=session;os.set_blocking(p.stdin.fileno(),False);p.stdin=PipeInput(p.stdin,session,c);return session.process
        except BaseException:
            # No unverified TERM/KILL; EOF first, uncertainty remains unqualified.
            session.startup_failed=True
            try:self.abort_start(session)
            except BaseException as cleanup_error:c.errors.append('Early launcher cleanup unresolved: '+repr(cleanup_error))
            raise
    def abort_start(self,session):
        c=self.c;p=getattr(session.process,'real',session.process);previous=c.trace.budget.cleaning;c.trace.budget.cleaning=True
        failures=[];released=False
        try:
            owner=getattr(session,'owned',None)
            if owner is not None:
                try:owner.stop.set()
                except BaseException as error:failures.append(error)
            try:
                if p.stdin and not p.stdin.closed:p.stdin.close()
            except BaseException as error:failures.append(error)
            try:p.wait(timeout=c.trace.budget.remaining(20))
            except BaseException as error:failures.append(error)
            try:session.layout.require_absent()
            except BaseException as error:failures.append(error)
        finally:
            try:
                if owner is None:released=True
                else:
                    try:released=owner.shutdown()
                    except BaseException as error:failures.append(error)
                for stream in (getattr(p,'stdout',None),getattr(p,'stderr',None),getattr(session,'log',None),getattr(session,'receipts',None)):
                    try:
                        if stream is not None and not stream.closed:stream.close()
                    except BaseException as error:failures.append(error)
                c.sessions_by_fd.pop(getattr(session,'stdout_fd',None),None)
                c.errors.extend('Early independent cleanup: '+repr(error) for error in failures)
            finally:c.trace.budget.cleaning=previous
        if failures:raise failures[0]
        if not released:raise Refusal('Early resource shutdown unresolved; quarantine')
        session.closed=True
class Instrumentor:
    """Private module hooks; invocation remains OFF until separate activation."""
    def __init__(self,acceptance,directory,plugin,job,nonce,raw_sha):
        if os.getuid()!=1000:raise Refusal('Fixed normal UID1000 required')
        raw_path=ROOT/'scripts/plugin-release-preservation-raw.py';raw_data=module_buffer(raw_path,raw_sha);raw=load_buffer(raw_path,raw_data)
        if not directory.is_absolute() or not directory.is_relative_to(ROOT/'.local') or directory.exists():raise Refusal('New canonical fixed public.local trial directory required')
        self.raw,self.acceptance,self.directory,self.plugin=raw,acceptance,directory,plugin;self.raw_sha=raw_sha;self.sessions=[];self.sessions_by_fd={};self.creating=None;self.errors=[];self.body_error=None;self.command_argv=None;self.last_command=None;self.last_action=None;self.initial_captured=False;self.conflict_binding=None;self.inventory_index=0;self.installers=[];self.active_installer=None;self.quarantined=False;self.action_budget=None
        if acceptance.report.get('archive',{}).get('sha256')!=ARCHIVE_SHA or plugin.resolve(strict=True)!=directory.parent/'extracted/progress-checker-0.2.1-dev-linux-x86_64/plugin':raise Refusal('Exact extracted404 input under owned trial required')
        owner_data=module_buffer(ROOT/'scripts/plugin-original-demo-collector.py',OWNERSHIP_SHA);self.ownership=load_buffer(ROOT/'scripts/plugin-original-demo-collector.py',owner_data);self.OwnedProcesses=private_owned_class(self.ownership.OwnedProcesses);self.OwnedProcesses.identity=staticmethod(self.ownership.identity)
        installer_path=ROOT/'scripts/plugin-release-preservation-installer.py';self.installer=load_buffer(installer_path,module_buffer(installer_path,INSTALLER_SHA));self.installer_hashes={name:self.installer.digest_file(path) for name,path in {'python':Path('/usr/bin/python3'),'codex':CODEX,'git':Path('/usr/bin/git')}.items()}
        release_path=ROOT/'scripts/plugin-release-acceptance.py';release_data=module_buffer(release_path,RELEASE_SHA);tree=ast.parse(release_data);function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='in_place_evidence_preservation')
        if sha(ast.get_source_segment(release_data.decode(),function).encode())!=BODY_SHA:raise Refusal('Original fixed body differs')
        self.release=load_buffer(release_path,release_data);self.deadline=self.release.Deadline(getattr(acceptance,'started_at',None));self.trace=Trace(raw,job,nonce,self.deadline);self.inventory=PublicInventory(self.ownership);self._activation=None
        self.install_private_hooks()
    def check(self,name,passed,detail=None):
        if name=='isolated profile contains exactly one expected plugin':self.trace.phase='after-install' if self.last_action=='install' else 'after-update'
        if name=='retained fixture original file bytes and modes restored':self.trace.phase='final'
        error=None
        try:return self.acceptance.check(name,passed,detail)
        except BaseException as exc:error=type(exc).__name__+': '+str(exc);raise
        finally:
            capture_failure=None
            try:
                if name=='native cached package files match checked archive before use':self.capture_cache()
                if name=='retained fixture original file bytes and modes restored':self.trace.emit('public-files',self.inventory.capture())
                if name=='refused state migration leaves native binding unchanged':
                    path=self.installed_binding();self.trace.emit('cache',{'mcp_before_base64':base64.b64encode(self.conflict_binding).decode(),'mcp_after_base64':base64.b64encode(bounded(path,65536)[0]).decode()})
                self.trace.emit('assertion',{'name':name,'passed':bool(passed),'error':error})
            except BaseException as capture_error:
                self.errors.append('Assertion facts capture failed: '+repr(capture_error))
                capture_failure=capture_error
            if name=='evidence packaged client shuts down cleanly' and self.creating is not None:
                session=self.creating
                try:
                    self.trace.emit('process',session.owned.payload(session.process.pid,'exit',session.process.returncode))
                    if error is None:
                        previous=self.trace.budget.cleaning
                        try:session.owned.drain();session.closed=True
                        finally:self.trace.budget.cleaning=previous
                    self.sessions_by_fd.pop(session.stdout_fd,None);self.creating=None
                except BaseException as capture_error:
                    self.errors.append('Original close/drain capture failed: '+repr(capture_error))
                    capture_failure=capture_failure or capture_error
                finally:
                    try:
                        if getattr(session,'owned',None) is not None and not session.owned.shutdown():raise Refusal('Close assertion resources unresolved; quarantine')
                    except BaseException as cleanup_error:self.errors.append('Close final resource cleanup: '+repr(cleanup_error));capture_failure=capture_failure or cleanup_error
                    self.sessions_by_fd.pop(getattr(session,'stdout_fd',None),None);self.creating=None
            if error is None and capture_failure is not None:raise capture_failure
    def installed_binding(self):return self.directory/'data/progress-checker-plugins'/hashlib.sha256(os.fsencode(FIXTURE)).hexdigest()[:12]/'plugins/progress-checker/mcp.json'
    def artifact(self,*args):return self.acceptance.artifact(*args)
    @property
    def options(self):return self.acceptance.options
    @property
    def report(self):return self.acceptance.report
    def capture_cache(self):
        profile=self.directory/'codex-profile';manifests=list((profile/'plugins/cache').rglob('plugin.json'))
        if len(manifests)!=1:raise Refusal('Fixed native cache inventory missing')
        cached=manifests[0].parent;checksums_data,_=bounded(self.plugin.parent/'checksums.json',1024*1024);checksums=self.raw.strict(checksums_data);files={};chunks=[];total=0;inventory=self.inventory_index
        if inventory>=4:raise Refusal('Only four literal cache inventories allowed')
        for relative in checksums:
            if not relative.startswith('plugin/') or relative=='plugin/mcp.json':continue
            name=relative.removeprefix('plugin/');path=cached/name;data,info=bounded(path,self.raw.MAX_CACHE_FILE);total+=len(data)
            if total>self.raw.MAX_CACHE_TOTAL:raise Refusal('Cache full-inventory byte bound')
            files[name]={'size':len(data),'sha256':sha(data),'regular':stat.S_ISREG(info.st_mode),'symlink':path.is_symlink()};count=max(1,(len(data)+self.raw.CACHE_CHUNK-1)//self.raw.CACHE_CHUNK)
            for index in range(count):
                offset=index*self.raw.CACHE_CHUNK;part=data[offset:offset+self.raw.CACHE_CHUNK];chunks.append({'inventory_id':inventory,'path':name,'index':index,'count':count,'offset':offset,'sha256':sha(part),'bytes_base64':base64.b64encode(part).decode()})
        self.trace.emit('cache',{'inventory_id':inventory,'archive_sha256':ARCHIVE_SHA,'root':str(FIXTURE),'state':str(STATE),'manifest_count':len(manifests),'checksums_base64':base64.b64encode(checksums_data).decode(),'mcp_base64':base64.b64encode(bounded(cached/'mcp.json',65536)[0]).decode(),'files':files})
        for chunk in chunks:self.trace.emit('cache-chunk',chunk)
        self.inventory_index+=1
    def instrument_evidence(self,evidence):
        original=evidence._MCP;c=self
        class PrivateBase(original):
            def __new__(cls,acceptance,directory,plugin,root,state,label):
                if root!=FIXTURE or state!=STATE or label not in ('release-'+x for x in c.raw.SESSIONS):raise Refusal('Four literal public preservation sessions only')
                if not c.initial_captured:
                    if label!='release-before-install':raise Refusal('Baseline public session must be first')
                    c.trace.emit('public-files',c.inventory.capture());c.initial_captured=True
                instance=super().__new__(cls);instance.label=label;instance.plugin=Path(plugin);instance.layout=c.ownership.FixtureLayout(FIXTURE,STATE);instance.closed=False;instance.owned=None;instance.stdout_fd=None;c.creating=instance;c.sessions.append(instance);c.trace.phase=label.removeprefix('release-');return instance
        evidence._MCP=PrivateBase;evidence.os=IOFacade(c);evidence.select=SelectFacade(c)
    def install_private_hooks(self):
        c=self;release=self.release;original_compile=compile;original_exec=exec
        evidence_path=ROOT/'scripts/plugin-evidence-acceptance.py';evidence_buffer=module_buffer(evidence_path,EVIDENCE_SHA)
        def checked_compile(source,filename,mode,*args,**kwargs):
            if filename!=str(evidence_path) or source!=evidence_buffer or mode!='exec':raise Refusal('Only exact original helper buffer may compile')
            return original_compile(source,filename,mode,*args,**kwargs)
        # The local evidence object and its dictionary must share replacements.
        def private_exec(code,namespace):
            original_exec(code,namespace);holder=SimpleNamespace(**namespace);c.instrument_evidence(holder);namespace.update(_MCP=holder._MCP,os=holder.os,select=holder.select)
        release.compile=checked_compile;release.exec=private_exec;release.subprocess=ProcessFacade(c)
        def guarded_cleanup(process,starttime,budget=None):
            action=c.active_installer
            if action is None or action.real is None or getattr(process,'real',process) is not action.real:raise Refusal('Unregistered installer cleanup handle')
            action.errors.append('Original command requested cleanup; no new signal policy authorized')
            # Return to preserve the active original wait exception. Unresolved
            # liveness is retained; every following action is forbidden.
            action.shutdown()
        release.stop_owned_group=guarded_cleanup
        original_command=release.command
        def command(arguments,timeout=30,*,budget=None,cleanup=False):
            values=list(map(str,arguments));common=['--project',str(FIXTURE),'--codex',str(CODEX),'--codex-home',str(c.directory/'codex-profile'),'--data-home',str(c.directory/'data'),'--skip-agent-instructions'];prefix=['/usr/bin/python3',str(c.plugin.parent/'install.py')]
            if values[:2]!=prefix or len(values)<3:raise Refusal('Fixed packaged installer only')
            action=values[2];extra=values[3+len(common):]
            if values[3:3+len(common)]!=common or action not in ('install','update','list','remove'):raise Refusal('Fixed native profile/data/project installer arguments only')
            if action=='install' and extra!=['--state-dir',str(STATE)] or action=='update' and extra not in ([],['--state-dir',str(c.directory/'conflicting-state')]) or action in ('list','remove') and extra:raise Refusal('No arbitrary state migration/action arguments')
            phase='conflicting-update' if extra==['--state-dir',str(c.directory/'conflicting-state')] else action
            if cleanup:phase='cleanup'
            c.trace.phase=phase;c.command_argv=values;c.last_command=None;c.last_action=action
            if c.quarantined:raise Refusal('Earlier installer unresolved; no follow-on action')
            previous_budget=c.trace.budget;c.action_budget=ActionBudget(c.deadline,timeout,cleanup);c.trace.budget=c.action_budget
            if phase=='conflicting-update':c.conflict_binding=bounded(c.installed_binding(),65536)[0]
            try:
                result=original_command(arguments,timeout,budget=c.action_budget,cleanup=cleanup)
                if c.last_command is None:raise Refusal('Actual native output capture missing')
                if c.quarantined:raise Refusal('Installer remains quarantined after command')
                payload=dict(c.last_command,action=action,cleanup=cleanup,action_errors=list(c.active_installer.errors));c.trace.emit('installer',payload);return result
            except BaseException as exc:
                if c.last_command is not None:
                    try:c.trace.emit('installer',dict(c.last_command,action=action,cleanup=cleanup,error=type(exc).__name__+': '+str(exc),action_errors=list(c.active_installer.errors)))
                    except BaseException as capture_error:c.errors.append('Original installer exception retained; capture emission: '+repr(capture_error))
                raise
            finally:c.command_argv=None;c.trace.budget=previous_budget
        release.command=command
    def invoke(self):
        # No registration, activation or transport is exposed by this module.
        return ['OFF: fixed-body live invocation/installer descendant drain/registration/committed observation is not integrated.']
if __name__=='__main__':
    argparse.ArgumentParser(description=__doc__).parse_args();print('OFF: private preservation instrumentation staging only; no preparation or body invocation.')
