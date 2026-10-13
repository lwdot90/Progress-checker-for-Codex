#!/usr/bin/python3
"""OFF-default fixed original-demo application collector. No reader-selected work.

Staged source only: invoke --prepare-live only after separate root review. The
unchanged evidence body runs once after independently guarded SIGUSR1 activation.
No approval function, credential copy, saved evidence read, or generic RPC exists.
"""
from __future__ import annotations
import argparse,base64,fcntl,hashlib,importlib.util,json,math,os,select,secrets,signal,socket,stat,struct,subprocess,sys,threading,time
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parent.parent
FIXTURE=ROOT/'.local/checker-demo/session-c5c6vsyz/project'
STATE=FIXTURE.parent/'state'
ARCHIVE=ROOT/'.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz'
ARCHIVE_SHA='404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
BODY_SHA='bb4b6e9e761836bc33f4c42e70c5a7c7b204558783e5ebdd9b2a56d5077d6aeb'
RAW_SHA='e61a08643d6c3cb37941c3a328f6d460277d2df23e8ab682d2ca4188dad9dac8'
LIFECYCLE_SHA='1aa5036b06bb3c2cf54afccbc3065c67b51ca830b1d3e45ccc83e3129da3631d'
RUNTIME_HASHES={'checker-plugin':'82fb1e7cef3172e465f33fec54d4d7be4f799c66193b5dd8f9b989689009fcaa','progress-checker':'9ece1092eba4232a3c66c745d90c7d62df5aaa25a3587a9363c6fe142c830d99','progress-checker-mcp':'6be43b4c12d46555d6443d2619bd15e1dd1754f297781f0fa5c0059bf5c79e7a'}
MODULE_NAMES=('plugin-original-demo-collector.py','plugin-original-demo-activate.py','plugin-original-demo-observer.py','plugin-original-demo-raw.py','plugin-original-demo-lifecycle.py','plugin-evidence-acceptance.py','plugin-acceptance.py')
TRUST='explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime'
PREP_SECONDS=1800;WORK_SECONDS=240;CLEANUP_SECONDS=120;OBSERVE_SECONDS=90;HARD_SECONDS=480

class Refusal(RuntimeError):pass

def digest(data):return hashlib.sha256(data).hexdigest()
def pairs(items):
    result={}
    for key,value in items:
        if key in result:raise Refusal('Duplicate JSON key')
        result[key]=value
    return result

def finite(value):
    result=float(value)
    if not math.isfinite(result):raise Refusal('Nonfinite JSON number')
    return result
def parse(data):return json.loads(data,object_pairs_hook=pairs,parse_float=finite,parse_constant=lambda _:(_ for _ in ()).throw(Refusal('Nonfinite JSON')))
def valid_record(value):
    return type(value) is dict and set(value)=={'pid','starttime'} and type(value['pid']) is int and value['pid']>0 and type(value['starttime']) is str and value['starttime'].isascii() and value['starttime'].isdecimal()
def valid_identity(value):
    return type(value) is dict and set(value)=={'pid','starttime','uid','state','ppid','argv'} and valid_record({key:value[key] for key in ('pid','starttime')}) and type(value['uid']) is int and value['uid']==1000 and type(value['ppid']) is int and value['ppid']>=0 and type(value['state']) is str and len(value['state'])==1 and type(value['argv']) is list and all(type(arg) is str for arg in value['argv'])

def anchored(path,limit,private=False):
    path=Path(path)
    if not path.is_absolute() or path.resolve(strict=True)!=path:raise Refusal('Noncanonical input')
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);os.close(parent);parent=next_fd
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno());data=stream.read(limit+1);after=os.fstat(stream.fileno());current=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or before.st_size>limit or len(data)!=before.st_size or identity(before)!=identity(after) or identity(before)!=identity(current) or before.st_mode&0o022:raise Refusal('Unsafe or changed bounded file')
            if private and (stat.S_IMODE(before.st_mode)!=0o600 or stat.S_IMODE(os.fstat(parent).st_mode)!=0o700):raise Refusal('Registration must be private')
            return data,before,after,current
    finally:os.close(parent)

def load(path,expected):
    data=anchored(path,8*1024*1024)[0]
    if digest(data)!=expected:raise Refusal('Imported buffer changed before compile/exec')
    spec=importlib.util.spec_from_file_location(path.stem.replace('-','_'),path);module=importlib.util.module_from_spec(spec)
    exec(compile(data,str(path),'exec'),module.__dict__);module.loaded_sha256=expected;return module

def identity(pid):
    try:
        proc=Path('/proc')/str(pid);fields=(proc/'stat').read_text().rsplit(')',1)[1].split()
        return {'pid':pid,'starttime':fields[19],'uid':proc.stat().st_uid,'state':fields[0],'ppid':int(fields[1]),'argv':(proc/'cmdline').read_bytes().decode().split('\0')[:-1]}
    except (OSError,IndexError,UnicodeError):return None

def socket_identity(path):
    info=path.lstat()
    if not stat.S_ISSOCK(info.st_mode):raise Refusal('Expected owned socket')
    return {'dev':info.st_dev,'ino':info.st_ino,'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}

def stat_record(s):return {'device':s.st_dev,'inode':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'nlink':s.st_nlink,'size':s.st_size,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'regular':stat.S_ISREG(s.st_mode)}

def directory_record(path):
    if path.resolve(strict=True)!=path:raise Refusal('Directory alias')
    # Anchor every parent independently, including directories with no file read.
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);os.close(fd);fd=child
        info=os.fstat(fd)
        if info.st_uid!=os.getuid():raise Refusal('Directory owner differs')
        return {'path':str(path),'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),'directory':True,'symlink':False}
    finally:os.close(fd)

class Budget:
    def __init__(self):self.activated=None;self.work=None;self.cleanup=None;self.hard=None;self.cleaning=False
    def activate(self):
        self.activated=time.monotonic();self.work=self.activated+WORK_SECONDS;self.cleanup=self.work+CLEANUP_SECONDS;self.hard=self.activated+HARD_SECONDS
    def deadline(self):return self.cleanup if self.cleaning else self.work
    def remaining(self,cap):
        remaining=min(cap,self.deadline()-time.monotonic())
        if remaining<=0:raise Refusal('Shared application deadline expired')
        return remaining
    def check(self):self.remaining(1)

class Trace:
    def __init__(self,raw,job,nonce,budget):self.raw=raw;self.capture=raw.Capture(job,nonce);self.budget=budget;self.phase='fixture-preflight';self.lock=threading.RLock();self.encoded_bytes=0;self.operations=[]
    def emit(self,kind,payload,phase=None,stamp=None):
        with self.lock:
            self.budget.check();frame=self.capture.event(phase or self.phase,kind,payload,stamp);line=json.dumps(frame,separators=(',',':'),allow_nan=False).encode()+b'\n'
            self.encoded_bytes+=len(line)
            if len(line)>self.raw.MAX_FRAME or self.encoded_bytes>self.raw.MAX_STREAM or len(self.capture.frames)>self.raw.MAX_FRAMES:raise Refusal('Raw capture bound exceeded')
            return frame
    def rpc(self,session,request_line,response_line,sent):
        with self.lock:
            received=time.monotonic_ns();q=self.raw.raw_line(base64.b64encode(request_line).decode());r=self.raw.raw_line(base64.b64encode(response_line).decode())
            payload={'session':session.label,'ordinal':q['id'],'request_line_base64':base64.b64encode(request_line).decode(),'response_line_base64':base64.b64encode(response_line).decode(),'request':q,'response':r,'sent_monotonic_ns':sent,'received_monotonic_ns':received}
            frame=self.emit('rpc',payload,session.request_phase,received)
            if q['method']=='tools/call' and q['params']['name']=='checker_run_checks':
                if session.label=='unapproved':self.phase='unapproved-after'
                elif not r.get('result',{}).get('isError',True):self.phase=self.phase.replace('-request','-finished')
            return frame
    def serialized(self):return [json.dumps(f,separators=(',',':'),allow_nan=False).encode()+b'\n' for f in self.capture.frames]

class FixtureLayout:
    def __init__(self,root,state):
        self.root,self.state=root,state;key=hashlib.sha256(os.fsencode(root)).hexdigest()[:24];self.runtime=state/('plugin-'+key);self.leases=self.runtime/'leases';self.record=self.runtime/'service.json'
        direct=state/('ipc-'+key+'.sock');self.endpoint=direct if len(os.fsencode(direct))<=100 else Path('/tmp')/('progress-checker-ipc-'+str(os.getuid()))/('ipc-'+hashlib.sha256(os.fsencode(root)+b'\0'+os.fsencode(state)).hexdigest()[:24]+'.sock')
    def metadata(self):
        for directory in (self.runtime,self.leases):
            if directory.exists() and directory_record(directory)['mode']!=0o700:raise Refusal('Runtime metadata directory not private')
        record=parse(anchored(self.record,4096)[0]) if self.record.exists() else None
        leases={p.name:parse(anchored(p,4096)[0]) for p in self.leases.glob('*.json')} if self.leases.exists() else {}
        if (record is not None and not valid_record(record)) or any(not valid_record(value) for value in leases.values()):raise Refusal('Runtime record/lease typed identity differs')
        return record,leases
    def matches(self,info):
        return info and '--root' in info['argv'] and '--state-dir' in info['argv'] and info['argv'][info['argv'].index('--root')+1]==str(self.root) and info['argv'][info['argv'].index('--state-dir')+1]==str(self.state)
    def processes(self):
        return [i for p in Path('/proc').iterdir() if p.name.isdigit() and (i:=identity(int(p.name))) and i['uid']==os.getuid() and i['state']!='Z' and self.matches(i)]
    def require_absent(self):
        record,leases=self.metadata()
        if record is not None or leases or self.endpoint.exists() or self.processes():raise Refusal('Existing fixture application/runtime ownership; do not adopt it')

class OwnedProcesses:
    def __init__(self,trace,layout,plugin,label):
        self.trace,self.layout,self.plugin,self.label=trace,layout,plugin,label;self.owned={};self.stop=threading.Event();self.errors=[];self.lock=threading.RLock();self.thread=threading.Thread(target=self.monitor,daemon=True)
    def start(self,process):
        self.launcher=process;self.pin(process.pid,'client',bootstrap=True);self.thread.start()
    def bootstrap_client(self,pid,fd):
        expected=['/usr/bin/python3',str(self.plugin/'bin/checker-plugin'),'--root',str(self.layout.root),'--state-dir',str(self.layout.state)]
        expected_exe=digest(Path('/usr/bin/python3').read_bytes());until=time.monotonic()+self.trace.budget.remaining(2);baseline=None;samples=[]
        def diagnostic(error):
            self.trace.emit('public-files',{'role':'launcher-bootstrap-diagnostic','session':self.label,'returned_child_pid':pid,'expected_argv':expected,'samples':samples,'error':error})
        try:
            while time.monotonic()<until and len(samples)<64:
                poll=select.poll();poll.register(fd,select.POLLIN)
                if poll.poll(0):raise Refusal('Returned launcher child exited during bootstrap')
                info=identity(pid);sample={'sampled_ns':time.monotonic_ns(),'identity':info,'executable_sha256':None};samples.append(sample)
                if info is not None:
                    if info.get('pid')!=pid or type(info.get('ppid')) is not int or info['ppid']!=os.getpid() or type(info.get('starttime')) is not str or not info['starttime'].isascii() or not info['starttime'].isdecimal():raise Refusal('Returned launcher PID/start/parent differs during bootstrap')
                    key=(info['pid'],info['starttime'],info['ppid'])
                    if baseline is None:baseline=key
                    elif key!=baseline:raise Refusal('Returned launcher identity changed during bootstrap')
                    # Empty argv or temporary /proc ownership is observed but
                    # never pinned. Nonempty foreign argv is not a new actor.
                    if info.get('argv') and info['argv']!=expected:raise Refusal('Returned launcher complete argv differs during bootstrap')
                    if valid_identity(info) and info['state']!='Z' and info['argv']==expected:
                        exe=digest(Path('/proc',str(pid),'exe').read_bytes());sample['executable_sha256']=exe
                        if exe!=expected_exe:raise Refusal('Returned launcher interpreter bytes differ during bootstrap')
                        if poll.poll(0):raise Refusal('Returned launcher exited before bootstrap pin')
                        diagnostic(None);return info
                remaining=min(.05,until-time.monotonic(),self.trace.budget.remaining(.05))
                if remaining>0:time.sleep(remaining)
            raise Refusal('Exact returned launcher did not stabilize within bootstrap deadline')
        except BaseException as exc:
            diagnostic(type(exc).__name__+': '+str(exc));raise
    def pin(self,pid,role,bootstrap=False):
        with self.lock:
            if pid in self.owned:return
            fd=os.pidfd_open(pid,0)
            try:
                info=self.bootstrap_client(pid,fd) if bootstrap else identity(pid)
                if not info or info['uid']!=1000 or info['state']=='Z' or not self.layout.matches(info):raise Refusal('Owned application identity/root/state differs')
                expected_parent=os.getpid() if role=='client' else self.launcher.pid
                if info['ppid']!=expected_parent:raise Refusal('Owned initial launcher ancestry differs')
                exe=digest(Path('/proc',str(pid),'exe').read_bytes());argv=info['argv'];names={str(self.plugin/'bin'/name):name for name in RUNTIME_HASHES}
                product=[x for x in argv if x in names]
                if len(product)!=1:raise Refusal('Unexpected owned executable argv')
                name=names[product[0]]
                if name!='checker-plugin' and exe!=RUNTIME_HASHES[name]:raise Refusal('Owned native executable bytes differ')
                if name=='checker-plugin' and digest(anchored(self.plugin/'bin/checker-plugin',1024*1024)[0])!=RUNTIME_HASHES[name]:raise Refusal('Owned launcher source differs')
                if role=='client' and argv[-4:]!=['--root',str(self.layout.root),'--state-dir',str(self.layout.state)]:raise Refusal('Unexpected launcher command')
                self.owned[pid]={'info':info,'pidfd':fd,'role':role,'exe':exe};fd=None
                self.trace.emit('process',self.payload(pid,'start'))
            finally:
                if fd is not None:os.close(fd)
    def payload(self,pid,operation,returncode=None,drain_facts=None):
        item=self.owned[pid];record,leases=self.layout.metadata()
        result={'session':self.label,'role':item['role'],'operation':operation,'pid_identity':item['info'],'executable_sha256':item['exe'],'argv':item['info']['argv'],'root':str(self.layout.root),'state':str(self.layout.state),'endpoint_identity':socket_identity(self.layout.endpoint) if self.layout.endpoint.exists() else None,'lease_snapshot':leases,'service_record':record,'returncode':returncode}
        if drain_facts is not None:result.update(drain_facts)
        return result
    def sample(self):
        record,leases=self.layout.metadata()
        candidates=self.layout.processes()
        for info in candidates:
            argv=info['argv'];pid=info['pid']
            if pid in self.owned:
                before=self.owned[pid]['info']
                if any(info[key]!=before[key] for key in ('pid','starttime','uid','argv')):raise Refusal('Owned application identity changed')
                continue
            if str(self.plugin/'bin/progress-checker') in argv and argv[-1]=='serve':
                if info['ppid']!=self.launcher.pid:raise Refusal('Backend initial ancestry differs')
                if record!={'pid':pid,'starttime':info['starttime']}:raise Refusal('Backend record identity differs')
                self.pin(pid,'backend')
            elif str(self.plugin/'bin/progress-checker') in argv and argv[-1]=='status':
                if info['ppid']!=self.launcher.pid:raise Refusal('Health probe ancestry differs')
                try:self.pin(pid,'health-probe')
                except ProcessLookupError:pass
            elif str(self.plugin/'bin/progress-checker-mcp') in argv:
                if info['ppid']!=self.launcher.pid:raise Refusal('Adapter ancestry differs')
                self.pin(pid,'adapter')
            elif str(self.plugin/'bin/checker-plugin') in argv and '--watch-service' in argv:
                if info['ppid']!=self.launcher.pid:raise Refusal('Watchdog initial ancestry differs')
                index=argv.index('--watch-service')
                expected=record or next(({'pid':item['info']['pid'],'starttime':item['info']['starttime']} for item in self.owned.values() if item['role']=='backend'),None)
                if expected is None or argv[index+1:]!=[str(expected['pid']),expected['starttime']]:raise Refusal('Watchdog record identity differs')
                self.pin(pid,'watchdog')
            else:raise Refusal('Unexpected fixture application process')
        if any(value!={'pid':self.launcher.pid,'starttime':self.owned[self.launcher.pid]['info']['starttime']} for value in leases.values()):raise Refusal('Foreign fixture lease')
    def monitor(self):
        while not self.stop.wait(.025):
            try:self.sample()
            except FileNotFoundError:pass
            except BaseException as error:self.errors.append(repr(error));return
    def signal_client(self):
        self.sample();item=self.owned[self.launcher.pid];current=identity(self.launcher.pid);baseline=item['info']
        if not current or any(current[k]!=baseline[k] for k in ('pid','starttime','uid','argv')) or digest(Path('/proc',str(self.launcher.pid),'exe').read_bytes())!=item['exe']:raise Refusal('Client changed before owned PIDfd TERM')
        signal.pidfd_send_signal(item['pidfd'],signal.SIGTERM,None,0);self.trace.emit('process',self.payload(self.launcher.pid,'TERM'))
    def drain(self):
        self.trace.budget.cleaning=True
        until=time.monotonic()+self.trace.budget.remaining(45)
        while time.monotonic()<until:
            self.sample();record,leases=self.layout.metadata()
            live=[]
            for pid,item in self.owned.items():
                poll=select.poll();poll.register(item['pidfd'],select.POLLIN)
                if not poll.poll(0):live.append(pid)
            if not live and record is None and not leases and not self.layout.endpoint.exists() and not self.layout.processes():break
            time.sleep(.05)
        else:raise Refusal('Owned launcher/backend/watchdog/lease/socket drain unresolved')
        self.stop.set();self.thread.join(timeout=1)
        if self.thread.is_alive():raise Refusal('Owned monitor thread remains live; preserving PIDfds')
        if self.errors:raise Refusal('Ownership monitor failed: '+repr(self.errors))
        roles={i['role'] for i in self.owned.values()}
        if not {'client','adapter','backend','watchdog'}<=roles:raise Refusal('Incomplete owned application startup identities')
        # Record real bound-handle readiness and fresh public observations before
        # closing any handle. An operation label alone is never exit evidence.
        drain_facts={}
        for pid,item in self.owned.items():
            poll=select.poll();poll.register(item['pidfd'],select.POLLIN)
            events=poll.poll(0);revents=0
            for _,value in events:revents|=value
            if not revents&select.POLLIN:raise Refusal('Owned PIDfd no longer exit-ready')
            current=identity(pid);processes=self.layout.processes();record,leases=self.layout.metadata()
            if processes or record is not None or leases or self.layout.endpoint.exists():raise Refusal('Runtime reappeared before drain capture')
            drain_facts[pid]={'pidfd_poll_revents':revents,'current_identity':current,'fixture_processes':processes}
        for pid,item in self.owned.items():self.trace.emit('process',self.payload(pid,'drain',self.launcher.returncode if pid==self.launcher.pid else None,drain_facts[pid]))
        for item in self.owned.values():os.close(item['pidfd'])
        self.trace.operations.append({'label':self.label,'backend':[i['info'] for i in self.owned.values() if i['role']=='backend'],'drained':True})

class RecordingInput:
    def __init__(self,stream,session):self.stream,self.session=stream,session
    def write(self,data):
        with self.session.trace.lock:return self._write(data)
    def _write(self,data):
        self.session.trace.budget.check();line=bytes(data);q=self.session.trace.raw.raw_line(base64.b64encode(line).decode());stamp=time.monotonic_ns();count=0
        while count<len(line):
            remaining=self.session.trace.budget.remaining(55)
            if not select.select([], [self.stream.fileno()], [], remaining)[1]:raise Refusal('Original MCP write deadline')
            try:written=os.write(self.stream.fileno(),line[count:])
            except BlockingIOError:continue
            if written<=0:raise Refusal('Original MCP pipe write failed')
            count+=written
        if count!=len(data):raise Refusal('Incomplete original MCP write')
        if q.get('method')=='notifications/initialized':
            self.session.trace.emit('rpc-notification',{'session':self.session.label,'request_line_base64':base64.b64encode(line).decode(),'request':q,'sent_monotonic_ns':stamp},self.session.label+'-open' if self.session.label!='approved' else 'approved-open',stamp)
        else:
            if self.session.pending is not None:raise Refusal('Unexpected concurrent MCP request')
            self.session.pending=(line,stamp);self.session.request_phase=self.session.trace.phase
        return count
    def flush(self):return None
    def close(self):
        self.session.trace.emit('process',self.session.owned.payload(self.session.process.pid,'EOF'));return self.stream.close()
    def __getattr__(self,key):return getattr(self.stream,key)

class IOFacade:
    def __init__(self,collector):self.c=collector
    def __getattr__(self,key):return getattr(os,key)
    def read(self,fd,size):
        self.c.trace.budget.check();data=os.read(fd,size)
        session=self.c.sessions_by_fd.get(fd)
        if session:
            session.raw_buffer.extend(data)
            if len(session.raw_buffer)>self.c.raw.MAX_LINE:raise Refusal('Actual original MCP bytes exceed line bound')
            while b'\n' in session.raw_buffer:
                line,_,rest=session.raw_buffer.partition(b'\n');session.raw_buffer[:]=rest
                if session.pending is None:raise Refusal('Unexpected MCP output')
                request,sent=session.pending;session.pending=None;self.c.trace.rpc(session,request,line+b'\n',sent);session.owned.sample()
        return data
    def open(self,path,flags,*args,**kwargs):
        fd=os.open(path,flags,*args,**kwargs)
        if self.c.cas is not None and Path(path)==FIXTURE/'feature.txt' and flags&os.O_RDWR:
            self.c.cas['fd']=fd;info=os.fstat(fd);self.c.cas['opened_identity']=stat_record(info);self.c.cas['pathname_identity']=stat_record((FIXTURE/'feature.txt').lstat())
        return fd
    def write(self,fd,data):
        self.c.trace.budget.check();n=os.write(fd,data)
        if self.c.cas and fd==self.c.cas.get('fd'):self.c.cas['write_counts'].append(n)
        return n
    def ftruncate(self,fd,size):
        result=os.ftruncate(fd,size)
        if self.c.cas and fd==self.c.cas.get('fd'):self.c.cas['truncate_size']=size
        return result
    def fsync(self,fd):
        result=os.fsync(fd)
        if self.c.cas and fd==self.c.cas.get('fd'):self.c.cas['fsync_return']=0
        return result

class SelectFacade:
    def __init__(self,collector):self.c=collector
    def __getattr__(self,key):return getattr(select,key)
    def select(self,read,write,error,timeout=None):
        return select.select(read,write,error,self.c.trace.budget.remaining(timeout if timeout is not None else 55))


class LockFacade:
    def __init__(self,collector):self.c=collector
    def __getattr__(self,key):return getattr(fcntl,key)
    def flock(self,fd,flags):
        result=fcntl.flock(fd,flags)
        if self.c.cas and fd==self.c.cas.get('fd') and flags==fcntl.LOCK_EX|fcntl.LOCK_NB:self.c.cas['lock_acquired']=True
        return result

class ProcessProxy:
    def __init__(self,process,session):self.real=process;self.session=session
    def __getattr__(self,key):return getattr(self.real,key)
    def wait(self,timeout=None):return self.real.wait(timeout=self.session.trace.budget.remaining(timeout or 20))
    def terminate(self):return self.session.owned.signal_client()

class SubprocessFacade:
    def __init__(self,collector):self.c=collector
    def __getattr__(self,key):return getattr(subprocess,key)
    def Popen(self,argv,*args,**kwargs):
        c=self.c;session=c.creating
        if session is None or list(map(str,argv))!=[str(c.plugin/'bin/checker-plugin'),'--root',str(session.root),'--state-dir',str(session.state)]:raise Refusal('Only fixed body launcher allowed')
        session.layout.require_absent();p=subprocess.Popen(argv,*args,**kwargs)
        # Establish the proxy and all cleanup fields before any ownership probe
        # can fail. Never expose a bare Popen to the original close fallback.
        session.owned=OwnedProcesses(c.trace,session.layout,c.plugin,session.label)
        session.process=ProcessProxy(p,session);session.stdout_fd=p.stdout.fileno()
        session.pending=None;session.raw_buffer=bytearray();session.trace=c.trace;session.request_phase=c.trace.phase;session.startup_failed=False
        try:
            session.owned.start(p);c.sessions_by_fd[session.stdout_fd]=session
            os.set_blocking(p.stdin.fileno(),False);p.stdin=RecordingInput(p.stdin,session)
            return session.process
        except BaseException:
            session.startup_failed=True
            try:self.abort_start(session)
            except BaseException as cleanup_error:c.cleanup_errors.append('Early launcher cleanup unresolved: '+repr(cleanup_error))
            raise
    def abort_start(self,session):
        # A failed ownership probe cannot authorize signaling an unverified
        # process. Close only our pipe, wait for normal EOF exit, and quarantine
        # any remaining process/runtime instead of adopting or force killing it.
        p=session.process.real;previous=self.c.budget.cleaning;self.c.budget.cleaning=True
        try:
            session.owned.stop.set()
            if p.stdin and not p.stdin.closed:p.stdin.close()
            p.wait(timeout=self.c.budget.remaining(20))
            if session.owned.thread.ident is not None:session.owned.thread.join(timeout=self.c.budget.remaining(1))
            if session.owned.thread.is_alive():raise Refusal('Early ownership monitor remains live; preserving PIDfds')
            session.layout.require_absent()
            for item in session.owned.owned.values():
                poll=select.poll();poll.register(item['pidfd'],select.POLLIN)
                if not poll.poll(0):raise Refusal('Early owned process did not exit')
            for item in session.owned.owned.values():os.close(item['pidfd'])
            session.owned.owned.clear()
            for stream in (p.stdout,p.stderr,getattr(session,'log',None),getattr(session,'receipts',None)):
                if stream is not None and not stream.closed:stream.close()
            self.c.sessions_by_fd.pop(session.stdout_fd,None);session.closed=True
        finally:self.c.budget.cleaning=previous
    def run(self,argv,*args,**kwargs):
        c=self.c;command=list(map(str,argv));expected=c.sentinel_root
        allowed=command[:3]==['/usr/bin/git','-C',str(expected)] and command[3:] in (['init','--quiet'],['add','.'],['-c','user.name=Evidence probe','-c','user.email=evidence@example.invalid','commit','--quiet','-m','Unapproved fixture'])
        if not allowed:raise Refusal('Unexpected public fixture command')
        start=time.monotonic_ns();kwargs['timeout']=c.trace.budget.remaining(min(kwargs.get('timeout',10),10));result=subprocess.run(argv,*args,**kwargs)
        self.record(command,result,start,'sentinel-git');return result
    def check_output(self,argv,*args,**kwargs):
        command=list(map(str,argv))
        if command!=['/usr/bin/git','-C',str(FIXTURE),'rev-parse','--show-toplevel']:raise Refusal('Unexpected Git preflight')
        start=time.monotonic_ns();kwargs['timeout']=self.c.trace.budget.remaining(min(kwargs.get('timeout',10),10));result=subprocess.run(argv,*args,capture_output=True,**kwargs);self.record(command,result,start,'fixture-git')
        if result.returncode:raise subprocess.CalledProcessError(result.returncode,argv,output=result.stdout,stderr=result.stderr)
        return result.stdout
    def record(self,command,result,start,role):
        if len(result.stdout or b'')+len(result.stderr or b'')>65536:raise Refusal('Git output bound')
        self.c.trace.emit('public-command',{'role':role,'argv':command,'cwd':str(ROOT),'env_policy_id':'original-body-env-values-not-exported','stdout_base64':base64.b64encode(result.stdout or b'').decode(),'stderr_base64':base64.b64encode(result.stderr or b'').decode(),'returncode':result.returncode,'started_ns':start,'ended_ns':time.monotonic_ns(),'pid_identity':None})

class Collector:
    def __init__(self,body,raw,acceptance,plugin,directory,budget,job,nonce,registration):
        self.body,self.raw,self.acceptance,self.plugin,self.directory,self.budget=body,raw,acceptance,plugin,directory,budget
        self.registration=registration;self.trace=Trace(raw,job,nonce,budget);self.sessions_by_fd={};self.sessions=[];self.creating=None;self.cas=None;self.sentinel_root=directory/'unapproved/project';self.fixture=None;self.original_checks=[];self.cleanup_errors=[]
    def snapshot(self,role):
        files=[]
        for name,path,limit in [('config',FIXTURE/'.progress-checker/config.json',65536),('script',FIXTURE/'check.py',4096),('feature',FIXTURE/'feature.txt',4096)]:
            data,before,after,current=anchored(path,limit);files.append({'relative_role':name,'bytes_base64':base64.b64encode(data).decode(),'before_stat':stat_record(before),'after_stat':stat_record(after),'path_lstat':stat_record(current)})
        return {'role':role,'files':files,'directory_stats':{'root':directory_record(FIXTURE),'state':directory_record(STATE),'config':directory_record(FIXTURE/'.progress-checker')},'capture_process':identity(os.getpid())}
    def check(self,name,condition,detail=None):
        self.original_checks.append({'name':name,'passed':bool(condition)});return self.acceptance.check(name,condition,detail)
    def artifact(self,*args):return self.acceptance.artifact(*args)
    @property
    def options(self):return self.acceptance.options
    @property
    def report(self):return self.acceptance.report
    def install(self):
        c=self;b=self.body;original_fixture=b._Fixture;original_mcp=b._MCP;original_run=b._run;original_unapproved=b._unapproved
        class ObservedFixture(original_fixture):
            def __init__(self,root,state):
                if (Path(root),Path(state))!=(FIXTURE,STATE):raise Refusal('Literal fixture only')
                super().__init__(root,state);c.fixture=self;c.trace.emit('public-files',c.snapshot('fixture'))
            def guard(self):
                super().guard()
                if c.trace.phase=='after-readonly':c.trace.phase='fixture-final'
                role='final' if c.trace.phase=='fixture-final' else 'guard';payload=c.snapshot(role)
                if c.cas is not None:payload['cas_guard_stage']='after' if c.cas.get('fsync_return')==0 else 'before'
                c.trace.emit('public-files',payload)
            def cas_feature(self,expected,replacement):
                if c.cas is not None:raise Refusal('Nested CAS')
                phase='feature-to-expected' if replacement==b.EXPECTED_FEATURE else 'feature-to-original' if replacement==self.original else 'cleanup'
                if c.budget.cleaning:phase='cleanup'
                c.trace.phase=phase;c.cas={'role':'to-expected' if phase=='feature-to-expected' else 'to-original','expected_base64':base64.b64encode(expected).decode(),'replacement_base64':base64.b64encode(replacement).decode(),'parent_identity':directory_record(FIXTURE),'write_counts':[],'lock_acquired':False,'truncate_size':None,'fsync_return':None}
                try:
                    super().cas_feature(expected,replacement);c.cas.pop('fd',None);c.cas['final_public_files']=c.snapshot('guard');c.trace.emit('feature-cas',dict(c.cas))
                except BaseException as exc:
                    c.cas.pop('fd',None);c.cas['error']=type(exc).__name__+': '+str(exc)
                    try:c.cas['final_public_files']=c.snapshot('guard')
                    except BaseException as capture_error:c.cas['snapshot_error']=repr(capture_error)
                    c.trace.emit('feature-cas',dict(c.cas));raise
                finally:c.cas=None
                if phase=='feature-to-original':c.trace.phase='stale'
        class ObservedMCP(original_mcp):
            def __init__(self,acceptance,directory,plugin,root,state,label):
                if label not in ('unapproved','approved','restart'):raise Refusal('Unknown fixed session')
                expected=(c.sentinel_root,c.directory/'unapproved/state') if label=='unapproved' else (FIXTURE,STATE)
                if (Path(root),Path(state))!=expected:raise Refusal('Unexpected body session fixture')
                self.label,self.root,self.state=label,Path(root),Path(state);self.layout=FixtureLayout(self.root,self.state);self.trace=c.trace;c.trace.phase=label+'-open';c.creating=self;c.sessions.append(self);self.closed=False
                try:super().__init__(acceptance,directory,plugin,root,state,label)
                finally:c.creating=None
                c.trace.phase='unapproved-before' if label=='unapproved' else 'initial' if label=='approved' else 'restored'
            def current(self):
                if self.label=='restart' and c.trace.phase=='readonly-plan':c.trace.phase='after-readonly'
                result=super().current()
                if c.trace.phase=='unapproved-after':c.trace.emit('public-files',{'role':'sentinel-marker','exists':(self.root/'EXECUTED').exists()})
                return result
            def tool(self,name,arguments=None,read_only=False):
                if self.label=='unapproved' and name=='checker_run_checks':c.trace.phase='unapproved-request'
                if read_only:c.trace.phase={'checker_run_checks':'readonly-run','checker_set_claim':'readonly-claim','checker_submit_plan':'readonly-plan'}[name]
                return super().tool(name,arguments,read_only)
            def close(self):
                if self.closed:return
                if getattr(self,'startup_failed',False):
                    return SubprocessFacade(c).abort_start(self)
                previous=c.budget.cleaning;c.budget.cleaning=True;c.trace.phase=self.label+'-close' if self.label!='restart' else 'restart-close'
                error=None
                try:
                    try:super().close()
                    finally:
                        # Capture the original wait's actual status, including a
                        # failed original clean-exit assertion, without changing
                        # that assertion or manufacturing success from drain.
                        code=self.process.returncode
                        if code is not None and not getattr(self,'client_exit_recorded',False):
                            c.trace.emit('process',self.owned.payload(self.process.pid,'exit',code));self.client_exit_recorded=True
                    self.owned.drain()
                except BaseException as exc:error=exc;c.cleanup_errors.append(repr(exc));raise
                finally:
                    if hasattr(self,'process'):c.sessions_by_fd.pop(self.stdout_fd,None)
                    self.closed=error is None;c.budget.cleaning=previous
                    if self.label=='restart':c.trace.phase='cleanup'
        def run(session,fixture,label):
            if label not in ('fail','pass'):raise Refusal('Unexpected fixed run label')
            c.trace.phase=label+'-request';return original_run(session,fixture,label)
        def unapproved(acceptance,directory,plugin):
            if Path(directory)!=c.directory/'unapproved':raise Refusal('Unexpected sentinel directory')
            c.trace.phase='unapproved-open';return original_unapproved(acceptance,directory,plugin)
        b._Fixture,b._MCP,b._run,b._unapproved=ObservedFixture,ObservedMCP,run,unapproved
        b.os,b.fcntl,b.subprocess,b.select=IOFacade(c),LockFacade(c),SubprocessFacade(c),SelectFacade(c)
    def execute(self):
        self.install();remaining=[];error=None;exitcode=0
        try:remaining=self.body.evidence_integrity(self,self.directory,FIXTURE,STATE)
        except BaseException as exc:error=type(exc).__name__+': '+str(exc);exitcode=2
        finally:
            self.budget.cleaning=True;self.trace.phase='cleanup'
            for session in self.sessions:
                if not session.closed:
                    try:session.close()
                    except BaseException as exc:self.cleanup_errors.append(repr(exc))
            if self.fixture is not None:
                try:
                    if self.fixture.feature_owned!=self.fixture.original:self.fixture.cas_feature(self.fixture.feature_owned,self.fixture.original)
                    self.fixture.guard()
                except BaseException as exc:self.cleanup_errors.append(repr(exc))
            if self.cleanup_errors:exitcode=2
            # Original function has a final guard before returning its public report.
            # Capture final restoration explicitly without claiming saved-record proof.
            if not self.cleanup_errors:
                self.trace.phase='fixture-final' if not any(f['phase']=='restart-close' for f in self.trace.capture.frames) else 'cleanup'
                try:self.trace.emit('public-files',self.snapshot('final'))
                except BaseException as exc:self.cleanup_errors.append(repr(exc));exitcode=2
            try:
                unchanged(self.registration,final=True)
                final_hashes={'module_hashes':{path:digest(anchored(Path(path),8*1024*1024)[0]) for path in self.registration['module_hashes']},'runtime_files':{path:digest(anchored(Path(path),32*1024*1024)[0]) for path in self.registration['runtime_files']},'fixture_files':public_pins()}
            except BaseException as exc:final_hashes={};self.cleanup_errors.append(repr(exc));exitcode=2
            self.report['registered_input_hashes_after']=final_hashes
            self.trace.phase='terminal';self.trace.emit('terminal',{'body_exit':exitcode,'remaining_unqualified':remaining,'error':error,'phase_completed':self.trace.phase,'cleanup_complete':not self.cleanup_errors,'cleanup_errors':self.cleanup_errors,'registered_input_hashes_after':self.report.get('registered_input_hashes_after',{})})
        return exitcode,remaining,error

class ActivationGate:
    def __init__(self):self.event=threading.Event();self.armed=False;self.early=False;self.deadline=None
    def signal(self,number,frame):
        if number!=signal.SIGUSR1:return
        if not self.armed or time.monotonic()>=self.deadline:self.early=True;return
        self.event.set()
    def publish(self,callback,deadline,mask):
        if signal.SIGUSR1 in signal.sigpending():raise Refusal('Early pending activation')
        callback()
        if signal.SIGUSR1 in signal.sigpending():raise Refusal('Signal raced publication')
        if time.monotonic()>=deadline:raise Refusal('Expired preparation')
        self.deadline=deadline;self.armed=True;signal.pthread_sigmask(signal.SIG_SETMASK,mask)
    def wait(self,server):
        while True:
            if self.early or not self.armed or time.monotonic()>=self.deadline:raise Refusal('Early/expired activation')
            if self.event.is_set():return
            try:
                reader,_=server.accept()
                with reader:reader.settimeout(.2);reader.sendall(b'NOT_READY\n')
            except socket.timeout:pass


def atomic(path,value):
    temp=path.with_name(path.name+'.tmp');data=json.dumps(value,indent=2).encode()+b'\n';fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    os.replace(temp,path)

def public_pins():
    pins={}
    for path,limit in [(FIXTURE/'.progress-checker/config.json',65536),(FIXTURE/'check.py',4096),(FIXTURE/'feature.txt',4096)]:
        data,info,_,_=anchored(path,limit);pins[str(path)]={'sha256':digest(data),'stat':stat_record(info)}
    return pins

def transfer_audit(meta,collector,payload):
    unchanged(meta,final=True)
    layouts=[FixtureLayout(FIXTURE,STATE),FixtureLayout(collector.sentinel_root,collector.directory/'unapproved/state')]
    censuses=[]
    for layout in layouts:
        layout.require_absent();record,leases=layout.metadata()
        censuses.append({'root':str(layout.root),'state':str(layout.state),'service_record':record,'leases':leases,'endpoint_identity':socket_identity(layout.endpoint) if layout.endpoint.exists() else None,'processes':layout.processes()})
    result={'schema_version':1,'job_id':meta['job_id'],'nonce':meta['nonce'],'observed_ns':time.monotonic_ns(),'raw_exact_bytes_sha256':digest(payload),'module_hashes':{path:digest(anchored(Path(path),8*1024*1024)[0]) for path in meta['module_hashes']},'runtime_files':{path:digest(anchored(Path(path),32*1024*1024)[0]) for path in meta['runtime_files']},'public_files':collector.snapshot('transfer'),'layout_censuses':censuses}
    data=json.dumps(result,separators=(',',':'),allow_nan=False).encode()
    if len(data)>1024*1024:raise Refusal('Fresh transfer audit exceeds byte bound')
    return data

def unchanged(meta,final=False):
    if digest(anchored(ARCHIVE,64*1024*1024)[0])!=ARCHIVE_SHA:raise Refusal('Registered archive changed')
    current_files=public_pins()
    for path,expected in meta['fixture_files'].items():
        current=current_files[path]
        if final and path==str(FIXTURE/'feature.txt'):
            if current['sha256']!=expected['sha256'] or any(current['stat'][k]!=expected['stat'][k] for k in ('device','inode','mode','uid','nlink','size','regular')):raise Refusal('Original feature bytes/identity not restored')
        elif current!=expected:raise Refusal('Registered fixture changed')
    for path,expected in meta['module_hashes'].items():
        if digest(anchored(Path(path),8*1024*1024)[0])!=expected:raise Refusal('Registered source changed')
    for path,expected in meta['runtime_files'].items():
        if digest(anchored(Path(path),32*1024*1024)[0])!=expected:raise Refusal('Registered extracted runtime changed')
    if directory_record(FIXTURE)!=meta['fixture_directories']['root'] or directory_record(STATE)!=meta['fixture_directories']['state']:raise Refusal('Fixture directory changed')

def prepare(directory):
    if os.getuid()!=1000:raise Refusal('Fixed normal host UID1000 required')
    directory=Path(directory)
    if not directory.is_absolute() or not directory.is_relative_to(ROOT/'.local') or directory.parent.resolve(strict=True)!=directory.parent or directory.exists() or len(os.fsencode(directory/'observe.sock'))>100:raise Refusal('New short canonical public.local directory required')
    fd=server=endpoint=socket_owned=None;created=False;locked=False
    lock_path=FIXTURE.parent/'.original-demo-observation-reservation'
    try:
        FixtureLayout(FIXTURE,STATE).require_absent();directory.mkdir(mode=0o700);created=True
        fd=os.open(lock_path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locked=True
        reservation={'pid':os.getpid(),'starttime':identity(os.getpid())['starttime'],'uid':os.getuid()};os.write(fd,json.dumps(reservation).encode());os.fsync(fd)
        # Persistent marker is intentionally not auto-cleared after unresolved cleanup.
        modules={str(ROOT/'scripts'/name):digest(anchored(ROOT/'scripts'/name,8*1024*1024)[0]) for name in MODULE_NAMES}
        if modules[str(ROOT/'scripts/plugin-evidence-acceptance.py')]!=BODY_SHA:raise Refusal('Original evidence body changed')
        if modules[str(ROOT/'scripts/plugin-original-demo-raw.py')]!=RAW_SHA:raise Refusal('Reviewed raw evaluator changed')
        if modules[str(ROOT/'scripts/plugin-original-demo-lifecycle.py')]!=LIFECYCLE_SHA:raise Refusal('Reviewed lifecycle evaluator changed')
        runner=load(ROOT/'scripts/plugin-acceptance.py',modules[str(ROOT/'scripts/plugin-acceptance.py')]);body=load(ROOT/'scripts/plugin-evidence-acceptance.py',BODY_SHA);raw=load(ROOT/'scripts/plugin-original-demo-raw.py',modules[str(ROOT/'scripts/plugin-original-demo-raw.py')])
        acceptance=runner.Acceptance(SimpleNamespace(milestone='evidence-integrity',archive=ARCHIVE,plugin_directory=None));plugin=runner.extract_archive(acceptance,ARCHIVE,directory/'extracted')
        if acceptance.report['archive']['sha256']!=ARCHIVE_SHA:raise Refusal('Exact404 archive required')
        runtime={str(plugin/'bin'/name):digest(anchored(plugin/'bin'/name,32*1024*1024)[0]) for name in RUNTIME_HASHES}
        if runtime!={str(plugin/'bin'/name):value for name,value in RUNTIME_HASHES.items()}:raise Refusal('Exact extracted runtime differs')
        # Read-only fixed fixture preflight; no Store, launcher, check or feature write.
        fixture=body._Fixture(FIXTURE,STATE);endpoint=directory/'observe.sock';server=socket.socket(socket.AF_UNIX);server.bind(str(endpoint));endpoint.chmod(0o600);socket_owned=socket_identity(endpoint);server.listen(1);server.settimeout(.2)
        now=time.monotonic_ns();meta={'schema_version':1,'job_id':secrets.token_hex(16),'nonce':secrets.token_hex(32),'mode':'original-demo','trust_policy':TRUST,'producer':identity(os.getpid()),'producer_argv':list(sys.argv),'python_exe_sha256':digest(Path('/proc/self/exe').read_bytes()),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'root':str(FIXTURE),'state':str(STATE),'body_sha256':BODY_SHA,'archive_sha256':ARCHIVE_SHA,'module_hashes':modules,'runtime_files':runtime,'fixture_files':public_pins(),'fixture_directories':{'root':directory_record(FIXTURE),'state':directory_record(STATE)},'endpoint':str(endpoint),'socket':socket_identity(endpoint),'prepared_ns':now,'activation_expires_ns':now+PREP_SECONDS*1_000_000_000,'budget_seconds':{'work':240,'cleanup':120,'observation':90,'final_margin':30,'hard':480,'preparation':1800},'check_definition':fixture.config['checks'][0]}
        return directory,fd,lock_path,server,meta,runner,body,raw,acceptance,plugin
    except BaseException as error:
        # prepare owns resources until return: main has no handles if we raise.
        cleanup_errors=[]
        if server is not None:
            try:server.close()
            except BaseException as exc:cleanup_errors.append('server close: '+repr(exc))
        if endpoint is not None and socket_owned is not None:
            try:
                if endpoint.exists():
                    if socket_identity(endpoint)!=socket_owned:raise Refusal('Prepared socket identity changed; preserving it')
                    endpoint.unlink()
            except BaseException as exc:cleanup_errors.append('socket cleanup: '+repr(exc))
        elif endpoint is not None and endpoint.exists():
            cleanup_errors.append('Prepared endpoint ownership was not captured; preserving it')
        if fd is not None:
            try:
                if not locked:raise Refusal('Reservation lock was not obtained; preserving marker')
                if cleanup_errors:raise Refusal('Preparation cleanup unresolved; preserving reservation marker')
                FixtureLayout(FIXTURE,STATE).require_absent()
                current=lock_path.lstat();opened=os.fstat(fd)
                if (current.st_dev,current.st_ino)!=(opened.st_dev,opened.st_ino):raise Refusal('Prepared reservation identity changed; preserving marker')
                lock_path.unlink()
            except BaseException as exc:cleanup_errors.append('reservation cleanup: '+repr(exc))
            finally:
                try:os.close(fd)
                except BaseException as exc:cleanup_errors.append('reservation close: '+repr(exc))
        if created:
            try:atomic(directory/'failure.json',{'status':'failed','phase':'preparation','error':type(error).__name__+': '+str(error),'cleanup_complete':not cleanup_errors,'cleanup_errors':cleanup_errors,'qualification_possible':False,'workflow_started':False,'reservation_policy':'Unresolved marker is retained; descriptor lock ends when this process exits.'})
            except BaseException as exc:raise Refusal('Preparation failed and failure report could not be saved: '+repr(exc)) from error
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--prepare-live',action='store_true');parser.add_argument('--output-dir',type=Path);args=parser.parse_args()
    if not args.prepare_live:
        print('OFF: no fixture process/check/preparation/activation operation.');return 0
    if args.output_dir is None:parser.error('--prepare-live requires a new explicit --output-dir')
    gate=ActivationGate();mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGUSR1});signal.signal(signal.SIGUSR1,gate.signal)
    directory=fd=lock_path=server=meta=None;clean=False;collector=None;remaining=[];error=None
    try:
        directory,fd,lock_path,server,meta,runner,body,raw,acceptance,plugin=prepare(args.output_dir)
        attestation=directory/'attestation.json';ready=directory/'readiness.json';data=json.dumps(meta,indent=2).encode()+b'\n'
        att_fd=os.open(attestation,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(att_fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        sha=digest(data);live={'schema_version':1,'attestation_path':str(attestation),'attestation_sha256':sha,'job_id':meta['job_id'],'nonce':meta['nonce'],'awaiting_activation':True,'ready':False,'consumed':False,'producer':meta['producer'],'endpoint':meta['endpoint'],'socket':meta['socket']}
        gate.publish(lambda:atomic(ready,live),meta['activation_expires_ns']/1e9,mask);print(str(attestation)+' SHA256 '+sha,flush=True);gate.wait(server)
        if anchored(attestation,1024*1024,True)[0]!=data:raise Refusal('Immutable registration changed')
        unchanged(meta);FixtureLayout(FIXTURE,STATE).require_absent();budget=Budget();budget.activate();live.update(awaiting_activation=False,activated_ns=int(budget.activated*1e9),workflow_deadline_ns=int(budget.work*1e9),hard_deadline_ns=int(budget.hard*1e9));atomic(ready,live)
        acceptance.options.plugin_directory=plugin;collector=Collector(body,raw,acceptance,plugin,directory/'body',budget,meta['job_id'],meta['nonce'],meta);code,remaining,error=collector.execute();unchanged(meta,final=True)
        clean=not collector.cleanup_errors;live.update(body_exit=code,error=error,cleanup_complete=clean,remaining_unqualified=remaining)
        events=directory/'events.jsonl';event_fd=os.open(events,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(event_fd,'wb') as stream:stream.write(b''.join(collector.trace.serialized()));stream.flush();os.fsync(stream.fileno())
        # No successful observation unless actual original checks and full owned drain succeeded.
        if not clean:raise Refusal('Owned cleanup unresolved; no ready stream')
        if not code and not remaining and len(collector.original_checks)!=18:raise Refusal('Original assertion instance coverage incomplete')
        lines=collector.trace.serialized();result=raw.evaluate_raw(lines,meta['job_id'],meta['nonce'],{'prepared_ns':meta['prepared_ns'],'activated_ns':live['activated_ns'],'workflow_deadline_ns':live['workflow_deadline_ns'],'hard_deadline_ns':live['hard_deadline_ns'],'observer_now_ns':time.monotonic_ns()})
        if not code and not remaining and (not all(x['passed'] for x in result['assertions']) or any(not value for group in ('fixture_cas_gates','session_binding_gates','run_association_gates') for value in result[group].values())):raise Refusal('Raw finite body predicates incomplete')
        payload=b''.join(lines);ready_until=min(budget.hard-30,time.monotonic()+OBSERVE_SECONDS);live.update(ready=True,observer_expires_ns=int(ready_until*1e9),collector_validation=result);atomic(ready,live)
        while time.monotonic()<ready_until:
            try:connection,_=server.accept();break
            except socket.timeout:pass
        else:raise Refusal('One-use observer did not arrive')
        with connection:
            peer_pid,peer_uid,peer_gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if peer_uid!=os.getuid():raise Refusal('Observer peer UID differs')
            handshake_deadline=min(ready_until,budget.hard-30)
            def set_remaining_timeout():
                remaining=handshake_deadline-time.monotonic()
                if remaining<=0:raise Refusal('Absolute observer handshake deadline expired')
                connection.settimeout(min(15,remaining))
            set_remaining_timeout();request=bytearray()
            while b'\n' not in request and len(request)<=4096:
                set_remaining_timeout()
                chunk=connection.recv(4097-len(request))
                if not chunk:break
                request.extend(chunk)
            decoded=parse(request)
            if type(decoded.get('schema_version')) is not int or decoded!={'schema_version':1,'job_id':meta['job_id'],'nonce':meta['nonce'],'request':'read-events'}:raise Refusal('No reader-selected work or additional request allowed')
            # Repeat the fixed public/source/drain audit after connection. This is
            # autonomous collection, never a reader-selected backend operation.
            unchanged(meta,final=True);FixtureLayout(FIXTURE,STATE).require_absent()
            for session in collector.sessions:session.layout.require_absent()
            if anchored(attestation,1024*1024,True)[0]!=data:raise Refusal('Immutable changed before stream')
            if parse(anchored(ready,1024*1024,True)[0])!=live:raise Refusal('Readiness changed before stream')
            audit=transfer_audit(meta,collector,payload)
            set_remaining_timeout()
            connection.sendall(struct.pack('!I',len(payload))+payload)
            set_remaining_timeout()
            connection.sendall(struct.pack('!I',len(audit))+audit)
            set_remaining_timeout()
            if connection.recv(1):raise Refusal('Forbidden observer followup')
            unchanged(meta,final=True);FixtureLayout(FIXTURE,STATE).require_absent()
            for session in collector.sessions:session.layout.require_absent()
            set_remaining_timeout()
            # Commit only after owned endpoint/reservation teardown. Keep the
            # accepted connection alive solely for the finite completion ACK.
            clean=False;server.close();server=None
            endpoint=Path(meta['endpoint'])
            if socket_identity(endpoint)!=meta['socket']:raise Refusal('Endpoint changed before completion cleanup')
            endpoint.unlink()
            opened=os.fstat(fd);current=lock_path.lstat()
            if (opened.st_dev,opened.st_ino)!=(current.st_dev,current.st_ino):raise Refusal('Reservation identity changed before completion cleanup')
            owner=parse(anchored(lock_path,4096,True)[0]);producer=identity(os.getpid())
            if owner!={'pid':producer['pid'],'starttime':producer['starttime'],'uid':producer['uid']}:raise Refusal('Reservation owner changed before completion cleanup')
            lock_path.unlink();os.close(fd);fd=None
            if os.path.lexists(endpoint) or os.path.lexists(lock_path):raise Refusal('Owned handoff resource reappeared')
            live.update(ready=False,consumed=True);atomic(ready,live)
            committed=anchored(ready,1024*1024,True)[0]
            if parse(committed)!=live:raise Refusal('Consumed readiness commit changed')
            completion={'schema_version':1,'job_id':meta['job_id'],'nonce':meta['nonce'],'completed_ns':time.monotonic_ns(),'raw_exact_bytes_sha256':digest(payload),'transfer_audit_sha256':digest(audit),'readiness_sha256':digest(committed),'module_hashes':meta['module_hashes'],'runtime_files':meta['runtime_files'],'endpoint_identity':None,'reservation_identity':None}
            acknowledgement=json.dumps(completion,separators=(',',':'),allow_nan=False).encode()
            if len(acknowledgement)>1024*1024:raise Refusal('Completion packet bound')
            set_remaining_timeout();connection.sendall(struct.pack('!I',len(acknowledgement))+acknowledgement);clean=True
            # Reader half-close requested no work. Full close releases the sole
            # ACK connection; wait boundedly so peer lifetime remains observable.
            hangup=select.poll();hangup.register(connection,select.POLLHUP|select.POLLERR)
            while True:
                set_remaining_timeout()
                if any(events&(select.POLLHUP|select.POLLERR) for _,events in hangup.poll(min(100,int((handshake_deadline-time.monotonic())*1000)))):break
        return 2 if code or remaining or error else 0
    except BaseException as exc:
        if directory is not None and collector is not None and not (directory/'events.jsonl').exists():
            try:
                event_fd=os.open(directory/'events.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(event_fd,'wb') as stream:stream.write(b''.join(collector.trace.serialized()));stream.flush();os.fsync(stream.fileno())
            except BaseException as capture_error:
                error=(error or '')+'; raw failure capture: '+repr(capture_error)
        if directory is not None:atomic(directory/'failure.json',{'status':'failed','error':type(exc).__name__+': '+str(exc),'cleanup_complete':clean,'qualification_possible':False,'body_remaining_unqualified':remaining,'body_error':error,'raw_event_file':str(directory/'events.jsonl') if (directory/'events.jsonl').exists() else None})
        return 2
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK,mask)
        if server:server.close()
        if meta:
            endpoint=Path(meta['endpoint'])
            if endpoint.exists() and socket_identity(endpoint)==meta['socket']:endpoint.unlink()
        if fd is not None:
            if clean and lock_path is not None:
                expected=parse(anchored(lock_path,4096,True)[0]);current=identity(os.getpid())
                if expected=={'pid':current['pid'],'starttime':current['starttime'],'uid':current['uid']}:lock_path.unlink()
            os.close(fd)

if __name__=='__main__':raise SystemExit(main())
