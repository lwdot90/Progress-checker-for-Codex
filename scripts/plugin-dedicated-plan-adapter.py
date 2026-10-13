#!/usr/bin/python3
"""OFF-default fixed original-body instrumentation adapter, SOURCE STAGING ONLY.

No CLI activation, preparation, registration or transport. Explicit run_once is
reserved for a separately reviewed future fixed host. It never approves checks
or reads private evidence/approval records. Default invocation performs no I/O.
"""
import base64
import hashlib
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import threading
import time
import types

ROOT = Path('/home/luis/progress-checker')
FIXTURE = ROOT/'.local/plugin-acceptance/plan-invalidation-human-fixture-v2/project'
STATE = FIXTURE.parent/'state'
ARCHIVE = ROOT/'.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz'
ARCHIVE_SHA = '404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
SOURCE_HASHES = {'plugin-acceptance.py':'ad1fc66caa841211d6f485832be4a602ac5c1a00743b5c42aefdbdd6f6ff1d99',
                 'plugin-dedicated-plan-capture.py':'a19413a48ca9f6fcd6b91344d21e66f0f6679aacad01cfc5d7359dcffc5d122c'}
RUNTIME_HASHES = {'checker-plugin':'82fb1e7cef3172e465f33fec54d4d7be4f799c66193b5dd8f9b989689009fcaa',
                  'progress-checker':'9ece1092eba4232a3c66c745d90c7d62df5aaa25a3587a9363c6fe142c830d99',
                  'progress-checker-mcp':'6be43b4c12d46555d6443d2619bd15e1dd1754f297781f0fa5c0059bf5c79e7a'}


class AdapterError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise AdapterError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_buffer(name, data):
    require(name in SOURCE_HASHES and type(data) is bytes and len(data) <= 8*1024*1024
            and digest(data) == SOURCE_HASHES[name], 'Exact bounded reviewed source buffer required')
    module = types.ModuleType(name.replace('-','_'))
    module.__file__ = str(ROOT/'scripts'/name)
    exec(compile(data,module.__file__,'exec'),module.__dict__)
    return module


def stat_record(info):
    return {'device':info.st_dev,'inode':info.st_ino,'mode':stat.S_IMODE(info.st_mode),
            'uid':info.st_uid,'nlink':info.st_nlink,'size':info.st_size,
            'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns,'regular':stat.S_ISREG(info.st_mode)}


def directory_record(path):
    fd = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd); fd = child
        info = os.fstat(fd)
        require(info.st_uid == 1000 and not info.st_mode & 0o022, 'Owned anchored directory required')
        return {'path':str(path),'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,
                'mode':stat.S_IMODE(info.st_mode),'directory':True,'symlink':False}
    finally:
        os.close(fd)


def anchored(path, limit):
    require(path.is_absolute() and '..' not in path.parts, 'Canonical bounded input required')
    parent = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            os.close(parent); parent = child
        fd = os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            before = os.fstat(stream.fileno()); data = stream.read(limit+1)
            after = os.fstat(stream.fileno()); current = os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 1000 and before.st_nlink == 1
                    and not before.st_mode & 0o022 and len(data) == before.st_size <= limit
                    and stat_record(before) == stat_record(after) == stat_record(current),
                    'Unsafe or changed anchored input')
            return data,stat_record(before),stat_record(after),stat_record(current)
    finally:
        os.close(parent)


def process_identity(pid):
    try:
        proc = Path('/proc')/str(pid)
        fields = (proc/'stat').read_text().rsplit(')',1)[1].split()
        return {'pid':pid,'starttime':fields[19],'uid':proc.stat().st_uid,'state':fields[0],
                'ppid':int(fields[1]),'argv':(proc/'cmdline').read_bytes().decode().split('\0')[:-1]}
    except (OSError,IndexError,UnicodeError):
        return None


def socket_identity(path):
    info = path.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 1000
            and stat.S_IMODE(info.st_mode) == 0o600, 'Owned service socket required')
    return {'dev':info.st_dev,'ino':info.st_ino,'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),
            'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}


class Budget:
    def __init__(self):
        self.started = time.monotonic()
        self.work_deadline = self.started+120
        self.cleanup_deadline = self.work_deadline+120
        self.cleaning = False
    def remaining(self, cap):
        deadline = self.cleanup_deadline if self.cleaning else self.work_deadline
        remaining = min(cap,deadline-time.monotonic())
        require(remaining > 0, 'Shared fixed-body deadline expired')
        return remaining


class Layout:
    """Only typed public launcher metadata; no Store/evidence/approval path."""
    def __init__(self, parser):
        self.parser = parser
        self.last_census = None
        key = hashlib.sha256(os.fsencode(FIXTURE)).hexdigest()[:24]
        self.runtime = STATE/('plugin-'+key)
        self.leases = self.runtime/'leases'
        self.record = self.runtime/'service.json'
        direct = STATE/('ipc-'+key+'.sock')
        short = hashlib.sha256(os.fsencode(FIXTURE)+b'\0'+os.fsencode(STATE)).hexdigest()[:24]
        self.endpoint = direct if len(os.fsencode(direct)) <= 100 else Path('/tmp')/'progress-checker-ipc-1000'/('ipc-'+short+'.sock')
    def metadata(self):
        for path in (self.runtime,self.leases):
            if path.exists(): require(directory_record(path)['mode'] == 0o700, 'Private public-runtime directory mode differs')
        def read(path):
            data, *_ = anchored(path,4096)
            value = self.parser(data)
            require(type(value) is dict and set(value) == {'pid','starttime'}
                    and type(value['pid']) is int and value['pid'] > 0
                    and type(value['starttime']) is str and value['starttime'].isascii()
                    and value['starttime'].isdecimal(), 'Typed public runtime identity required')
            return value
        record = read(self.record) if self.record.exists() else None
        paths = sorted(self.leases.glob('*.json')) if self.leases.exists() else []
        require(len(paths) <= 32, 'Public runtime lease count bound')
        return record,{path.name:read(path) for path in paths}
    def matches(self, info):
        if not info: return False
        argv = info['argv']
        if '--root' not in argv or '--state-dir' not in argv: return False
        root_index,state_index = argv.index('--root'),argv.index('--state-dir')
        return root_index+1 < len(argv) and state_index+1 < len(argv) and argv[root_index+1] == str(FIXTURE) and argv[state_index+1] == str(STATE)
    def processes(self):
        return [info for path in Path('/proc').iterdir() if path.name.isdecimal()
                and (info := process_identity(int(path.name))) and info['uid'] == 1000
                and info['state'] not in {'Z','X','x'} and self.matches(info)]
    def census(self):
        self.last_census = None
        record,leases = self.metadata()
        facts = {'service_record':record,'lease_snapshot':leases,
                'endpoint_identity':socket_identity(self.endpoint) if self.endpoint.exists() else None,
                'fixture_processes':self.processes()}
        self.last_census = facts
        return facts
    def absent(self):
        facts = self.census()
        require(facts['service_record'] is None and facts['lease_snapshot'] == {}
                and facts['endpoint_identity'] is None and facts['fixture_processes'] == [],
                'Existing fixture ownership must not be adopted')
        return facts


class Ownership:
    def __init__(self, adapter, process, session):
        self.adapter,self.process,self.session = adapter,process,session
        self.layout,self.owned,self.queue = adapter.layout,{},[]
        self.lock,self.stop = threading.RLock(),threading.Event()
        self.errors,self.pending_fds = [],set()
        self.resource_state = {'monitor_stopped':False,'pidfds_retained':[],
                               'handles_closed':[],'errors':[]}
        self.resources_closed,self.drain_attempted,self.drain_failure = False,False,None
        self.thread = threading.Thread(target=self.monitor,daemon=True)
    def payload(self,pid,operation,returncode=None):
        item = self.owned[pid]; record,leases = self.layout.metadata()
        return {'session':self.session,'role':item['role'],'operation':operation,
                'pid_identity':item['identity'],'executable_sha256':item['exe'],'argv':item['identity']['argv'],
                'root':str(FIXTURE),'state':str(STATE),'endpoint_identity':socket_identity(self.layout.endpoint) if self.layout.endpoint.exists() else None,
                'lease_snapshot':leases,'service_record':record,'returncode':returncode}
    def pin(self,pid,role,fd=None,info=None):
        if pid in self.owned: return
        if fd is None:
            fd = os.pidfd_open(pid,0); self.pending_fds.add(fd)
        try:
            info = info or process_identity(pid)
            require(info and info['uid'] == 1000 and info['state'] not in {'Z','X','x'}
                    and self.layout.matches(info) and info['ppid'] == (os.getpid() if role == 'client' else self.process.pid),
                    'Actual owned startup ancestry differs')
            args = ['--root',str(FIXTURE),'--state-dir',str(STATE)]
            expected_argv = {'client':['/usr/bin/python3',str(self.adapter.plugin/'bin/checker-plugin')]+args,
                'adapter':[str(self.adapter.plugin/'bin/progress-checker-mcp')]+args,
                'backend':[str(self.adapter.plugin/'bin/progress-checker')]+args+['serve'],
                'health-probe':[str(self.adapter.plugin/'bin/progress-checker')]+args+['status']}
            if role == 'watchdog':
                backend,_ = self.layout.metadata()
                backend = backend or next(({'pid':item['identity']['pid'],'starttime':item['identity']['starttime']}
                    for item in self.owned.values() if item['role'] == 'backend'),None)
                require(backend is not None, 'Watchdog needs actual backend identity')
                expected_argv[role] = (['/usr/bin/python3',str(self.adapter.plugin/'bin/checker-plugin')]+args+
                    ['--watch-service',str(backend['pid']),backend['starttime']])
            require(info['argv'] == expected_argv[role], 'Actual complete owned command differs')
            exe = digest((Path('/proc')/str(pid)/'exe').read_bytes())
            expected = self.adapter.python_sha if role in {'client','watchdog'} else RUNTIME_HASHES[
                'progress-checker-mcp' if role == 'adapter' else 'progress-checker']
            require(exe == expected, 'Actual owned executable bytes differ')
            self.owned[pid] = {'identity':info,'pidfd':fd,'role':role,'exe':exe}
            self.pending_fds.discard(fd)
            self.queue.append(self.payload(pid,'start'))
        except BaseException:
            # New unqualified handles remain bounded and owned until monitor
            # shutdown. Never race a running ownership thread by closing them.
            self.pending_fds.add(fd)
            raise
    def bootstrap_client(self,fd):
        pid = self.process.pid
        expected = ['/usr/bin/python3',str(self.adapter.plugin/'bin/checker-plugin'),
                    '--root',str(FIXTURE),'--state-dir',str(STATE)]
        until = time.monotonic()+self.adapter.budget.remaining(2)
        baseline,samples,error = None,[],None
        try:
            while time.monotonic() < until and len(samples) < 64:
                poll = select.poll(); poll.register(fd,select.POLLIN)
                require(not poll.poll(0), 'Exact returned child exited during bootstrap')
                info = process_identity(pid)
                sample = {'sampled_ns':time.monotonic_ns(),'identity':info,'executable_sha256':None}
                samples.append(sample)
                if info is not None:
                    require(type(info) is dict and set(info) == {'pid','starttime','uid','state','ppid','argv'}
                            and type(info['pid']) is int and info['pid'] == pid
                            and type(info['ppid']) is int and info['ppid'] == os.getpid()
                            and type(info['starttime']) is str and info['starttime'].isascii()
                            and info['starttime'].isdecimal(), 'Returned child PID/start/parent differs')
                    key = (info['pid'],info['starttime'],info['ppid'])
                    if baseline is None: baseline = key
                    require(key == baseline, 'Returned child identity changed during bootstrap')
                    require(type(info['argv']) is list and (not info['argv'] or info['argv'] == expected),
                            'Returned child complete argv differs')
                    if (type(info['uid']) is int and info['uid'] == 1000 and type(info['state']) is str
                            and len(info['state']) == 1 and info['state'] in 'RSDTtKWPI'
                            and info['argv'] == expected):
                        exe = digest((Path('/proc')/str(pid)/'exe').read_bytes())
                        sample['executable_sha256'] = exe
                        require(exe == self.adapter.python_sha and not poll.poll(0),
                                'Returned child interpreter or lifetime differs')
                        return info
                time.sleep(min(.05,max(0,until-time.monotonic()),self.adapter.budget.remaining(.05)))
            raise AdapterError('Exact returned child bootstrap deadline')
        except BaseException as exc:
            error = type(exc).__name__+': '+str(exc); raise
        finally:
            # These observations are diagnostics, never ownership/PASS facts.
            self.adapter.bootstrap_diagnostics.append({'session':self.session,'returned_child_pid':pid,
                'expected_argv':expected,'samples':samples,'error':error,'qualification_possible':False})
    def start(self):
        # Bind the exact returned child ONCE before its short stabilization
        # window. Empty argv is transient, never a selector for another actor.
        fd = os.pidfd_open(self.process.pid,0); self.pending_fds.add(fd)
        info = self.bootstrap_client(fd)
        with self.lock: self.pin(self.process.pid,'client',fd,info)
        self.thread.start()
    def sample(self):
        with self.lock:
            record,leases = self.layout.metadata()
            for info in self.layout.processes():
                pid,argv = info['pid'],info['argv']
                if pid in self.owned:
                    baseline = self.owned[pid]['identity']
                    require(all(info[key] == baseline[key] for key in ('pid','starttime','uid','argv')),
                            'Live owned PID identity changed')
                    continue
                if str(self.adapter.plugin/'bin/progress-checker') in argv and argv[-1] == 'serve':
                    require(record == {'pid':pid,'starttime':info['starttime']}, 'Actual backend record binding differs')
                    role = 'backend'
                elif str(self.adapter.plugin/'bin/progress-checker-mcp') in argv: role = 'adapter'
                elif str(self.adapter.plugin/'bin/checker-plugin') in argv and '--watch-service' in argv:
                    index = argv.index('--watch-service')
                    backend = record or next(({'pid':item['identity']['pid'],'starttime':item['identity']['starttime']}
                                             for item in self.owned.values() if item['role'] == 'backend'),None)
                    require(backend and argv[index+1:] == [str(backend['pid']),backend['starttime']],
                            'Actual watchdog backend binding differs')
                    role = 'watchdog'
                elif str(self.adapter.plugin/'bin/progress-checker') in argv and argv[-1] == 'status': role = 'health-probe'
                else: raise AdapterError('Foreign fixture process')
                try: self.pin(pid,role)
                except ProcessLookupError:
                    if role != 'health-probe': raise
            client = self.owned[self.process.pid]['identity']
            require(all(value == {'pid':client['pid'],'starttime':client['starttime']} for value in leases.values()),
                    'Foreign fixture launcher lease')
    def monitor(self):
        while not self.stop.wait(.025):
            try: self.sample()
            except FileNotFoundError: continue
            except BaseException as exc:
                self.errors.append(type(exc).__name__+': '+str(exc)); return
    def flush(self):
        with self.lock:
            if self.adapter.capture.pending is not None: return
            while self.queue:
                self.adapter.emit('process',self.queue.pop(0))
    def operation(self,name,returncode=None):
        with self.lock:
            self.queue.append(self.payload(self.process.pid,name,returncode)); self.flush()
    def term_client(self):
        self.sample(); item = self.owned[self.process.pid]; current = process_identity(self.process.pid)
        require(current and all(current[key] == item['identity'][key] for key in ('pid','starttime','uid','argv'))
                and digest((Path('/proc')/str(self.process.pid)/'exe').read_bytes()) == item['exe'],
                'Owned client changed before PIDfd TERM')
        signal.pidfd_send_signal(item['pidfd'],signal.SIGTERM,None,0); self.operation('TERM')
    def stop_monitor(self):
        self.stop.set()
        if self.thread.ident is not None:
            reserve = min(2,max(0,self.adapter.budget.cleanup_deadline-time.monotonic()))
            self.thread.join(timeout=reserve)
        stopped = not self.thread.is_alive()
        self.resource_state['monitor_stopped'] = stopped
        return stopped
    def shutdown(self):
        if self.resources_closed: return not self.resource_state['errors']
        stopped = self.stop_monitor()
        if not stopped:
            self.resource_state['pidfds_retained'] = [item['pidfd'] for item in self.owned.values()]+list(self.pending_fds)
            message = 'Monitor remains alive; PIDfds quarantined and retained'
            self.resource_state['errors'].append(message); self.adapter.cleanup_errors.append(message)
            return False
        handles = {item['pidfd'] for item in self.owned.values()} | self.pending_fds
        for fd in handles:
            try:
                os.close(fd); self.resource_state['handles_closed'].append(fd)
            except OSError as exc:
                message = 'PIDfd close failed: '+str(exc)
                self.resource_state['errors'].append(message); self.adapter.cleanup_errors.append(message)
        for item in self.owned.values(): item['pidfd'] = None
        self.pending_fds.clear()
        self.resources_closed = True
        return not self.resource_state['errors']
    def drain(self):
        if self.drain_attempted:
            released = self.shutdown()
            if self.drain_failure is not None: raise self.drain_failure
            require(released, 'Owned resource shutdown unresolved'); return
        self.drain_attempted = True
        failure = None
        try: self.observe_drain()
        except BaseException as exc: failure = exc
        finally: released = self.shutdown()
        self.drain_failure = failure
        if failure is not None: raise failure
        require(released, 'Owned resource shutdown unresolved')
    def observe_drain(self):
        self.adapter.budget.cleaning = True
        until = time.monotonic()+self.adapter.budget.remaining(45)
        while time.monotonic() < until:
            self.sample(); self.flush(); record,leases = self.layout.metadata()
            live = []
            for pid,item in self.owned.items():
                poll = select.poll(); poll.register(item['pidfd'],select.POLLIN)
                if not poll.poll(0): live.append(pid)
            if not live and record is None and not leases and not self.layout.endpoint.exists() and not self.layout.processes(): break
            time.sleep(.05)
        else: raise AdapterError('Owned fixture drain unresolved')
        require(self.stop_monitor() and not self.errors, 'Owned monitor did not finish cleanly')
        require({'client','adapter','backend','watchdog'} <= {item['role'] for item in self.owned.values()},
                'Actual startup role capture incomplete')
        with self.lock:
            for pid,item in self.owned.items():
                poll = select.poll(); poll.register(item['pidfd'],select.POLLIN)
                mask = 0
                for _,value in poll.poll(0): mask |= value
                require(mask & select.POLLIN and not mask & ~17, 'Actual PIDfd death readiness disappeared')
                payload = self.payload(pid,'drain',self.process.returncode if pid == self.process.pid else None)
                payload.update(pidfd_poll_revents=mask,current_identity=process_identity(pid),fixture_processes=self.layout.processes())
                require(payload['service_record'] is None and payload['lease_snapshot'] == {}
                        and payload['endpoint_identity'] is None and payload['fixture_processes'] == [],
                        'Runtime reappeared before final drain observation')
                self.queue.append(payload)
            self.flush()


class RecordingInput:
    def __init__(self,stream,session): self.stream,self.session = stream,session
    def write(self,data):
        with self.session.adapter.lock:
            wire = bytes(data); self.session.adapter.raw.wire_line(wire); count = 0
            while count < len(wire):
                remaining = self.session.adapter.budget.remaining(55)
                require(select.select([],[self.stream.fileno()],[],remaining)[1], 'Original pipe write deadline')
                try: written = os.write(self.stream.fileno(),wire[count:])
                except BlockingIOError: continue
                require(written > 0, 'Original pipe write failed'); count += written
            self.session.adapter.capture.request(self.session.label,wire,time.monotonic_ns())
            return count
    def flush(self): return None
    def close(self):
        self.session.owned.operation('EOF'); return self.stream.close()
    def __getattr__(self,name): return getattr(self.stream,name)


class ProcessProxy:
    def __init__(self,real,session):
        self.real,self.session,self.exited = real,session,False
        self.stdin = RecordingInput(real.stdin,session)
    def wait(self,timeout=None):
        result = self.real.wait(timeout=self.session.adapter.budget.remaining(timeout or 20))
        if not self.exited:
            self.session.owned.operation('exit',result); self.exited = True
        return result
    def terminate(self): self.session.owned.term_client()
    def __getattr__(self,name): return getattr(self.real,name)


class IOFacade:
    def __init__(self,adapter): self.adapter = adapter
    def read(self,fd,size):
        self.adapter.budget.remaining(1); data = os.read(fd,size)
        session = self.adapter.sessions_by_fd.get(fd)
        if session:
            session.raw_buffer.extend(data)
            require(len(session.raw_buffer) <= self.adapter.raw.MAX_LINE, 'Actual raw pipe line exceeds bound')
            while b'\n' in session.raw_buffer:
                line,_,rest = session.raw_buffer.partition(b'\n'); session.raw_buffer[:] = rest
                self.adapter.capture.response(session.label,bytes(line)+b'\n',time.monotonic_ns())
                session.owned.sample(); session.owned.flush()
        return data
    def __getattr__(self,name): return getattr(os,name)


class SelectFacade:
    def __init__(self,adapter): self.adapter = adapter
    def select(self,read,write,error,timeout=None):
        return select.select(read,write,error,self.adapter.budget.remaining(timeout if timeout is not None else 55))
    def __getattr__(self,name): return getattr(select,name)


class SubprocessFacade:
    def __init__(self,adapter): self.adapter = adapter
    def Popen(self,argv,**kwargs):
        session = self.adapter.creating
        require(session is not None and argv == [str(self.adapter.plugin/'bin/checker-plugin'),
                '--root',str(FIXTURE),'--state-dir',str(STATE)], 'Only original fixed packaged launcher allowed')
        process = subprocess.Popen(argv,**kwargs)
        # Publish all owned cleanup fields before any setblocking/bootstrap/
        # ownership probe can fail; original close never sees a bare Popen.
        session.real = process
        session.owned = Ownership(self.adapter,process,session.label)
        session.stdout_fd = process.stdout.fileno()
        session.proxy = ProcessProxy(process,session)
        session.wire = session.proxy
        session.startup_failed,session.abort_attempted = True,False
        try:
            session.owned.start(); session.owned.flush()
            os.set_blocking(process.stdin.fileno(),False)
            self.adapter.sessions_by_fd[session.stdout_fd] = session
            session.startup_failed = False
            return session.proxy
        except BaseException:
            try: self.abort_start(session)
            except BaseException as exc:
                self.adapter.cleanup_errors.append('Startup cleanup unresolved: '+type(exc).__name__+': '+str(exc))
            raise
    def abort_start(self,session):
        # Never TERM an unverified actor. Our own pipe EOF and bounded wait
        # preserve the real startup failure; remaining runtime is quarantined.
        previous = self.adapter.budget.cleaning; self.adapter.budget.cleaning = True
        failure,result = None,None
        session.owned.stop.set()
        try:
            if not session.abort_attempted:
                session.abort_attempted = True
                if session.real.stdin and not session.real.stdin.closed:
                    try:
                        if session.real.pid in session.owned.owned:
                            session.owned.operation('EOF')
                    except BaseException as exc:
                        self.adapter.cleanup_errors.append('Startup EOF capture failed: '+str(exc))
                    try: session.real.stdin.close()
                    except BaseException as exc:
                        failure = exc
                        self.adapter.cleanup_errors.append('Startup own-pipe close failed: '+str(exc))
                # Waiting is independent of diagnostic/pipe failures. It never
                # signals an actor whose startup identity was not qualified.
                try:
                    result = session.real.wait(timeout=self.adapter.budget.remaining(20))
                    if session.real.pid in session.owned.owned:
                        session.owned.operation('exit',result)
                except BaseException as exc:
                    failure = failure or exc
            else:
                result = session.real.returncode
        except BaseException as exc:
            failure = exc
        finally:
            released = session.owned.shutdown()
            try:
                if session.real.stdout and not session.real.stdout.closed: session.real.stdout.close()
            except BaseException as exc:
                self.adapter.cleanup_errors.append('Startup stdout close failed: '+str(exc))
            self.adapter.sessions_by_fd.pop(session.stdout_fd,None)
            session.abort_facts = {'pipe_closed':session.real.stdin.closed,
                                   'wait_returncode':session.real.returncode,
                                   'failure':None if failure is None else type(failure).__name__+': '+str(failure),
                                   'qualified_startup':session.real.pid in session.owned.owned,
                                   'qualification_possible':False}
            self.adapter.budget.cleaning = previous
        if failure is not None: raise failure
        require(released and result is not None, 'Startup child/resource lifetime unresolved; quarantine')
        # Parent wait/monitor shutdown do not prove that owned backend/watchdog
        # or public runtime disappeared. Take a fresh fixed public census before
        # declaring this exceptional cleanup finished; never signal a backend.
        try:
            session.abort_facts['public_census'] = self.adapter.layout.absent()
            session.abort_facts['runtime_absent'] = True
        except BaseException as exc:
            session.abort_facts['runtime_absent'] = False
            session.abort_facts['public_census'] = self.adapter.layout.last_census
            session.abort_facts['census_error'] = type(exc).__name__+': '+str(exc)
            self.adapter.cleanup_errors.append('Startup runtime quarantine: '+str(exc))
            raise
        session.closed = True
        return result
    def run(self,argv,**kwargs):
        require(list(map(str,argv)) == ['/usr/bin/git','-C',str(FIXTURE),'rev-parse','--show-toplevel'],
                'Only original fixed Git root probe allowed')
        kwargs['timeout'] = self.adapter.budget.remaining(kwargs.get('timeout',15))
        completed = subprocess.run(argv,**kwargs)
        self.adapter.emit('git-root',{'argv':list(map(str,argv)),'exit_code':completed.returncode,
           'stdout_base64':base64.b64encode(completed.stdout).decode(),
           'stderr_base64':base64.b64encode(completed.stderr).decode()})
        return completed
    def __getattr__(self,name): return getattr(subprocess,name)


class FixedAdapter:
    """Constructor loads pinned source only; run_once requires future host review.

    collection_directory chooses only the future public capture workspace. It
    cannot select a fixture, command, API operation, approval or state store.
    No method supplies a human confirmation or reads saved verification data.
    """
    def __init__(self,source_buffers,collection_directory,job_id,nonce,python_sha256):
        require(type(source_buffers) is dict and set(source_buffers) == set(SOURCE_HASHES),
                'Exact original/pure capture source inventory required')
        self.runner = load_buffer('plugin-acceptance.py',source_buffers['plugin-acceptance.py'])
        self.raw = load_buffer('plugin-dedicated-plan-capture.py',source_buffers['plugin-dedicated-plan-capture.py'])
        self.capture = self.raw.Capture(job_id,nonce)
        self.directory = Path(collection_directory)
        require(self.directory.is_absolute() and self.directory.is_relative_to(ROOT/'.local')
                and '..' not in self.directory.parts, 'Fixed public collection workspace required')
        self.plugin = self.directory/'extracted/progress-checker-0.2.1-dev-linux-x86_64/plugin'
        self.body_directory = self.directory/'body'
        require(type(python_sha256) is str and len(python_sha256) == 64
                and all(char in '0123456789abcdef' for char in python_sha256), 'Registered Python executable hash required')
        self.python_sha = python_sha256
        self.layout = Layout(self.raw.strict)
        self.sessions,self.sessions_by_fd = [],{}
        self.lock,self.creating,self.used = threading.RLock(),None,False
        self.cleanup_errors,self.bootstrap_diagnostics,self.uncorrelated_closes = [],[],[]
    def emit(self,kind,payload):
        with self.lock:
            self.budget.remaining(1)
            return self.capture.event(kind,payload,time.monotonic_ns())
    def public_snapshot(self,role):
        files = []
        for name,path,limit in [('config',FIXTURE/'.progress-checker/config.json',65536),
                                ('script',FIXTURE/'plan-check.py',4096),('feature',FIXTURE/'feature.txt',4096)]:
            data,before,after,current = anchored(path,limit)
            files.append({'role':name,'bytes_base64':base64.b64encode(data).decode(),
                          'before_stat':before,'after_stat':after,'path_lstat':current})
        return {'role':role,'root':str(FIXTURE),'state':str(STATE),'files':files,
                'directories':{'root':directory_record(FIXTURE),'state':directory_record(STATE),
                               'config':directory_record(FIXTURE/'.progress-checker')}}
    def install_instrumentation(self):
        adapter = self; runner = self.runner; original_session = runner.LauncherSession
        class ObservedAcceptance(runner.Acceptance):
            def check(self,name,condition,detail=None):
                try: result = super().check(name,condition,detail)
                except RuntimeError:
                    adapter.emit('original-assertion',{'name':name,'passed':False,'exception_type':'RuntimeError'})
                    raise
                adapter.emit('original-assertion',{'name':name,'passed':True,'exception_type':None})
                return result
            def artifact(self,name,path):
                expected = {('plan_invalidation_'+role):adapter.plugin/'bin'/binary
                            for role,binary in [('launcher','checker-plugin'),('checker','progress-checker'),('mcp','progress-checker-mcp')]}
                require(name in expected and path == expected[name], 'Only original fixed artifact identities allowed')
                result = super().artifact(name,path)
                require(self.report['artifacts'][name]['sha256'] == RUNTIME_HASHES[path.name], 'Original artifact hash differs')
                return result
        class ObservedSession(original_session):
            def __init__(self,acceptance,launcher,root,state,env,cwd,log):
                require((Path(launcher),Path(root),Path(state),Path(cwd)) ==
                        (adapter.plugin/'bin/checker-plugin',FIXTURE,STATE,adapter.plugin), 'Literal original session scope required')
                require(len(adapter.sessions) < 2, 'Only original initial/restart sessions allowed')
                self.adapter,self.label = adapter,'initial' if not adapter.sessions else 'restart'
                self.raw_buffer,self.closed = bytearray(),False
                self.wire = None
                adapter.guard_runtime()
                adapter.layout.absent(); adapter.emit('session-open',{'session':self.label})
                adapter.sessions.append(self); adapter.creating = self
                try: super().__init__(acceptance,launcher,root,state,env,cwd,log)
                finally: adapter.creating = None
            def close(self):
                if self.closed: return None
                if not hasattr(self,'owned'):
                    self.closed = True; return None
                if getattr(self,'startup_failed',False):
                    return SubprocessFacade(adapter).abort_start(self)
                previous = adapter.budget.cleaning; adapter.budget.cleaning = True
                try:
                    result = super().close()
                    self.owned.drain()
                    if adapter.capture.pending is None:
                        adapter.emit('session-close',{'session':self.label,'exit_code':result})
                    else:
                        # A failed original receive leaves its raw request
                        # pending. Do not overwrite that transport exception
                        # with an overlapping synthetic close event or assert
                        # successful transcript/lifecycle semantics.
                        adapter.uncorrelated_closes.append({'session':self.label,'actual_wait_returncode':result,
                            'reason':'Original RPC remains pending','qualification_possible':False})
                    self.closed = True
                    return result
                except BaseException as exc:
                    adapter.cleanup_errors.append(type(exc).__name__+': '+str(exc)); raise
                finally:
                    if hasattr(self,'stdout_fd'): adapter.sessions_by_fd.pop(self.stdout_fd,None)
                    adapter.budget.cleaning = previous
        runner.LauncherSession = ObservedSession
        runner.os,runner.select,runner.subprocess = IOFacade(self),SelectFacade(self),SubprocessFacade(self)
        options = types.SimpleNamespace(milestone='plan-submission',archive=ARCHIVE,plugin_directory=self.plugin,
                                        plan_fixture_root=FIXTURE,plan_fixture_state=STATE)
        self.acceptance = ObservedAcceptance(options)
    def guard_runtime(self):
        require(digest(anchored(ARCHIVE,64*1024*1024)[0]) == ARCHIVE_SHA, 'Exact registered archive bytes required')
        for name,value in RUNTIME_HASHES.items():
            require(digest(anchored(self.plugin/'bin'/name,32*1024*1024)[0]) == value, 'Exact runtime input bytes required')
    def run_once(self):
        require(not self.used, 'Fixed original body may execute only once')
        self.used = True
        self.budget = Budget()
        self.install_instrumentation()
        body_exit,error,error_type = 2,None,None
        try:
            require(os.getuid() == 1000 and digest(Path('/proc/self/exe').read_bytes()) == self.python_sha,
                    'Registered normal host Python identity required')
            directory_record(self.directory); directory_record(self.plugin)
            require(not self.body_directory.exists(), 'Original body workspace must be new')
            self.guard_runtime()
            self.layout.absent(); self.emit('public-files',self.public_snapshot('initial'))
            # This is the sole acceptance-body invocation. No substituted body,
            # approval, or altered assertion function is used.
            self.runner.plan_invalidation(self.acceptance,self.body_directory)
            body_exit = 0
        except BaseException as exc:
            error,error_type = str(exc),type(exc).__name__
        finally:
            self.budget.cleaning = True
            for session in self.sessions:
                if not session.closed:
                    try: session.close()
                    except BaseException as exc: self.cleanup_errors.append(type(exc).__name__+': '+str(exc))
            if self.capture.pending is None:
                try: self.emit('public-files',self.public_snapshot('final'))
                except BaseException as exc: self.cleanup_errors.append(type(exc).__name__+': '+str(exc))
            if self.cleanup_errors: body_exit = 2
            if time.monotonic() >= self.budget.cleanup_deadline:
                body_exit = 2
                self.cleanup_errors.append('Shared cleanup deadline expired')
            # A terminal failure may be recorded after an expired budget. It
            # must not be lost or reported as success merely because emit's
            # ordinary work-deadline guard has already expired.
            self.capture.event('terminal',{'body_exit':body_exit,'error':error,'error_type':error_type,
                'cleanup_complete':not self.cleanup_errors,'cleanup_errors':list(self.cleanup_errors),
                'bootstrap_diagnostics':list(self.bootstrap_diagnostics),
                'resource_shutdown':[{'session':s.label,'facts':s.owned.resource_state}
                                     for s in self.sessions if hasattr(s,'owned')],
                'startup_abort':[{'session':s.label,'facts':s.abort_facts}
                                 for s in self.sessions if hasattr(s,'abort_facts')],
                'uncorrelated_closes':list(self.uncorrelated_closes),
                'plan_invalidation_probe':self.acceptance.report.get('plan_invalidation_probe'),
                'qualification_possible':False,'approval_created':False},time.monotonic_ns())
        return {'lines':self.capture.serialized(),'original_report':self.acceptance.report,
                'body_exit':body_exit,'complete':False,'qualification_possible':False,
                'unqualified':['Separate reviewed host activation and provenance remain required.',
                               'Genuine dedicated human grant and fresh unchanged full acceptance integration remain required.']}


if __name__ == '__main__':
    print('OFF: fixed adapter source staging only; no preparation, host, process, check or approval operation.')
