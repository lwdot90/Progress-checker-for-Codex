#!/usr/bin/python3
"""OFF-default fixed dedicated host coordinator, staged source only.

Explicit future --prepare-live is separate from independent activation. No
approval API, prompt input, private Store reads or reader-selected operation.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import stat
import struct
import sys
import time
import types

ROOT = Path('/home/luis/progress-checker')
FIXTURE = ROOT/'.local/plugin-acceptance/plan-invalidation-human-fixture-v2/project'
STATE = FIXTURE.parent/'state'
ARCHIVE = ROOT/'.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz'
ARCHIVE_SHA = '404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
PINS = {'plugin-acceptance.py':'ad1fc66caa841211d6f485832be4a602ac5c1a00743b5c42aefdbdd6f6ff1d99',
        'plugin-dedicated-plan-capture.py':'a19413a48ca9f6fcd6b91344d21e66f0f6679aacad01cfc5d7359dcffc5d122c',
        'plugin-dedicated-plan-public.py':'977ce1b54f9b73386d0db90e59b7ae0a3b9189ff7ee95967ca884d32c98531b2',
        'plugin-dedicated-plan-lifecycle.py':'1a52ba75e8b230dff8bf548b302084c759899de90a0a2bc8fc599ec90028d30e',
        'plugin-dedicated-plan-adapter.py':'d8b02f2b3cb6ac45d0daf0d9753479ed7001a9dea1433f8b3a428b5a791fd646',
        'plugin-acceptance-runtime.py':'a001a978a55d305993b9d55375fe7f65c2c6b2509973e20135ac86e2bd3d4f51',
        'plugin-sandbox-recipient.py':'7408c56f0b9aa39d8ed97bb238be960bec7a2ee07053ba372f574b744aef1a96'}
NAMES = tuple(PINS)+('plugin-dedicated-plan-host.py','plugin-dedicated-plan-activate.py',
                    'plugin-dedicated-plan-observer.py','plugin-dedicated-plan-acceptance.py')
BUDGETS = {'preparation':1800,'start':5,'work':120,'cleanup':120,'observation':90,'final_margin':30,'hard':365}
TRUST = 'explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime'
MAX_STREAM,MAX_PACKET = 8*1024*1024,1024*1024


class HostError(RuntimeError):
    pass


def require(condition,message):
    if not condition: raise HostError(message)


def digest(data): return hashlib.sha256(data).hexdigest()
def encoded(value): return json.dumps(value,separators=(',',':'),allow_nan=False).encode()+b'\n'


def bounded(path,limit,private=False):
    require(path.is_absolute() and '..' not in path.parts, 'Canonical bounded input required')
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            os.close(parent);parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno());data=stream.read(limit+1);after=os.fstat(stream.fileno())
            current=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            facts=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_mode,info.st_uid,info.st_nlink)
            require(stat.S_ISREG(before.st_mode) and before.st_uid==1000 and before.st_nlink==1
                    and not before.st_mode&0o022 and len(data)==before.st_size<=limit
                    and facts(before)==facts(after)==facts(current), 'Unsafe/changed bounded file')
            if private:
                require(stat.S_IMODE(before.st_mode)==0o600 and stat.S_IMODE(os.fstat(parent).st_mode)==0o700,
                        'Private coordination ownership required')
            return data
    finally: os.close(parent)


def load(name,data):
    require(name in PINS and type(data) is bytes and digest(data)==PINS[name]
            and len(data)<=8*1024*1024, 'Exact source buffer required')
    module=types.ModuleType(name.replace('-','_'));module.__file__=str(ROOT/'scripts'/name)
    exec(compile(data,module.__file__,'exec'),module.__dict__)
    return module


def write_new(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())


def atomic(path,value):
    temp=path.with_name(path.name+'.next-'+secrets.token_hex(8))
    write_new(temp,encoded(value))
    try:
        os.replace(temp,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if temp.exists():temp.unlink()


def exact_request(data,job_id,nonce,parser):
    require(type(data) is bytes and 0<len(data)<=4096 and data.endswith(b'\n')
            and b'\n' not in data[:-1], 'Exactly one bounded reader request required')
    value=parser(data)
    require(type(value) is dict and type(value.get('schema_version')) is int
            and value=={'schema_version':1,'job_id':job_id,'nonce':nonce,'request':'read-events'},
            'No reader-selected work or followup allowed')
    return value


def clock_binding(activated_ns,started_ns,work_ns,cleanup_ns,now_ns):
    require(all(type(value) is int and value>=0 for value in (activated_ns,started_ns,work_ns,cleanup_ns,now_ns)),
            'Exact integer clock binding required')
    require(activated_ns<=started_ns<=activated_ns+5_000_000_000
            and abs(work_ns-started_ns-120_000_000_000)<=1000
            and abs(cleanup_ns-started_ns-240_000_000_000)<=1000
            and started_ns<=now_ns<=activated_ns+365_000_000_000, 'Fixed cumulative body budgets differ')
    return {'body_started_ns':started_ns,'body_work_deadline_ns':work_ns,
            'body_cleanup_deadline_ns':cleanup_ns,'hard_deadline_ns':activated_ns+365_000_000_000}


class ActivationGate:
    def __init__(self):
        self.armed,self.early,self.activated,self.deadline=False,False,False,0
        self.activated_ns=None
    def receive(self,*args):
        received=time.monotonic_ns()
        if not self.armed:self.early=True
        elif received>=self.deadline:self.early=True
        elif self.activated:self.early=True
        else:self.activated=True;self.activated_ns=received
    def valid_stamp(self):
        require(self.armed and self.activated and not self.early and type(self.activated_ns) is int
                and 0<=self.activated_ns<self.deadline
                and time.monotonic_ns()<self.activated_ns+365_000_000_000,
                'Activation identity invalid/duplicate/expired')
        return self.activated_ns
    def publish(self,callback,deadline,mask):
        require(signal.SIGUSR1 not in signal.sigpending() and not self.early, 'Early pending activation')
        self.deadline=deadline;callback()
        require(signal.SIGUSR1 not in signal.sigpending() and not self.early, 'Publication-time pending activation')
        self.armed=True
        signal.pthread_sigmask(signal.SIG_SETMASK,mask)
    def wait(self,server):
        while not self.activated:
            require(not self.early and time.monotonic_ns()<self.deadline, 'Early/expired activation')
            ready=select.select([server],[],[],.2)[0]
            if ready:
                connection,_=server.accept();connection.close()
                raise HostError('Observer arrived before independent activation')
        require(not self.early, 'Duplicate/invalid activation')


class Coordinator:
    def __init__(self,directory):
        self.directory=Path(directory)
        self.server,self.reservation_fd,self.adapter=None,None,None
        self.meta,self.ready,self.attestation_bytes=None,None,None
        self.cleanup_errors,self.workflow_started=[],False
        self.created,self.layout=False,None
        self.gate=None
        self.reservation=FIXTURE.parent/'.dedicated-plan-capture-reservation'
        self.reservation_identity=None
    def public_pins(self):
        return {role:{'sha256':digest(bounded(path,limit))}
                for role,path,limit in [('config',FIXTURE/'.progress-checker/config.json',65536),
                                       ('script',FIXTURE/'plan-check.py',4096),('feature',FIXTURE/'feature.txt',4096)]}
    def prepare(self):
        require(os.getuid()==1000, 'Fixed ordinary host UID required')
        require(self.directory.is_absolute() and self.directory.is_relative_to(ROOT/'.local')
                and '..' not in self.directory.parts and not self.directory.exists()
                and self.directory.parent.resolve(strict=True)==self.directory.parent
                and len(os.fsencode(self.directory/'observe.sock'))<=100, 'New canonical short public workspace required')
        # Read all eleven files before creating anything. Missing future frozen
        # entrypoints fail OFF; this first source stage cannot prepare a job.
        self.buffers={name:bounded(ROOT/'scripts'/name,8*1024*1024) for name in NAMES}
        for name,pin in PINS.items():require(digest(self.buffers[name])==pin, 'Reviewed input source changed')
        self.runner=load('plugin-acceptance.py',self.buffers['plugin-acceptance.py'])
        self.raw=load('plugin-dedicated-plan-capture.py',self.buffers['plugin-dedicated-plan-capture.py'])
        self.public=load('plugin-dedicated-plan-public.py',self.buffers['plugin-dedicated-plan-public.py'])
        self.lifecycle=load('plugin-dedicated-plan-lifecycle.py',self.buffers['plugin-dedicated-plan-lifecycle.py'])
        self.actor=load('plugin-dedicated-plan-adapter.py',self.buffers['plugin-dedicated-plan-adapter.py'])
        self.layout=self.actor.Layout(self.raw.strict);self.layout.absent()
        require(digest(bounded(ARCHIVE,64*1024*1024))==ARCHIVE_SHA, 'Exact archive required')
        self.directory.mkdir(mode=0o700)
        self.created=True
        self.actor.directory_record(self.directory)
        self.reservation_fd=os.open(self.reservation,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        fcntl.flock(self.reservation_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        owner=self.actor.process_identity(os.getpid())
        require(owner and owner['uid']==1000 and owner['state'] not in {'Z','X','x'}, 'Producer identity unavailable')
        reservation={'pid':owner['pid'],'starttime':owner['starttime'],'uid':owner['uid']}
        reservation_bytes=encoded(reservation)
        require(os.write(self.reservation_fd,reservation_bytes)==len(reservation_bytes), 'Reservation write incomplete')
        os.fsync(self.reservation_fd)
        info=os.fstat(self.reservation_fd);self.reservation_identity=(info.st_dev,info.st_ino)
        acceptance=self.runner.Acceptance(types.SimpleNamespace(milestone='plan-submission',archive=ARCHIVE,plugin_directory=None))
        plugin=self.runner.extract_archive(acceptance,ARCHIVE,self.directory/'extracted')
        runtime={str(plugin/'bin'/name):digest(bounded(plugin/'bin'/name,32*1024*1024)) for name in self.actor.RUNTIME_HASHES}
        require(runtime=={str(plugin/'bin'/name):value for name,value in self.actor.RUNTIME_HASHES.items()}, 'Exact extracted runtime required')
        python_sha=digest(Path('/proc/self/exe').read_bytes())
        job_id,nonce=secrets.token_hex(16),secrets.token_hex(32)
        source_buffers={name:self.buffers[name] for name in self.actor.SOURCE_HASHES}
        self.adapter=self.actor.FixedAdapter(source_buffers,self.directory,job_id,nonce,python_sha)
        snapshot=self.adapter.public_snapshot('initial')
        config=self.raw.strict(base64.b64decode(snapshot['files'][0]['bytes_base64'],validate=True))
        require(config.get('project_id')=='isolated-plan-invalidation' and config.get('checks')==[self.raw.CHECK],
                'Literal dedicated fixture configuration required')
        self.public.file_snapshot(snapshot,self.raw,config)
        self.initial_config=config
        self.server=socket.socket(socket.AF_UNIX);endpoint=self.directory/'observe.sock'
        self.server.bind(str(endpoint));endpoint.chmod(0o600);self.server.listen(1);self.server.settimeout(.2)
        prepared=time.monotonic_ns()
        self.meta={'schema_version':1,'mode':'dedicated-plan','trust_policy':TRUST,'job_id':job_id,'nonce':nonce,
            'root':str(FIXTURE),'state':str(STATE),'producer':owner,'producer_argv':list(sys.argv),
            'python_exe_sha256':python_sha,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'body_sha256':PINS['plugin-acceptance.py'],'archive_sha256':ARCHIVE_SHA,
            'module_hashes':{str(ROOT/'scripts'/name):digest(data) for name,data in self.buffers.items()},
            'runtime_files':runtime,'fixture_files':self.public_pins(),'initial_public_snapshot':snapshot,
            'check_definition':self.raw.CHECK,'endpoint':str(endpoint),'socket':self.actor.socket_identity(endpoint),
            'prepared_ns':prepared,'activation_expires_ns':prepared+1800_000_000_000,'budget_seconds':BUDGETS}
        self.attestation_bytes=encoded(self.meta);write_new(self.directory/'attestation.json',self.attestation_bytes)
        self.ready={'schema_version':1,'attestation_path':str(self.directory/'attestation.json'),
            'attestation_sha256':digest(self.attestation_bytes),'job_id':job_id,'nonce':nonce,'producer':owner,
            'endpoint':str(endpoint),'socket':self.meta['socket'],'awaiting_activation':True,'ready':False,'consumed':False}
        return self.meta
    def check_activation(self):
        require(self.gate is not None, 'Independent activation gate required')
        stamp=self.gate.valid_stamp()
        require(self.ready['activated_ns']==stamp and self.ready['hard_deadline_ns']==stamp+365_000_000_000,
                'Readiness must bind actual signal receipt deadline')
        return stamp
    def publish(self):
        if not self.ready.get('awaiting_activation',False):self.check_activation()
        atomic(self.directory/'readiness.json',self.ready)
    def guard(self,final=False):
        self.check_activation()
        require(bounded(self.directory/'attestation.json',MAX_PACKET,True)==self.attestation_bytes, 'Immutable registration changed')
        for path,pin in self.meta['module_hashes'].items():require(digest(bounded(Path(path),8*1024*1024))==pin, 'Registered source changed')
        require(digest(bounded(ARCHIVE,64*1024*1024))==ARCHIVE_SHA, 'Registered archive changed')
        for path,pin in self.meta['runtime_files'].items():require(digest(bounded(Path(path),32*1024*1024))==pin, 'Registered runtime changed')
        current=self.public_pins()
        expected=self.final_public_pins if final else self.meta['fixture_files']
        require(current==expected, 'Registered public fixture changed')
        snapshot=self.adapter.public_snapshot('final' if final else 'initial')
        expected_snapshot=self.final_snapshot if final else self.meta['initial_public_snapshot']
        require(snapshot==expected_snapshot, 'Registered public file/directory identities changed')
        self.adapter.layout.absent()
        self.check_activation()
    def execute(self,gate):
        self.gate=gate;activated=gate.valid_stamp()
        self.ready.update(awaiting_activation=False,activated_ns=activated,hard_deadline_ns=activated+365_000_000_000)
        self.publish()
        self.guard()
        require(time.monotonic_ns()<=activated+5_000_000_000, 'Guard delayed adapter start beyond actual activation budget')
        self.check_activation();self.workflow_started=True
        self.result=self.adapter.run_once()
        self.check_activation()
        budget=self.adapter.budget
        clocks=clock_binding(activated,int(budget.started*1e9),int(budget.work_deadline*1e9),
                             int(budget.cleanup_deadline*1e9),time.monotonic_ns())
        self.ready.update(clocks)
        require(self.result['body_exit']==0 and not self.adapter.cleanup_errors
                and self.adapter.capture.pending is None, 'Original body/cleanup/RPC failure; no ready stream')
        lines=self.result['lines'];payload=b''.join(lines)
        require(0<len(payload)<=MAX_STREAM, 'Exact bounded transcript required')
        public=self.public.evaluate(lines,self.meta['job_id'],self.meta['nonce'],
            self.buffers['plugin-acceptance.py'],self.buffers['plugin-dedicated-plan-capture.py'])
        lifecycle=self.lifecycle.evaluate(lines,self.meta,self.buffers['plugin-dedicated-plan-capture.py'])
        require(public['status'] in {'full-public-captured-semantics','blocked-missing-grant-captured-semantics'}
                and lifecycle['captured_lifecycle_semantics_passed'], 'Raw public/lifecycle predicates incomplete')
        parsed=self.raw.classify_serialized(lines,self.meta['job_id'],self.meta['nonce'])
        for item in parsed['classified_frames']:
            frame=item['frame'];bound=clocks['body_work_deadline_ns'] if frame['kind'] in {'request','response'} else clocks['body_cleanup_deadline_ns']
            require(activated<=frame['monotonic_ns']<=bound, 'Actual captured event outside fixed budget')
        final=[item['frame']['payload'] for item in parsed['classified_frames']
               if item['frame']['kind']=='public-files' and item['frame']['payload'].get('role')=='final']
        require(len(final)==1, 'Actual original final public snapshot required')
        self.final_snapshot=final[0]
        self.final_public_pins={value['role']:{'sha256':digest(base64.b64decode(value['bytes_base64'],validate=True))}
                                for value in self.final_snapshot['files']}
        self.guard(final=True)
        write_new(self.directory/'events.jsonl',payload)
        self.ready.update(ready=True,cleanup_complete=True,body_exit=0,body_status=public['status'],
            observer_expires_ns=min(time.monotonic_ns()+90_000_000_000,clocks['hard_deadline_ns']-30_000_000_000))
        self.publish();return payload
    def audit(self,payload,connected_ns):
        self.guard(final=True)
        return {'schema_version':1,'job_id':self.meta['job_id'],'nonce':self.meta['nonce'],
            'connected_ns':connected_ns,'audited_ns':time.monotonic_ns(),'raw_exact_bytes_sha256':digest(payload),
            'module_hashes':self.meta['module_hashes'],'runtime_files':self.meta['runtime_files'],
            'final_public_pins':self.final_public_pins,'fixture_census':self.adapter.layout.absent(),
            'ready_sha256':digest(bounded(self.directory/'readiness.json',MAX_PACKET,True))}
    def remove_handoff(self):
        require(self.actor.socket_identity(Path(self.meta['endpoint']))==self.meta['socket'], 'Owned endpoint changed')
        self.server.close();self.server=None;Path(self.meta['endpoint']).unlink()
        current=self.reservation.lstat();opened=os.fstat(self.reservation_fd)
        require((current.st_dev,current.st_ino)==self.reservation_identity==(opened.st_dev,opened.st_ino),
                'Owned reservation changed')
        expected={key:self.meta['producer'][key] for key in ('pid','starttime','uid')}
        require(self.raw.strict(bounded(self.reservation,4096))==expected, 'Reservation owner changed')
        self.reservation.unlink();os.close(self.reservation_fd);self.reservation_fd=None
        require(not os.path.lexists(self.meta['endpoint']) and not os.path.lexists(self.reservation), 'Handoff resource reappeared')
    def serve_once(self,payload):
        deadline=min(self.ready['observer_expires_ns'],self.ready['hard_deadline_ns']-30_000_000_000)/1e9
        while time.monotonic()<deadline:
            try:connection,_=self.server.accept();break
            except socket.timeout:continue
        else:raise HostError('One-use reader did not arrive')
        with connection:
            def remaining():
                self.check_activation()
                value=min(15,deadline-time.monotonic());require(value>0, 'Shared transfer deadline expired')
                connection.settimeout(value)
            remaining();peer=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(peer[1]==1000, 'Reader kernel UID differs')
            request=bytearray()
            while b'\n' not in request and len(request)<=4096:
                remaining();chunk=connection.recv(4097-len(request))
                require(chunk, 'Incomplete reader request');request.extend(chunk)
            exact_request(bytes(request),self.meta['job_id'],self.meta['nonce'],self.raw.strict)
            connected=time.monotonic_ns();audit=encoded(self.audit(payload,connected))
            require(len(audit)<=MAX_PACKET, 'Audit packet bound')
            require(self.raw.strict(bounded(self.directory/'readiness.json',MAX_PACKET,True))==self.ready, 'Readiness changed before stream')
            remaining();connection.sendall(struct.pack('!I',len(payload))+payload)
            remaining();connection.sendall(struct.pack('!I',len(audit))+audit)
            remaining();require(connection.recv(1)==b'', 'Forbidden reader followup')
            self.guard(final=True);self.remove_handoff()
            self.ready.update(ready=False,consumed=True);self.publish()
            committed=bounded(self.directory/'readiness.json',MAX_PACKET,True)
            require(self.raw.strict(committed)==self.ready, 'Consumed readiness commit changed')
            completion=encoded({'schema_version':1,'job_id':self.meta['job_id'],'nonce':self.meta['nonce'],
                'completed_ns':time.monotonic_ns(),'raw_exact_bytes_sha256':digest(payload),
                'transfer_audit_sha256':digest(audit),'readiness_sha256':digest(committed),
                'module_hashes':self.meta['module_hashes'],'runtime_files':self.meta['runtime_files'],
                'endpoint_identity':None,'reservation_identity':None})
            require(len(completion)<=MAX_PACKET, 'Completion ACK packet bound')
            remaining();connection.sendall(struct.pack('!I',len(completion))+completion)
            poll=select.poll();poll.register(connection.fileno(),select.POLLHUP)
            while time.monotonic()<deadline:
                self.check_activation()
                events=poll.poll(max(1,int(min(.2,deadline-time.monotonic())*1000)))
                if any(value&select.POLLHUP for _,value in events):self.check_activation();return
            raise HostError('Reader full close absent before shared deadline')
    def fail(self,error):
        if self.server is not None:self.server.close();self.server=None
        safe=False
        try:
            if self.layout is not None:self.layout.absent();safe=True
            if safe and self.meta is not None and self.reservation_fd is not None:
                # Owned endpoint only; leave unresolved reservation/runtime
                # quarantined rather than kill, adopt or report clean success.
                if os.path.lexists(self.meta['endpoint']):
                    require(self.actor.socket_identity(Path(self.meta['endpoint']))==self.meta['socket'], 'Failed endpoint ownership changed')
                    Path(self.meta['endpoint']).unlink()
        except BaseException as exc:self.cleanup_errors.append(type(exc).__name__+': '+str(exc))
        if self.reservation_fd is not None:os.close(self.reservation_fd);self.reservation_fd=None
        if self.created:
            if self.ready is not None:
                self.ready.update(ready=False,activation_invalid=bool(self.gate is not None and self.gate.early),failed=True)
                atomic(self.directory/'readiness.json',self.ready)
            atomic(self.directory/'failure.json',{'status':'failed','error':type(error).__name__+': '+str(error),
                'workflow_started':self.workflow_started,'cleanup_errors':self.cleanup_errors,
                'reservation_retained':os.path.lexists(self.reservation),'complete':False,'qualification_possible':False})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-live',action='store_true');parser.add_argument('--output-dir',type=Path)
    args=parser.parse_args()
    if not args.prepare_live:print('OFF: no fixture, process, registration, activation or stream operation.');return 0
    if args.output_dir is None:parser.error('--prepare-live requires explicit new public output directory')
    coordinator=Coordinator(args.output_dir);gate=ActivationGate()
    mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGUSR1});signal.signal(signal.SIGUSR1,gate.receive)
    try:
        meta=coordinator.prepare()
        gate.publish(coordinator.publish,meta['activation_expires_ns'],mask)
        print(str(coordinator.directory/'attestation.json')+' SHA256 '+digest(coordinator.attestation_bytes),flush=True)
        gate.wait(coordinator.server);payload=coordinator.execute(gate);coordinator.serve_once(payload)
        return 0
    except BaseException as exc:
        coordinator.fail(exc);raise


if __name__=='__main__':raise SystemExit(main())
