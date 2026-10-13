#!/usr/bin/python3
"""OFF-default independent activation of one registered dedicated producer.

Only an explicit future root invocation with independently reviewed immutable
SHA may signal. No fixture preparation, check approval, API, or private reads.
Registration is reviewed-host trust, not independent hidden-host source proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import time
import types

ROOT=Path('/home/luis/progress-checker')
HOST=ROOT/'scripts/plugin-dedicated-plan-host.py'
HOST_SHA='c1440e86162097cd3a7d7f65c478a57c42b5817f627f0d91e4802e05ed0a0b38'


class ActivationError(RuntimeError):pass


def require(condition,message):
    if not condition:raise ActivationError(message)


def sha(data):return hashlib.sha256(data).hexdigest()


def hash_string(value):
    return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)


def pairs(items):
    result={}
    for key,value in items:
        require(key not in result,'Duplicate registration key');result[key]=value
    return result


def parse(data):
    return json.loads(data,object_pairs_hook=pairs,parse_constant=lambda value:(_ for _ in ()).throw(ActivationError('Nonfinite registration')))


def bounded(path,limit,coordination=False):
    require(path.is_absolute() and '..' not in path.parts,'Canonical bounded path required')
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            os.close(parent);parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno());data=stream.read(limit+1);after=os.fstat(stream.fileno())
            current=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_nlink)
            require(stat.S_ISREG(before.st_mode) and before.st_uid==1000 and before.st_nlink==1
                    and not before.st_mode&0o022 and len(data)==before.st_size<=limit
                    and identity(before)==identity(after)==identity(current),'Unsafe or changed bounded file')
            if coordination:
                directory=os.fstat(parent)
                require(stat.S_IMODE(before.st_mode)==0o600 and directory.st_uid==1000
                        and stat.S_IMODE(directory.st_mode)==0o700,'Owned coordination modes required')
            return data
    finally:os.close(parent)


def load_host():
    source=bounded(HOST,8*1024*1024)
    require(sha(source)==HOST_SHA,'Reviewed host source changed before compile')
    host=types.ModuleType('frozen_dedicated_host');host.__file__=str(HOST)
    exec(compile(source,str(HOST),'exec'),host.__dict__)
    return host


class Activation:
    def __init__(self,path,reviewed_sha,host):
        self.path,self.reviewed_sha,self.host=path,reviewed_sha,host
        self.handle=None;self.sent=False
    def prepare(self):
        h=self.host;p=self.path
        require(os.getuid()==1000 and p.is_absolute() and p.name=='attestation.json'
                and p.is_relative_to(ROOT/'.local') and '..' not in p.parts
                and p.parent.resolve(strict=True)==p.parent,'Fixed canonical reviewed collection required')
        require(hash_string(self.reviewed_sha),'Exact independently reviewed SHA required')
        self.original=bounded(p,1024*1024,True)
        require(sha(self.original)==self.reviewed_sha,'Reviewed immutable SHA differs')
        self.meta=parse(self.original);m=self.meta
        require(type(m) is dict,'Registration object required')
        for key in ('prepared_ns','activation_expires_ns'):
            require(type(m.get(key)) is int and m[key]>=0,'Typed registration clocks required')
        require(type(m.get('schema_version')) is int and m['schema_version']==1
                and m.get('mode')=='dedicated-plan' and m.get('trust_policy')==h.TRUST
                and m.get('root')==str(h.FIXTURE) and m.get('state')==str(h.STATE)
                and m.get('body_sha256')==h.PINS['plugin-acceptance.py']
                and m.get('archive_sha256')==h.ARCHIVE_SHA and m.get('budget_seconds')==h.BUDGETS,
                'Fixed job binding differs')
        require(type(m.get('module_hashes')) is dict and set(m['module_hashes'])=={str(ROOT/'scripts'/n) for n in h.NAMES}
                and all(hash_string(v) for v in m['module_hashes'].values()),'Exact eleven-source inventory required')
        self.buffers={n:bounded(ROOT/'scripts'/n,8*1024*1024) for n in h.NAMES}
        for n,data in self.buffers.items():
            require(sha(data)==m['module_hashes'][str(ROOT/'scripts'/n)],'Registered source changed')
            if n in h.PINS:require(sha(data)==h.PINS[n],'Literal reviewed source pin differs')
        require(sha(self.buffers[HOST.name])==HOST_SHA,'Registered host pin differs')
        self.actor=h.load('plugin-dedicated-plan-adapter.py',self.buffers['plugin-dedicated-plan-adapter.py'])
        self.raw=h.load('plugin-dedicated-plan-capture.py',self.buffers['plugin-dedicated-plan-capture.py'])
        self.public=h.load('plugin-dedicated-plan-public.py',self.buffers['plugin-dedicated-plan-public.py'])
        self.life=h.load('plugin-dedicated-plan-lifecycle.py',self.buffers['plugin-dedicated-plan-lifecycle.py'])
        self.life.identity(m.get('producer'))
        require(m['producer']['state'] not in {'Z','X','x'},'Registered producer dead')
        require(type(m.get('socket')) is dict,'Registered listening socket required')
        self.life.socket_identity(m['socket'])
        require(m.get('endpoint')==str(p.parent/'observe.sock'),'Fixed endpoint differs')
        self.expected_argv=m.get('producer_argv')
        require(type(self.expected_argv) is list and len(self.expected_argv)==4
                and self.expected_argv[0] in {str(HOST),'scripts/'+HOST.name}
                and self.expected_argv[1:]==['--prepare-live','--output-dir',str(p.parent)],'Exact fixed producer controls required')
        require(m['producer']['argv']==['/usr/bin/python3']+self.expected_argv,'Complete registered producer argv differs')
        require(hash_string(m.get('python_exe_sha256')),'Typed executable pin required')
        prefix=p.parent/'extracted/progress-checker-0.2.1-dev-linux-x86_64/plugin/bin'
        require(m.get('runtime_files')=={str(prefix/n):v for n,v in self.actor.RUNTIME_HASHES.items()},'Exact runtime inventory required')
        require(type(m.get('job_id')) is str and len(m['job_id'])==32
                and all(c in '0123456789abcdef' for c in m['job_id'])
                and hash_string(m.get('nonce')),'Typed job nonce required')
        require(m['activation_expires_ns']-m['prepared_ns']==1800_000_000_000,'Fixed preregistration lifetime differs')
        self.handle=os.pidfd_open(m['producer']['pid'],0)
    def alive(self):
        poll=select.poll();poll.register(self.handle,select.POLLIN|select.POLLHUP)
        require(not poll.poll(0),'Exact registered producer PIDfd exited/error')
    def guard(self):
        self.alive();h=self.host;m=self.meta;p=self.path
        require(bounded(p,1024*1024,True)==self.original,'Immutable registration changed')
        require(m['prepared_ns']<=time.monotonic_ns()<m['activation_expires_ns'],'Activation expiry differs')
        require(m['boot_id']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'Boot identity differs')
        live=self.actor.process_identity(m['producer']['pid']);self.life.identity(live)
        require(live['state'] not in {'Z','X','x'}
                and all(live[k]==m['producer'][k] for k in ('pid','starttime','uid','ppid','argv')),'Exact producer identity reused/changed')
        require(Path(os.readlink(Path('/proc')/str(live['pid'])/'cwd'))==ROOT,'Producer cwd differs')
        executable=Path('/proc')/str(live['pid'])/'exe'
        require(sha(executable.read_bytes())==m['python_exe_sha256']==sha(Path('/usr/bin/python3').read_bytes()),'Actual producer executable differs')
        for name,data in self.buffers.items():require(bounded(ROOT/'scripts'/name,8*1024*1024)==data,'Source changed before signal')
        require(sha(bounded(h.ARCHIVE,64*1024*1024))==h.ARCHIVE_SHA,'Archive changed')
        for path,pin in m['runtime_files'].items():require(sha(bounded(Path(path),32*1024*1024))==pin,'Runtime changed')
        snapshot=self.actor.FixedAdapter.public_snapshot(None,'initial')
        require(snapshot==m['initial_public_snapshot'],'Public file/directory identity changed')
        config=self.raw.strict(__import__('base64').b64decode(snapshot['files'][0]['bytes_base64'],validate=True))
        require(config.get('project_id')=='isolated-plan-invalidation' and config.get('checks')==[self.raw.CHECK]
                and m['check_definition']==self.raw.CHECK,'Literal dedicated check differs')
        self.public.file_snapshot(snapshot,self.raw,config)
        pins={v['role']:{'sha256':sha(__import__('base64').b64decode(v['bytes_base64'],validate=True))} for v in snapshot['files']}
        require(pins==m['fixture_files'],'Public byte pins changed')
        self.actor.Layout(self.raw.strict).absent()
        require(self.actor.socket_identity(Path(m['endpoint']))==m['socket'],'Endpoint inode changed')
        ready=parse(bounded(p.parent/'readiness.json',1024*1024,True))
        require(type(ready) is dict and ready.get('awaiting_activation') is True and ready.get('ready') is False
                and ready.get('consumed') is False and not ready.get('failed') and not ready.get('activation_invalid')
                and 'activated_ns' not in ready and ready.get('attestation_path')==str(p)
                and ready.get('attestation_sha256')==self.reviewed_sha,'Producer no longer awaits activation')
        for key in ('schema_version','job_id','nonce','producer','endpoint','socket'):
            require(type(ready.get(key)) is type(m[key]) and ready.get(key)==m[key],'Readiness binding differs')
        require(not os.path.lexists(p.parent/'failure.json'),'Producer failure record present')
        self.alive();require(time.monotonic_ns()<m['activation_expires_ns'],'Expired during guard')
    def activate(self):
        require(not self.sent,'Activation is one-shot')
        try:
            self.prepare();self.guard();self.guard()
            # Handle is opened once for the exact returned PID and retained
            # through the sole signal; never signal a numeric PID fallback.
            self.alive();require(time.monotonic_ns()<self.meta['activation_expires_ns'],'Expired before signal')
            signal.pidfd_send_signal(self.handle,signal.SIGUSR1,None,0);self.sent=True
        finally:
            if self.handle is not None:os.close(self.handle);self.handle=None
        return {'activated':True,'job_id':self.meta['job_id'],'nonce':self.meta['nonce'],
                'qualification_possible':False,'trust_policy':self.host.TRUST}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--activate-live',action='store_true');parser.add_argument('--attestation',type=Path);parser.add_argument('--sha256')
    args=parser.parse_args()
    if not args.activate_live:print('OFF: no signal, registration, fixture or check operation.');return 0
    if args.attestation is None or args.sha256 is None:parser.error('Explicit activation requires reviewed attestation and SHA256')
    print(json.dumps(Activation(args.attestation,args.sha256,load_host()).activate(),sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
