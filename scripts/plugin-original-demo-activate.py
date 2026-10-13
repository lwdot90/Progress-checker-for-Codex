#!/usr/bin/python3
"""Root-only guarded PIDfd activation of the fixed demo collector; OFF by missing args.

No backend/check/approval/model operation. Registration and source are validated
before importing the collector. This is not a reader or generic signal service.
"""
import argparse,hashlib,importlib.util,json,os,select,signal,stat,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
NAMES=('plugin-original-demo-collector.py','plugin-original-demo-activate.py','plugin-original-demo-observer.py','plugin-original-demo-raw.py','plugin-original-demo-lifecycle.py','plugin-evidence-acceptance.py','plugin-acceptance.py')

def pairs(items):
    value={}
    for key,item in items:
        if key in value:raise RuntimeError('Duplicate registration key')
        value[key]=item
    return value

def bounded(path,limit):
    if not path.is_absolute() or path.resolve(strict=True)!=path:raise RuntimeError('Noncanonical bootstrap path')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);os.close(fd);fd=child
        source=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
        with os.fdopen(source,'rb') as stream:
            before=os.fstat(stream.fileno());data=stream.read(limit+1);after=os.fstat(stream.fileno());current=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
            key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or before.st_mode&0o022 or before.st_size>limit or len(data)!=before.st_size or key(before)!=key(after) or key(before)!=key(current):raise RuntimeError('Unsafe bounded bootstrap file')
            return data
    finally:os.close(fd)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--attestation',required=True,type=Path);parser.add_argument('--sha256',required=True);args=parser.parse_args()
    path=args.attestation
    if not path.is_absolute() or not path.is_relative_to(ROOT/'.local') or path.resolve(strict=True)!=path or path.name!='attestation.json':raise RuntimeError('Exact private public.local attestation required')
    info=path.stat();parent=path.parent.stat()
    if stat.S_IMODE(info.st_mode)!=0o600 or parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)!=0o700:raise RuntimeError('Private registration required')
    original=bounded(path,1024*1024)
    if hashlib.sha256(original).hexdigest()!=args.sha256:raise RuntimeError('Independently reviewed immutable SHA differs')
    meta=json.loads(original,object_pairs_hook=pairs)
    expected_paths={str(ROOT/'scripts'/name) for name in NAMES}
    if set(meta['module_hashes'])!=expected_paths:raise RuntimeError('Unexpected source inventory')
    actor_path=ROOT/'scripts/plugin-original-demo-collector.py';source=bounded(actor_path,8*1024*1024)
    if hashlib.sha256(source).hexdigest()!=meta['module_hashes'][str(actor_path)]:raise RuntimeError('Collector source buffer differs before compile/exec')
    spec=importlib.util.spec_from_file_location('fixed_demo_collector',actor_path);actor=importlib.util.module_from_spec(spec);exec(compile(source,str(actor_path),'exec'),actor.__dict__)
    meta=actor.parse(original)
    if not actor.valid_identity(meta['producer']):raise RuntimeError('Complete typed producer identity required')
    if any(type(meta.get(key)) is not int for key in ('prepared_ns','activation_expires_ns')):raise RuntimeError('Exact activation clocks required')
    pid=meta['producer']['pid'];handle=os.pidfd_open(pid,0)
    try:
        def guard():
            poll=select.poll();poll.register(handle,select.POLLIN)
            if poll.poll(0):raise RuntimeError('Collector exited')
            if bounded(path,1024*1024)!=original:raise RuntimeError('Immutable registration changed')
            if type(meta['schema_version']) is not int or meta['schema_version']!=1 or meta['mode']!='original-demo' or meta['trust_policy']!=actor.TRUST or meta['root']!=str(actor.FIXTURE) or meta['state']!=str(actor.STATE) or meta['body_sha256']!=actor.BODY_SHA or meta['archive_sha256']!=actor.ARCHIVE_SHA:raise RuntimeError('Unexpected fixed job identity')
            if os.getuid()!=1000 or meta['producer']['uid']!=1000 or meta['boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip() or not meta['prepared_ns']<=time.monotonic_ns()<meta['activation_expires_ns'] or meta['activation_expires_ns']-meta['prepared_ns']!=1800_000_000_000:raise RuntimeError('UID/boot/activation expiry differs')
            live=actor.identity(pid);before=meta['producer']
            if not live or live['state']=='Z' or any(live[k]!=before[k] for k in ('pid','starttime','uid','argv')):raise RuntimeError('Actual collector identity differs')
            if live['argv'][0]!='/usr/bin/python3' or live['argv'][1:]!=meta['producer_argv'] or Path(os.readlink(Path('/proc',str(pid),'cwd')))!=ROOT or (ROOT/meta['producer_argv'][0]).resolve(strict=True)!=actor_path:raise RuntimeError('Interpreter/script/cwd/argv differs')
            if meta['producer_argv'][1:]!=['--prepare-live','--output-dir',str(path.parent)]:raise RuntimeError('Unexpected collector controls')
            exe=hashlib.sha256(Path('/proc',str(pid),'exe').read_bytes()).hexdigest()
            if exe!=meta['python_exe_sha256'] or exe!=hashlib.sha256(Path('/usr/bin/python3').read_bytes()).hexdigest():raise RuntimeError('Python executable differs')
            runtime_prefix=path.parent/'extracted/progress-checker-0.2.1-dev-linux-x86_64/plugin/bin'
            if meta['runtime_files']!={str(runtime_prefix/name):value for name,value in actor.RUNTIME_HASHES.items()}:raise RuntimeError('Unexpected extracted runtime inventory')
            if meta['fixture_files'].keys()!={str(actor.FIXTURE/'.progress-checker/config.json'),str(actor.FIXTURE/'check.py'),str(actor.FIXTURE/'feature.txt')}:raise RuntimeError('Unexpected public fixture paths')
            actor.unchanged(meta);actor.FixtureLayout(actor.FIXTURE,actor.STATE).require_absent()
            endpoint=Path(meta['endpoint'])
            if endpoint!=path.parent/'observe.sock' or endpoint.resolve(strict=True)!=endpoint or actor.socket_identity(endpoint)!=meta['socket'] or meta['socket']['uid']!=1000 or meta['socket']['mode']!=0o600:raise RuntimeError('Bound private endpoint differs')
            ready=actor.parse(actor.anchored(path.parent/'readiness.json',1024*1024,True)[0])
            if ready.get('attestation_path')!=str(path) or ready.get('attestation_sha256')!=args.sha256 or not ready.get('awaiting_activation') or ready.get('ready') or ready.get('consumed'):raise RuntimeError('Collector no longer awaits activation')
            for key in ('schema_version','job_id','nonce','producer','endpoint','socket'):
                if ready[key]!=meta[key]:raise RuntimeError('Readiness crosspin differs')
            if poll.poll(0):raise RuntimeError('Collector exited during guard')
        guard();guard();signal.pidfd_send_signal(handle,signal.SIGUSR1,None,0)
        print('Activated exact registered fixed demo job via PIDfd; no approval/check requested by helper.')
    finally:os.close(handle)
    return 0

if __name__=='__main__':raise SystemExit(main())
