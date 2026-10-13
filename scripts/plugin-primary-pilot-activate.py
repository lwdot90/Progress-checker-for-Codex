#!/usr/bin/env python3
"""Explicit host/root activation of a pinned pre-registered producer.

Read-only backend discovery and PIDfd SIGUSR1 only. Invoke after actual human
approval of unchanged plan-definition. No approval, check, model, source edit,
or socket-reader control message. Missing arguments perform no operation.
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

ROOT=Path(__file__).resolve().parent.parent
NATIVE_SHA='12eb3e81114588aca3b7998f4f19e8997b056aca08e57a7ca7c8a3ec8c652aad'
RUNTIME_KEYS={'checker-plugin','progress-checker','progress-checker-mcp'}
MODULE_PATHS={str(ROOT/'scripts'/name) for name in ['plugin-primary-upgrade.py','plugin-acceptance.py','plugin-primary-pilot-activate.py','plugin-pilot-acceptance.py','plugin-primary-pilot-producer.py']}


def bounded_bytes(path,limit):
    path=Path(path).absolute();parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            next_fd=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);os.close(parent);parent=next_fd
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>limit:raise RuntimeError('Bootstrap expects bounded owned nonaliased file')
            data=stream.read(limit+1);after=os.fstat(stream.fileno());current=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
            if len(data)>limit or len(data)!=info.st_size or identity(info)!=identity(after) or identity(info)!=identity(current):raise RuntimeError('Bootstrap file changed during read')
            return data
    finally:os.close(parent)


def load(path,expected_sha256):
    # Verified attestation is parsed before any local module executes.
    import importlib.util
    data=bounded_bytes(path,8*1024*1024);digest=hashlib.sha256(data).hexdigest()
    if digest!=expected_sha256:raise RuntimeError('Module buffer differs from immutable pin before compile/exec')
    spec=importlib.util.spec_from_file_location(path.stem,path);result=importlib.util.module_from_spec(spec)
    exec(compile(data,str(path),'exec'),result.__dict__);result.loaded_source_sha256=digest;result.loaded_source_path=str(path);return result


def strict_object(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise RuntimeError('Duplicate JSON field refused')
        value[key]=item
    return value


def anchored_attestation(path):
    path=path.absolute()
    if not path.is_relative_to(ROOT/'.local') or path.resolve(strict=True)!=path or path.parent.resolve(strict=True)!=path.parent:
        raise RuntimeError('Attestation must be a canonical public.local file')
    parent=path.parent.stat();info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)!=0o700:
        raise RuntimeError('Attestation needs owned/private file0600 and directory0700')
    return path


def argv_readiness(meta,path,proc_argv,proc_cwd):
    argv=meta['producer_argv']
    script=ROOT/'scripts/plugin-primary-pilot-producer.py'
    if proc_cwd!=ROOT or not argv or (proc_cwd/argv[0]).resolve(strict=True)!=script or proc_argv[0]!='/usr/bin/python3' or proc_argv[1:]!=argv:
        raise RuntimeError('Producer interpreter/script/cwd/argv differs')
    options={};i=1
    while i<len(argv):
        key=argv[i]
        if key in options:raise RuntimeError('Duplicate producer argument')
        if key=='--prepare-live':options[key]=True;i+=1;continue
        if key not in ['--report-dir','--registration','--attestation','--approved-check'] or i+1>=len(argv):raise RuntimeError('Unexpected producer argument')
        options[key]=argv[i+1];i+=2
    if set(options)!={'--prepare-live','--report-dir','--registration','--attestation','--approved-check'} or options['--approved-check']!='plan-definition':raise RuntimeError('Producer activation mode differs')
    if Path(options['--attestation']).absolute()!=path or Path(options['--report-dir']).absolute()!=path.parent:raise RuntimeError('Producer attestation/output path differs')
    readiness=Path(options['--registration']).absolute()
    if readiness.parent!=path.parent or readiness==path or readiness.resolve(strict=True)!=readiness:raise RuntimeError('Producer readiness path differs')
    info=readiness.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:raise RuntimeError('Readiness file must be owned/private')
    return readiness


def validate(driver,runner,producer,path,raw,meta,handle):
    # Repeat this complete guard immediately before signaling, after backend I/O.
    poll=select.poll();poll.register(handle,select.POLLIN)
    if poll.poll(0):raise RuntimeError('Pinned producer PIDfd exited')
    owned=meta['producer'];pid=owned['pid'];proc=Path(f'/proc/{pid}')
    if proc.stat().st_uid!=os.getuid() or owned.get('uid')!=os.getuid() or meta['uid']!=os.getuid() or runner.process_identity(pid)!={'pid':pid,'starttime':owned['starttime']}:
        raise RuntimeError('Actual producer UID/PID/starttime differs')
    if meta['root']!=str(ROOT) or meta['state']!=str(producer.STATE) or meta['trust_policy']!='explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime':raise RuntimeError('Pinned target/trustpolicy differs')
    if time.monotonic_ns()>=meta['activation_expires_monotonic_ns'] or meta['activation_expires_monotonic_ns']-meta['prepared_monotonic_ns']>1_800_000_000_000 or meta['boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip():raise RuntimeError('Activation expired/from anotherboot')
    if driver.regular(anchored_attestation(path),1024*1024)!=raw:raise RuntimeError('Immutable attestation changed')
    if set(meta['module_hashes'])!=MODULE_PATHS or set(meta['runtime_hashes'])!=RUNTIME_KEYS:raise RuntimeError('Unexpected module/runtime path inventory')
    if meta['archive_sha256']!=driver.ARCHIVE_HASH or meta['native_cli_sha256']!=NATIVE_SHA or driver.digest(producer.CODEX)!=NATIVE_SHA:raise RuntimeError('Reviewed archive/native pin differs')
    if driver.digest(proc/'exe')!=meta['python_exe_sha256'] or driver.digest(Path('/usr/bin/python3'))!=meta['python_exe_sha256']:raise RuntimeError('Producer is not the pinned installed Python interpreter')
    commands=(proc/'cmdline').read_bytes().decode().split('\0')[:-1]
    readiness=argv_readiness(meta,path,commands,Path(os.readlink(proc/'cwd')))
    live=json.loads(driver.regular(readiness,1024*1024),object_pairs_hook=strict_object)
    if live.get('attestation_sha256')!=hashlib.sha256(raw).hexdigest() or not live.get('awaiting_root_activation') or live.get('ready') or live.get('terminal'):raise RuntimeError('Producer is no longer awaiting independent activation')
    for key in ['producer','uid','nonce','endpoint','socket','producer_source_sha256','native_cli_sha256','archive_sha256','module_hashes','runtime_hashes','boot_id']:
        if live.get(key)!=meta[key]:raise RuntimeError('Readiness differs from immutable '+key)
    for loaded in [driver,runner,producer]:
        if loaded.loaded_source_sha256!=meta['module_hashes'][loaded.loaded_source_path]:raise RuntimeError('Executed module bytes differ from pinned source')
    source=ROOT/'scripts/plugin-primary-pilot-producer.py';source_info=source.stat()
    if {'device':source_info.st_dev,'inode':source_info.st_ino}!=meta['source_file_identity'] or driver.digest(source)!=meta['producer_source_sha256'] or any(driver.digest(Path(name))!=value for name,value in meta['module_hashes'].items()):raise RuntimeError('Pinned source/module identity changed')
    for name,value in meta['runtime_hashes'].items():
        if driver.digest(producer.CACHE/'bin'/name)!=value:raise RuntimeError('Pinned runtime changed')
    endpoint=Path(meta['endpoint'])
    if endpoint.parent!=path.parent or endpoint.resolve(strict=True)!=endpoint:raise RuntimeError('Pinned socket path differs')
    parent=driver.directory_fd(endpoint.parent)
    try:info=os.stat(endpoint.name,dir_fd=parent,follow_symlinks=False)
    finally:os.close(parent)
    observed={'dev':info.st_dev,'ino':info.st_ino,'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}
    if not stat.S_ISSOCK(info.st_mode) or observed!=meta['socket'] or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:raise RuntimeError('Pinned live socket identity changed')
    if poll.poll(0):raise RuntimeError('Producer exited during activation guard')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--attestation',required=True,type=Path);parser.add_argument('--sha256',required=True);parser.add_argument('--expected-config-hash',required=True)
    args=parser.parse_args();path=anchored_attestation(args.attestation)
    raw=bounded_bytes(path,1024*1024)
    if hashlib.sha256(raw).hexdigest()!=args.sha256:raise RuntimeError('Independent immutable attestation digest differs')
    meta=json.loads(raw,object_pairs_hook=strict_object)
    if set(meta['module_hashes'])!=MODULE_PATHS or set(meta['runtime_hashes'])!=RUNTIME_KEYS:raise RuntimeError('Bootstrap exact module/runtime keyset differs')
    if meta['root']!=str(ROOT) or meta['state']!='/home/luis/.local/share/progress-checker' or meta['native_cli_sha256']!=NATIVE_SHA:raise RuntimeError('Bootstrap pinned root/native differs')
    driver=load(ROOT/'scripts/plugin-primary-upgrade.py',meta['module_hashes'][str(ROOT/'scripts/plugin-primary-upgrade.py')]);runner=load(ROOT/'scripts/plugin-acceptance.py',meta['module_hashes'][str(ROOT/'scripts/plugin-acceptance.py')]);producer=load(ROOT/'scripts/plugin-primary-pilot-producer.py',meta['module_hashes'][str(ROOT/'scripts/plugin-primary-pilot-producer.py')])
    from types import SimpleNamespace
    driver.RUNNER=runner;driver.ACCEPTANCE=runner.Acceptance(SimpleNamespace(milestone='service-lifecycle'))
    handle=os.pidfd_open(meta['producer']['pid'],0);client=None
    try:
        validate(driver,runner,producer,path,raw,meta,handle)
        log_path=path.parent/('activation-readonly-'+str(time.time_ns())+'.stderr')
        log_fd=os.open(log_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(log_fd,'wb') as log:
            client=driver.wire(producer.CACHE/'bin/progress-checker-mcp',ROOT,producer.STATE,os.environ.copy(),log,time.monotonic()+30)
            current=client.current()['result']
            if current['running'] or current['canonical_root']!=str(ROOT) or current['status']['source']['config_hash']!=args.expected_config_hash:raise RuntimeError('Final accepted root config differs or checks active')
            if next(c for c in current['config']['checks'] if c['id']=='plan-definition')!=meta['check_definition']:raise RuntimeError('Concrete human approved definition differs')
            driver.close_wire(client);client=None
        validate(driver,runner,producer,path,raw,meta,handle)
        signal.pidfd_send_signal(handle,signal.SIGUSR1,None,0)
        print('Activated pinned producer through PIDfd SIGUSR1; no approval or check requested by helper.')
    finally:
        if client:driver.close_wire(client)
        os.close(handle)
    return 0


if __name__=='__main__':raise SystemExit(main())
