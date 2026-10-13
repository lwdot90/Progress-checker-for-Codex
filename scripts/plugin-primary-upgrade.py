#!/usr/bin/env python3
"""Reviewable read-only preparation / explicitly selected primary upgrade.

No model, plan, claim, configured-check or approval calls. Never copies auth or
private checker state. No force-kill, including subprocess cleanup. Failures
retain public backups and expose rollback decisions rather than guessing at a
concurrently modified root installation.
"""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import time
import tomllib

ROOT = Path(__file__).resolve().parent.parent
ARCHIVE_HASH = '404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
OLD_WRITER = '1f8a3015e84e26b83e5492eee3d8ac879c62ae385649189f0d8c7516c7b81584'
SELECTOR = 'progress-checker@progress-local-8b5742430514'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def module(path):
    spec = importlib.util.spec_from_file_location(path.stem.replace('-', '_'), path)
    result = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), result.__dict__)
    return result


def directory_fd(path):
    path=path.absolute()
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            next_fd=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=next_fd
        return fd
    except BaseException:
        os.close(fd);raise


def regular(path, limit=8 * 1024 * 1024):
    path=path.absolute();parent=directory_fd(path.parent)
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    try:
        info=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > limit:
            raise RuntimeError('Expected bounded owned regular file: ' + str(path))
        fd = os.open(path.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            opened=os.fstat(stream.fileno());data=stream.read(limit+1)
            if len(data)>limit or identity(opened)!=identity(info) or identity(os.fstat(stream.fileno()))!=identity(info) or identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False))!=identity(info):
                raise RuntimeError('File changed during anchored bounded read: '+str(path))
        again=directory_fd(path.parent)
        try:
            first,last=os.fstat(parent),os.fstat(again)
            if (first.st_dev,first.st_ino)!=(last.st_dev,last.st_ino):raise RuntimeError('Parent directory changed during bounded read')
        finally:os.close(again)
        return data
    finally:os.close(parent)


def inventory(path):
    values, total = {}, 0
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError('Public package directory missing or aliased: ' + str(path))
    for entry in sorted(path.rglob('*')):
        if entry.is_symlink():
            raise RuntimeError('Public backup refuses package symlink: ' + str(entry))
        if entry.is_dir():
            continue
        data = regular(entry, 32 * 1024 * 1024)
        total += len(data)
        if total > 64 * 1024 * 1024 or len(values) >= 2048:
            raise RuntimeError('Public package backup exceeds bounds')
        values[str(entry.relative_to(path))] = {'sha256': hashlib.sha256(data).hexdigest(), 'mode': stat.S_IMODE(entry.stat().st_mode)}
    return values


def group_members(child):
    members = []
    try:
        leader=Path(f'/proc/{child.pid}/stat').read_text().rsplit(')',1)[1].split()
        if leader[19]!=child.owned_starttime:raise RuntimeError('Owned session leader PID was reused')
    except FileNotFoundError:pass
    for p in Path('/proc').iterdir():
        if not p.name.isdigit(): continue
        try:
            fields = (p/'stat').read_text().rsplit(')', 1)[1].split()
            if fields[0] != 'Z' and int(fields[2]) == child.pid and int(fields[3]) == child.pid:
                if p.stat().st_uid != os.getuid() or int(fields[19])<int(child.owned_starttime): raise RuntimeError('Owned group UID/creation identity changed')
                members.append(int(p.name))
        except FileNotFoundError: pass
    return members


def backup_public(source, target, observed):
    target.mkdir(mode=0o700)
    for name, item in observed.items():
        data = regular(source/name, 32*1024*1024)
        if hashlib.sha256(data).hexdigest() != item['sha256']: raise RuntimeError('Public package changed before backup')
        dest = target/name; dest.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(dest, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, item['mode'])
        with os.fdopen(fd, 'wb') as stream: stream.write(data)
        os.chmod(dest, item['mode'])


def capture(argv, directory, label, deadline, env, cwd, report):
    """Live 8MiB/stream bound. TERM only our direct owned child; no SIGKILL."""
    if time.monotonic() >= deadline:
        raise RuntimeError('Shared work deadline expired before ' + label)
    child = subprocess.Popen(list(map(str, argv)), cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    child.owned_starttime=Path(f'/proc/{child.pid}/stat').read_text().rsplit(')',1)[1].split()[19]
    receipt = {'argv': list(map(str, argv)), 'pid': child.pid, 'starttime': RUNNER.process_identity(child.pid), 'status': 'running'}
    report.setdefault('commands', []).append(receipt)
    streams = {child.stdout: (directory / (label + '.stdout')).open('wb'), child.stderr: (directory / (label + '.stderr')).open('wb')}
    counts = {stream: 0 for stream in streams}
    try:
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(label + ' exceeded shared deadline')
            ready, _, _ = select.select(list(streams), [], [], min(.2, remaining))
            for stream in ready:
                data = os.read(stream.fileno(), 65536)
                if not data:
                    streams.pop(stream).close(); stream.close(); continue
                room = 8 * 1024 * 1024 - counts[stream]
                streams[stream].write(data[:room]); counts[stream] += len(data)
                if len(data) > room:
                    raise RuntimeError(label + ' exceeded live output bound')
        child.wait(timeout=max(.01, deadline - time.monotonic()))
        if group_members(child): raise RuntimeError(label+' left owned descendants alive')
        receipt.update(status='exited', returncode=child.returncode)
        if child.returncode:
            raise RuntimeError(label + ' failed with exit ' + str(child.returncode))
    except BaseException:
        members = group_members(child)
        if members:
            for pid in members:
                try: handle=os.pidfd_open(pid,0)
                except ProcessLookupError:continue
                try:
                    if pid in group_members(child):signal.pidfd_send_signal(handle,signal.SIGTERM,None,0)
                except ProcessLookupError:pass
                finally:os.close(handle)
            until = time.monotonic()+3
            while group_members(child) and time.monotonic()<until: time.sleep(.05)
        receipt['remaining_owned_group'] = group_members(child)
        try: child.wait(timeout=.1)
        except subprocess.TimeoutExpired: pass
        receipt.update(status='failed', returncode=child.poll(), still_alive=child.poll() is None,
                       cleanup='TERM only; no force kill; surviving child blocks further mutation')
        raise
    finally:
        for stream, output in streams.items(): output.close(); stream.close()


@contextlib.contextmanager
def locked(runtime, deadline):
    parent=directory_fd(runtime)
    try: fd = os.open('lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    finally:os.close(parent)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        os.close(fd); raise RuntimeError('Runtime mutex ownership invalid')
    try:
        while True:
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); break
            except BlockingIOError:
                if time.monotonic() >= deadline: raise RuntimeError('Runtime mutex deadline exceeded')
                time.sleep(.05)
        yield
    finally: os.close(fd)


def writer(record, checker, root, state, expected_hash):
    owned = json.loads(regular(record, 4096))
    if RUNNER.process_identity(owned['pid']) != owned:
        raise RuntimeError('Owned writer PID/starttime/UID changed')
    command = Path(f'/proc/{owned["pid"]}/cmdline').read_bytes().split(b'\0')
    expected = [os.fsencode(checker), b'--root', os.fsencode(root), b'--state-dir', os.fsencode(state), b'serve', b'']
    if command != expected or digest(Path(f'/proc/{owned["pid"]}/exe')) != expected_hash:
        raise RuntimeError('Owned writer exact command/executable changed')
    return owned


def wire(adapter, root, state, env, log, deadline):
    result = RUNNER.Project.__new__(RUNNER.Project)
    result.acceptance = ACCEPTANCE
    result.sequence, result.buffer = 0, bytearray()
    result.wire = subprocess.Popen([str(adapter), '--root', str(root), '--state-dir', str(state)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, env=env)
    original = result.receive
    result.receive = lambda timeout=15: original(min(timeout, max(.01, deadline-time.monotonic())))
    try:
        result.initialize()
        return result
    except BaseException:
        close_wire(result); raise


def close_wire(client):
    if client is None: return
    process = client.wire
    if process.poll() is None:
        process.stdin.close()
        try: process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: raise RuntimeError('Fresh owned MCP remains alive; no forcekill')
    process.stdout.close()


def snapshot(client):
    project = client.current()
    return {'config': project['result']['config'], 'config_hash': project['result']['status']['source']['config_hash'],
            'claims': project['result']['claims'], 'running': project['result']['running'],
            'latest': project['result']['status']['latest'], 'progress':project['result']['status']['progress'], 'history': client.history(),
            'canonical_root': project['result']['canonical_root'], 'revision': project['revision'],
            'service_instance_id': project['service_instance_id']}


class Prepared(Exception):
    pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--report-dir', required=True, type=Path)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--execute', action='store_true', help='Explicit reviewed root package update and gentle owned-writer restart')
    args = parser.parse_args()
    global RUNNER, ACCEPTANCE
    RUNNER = module(ROOT / 'scripts/plugin-acceptance.py')
    from types import SimpleNamespace
    ACCEPTANCE = RUNNER.Acceptance(SimpleNamespace(milestone='service-lifecycle'))
    started = time.monotonic(); deadline = started + 210
    directory = args.report_dir.absolute()
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {'status': 'blocked', 'execute_selected': args.execute, 'root_mutation_started': False,
              'approval_created': False, 'configured_checks_requested': False, 'forcekill_used': False,
              'private_state_backed_up': False, 'authenticated_model_proof': False,
              'rollback': {'attempted': False, 'decision': 'not needed before mutation'}}
    clients = []
    try:
        baseline = json.loads(regular(args.baseline, 1024*1024))
        root, state = Path(baseline['root']), Path(baseline['state'])
        if root.resolve(strict=True) != ROOT or str(state) != '/home/luis/.local/share/progress-checker' or baseline['selector'] != SELECTOR:
            raise RuntimeError('Driver binds only reviewed exact primary root/state/selector')
        home=Path('/home/luis/.codex'); cache=home/'plugins/cache/progress-local-8b5742430514/progress-checker/0.2.1-dev'
        source=Path('/home/luis/.local/share/progress-checker-plugins/8b5742430514/plugins/progress-checker')
        runtime=state/'plugin-8b5742430514e5c52baf368b'; record=runtime/'service.json'
        codex=Path('/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex')
        paths=[root/'.progress-checker/config.json',root/'AGENTS.md',root/'.codex/config.toml',home/'config.toml']
        protected={str(p):regular(p) for p in paths}
        def cas():
            for p,data in protected.items():
                if regular(Path(p)) != data: raise RuntimeError('Protected root/profile file changed: '+p)
        if {p:hashlib.sha256(v).hexdigest() for p,v in protected.items()} != baseline['file_sha256']:
            raise RuntimeError('Reviewed public root/profile baseline is stale')
        report['protected_hashes']=baseline['file_sha256']
        for label,path in [('cache',cache),('source',source)]:
            observed=inventory(path)
            # Protocol inventory contains hashes only; modes become part of this driver baseline.
            if {n:v['sha256'] for n,v in observed.items()} != baseline['package_inventory'][label]:
                raise RuntimeError('Reviewed public '+label+' inventory changed')
            backup=directory/('backup-'+label); backup_public(path,backup,observed)
            if inventory(backup) != observed or inventory(path) != observed: raise RuntimeError('Public backup changed while copying')
            report.setdefault('public_backups',{})[label]={'path':str(backup),'inventory':observed}
        legacy={int(p):v for p,v in baseline['processes'].items() if int(p)!=baseline['service_record']['pid']}
        for pid,item in legacy.items():
            if RUNNER.process_identity(pid) != {'pid':pid,'starttime':item['starttime']}: raise RuntimeError('Reviewed legacy process identity changed')
        report['legacy_processes']=legacy
        old=writer(record,cache/'bin/progress-checker',root,state,OLD_WRITER)
        if old != baseline['service_record']: raise RuntimeError('Reviewed owned writer changed')
        report['old_writer']=old
        env=os.environ.copy();env['CODEX_HOME']=str(home)
        with (directory/'mcp.log').open('ab') as log:
            observer=wire(cache/'bin/progress-checker-mcp',root,state,env,log,deadline);clients.append(observer)
            before=snapshot(observer);report['public_before']=before
            if before['running'] or before['config_hash']!=baseline['public_status']['source']['config_hash']:
                raise RuntimeError('Root has active checks or accepted config changed')
            reviewed=baseline['public_status']
            expected_claims={m['milestone_id']:'implemented' for m in reviewed['progress']['milestones'] if m['implementation_claim']=='implemented'}
            if before['claims']!=expected_claims or before['latest']!=reviewed['latest'] or any(before['progress'][key]!=reviewed['progress'][key] for key in ['scoped','verified','percent']):
                raise RuntimeError('Reviewed claims/latest/scope/verification baseline changed')
            plugin=RUNNER.extract_archive(ACCEPTANCE,args.archive,directory/'extracted')
            if ACCEPTANCE.report['archive']['sha256'] != ARCHIVE_HASH: raise RuntimeError('Archive hash is not reviewed immutable404')
            report['archive']=ACCEPTANCE.report['archive']
            newhash=digest(plugin/'bin/progress-checker')
            if not args.execute:
                report['status']='prepared';report['rollback']['decision']='No root mutation selected';raise Prepared()
            if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):raise RuntimeError('PIDfd unavailable; refusing root update')
            cas();writer(record,cache/'bin/progress-checker',root,state,OLD_WRITER)
            report['root_mutation_started']=True;report['rollback']['decision']='If any step fails retain backups; public restore requires exact ownership/CAS review; no automatic private/profile rewind'
            capture(['/usr/bin/python3',plugin.parent/'install.py','update','--project',root,'--codex-home',home,
                     '--data-home','/home/luis/.local/share','--state-dir',state,'--skip-agent-instructions','--codex',codex],
                    directory,'installer-update',deadline,env,root,report)
            cas()
            expected=inventory(plugin)
            for label, installed_path in [('cache',cache),('source',source)]:
                actual=inventory(installed_path)
                if actual.keys()!=expected.keys()|{'mcp.json'}: raise RuntimeError('Current '+label+' inventory differs from exact archive')
                for name,value in expected.items():
                    if name!='mcp.json' and actual.get(name)!=value: raise RuntimeError('Current '+label+' differs from exact archive: '+name)
            for path in [cache/'mcp.json',source/'mcp.json']:
                binding=json.loads(regular(path))['mcpServers']['progress_checker']
                if binding['args']!=['--root',str(root),'--state-dir',str(state)] or binding['command']!='./bin/checker-plugin':raise RuntimeError('New root/state binding changed')
            report['cache_current_hashes']={n:digest(cache/'bin'/n) for n in ['checker-plugin','progress-checker','progress-checker-mcp']}
            if snapshot(observer)['running']:raise RuntimeError('Check began before writer restart')
            with locked(runtime,min(deadline,time.monotonic()+10)):
                cas()
                if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
                    raise RuntimeError('PIDfd signaling unsupported; refusing writer restart')
                pidfd=os.pidfd_open(old['pid'],0)
                try:
                    owned=writer(record,cache/'bin/progress-checker',root,state,OLD_WRITER)
                    if owned!=old:raise RuntimeError('Owned writer changed immediately before PIDfd signal')
                    signal.pidfd_send_signal(pidfd,signal.SIGTERM,None,0)
                finally:os.close(pidfd)
                report['gentle_restart']={'signalled':owned,'signal':'SIGTERM via PIDfd','forcekill':False}
            until=min(deadline,time.monotonic()+35)
            while time.monotonic()<until:
                if RUNNER.process_identity(old['pid']) is None:
                    try:
                        current=writer(record,cache/'bin/progress-checker',root,state,newhash)
                        if current!=old:break
                    except (OSError,ValueError,RuntimeError):pass
                time.sleep(.1)
            else:raise RuntimeError('Current backend replacement deadline; no further signals')
            report['current_writer']=current
            after=snapshot(observer);report['public_after_legacy_adapter']=after
            for name in ['config','config_hash','claims','running','latest','history','canonical_root']:
                if after[name]!=before[name]:raise RuntimeError('Durable public state changed: '+name)
            for pid,item in legacy.items():
                if RUNNER.process_identity(pid)!={'pid':pid,'starttime':item['starttime']} or digest(Path(f'/proc/{pid}/exe'))!=item['exe_sha256']:raise RuntimeError('Legacy process changed: '+str(pid))
            fresh=wire(cache/'bin/progress-checker-mcp',root,state,env,log,deadline);clients.append(fresh)
            report['fresh_current_mcp']={'identity':RUNNER.process_identity(fresh.wire.pid),'exe_sha256':digest(Path(f'/proc/{fresh.wire.pid}/exe'))}
            if report['fresh_current_mcp']['exe_sha256']!=digest(plugin/'bin/progress-checker-mcp'):raise RuntimeError('Fresh adapter bytes not exact archive')
            observed=snapshot(fresh);report['public_after_current_adapter']=observed
            for name in ['config','config_hash','claims','running','latest','history','canonical_root','service_instance_id']:
                if observed[name]!=after[name]:raise RuntimeError('Fresh current adapter disagrees: '+name)
            cas();report['status']='passed';report['rollback']['decision']='Current runtime public compatibility passed; retain old public backups for reviewed rollback'
    except Prepared:
        pass
    except BaseException as exc:
        report['status']='failed';report['error']=repr(exc)
    finally:
        for client in reversed(clients):
            try:close_wire(client)
            except BaseException as exc:report.setdefault('cleanup_errors',[]).append(repr(exc));report['status']='failed'
        if 'old' in locals():
            try:
                expected_writer=report.get('current_writer',old)
                expected_hash=newhash if report.get('current_writer') else OLD_WRITER
                final_owned=writer(record,cache/'bin/progress-checker',root,state,expected_hash)
                if final_owned!=expected_writer:raise RuntimeError('Writer changed during owned adapter cleanup')
                final_leases={p.name:json.loads(regular(p,4096)) for p in (runtime/'leases').glob('*.json')}
                if final_leases!=baseline['leases']:raise RuntimeError('Existing root leases changed during trial')
                for pid,item in legacy.items():
                    if RUNNER.process_identity(pid)!={'pid':pid,'starttime':item['starttime']} or digest(Path(f'/proc/{pid}/exe'))!=item['exe_sha256']:raise RuntimeError('Existing legacy process changed during cleanup')
                report['final_root_runtime_audit']={'writer':final_owned,'leases':final_leases,'existing_legacy_identities_preserved':True}
            except BaseException as exc:
                report['final_root_runtime_audit']={'error':repr(exc)};report['status']='failed'
        if 'protected' in locals():
            final = {}
            for p,data in protected.items():
                try:
                    actual=regular(Path(p)); final[p]={'sha256':hashlib.sha256(actual).hexdigest(),'unchanged':actual==data}
                except BaseException as exc:
                    final[p]={'unchanged':False,'error':repr(exc)}
            report['final_protected_audit']=final
            report['protected_files_unchanged']=all(v['unchanged'] for v in final.values())
            if not report['protected_files_unchanged']:report['status']='failed'
        report['assertions']=ACCEPTANCE.report['assertions'];report['elapsed_seconds']=time.monotonic()-started
        report['limitations']=['No authentication/model trial performed.','Legacy adapters keep old process images.','Read-only compatibility does not constitute configured evidence or full primary pilot.']
        (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(directory/'report.json')
    return 0 if report['status'] in ('prepared','passed') else 2


if __name__=='__main__':raise SystemExit(main())
