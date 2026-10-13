#!/usr/bin/env python3
"""Fresh source-free recipient tests for the release-distribution gate.

Native qualification uses a prepared rootless Podman Fedora recipient when
available, and freshly builds a curated rootless namespace fixture otherwise.
Neither route exposes product source or a compiler. Namespace ownership and
execution limitations remain explicit; historical reports are never reused.
"""
from __future__ import annotations
import argparse
import ast
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import os
import stat
import json
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import uuid
import time

ROOT = Path(__file__).resolve().parent.parent
CONTAINER = 'pc-recipient-f44-20261004-compat'
OLD_SHA256 = 'fbf12375255af78ff30b042a9f9938ecccec5e03d7e8504042dac1872b0f646a'
MAX_TEST_SOURCE_BYTES = 2 * 1024 * 1024
PACKAGING_EXECUTION_LIMIT = 'Further nested checker execution is not qualified by this rootless mapped-root packaging fixture.'
EVIDENCE_PRESERVATION_LIMITS = {
    'No human-approved check evidence exists in the fixture; preservation covers actual public implementation claims and private state, not passing evidence.',
    'No genuine human-approved passing evidence was created or moved into the clean recipient. Upgrade and removal preserve actual public claims/configuration/private-state bytes, but evidence preservation still requires an in-place genuine-evidence scenario.',
}


class Deadline:
    """One release budget, with a separate reserve for owned cleanup."""
    def __init__(self, started_at=None, work_seconds=210, total_seconds=295):
        self.started_at = time.monotonic() if started_at is None else started_at
        self.work_end = self.started_at + work_seconds
        self.cleanup_end = self.started_at + total_seconds

    def remaining(self, maximum=None, *, cleanup=False):
        remaining = (self.cleanup_end if cleanup else self.work_end) - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Release '+('cleanup' if cleanup else 'work')+' shared deadline exceeded')
        return remaining if maximum is None else min(maximum, remaining)

    @contextmanager
    def operation(self, maximum, *, cleanup=False):
        # Bound Python RPC loops and synchronous prechecks as well as subprocesses.
        prior_handler = signal.getsignal(signal.SIGALRM)
        prior_timer = signal.getitimer(signal.ITIMER_REAL)
        started = time.monotonic()
        duration = self.remaining(maximum, cleanup=cleanup)
        if prior_timer[0] > 0:
            duration = min(duration, prior_timer[0])
        def expired(*_):
            raise TimeoutError('Release '+('cleanup' if cleanup else 'work')+' shared deadline exceeded')
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, duration)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, prior_handler)
            if prior_timer[0] > 0:
                signal.setitimer(signal.ITIMER_REAL, max(.000001, prior_timer[0]-(time.monotonic()-started)), prior_timer[1])


def owned_group_members(pid,starttime):
    """Identify only this newly created session; reject a reused leader PID."""
    try:
        leader=(Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()
        if leader[19]!=starttime:
            raise RuntimeError('Owned subprocess leader PID was reused')
    except FileNotFoundError:pass
    members=[]
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            values=path.read_text().rsplit(')',1)[1].split()
            if values[0]!='Z' and int(values[2])==pid:
                if int(values[3])!=pid or int(values[19])<int(starttime):
                    raise RuntimeError('Owned subprocess group identity changed')
                members.append(int(path.parent.name))
        except (FileNotFoundError,ProcessLookupError):pass
    return members


def stop_owned_group(process,starttime,budget=None):
    """Bounded group cleanup also handles an exited group leader."""
    if owned_group_members(process.pid,starttime):
        try:os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        deadline=time.monotonic()+5
        if budget is not None:deadline=min(deadline,budget.cleanup_end-.1)
        while owned_group_members(process.pid,starttime) and time.monotonic()<deadline:
            process.poll();time.sleep(.02)
        if owned_group_members(process.pid,starttime):
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
    process.wait(timeout=max(.001,min(1,budget.cleanup_end-time.monotonic())) if budget else 1)


def command(arguments, timeout=30, *, budget=None, cleanup=False):
    # File-backed capture and owned process groups bound external subprocesses.
    duration = timeout if budget is None else budget.remaining(timeout, cleanup=cleanup)
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        args=[str(value) for value in arguments]
        process=subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout,
                                 stderr=stderr, start_new_session=True)
        starttime=(Path('/proc')/str(process.pid)/'stat').read_text().rsplit(')',1)[1].split()[19]
        expired=False
        try:
            process.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            expired=True
            stop_owned_group(process,starttime,budget)
        except BaseException:
            stop_owned_group(process,starttime,budget)
            raise
        stdout.seek(0); stderr.seek(0)
        output,error=stdout.read(8*1024*1024+1),stderr.read(8*1024*1024+1)
        output,error=output[:8*1024*1024],error[:8*1024*1024]
        if expired:
            raise subprocess.TimeoutExpired(args,duration,output.decode('utf-8','replace'),error.decode('utf-8','replace'))
        stdout.seek(0,2);stderr.seek(0,2)
        if max(stdout.tell(),stderr.tell())>8*1024*1024:
            raise RuntimeError('Qualification subprocess output exceeds 8 MiB limit')
        return subprocess.CompletedProcess(args,process.returncode,output.decode('utf-8','replace'),error.decode('utf-8','replace'))


REMOTE_JOB_START = """import json,os,sys
from pathlib import Path
if os.getpgrp()!=os.getpid():os.setpgid(0,0)
if os.getsid(0)!=os.getpid():raise RuntimeError('Remote qualification requires its own session')
record={'pid':os.getpid(),'session':os.getsid(0),'harness':sys.argv[2],
        'starttime':Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]}
Path(sys.argv[1]).write_text(json.dumps(record))
os.execv(sys.executable,[sys.executable,*sys.argv[2:]])
"""
REMOTE_JOB_CLEANUP = r"""import json,os,signal,stat,sys,time
from pathlib import Path
job=Path(sys.argv[1]);expected=sys.argv[2]
receipt={'job':str(job),'owned_job_signaled':False,'leftover_live_group':[]}
if job.exists():
 info=job.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=1000 or info.st_size>4096:
  raise RuntimeError('Remote job ownership changed')
 record=json.loads(job.read_text());pid=record['pid']
 if record['harness']!=expected or type(pid)!=int or pid<=1:
  raise RuntimeError('Remote job identity changed')
 def owned_members():
  members=[]
  for entry in Path('/proc').glob('[0-9]*/stat'):
   try:
    values=entry.read_text().rsplit(')',1)[1].split()
    if values[0]!='Z' and int(values[2])==pid:
     if int(values[3])!=record.get('session') or int(values[19])<int(record['starttime']):
      raise RuntimeError('Remote process-group ownership changed')
     members.append(int(entry.parent.name))
   except (FileNotFoundError,ProcessLookupError):pass
  return members
 def live():
  try:
   values=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()
   return values[0]!='Z' and values[19]==record['starttime']
  except FileNotFoundError:return False
 if record.get('session')!=pid:raise RuntimeError('Remote job session ownership changed')
 try:
  leader=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()
  if leader[19]!=record['starttime']:raise RuntimeError('Remote job leader PID was reused; ownership unproven')
 except FileNotFoundError:pass
 if live():
  argv=Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0')
  if expected.encode() not in argv or os.getpgid(pid)!=pid:
   raise RuntimeError('Remote live process no longer matches owned harness')
 # A process-group ID cannot be reused while its original members remain.
 # Validate every member's session and creation time even if its leader exited.
 if owned_members():
  os.killpg(pid,signal.SIGTERM);receipt['owned_job_signaled']=True
  deadline=time.monotonic()+10
  while owned_members() and time.monotonic()<deadline:time.sleep(.1)
  if owned_members():os.killpg(pid,signal.SIGKILL)
  deadline=time.monotonic()+2
  while owned_members() and time.monotonic()<deadline:time.sleep(.05)
 receipt['leftover_live_group']=owned_members()
 receipt['cleanup_scope']='owned harness session/process group only; separate signed-state writer sessions are never force-killed'

 if not receipt['leftover_live_group']:job.unlink()
print(json.dumps(receipt))
if receipt['leftover_live_group']:sys.exit(1)
"""


def nested_qualification(archive, output_directory, reason, budget, old_archive=None):
    """Fresh curated rootfs fallback; never import a historical report."""
    helper=ROOT/'scripts/plugin-sandbox-recipient.py'
    helper_source=helper.read_bytes()
    helper_sha=hashlib.sha256(helper_source).hexdigest()
    spec=importlib.util.spec_from_file_location('fresh_nested_recipient',helper)
    module=importlib.util.module_from_spec(spec);exec(compile(helper_source,str(helper),'exec'),module.__dict__)
    old=Path(old_archive) if old_archive is not None else ROOT/'.local/plugin-build/progress-checker-0.2.0-dev-linux-x86_64.tar.gz'
    fresh=module.qualify(archive,old,ROOT/'scripts/plugin-recipient-qualify.py',
                         output=output_directory/'nested-recipient', timeout=budget.remaining(180))
    if hashlib.sha256(helper.read_bytes()).hexdigest()!=helper_sha:
        raise RuntimeError('Nested recipient implementation changed during qualification')
    recipient,inventory=fresh['report'],fresh['inventory']
    return {'status':'partial','complete':False,'assertions':recipient['assertions'],
            'unqualified':list(recipient['limitations']),
            'configured_checks_approved_or_executed':False,
            'archive_sha256':inventory['archive_sha256'],
            'harness_sha256':inventory['harness_sha256'],
            'nested_module_sha256':helper_sha,'podman_unavailable_reason':reason,
            'recipient':recipient,'nested_inventory':inventory,
            'environment':{'transport':'fresh rootless mapped-root namespace',
                           'privileged':False,'guest_euid':0,
                           'invoker_euid':inventory['invoker_attestation']['invoker_euid'],
                           'host_home_visible':False,'product_source_visible':False,
                           'mounts':[inventory['runtime_mounts']]}}


def qualify(archive: Path, output_directory: Path, container: str = CONTAINER, *, budget=None, old_archive: Path | None = None) -> dict:
    budget = Deadline() if budget is None else budget
    def run(arguments,timeout=30,cleanup=False):
        return command(arguments,timeout,budget=budget,cleanup=cleanup)
    output_directory.mkdir(parents=True, exist_ok=True)
    report = {'status': 'blocked', 'complete': False, 'assertions': [],
              'unqualified': [], 'configured_checks_approved_or_executed': False}
    podman = shutil.which('podman')
    if not podman:
        return nested_qualification(archive,output_directory,'Rootless Podman is unavailable in this execution environment.',budget,old_archive)
    inspected = run([podman, 'inspect', container],timeout=5)
    if inspected.returncode:
        return nested_qualification(archive,output_directory,'Prepared Podman recipient unavailable: '+inspected.stderr.strip()[:1000],budget,old_archive)
    inspected_objects = json.loads(inspected.stdout)
    if len(inspected_objects) != 1:
        raise RuntimeError('Recipient container identity is ambiguous')
    metadata = inspected_objects[0]
    if not metadata['State']['Running']:
        return nested_qualification(archive,output_directory,'Prepared Podman recipient is stopped.',budget,old_archive)
    if metadata.get('Mounts') or metadata['HostConfig'].get('Privileged'):
        raise RuntimeError('Recipient must be running, unprivileged, and have no host source mounts')
    report['environment'] = {'container_id': metadata['Id'], 'image': metadata['Image'],
                             'mounts': [], 'privileged': False, 'recipient_uid': 1000}
    budget.remaining()
    old = Path(old_archive) if old_archive is not None else ROOT / '.local/plugin-build/progress-checker-0.2.0-dev-linux-x86_64.tar.gz'
    if not old.is_file() or hashlib.sha256(old.read_bytes()).hexdigest() != OLD_SHA256:
        report['unqualified'].append('Pinned genuine prior 0.2.0-dev release archive is unavailable; cross-version upgrade qualification was not run.')
        return report
    archive = archive.resolve(strict=True)
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    budget.remaining()
    report['archive_sha256'] = archive_hash
    report['harness_sha256'] = hashlib.sha256((ROOT / 'scripts/plugin-recipient-qualify.py').read_bytes()).hexdigest()
    key = 'pc-qualification-' + uuid.uuid4().hex
    remote = '/tmp/' + key
    # Copy only bounded reviewed archives and this standalone Python harness.
    inputs = {'current.tar.gz': archive, 'old.tar.gz': old,
              'qualify.py': ROOT / 'scripts/plugin-recipient-qualify.py'}
    try:
        for name, path in inputs.items():
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
                raise RuntimeError('Qualification inputs must be bounded regular files')
            result = run([podman, 'cp', path, container + ':' + remote + '-' + name])
            if result.returncode:
                report['unqualified'].append('Could not transfer qualification inputs: ' + result.stderr.strip()[:1000])
                return report
        (output_directory / 'container-inspect.json').write_text(json.dumps(report['environment'], indent=2) + '\n')
        execution = run([podman, 'exec', '--user', '1000:1000', container,
                             '/usr/bin/python3', '-c', REMOTE_JOB_START, remote+'-job.json', remote + '-qualify.py',
                             '--archive', remote + '-current.tar.gz', '--sha256', archive_hash,
                             '--old-archive', remote + '-old.tar.gz'], timeout=180)
        (output_directory / 'qualification.stdout').write_text(execution.stdout)
        (output_directory / 'qualification.stderr').write_text(execution.stderr)
        try:
            response = json.loads(execution.stdout)
            recipient = response['report']
        except (ValueError, KeyError) as error:
            raise RuntimeError('Recipient did not return a fresh qualification report: ' + execution.stderr[-2000:]) from error
        (output_directory / 'recipient-report.json').write_text(json.dumps(recipient, indent=2) + '\n')
        if recipient.get('upgrade_archive_sha256') != archive_hash:
            raise RuntimeError('Recipient report does not bind the exact tested archive')
        result = run([podman, 'cp', container + ':' + str(Path(response['report_path']).parent), output_directory / 'recipient'])
        if result.returncode:
            raise RuntimeError('Could not retrieve fresh qualification artifacts: ' + result.stderr.strip())
        if execution.returncode or recipient.get('status') != 'passed':
            raise RuntimeError('Fresh recipient qualification failed: ' + str(recipient.get('error', execution.stderr[-2000:])))
        if hashlib.sha256(archive.read_bytes()).hexdigest() != archive_hash:
            raise RuntimeError('Archive changed during recipient qualification')
        report['recipient'] = recipient
        report['assertions'] = recipient['assertions']
        report['unqualified'] = list(recipient['limitations'])
        report['unqualified'].append('No genuine human-approved passing evidence was created or moved into the clean recipient. Upgrade and removal preserve actual public claims/configuration/private-state bytes, but evidence preservation still requires an in-place genuine-evidence scenario.')
        report['status'] = 'partial'
        return report
    except subprocess.TimeoutExpired as error:
        (output_directory/'qualification-timeout.stdout').write_text(error.output or '')
        (output_directory/'qualification-timeout.stderr').write_text(error.stderr or '')
        raise
    finally:
        stopped=run([podman,'exec',container,'/usr/bin/python3','-c',REMOTE_JOB_CLEANUP,
                     remote+'-job.json',remote+'-qualify.py'],timeout=20,cleanup=True)
        (output_directory/'remote-job-cleanup.stdout').write_text(stopped.stdout)
        (output_directory/'remote-job-cleanup.stderr').write_text(stopped.stderr)
        # Only our generated transfer files are removed; retained project state
        # and evidence are untouched on success and failure.
        cleanup = run([podman, 'exec', container, '/usr/bin/python3', '-c',
                           'from pathlib import Path; import sys; '
                           '[Path(value).unlink(missing_ok=True) for value in sys.argv[1:]]',
                           *[remote+'-'+name for name in inputs]],timeout=15,cleanup=True)
        if stopped.returncode:
            raise RuntimeError('Owned recipient job cleanup failed: '+stopped.stderr[-1000:])
        (output_directory/'transfer-cleanup.json').write_text(json.dumps({
            'paths': [remote+'-'+name for name in inputs],
            'exit_code': cleanup.returncode, 'stderr': cleanup.stderr[:1000],
        },indent=2)+'\n')


def installer_state_binding(installer: Path) -> bool:
    """Inspect the supported parser; never patch generated MCP configuration."""
    if installer.is_symlink() or not installer.is_file() or installer.stat().st_size>1024*1024:
        raise RuntimeError('Installer must be a bounded regular package file')
    source=ast.parse(installer.read_text())
    return any(isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
               and node.func.attr=='add_argument' and any(
                   isinstance(arg,ast.Constant) and arg.value=='--state-dir'
                   for arg in node.args) for node in ast.walk(source))


def settings_snapshot(path):
    """Bounded no-follow bytes plus file identity for owned cleanup."""
    try: fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    except FileNotFoundError:return None
    except OSError:return {'unsafe':True}
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size>64*1024 or info.st_uid!=os.geteuid():return {'unsafe':True}
        data=os.read(fd,64*1024+1);after=os.fstat(fd)
        identity=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,stat.S_IMODE(info.st_mode))
        if identity!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns,stat.S_IMODE(after.st_mode)):return {'unsafe':True}
        try:current=path.lstat()
        except OSError:return {'unsafe':True}
        if (current.st_dev,current.st_ino)!=(info.st_dev,info.st_ino):return {'unsafe':True}
        return {'bytes':data,'identity':identity}
    finally:os.close(fd)


def directory_identity(path):
    try:info=path.lstat()
    except FileNotFoundError:return None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid():return None
    return (info.st_dev,info.st_ino)


def cleanup_owned_empty_settings(root, original_files, owned_file, owned_directory, directory_created=True):
    """Preserve comments, replacements and any concurrent unowned bytes."""
    settings=root/'.codex/config.toml';directory=root/'.codex'
    result={'file_removed':False,'directory_removed':False,'concurrent_changes_preserved':False}
    # lexists includes dangling symlinks, which must be preserved.
    if '.codex/config.toml' not in original_files and os.path.lexists(settings):
        current=settings_snapshot(settings)
        if (owned_file is None or current!=owned_file or current.get('unsafe')
                or current['bytes'].strip() or directory_identity(directory)!=owned_directory):
            result['concurrent_changes_preserved']=True
            return result
        # Recheck both bytes and identity immediately before unlinking.
        if settings_snapshot(settings)!=owned_file:
            result['concurrent_changes_preserved']=True
            return result
        settings.unlink();result['file_removed']=True
    if directory_created and owned_directory is not None and os.path.lexists(directory):
        if directory_identity(directory)!=owned_directory or list(directory.iterdir()):
            result['concurrent_changes_preserved']=True
            return result
        directory.rmdir();result['directory_removed']=True
    return result


def in_place_evidence_preservation(acceptance, directory: Path, fixture_root, fixture_state, *, budget=None, codex_binary=None):
    """Preflight explicitly selected existing state without relocating records.

    This fails open for normal development (returns unmet gates), but never
    treats a different automatically selected empty state as preserved evidence.
    A supported installer binding and the live upgrade/removal scenario are
    required before this can contribute passing acceptance.
    """
    budget = Deadline() if budget is None else budget
    budget.remaining()
    if fixture_root is None or fixture_state is None:
        return ['Genuine passing-evidence upgrade/removal qualification requires explicit retained fixture root and state paths; no host-default state is inferred.']
    directory=directory.resolve()
    root=Path(fixture_root).resolve(strict=True)
    state=Path(fixture_state).resolve(strict=True)
    if not root.is_dir() or not state.is_dir() or root==state or root in state.parents or state in root.parents:
        raise RuntimeError('Retained fixture and private state must be distinct directories outside each other')
    installer=acceptance.options.plugin_directory.parent/'install.py'
    acceptance.artifact('release_installer',installer)
    for name in ['checker-plugin','checker-project','progress-checker','progress-checker-mcp']:
        acceptance.artifact('release_runtime_'+name,acceptance.options.plugin_directory/'bin'/name)
    supported=installer_state_binding(installer)
    receipt={'fixture_root':str(root),'fixture_state':str(state),
             'installer':str(installer),'installer_sha256':hashlib.sha256(installer.read_bytes()).hexdigest(),
             'explicit_state_binding_supported':supported,
             'project_mutated':False,'private_records_moved_or_copied':False,
             'approvals_or_checks_executed':False}
    directory.mkdir(parents=True,exist_ok=True)
    (directory/'state-binding-preflight.json').write_text(json.dumps(receipt,indent=2)+'\n')
    acceptance.report['release_evidence_preservation']=receipt
    if not supported:
        return ['Packaged installer has no --state-dir option and always derives state as --data-home/progress-checker. It cannot bind the explicitly retained '+str(state)+' through its supported interface. In-place evidence upgrade/removal was not run; generated MCP configuration was not overridden and records were not relocated.']
    acceptance.artifact('release_evidence_module',ROOT/'scripts/plugin-evidence-acceptance.py')
    spec=importlib.util.spec_from_file_location('release_evidence_runtime', ROOT/'scripts/plugin-evidence-acceptance.py')
    evidence=importlib.util.module_from_spec(spec);exec(compile(Path(spec.origin).read_bytes(),spec.origin,'exec'),evidence.__dict__)
    fixture=evidence._Fixture(root,state)
    original_files={}
    for path in root.rglob('*'):
        budget.remaining()
        if '.git' in path.relative_to(root).parts or path.is_dir(): continue
        if path.is_symlink() or not path.is_file() or path.stat().st_size>1024*1024:
            raise RuntimeError('Fixture contains an unsupported file for preservation audit')
        original_files[str(path.relative_to(root))]=(path.read_bytes(),stat.S_IMODE(path.stat().st_mode))
    codex_directory_existed=(root/'.codex').exists()
    profile=directory/'codex-profile';data=directory/'data'
    profile.mkdir();data.mkdir()
    codex=Path(codex_binary) if codex_binary is not None else Path('/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex')
    common=['--project',str(root),'--codex',str(codex),'--codex-home',str(profile),
            '--data-home',str(data),'--skip-agent-instructions']
    def installer_receipt(output,key):
        decoder=json.JSONDecoder()
        for offset,char in enumerate(output):
            if char!='{': continue
            try: value,_=decoder.raw_decode(output[offset:])
            except ValueError: continue
            if isinstance(value,dict) and key in value:return value
        raise RuntimeError('Installer did not return expected '+key+' receipt')
    owned_file=settings_snapshot(root/'.codex/config.toml')
    owned_directory=directory_identity(root/'.codex')
    def restore_owned_empty_settings():
        outcome=cleanup_owned_empty_settings(root,original_files,owned_file,owned_directory,not codex_directory_existed)
        receipt['settings_cleanup']=outcome
        return outcome
    def installer_action(action,*extra,success=True,cleanup=False):
        nonlocal owned_file,owned_directory
        before=settings_snapshot(root/'.codex/config.toml')
        before_directory=directory_identity(root/'.codex')
        owned_before=(before==owned_file and before_directory==owned_directory)
        if cleanup and not owned_before and '.codex/config.toml' not in original_files:
            # A timed-out first install may have written its exact managed table
            # before returning. Adopt only this known public installer output,
            # then keep the normal identity/bytes CAS checks around removal.
            selector='progress-checker@progress-local-'+hashlib.sha256(os.fsencode(root)).hexdigest()[:12]
            expected=('\n\n[plugins.'+json.dumps(selector)+']\nenabled = true\n').encode()
            if (isinstance(before,dict) and before.get('bytes')==expected
                    and settings_snapshot(root/'.codex/config.toml')==before
                    and directory_identity(root/'.codex')==before_directory):
                owned_file,owned_directory=before,before_directory
                owned_before=True
        try:
            result=command(['/usr/bin/python3',installer,action,*common,*extra],timeout=60,budget=budget,cleanup=cleanup)
        except subprocess.TimeoutExpired as error:
            (directory/(action+'-timeout.stdout')).write_text(error.output or '')
            (directory/(action+'-timeout.stderr')).write_text(error.stderr or '')
            raise
        (directory/(action+('-refused' if not success else '')+'.stdout')).write_text(result.stdout)
        (directory/(action+('-refused' if not success else '')+'.stderr')).write_text(result.stderr)
        acceptance.check('retained evidence installer '+action+(' succeeds' if success else ' refuses conflicting state'),
                         result.returncode==0 if success else result.returncode!=0)
        if success and action in ('install','update','remove') and owned_before:
            owned_file=settings_snapshot(root/'.codex/config.toml')
            owned_directory=directory_identity(root/'.codex')
        return result
    acceptance.artifact('release_checksum_inventory',installer.parent/'checksums.json')
    checksums=json.loads((installer.parent/'checksums.json').read_text())
    def validate_cached_plugin(cached):
        for relative,digest in checksums.items():
            budget.remaining()
            if not relative.startswith('plugin/') or relative=='plugin/mcp.json':continue
            target=cached/relative.removeprefix('plugin/')
            expected=installer.parent/relative
            if (target.is_symlink() or not target.is_file() or target.stat().st_size!=expected.stat().st_size
                    or any(parent.is_symlink() for parent in target.parents if parent!=cached and cached in parent.parents)
                    or hashlib.sha256(target.read_bytes()).hexdigest()!=digest):
                raise RuntimeError('Cached package file does not match checked archive: '+relative)
        acceptance.check('native cached package files match checked archive before use',True)
    def cache_plugin():
        manifests=list((profile/'plugins/cache').rglob('plugin.json'))
        acceptance.check('isolated profile contains exactly one expected plugin',len(manifests)==1)
        cached=manifests[0].parent
        definition=json.loads((cached/'mcp.json').read_text())['mcpServers']['progress_checker']
        acceptance.check('native installed configuration binds exact retained state',
                         definition['args']==['--root',str(root),'--state-dir',str(state)])
        validate_cached_plugin(cached)
        return cached
    class BoundedMCP(evidence._MCP):
        def __init__(self,acceptance,directory,plugin,root,state,label):
            budget.remaining()
            self.acceptance,self.directory=acceptance,directory
            self.sequence,self.buffer=0,bytearray()
            self.log=(directory/(label+'.stderr')).open('wb')
            self.receipts=(directory/(label+'.public-wire.jsonl')).open('w')
            env={'PATH':'/usr/bin:/bin','HOME':str(directory),'LANG':'C.UTF-8',
                 'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'}
            self.process=subprocess.Popen([str(plugin/'bin/checker-plugin'),'--root',str(root),
                                           '--state-dir',str(state)],stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE,stderr=self.log,cwd=plugin,env=env,
                                          start_new_session=True)
            self.starttime=(Path('/proc')/str(self.process.pid)/'stat').read_text().rsplit(')',1)[1].split()[19]
            try:
                self.rpc('initialize',{'protocolVersion':'2025-06-18','capabilities':{},
                                     'clientInfo':{'name':'live-evidence-acceptance','version':'1'}})
                self.process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n')
                self.process.stdin.flush()
                tools=self.rpc('tools/list',{})['tools']
                acceptance.check('evidence runtime advertises ten tools without any approval tool',
                                 len(tools)==10 and not any('approve' in t['name'] for t in tools))
            except BaseException as startup_error:
                cleanup_error=None
                try:self.close()
                except BaseException as error:cleanup_error=error
                try:
                    fd=os.open(self.log.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
                    with os.fdopen(fd,'rb') as diagnostic:
                        if not stat.S_ISREG(os.fstat(diagnostic.fileno()).st_mode):
                            raise RuntimeError('Launcher diagnostic is not a regular file')
                        diagnostic.seek(0,os.SEEK_END)
                        diagnostic.seek(max(0,diagnostic.tell()-8192))
                        stderr_tail=diagnostic.read(8192).decode('utf-8','replace')
                except Exception as error:
                    stderr_tail='Bounded launcher stderr unavailable: '+str(error)
                acceptance.report['release_launcher_startup_failure']={
                    'startup_error':str(startup_error),'cleanup_error':str(cleanup_error) if cleanup_error else None,
                    'returncode':self.process.returncode,'stderr_tail':stderr_tail}
                if cleanup_error is not None:
                    raise RuntimeError('Evidence launcher startup failed: '+str(startup_error)
                                       +'; shutdown also failed: '+str(cleanup_error)
                                       +'; stderr: '+stderr_tail) from startup_error
                raise
        def rpc(self,method,params):
            with budget.operation(55):
                return super().rpc(method,params)
        def close(self):
            try:
                if self.process.poll() is None:
                    self.process.stdin.close()
                    try:
                        self.process.wait(timeout=budget.remaining(15,cleanup=True))
                    except (subprocess.TimeoutExpired,TimeoutError):
                        # Only this launcher/client group is eligible; signed
                        # writers and watchdogs always use separate sessions.
                        stop_owned_group(self.process,self.starttime,budget)
            finally:
                self.process.stdout.close();self.log.close();self.receipts.close()
            self.acceptance.check('evidence packaged client shuts down cleanly',self.process.returncode==0)
    snapshots={}
    def public_snapshot(label,plugin):
        fixture.guard()
        if plugin!=acceptance.options.plugin_directory:validate_cached_plugin(plugin)
        session=BoundedMCP(acceptance,directory,plugin,root,state,'release-'+label)
        try:
            current=session.current()['result']
            latest=current['status']['latest'].get('demo-check',{})
            acceptance.check(label+' reads genuine passing stale evidence',
                             latest.get('outcome')=='passed' and latest.get('freshness')=='stale'
                             and bool(latest.get('run_id')) and bool(latest.get('log_ref')))
            project=session.tool('checker_get_project',read_only=True)
            run=session.tool('checker_get_run',{'run_id':latest['run_id']},read_only=True)
            log=session.tool('checker_get_log',{'run_id':latest['run_id'],'check_id':'demo-check',
                                              'offset':0,'limit':32768},read_only=True)
            acceptance.check(label+' reads authenticated original run and log',
                             not run['isError'] and not log['isError'] and not project['isError'])
            snapshot={'claims':current['claims'],'latest':latest,
                      'config':project['structuredContent']['result']['config'],
                      'run':run['structuredContent']['result'],'log':log['structuredContent']['result']}
            snapshots[label]=snapshot
            (directory/(label+'-public-evidence.json')).write_text(json.dumps(snapshot,indent=2)+'\n')
            return snapshot
        finally:
            session.close()
    installed=False
    try:
        baseline=public_snapshot('before-install',acceptance.options.plugin_directory)
        installed=True
        result=installer_action('install','--state-dir',str(state))
        receipt['project_mutated']=True
        acceptance.check('installer advertises retained state',installer_receipt(result.stdout,'state_directory')['state_directory']==str(state))
        cached=cache_plugin()
        acceptance.check('installation preserves signed public evidence',public_snapshot('after-install',cached)==baseline)
        installed_mcp=data/'progress-checker-plugins'/hashlib.sha256(os.fsencode(root)).hexdigest()[:12]/'plugins/progress-checker/mcp.json'
        binding_before=installed_mcp.read_bytes()
        installer_action('update','--state-dir',str(directory/'conflicting-state'),success=False)
        acceptance.check('refused state migration leaves native binding unchanged',installed_mcp.read_bytes()==binding_before)
        installer_action('update')
        acceptance.check('update without state flag retains signed public evidence',public_snapshot('after-update',cache_plugin())==baseline)
        installer_action('list')
        result=installer_action('remove');installed=False
        acceptance.check('remove explicitly preserves retained state',installer_receipt(result.stdout,'preserved_state_directory')['preserved_state_directory']==str(state))
        # Remove only a newly owned whitespace-only settings file left by
        # removing the managed plugin; never delete an existing user file.
        restore_owned_empty_settings()
        acceptance.check('removal preserves signed public evidence and readable log',public_snapshot('after-remove',acceptance.options.plugin_directory)==baseline)
        fixture.guard()
        actual={str(path.relative_to(root)):(path.read_bytes(),stat.S_IMODE(path.stat().st_mode))
                for path in root.rglob('*') if path.is_file() and '.git' not in path.relative_to(root).parts}
        acceptance.check('retained fixture original file bytes and modes restored',actual==original_files)
        receipt.update(complete=True,project_bytes_restored=True,
                       run_id=baseline['latest']['run_id'],log_ref=baseline['latest']['log_ref'],
                       snapshots=list(snapshots),upgrade='same-version installer transaction; genuine cross-version covered by clean recipient')
        acceptance.report['release_evidence_preservation']=receipt
        (directory/'preservation-report.json').write_text(json.dumps(receipt,indent=2)+'\n')
        return []
    finally:
        try:
            if installed:
                installer_action('remove',cleanup=True)
        finally:
            try:
                restore_owned_empty_settings()
            finally:
                fixture.guard()


def read_release_source(path):
    """Read only a bounded current acceptance source buffer, without symlinks."""
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        before=os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size>MAX_TEST_SOURCE_BYTES:
            raise ValueError('Release acceptance source is not bounded regular input')
        data=source.read(MAX_TEST_SOURCE_BYTES+1)
        after=os.fstat(source.fileno())
        def identity(info):return info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns
        if len(data)>MAX_TEST_SOURCE_BYTES or identity(before)!=identity(after):
            raise RuntimeError('Release acceptance source changed while reading')
        if identity(path.lstat())!=identity(after):
            raise RuntimeError('Release acceptance source was replaced while reading')
        return data


def retained_harness_source(sources, budget):
    """Materialize current test sources, retaining the original absolute budget."""
    return '''import argparse,base64,hashlib,importlib.util,json,os,traceback
from pathlib import Path
p=argparse.ArgumentParser()
for name in ['archive','old-archive','base-dir','data-home','output-dir','invoker-attestation','fixture-root','fixture-state']:p.add_argument('--'+name,type=Path)
p.add_argument('--sha256');p.add_argument('--namespace-mapped-root',action='store_true')
a=p.parse_args()
report={'status':'failed','upgrade_archive_sha256':a.sha256,
        'qualification_scope':'fixed retained demo signed-evidence preservation in place; separate from source-free recipient qualification',
        'retained_fixture':{'root':str(a.fixture_root),'state':str(a.fixture_state)},
        'private_records_moved_or_copied':False,'no_configured_checks_executed':True,
        'test_sources':{},'release_deadline':ORIGINAL_DEADLINE}
acceptance=None
try:
    caps={line.split(':')[0]:line.split(':')[1].strip() for line in Path('/proc/self/status').read_text().splitlines() if line.startswith(('CapEff:','CapPrm:','CapBnd:'))}
    if not a.namespace_mapped_root or os.getuid()!=0 or set(caps)!={'CapEff','CapPrm','CapBnd'} or any(int(value,16)!=0 for value in caps.values()):raise RuntimeError('Expected mapped root with all capabilities dropped')
    if Path('/proc/self/uid_map').read_text().split()!=['0','1000','1'] or Path('/proc/self/gid_map').read_text().split()!=['0','1000','1']:raise RuntimeError('Unexpected retained-runtime UID/GID mapping')
    if Path('/home/luis/.codex').exists() or Path('/home/luis/.local/share/progress-checker').exists():raise RuntimeError('Unselected host private home exposed')
    report.update(parent_capabilities=caps,invoker_attestation=json.loads(a.invoker_attestation.read_text()))
    source_directory=Path('/r/acceptance-harness/scripts');source_directory.mkdir(parents=True)
    for name,value in SOURCE_BUFFERS.items():
        data=base64.b64decode(value,validate=True)
        (source_directory/name).write_bytes(data)
        report['test_sources'][name]=hashlib.sha256(data).hexdigest()
    def load(name):
        path=source_directory/name
        spec=importlib.util.spec_from_file_location(name.replace('-','_'),path)
        module=importlib.util.module_from_spec(spec)
        exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
        return module
    product=load('plugin-acceptance.py');release=load('plugin-release-acceptance.py')
    options=argparse.Namespace(milestone='release-distribution',archive=a.archive,plugin_directory=None)
    acceptance=product.Acceptance(options);acceptance.started_at=ORIGINAL_DEADLINE['started_at']
    budget=release.Deadline(acceptance.started_at)
    if (budget.work_end,budget.cleanup_end)!=(ORIGINAL_DEADLINE['work_end'],ORIGINAL_DEADLINE['cleanup_end']):raise RuntimeError('Release deadline endpoints changed')
    with budget.operation(budget.remaining()):
        options.plugin_directory=product.extract_archive(acceptance,a.archive,Path('/r/release'))
        acceptance.check('retained runtime extracts the exact approved release archive',acceptance.report['archive']['sha256']==a.sha256)
    unqualified=release.in_place_evidence_preservation(acceptance,a.output_dir/'preservation',a.fixture_root,a.fixture_state,budget=budget,codex_binary=Path('/usr/local/bin/codex'))
    with budget.operation(budget.remaining(cleanup=True),cleanup=True):
        acceptance.check('retained runtime executable and test artifacts remained unchanged',all(hashlib.sha256(Path(record['path']).read_bytes()).hexdigest()==record['sha256'] for record in acceptance.report['artifacts'].values()))
    complete=not unqualified
    acceptance.report.update(unqualified=unqualified,status='passed' if complete else 'partial',complete=complete)
    report.update(status='passed',product_acceptance=acceptance.report)
except Exception as error:
    report.update(error=str(error),traceback=traceback.format_exc())
    if acceptance is not None:
        acceptance.report.update(status='failed',complete=False,error=str(error))
        report['product_acceptance']=acceptance.report
finally:
    (a.output_dir/'report.json').write_text(json.dumps(report,indent=2)+'\\n')
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if report['status']=='passed' else 1)
'''.replace('SOURCE_BUFFERS',repr(sources)).replace('ORIGINAL_DEADLINE',repr({
        'clock':'shared kernel monotonic','started_at':budget.started_at,
        'work_end':budget.work_end,'cleanup_end':budget.cleanup_end,
        'work_seconds':210,'total_seconds':295,'cleanup_reserve_seconds':85}))


def read_retained_report(path):
    """Reject ambiguous transport reports rather than accepting cached success."""
    def strict_pairs(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('Duplicate retained transport report field: '+key)
            value[key]=item
        return value
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>1024*1024:
            raise ValueError('Retained transport report is not bounded regular output')
        data=source.read(1024*1024+1)
    if len(data)>1024*1024:raise ValueError('Retained transport report exceeds its bound')
    report=json.loads(data,object_pairs_hook=strict_pairs)
    allowed={'status','upgrade_archive_sha256','qualification_scope','retained_fixture',
             'private_records_moved_or_copied','no_configured_checks_executed','test_sources',
             'release_deadline','parent_capabilities','invoker_attestation','product_acceptance','error','traceback'}
    if not isinstance(report,dict) or set(report)-allowed:
        raise ValueError('Unknown retained transport report field')
    return report


def mapped_in_place_evidence_preservation(acceptance,directory,fixture_root,fixture_state,*,budget):
    """Expose only the exact retained demo in place to a zero-cap mapped root."""
    if fixture_root is None or fixture_state is None:
        return ['Genuine passing-evidence upgrade/removal qualification requires explicit retained fixture root and state paths; no host-default state is inferred.']
    directory=directory.resolve();directory.mkdir(parents=True,exist_ok=True)
    names=('plugin-release-acceptance.py','plugin-acceptance.py','plugin-evidence-acceptance.py','plugin-sandbox-recipient.py')
    with budget.operation(budget.remaining()):
        buffers={name:read_release_source(ROOT/'scripts'/name) for name in names}
        hashes={name:hashlib.sha256(value).hexdigest() for name,value in buffers.items()}
        for name in names:
            acceptance.artifact('retained_source_'+name,ROOT/'scripts'/name)
            if acceptance.report['artifacts']['retained_source_'+name]['sha256']!=hashes[name]:
                raise RuntimeError('Retained test source changed before transport')
        def load(name):
            path=ROOT/'scripts'/name
            spec=importlib.util.spec_from_file_location('retained_'+name.replace('-','_'),path)
            module=importlib.util.module_from_spec(spec)
            exec(compile(buffers[name],str(path),'exec'),module.__dict__)
            return module
        evidence=load('plugin-evidence-acceptance.py');helper=load('plugin-sandbox-recipient.py')
        root,state=Path(fixture_root),Path(fixture_state)
        if (root,state)!=helper.RETAINED_DEMO:
            raise ValueError('Release preservation accepts only the exact retained demo paths')
        fixture=evidence._Fixture(root,state)
        for name in ['checker-plugin','checker-project','progress-checker','progress-checker-mcp']:
            acceptance.artifact('release_runtime_'+name,acceptance.options.plugin_directory/'bin'/name)
        acceptance.artifact('release_installer',acceptance.options.plugin_directory.parent/'install.py')
        acceptance.artifact('release_checksum_inventory',acceptance.options.plugin_directory.parent/'checksums.json')
    source_buffers={name:base64.b64encode(buffers[name]).decode('ascii') for name in names[:3]}
    output=directory/'mapped-runtime'
    def merge_report(report):
        expected_sources={name:hashes[name] for name in names[:3]}
        if (report.get('upgrade_archive_sha256')!=acceptance.report['archive']['sha256']
                or report.get('retained_fixture')!={'root':str(root),'state':str(state)}
                or report.get('test_sources')!=expected_sources
                or report.get('private_records_moved_or_copied') is not False
                or report.get('no_configured_checks_executed') is not True):
            raise RuntimeError('Retained transport report input or safety binding mismatch')
        # Assertions and the preservation receipt are merged below; avoid
        # printing a second copy in the bounded configured-check log.
        acceptance.report['release_evidence_transport']={key:value for key,value in report.items() if key!='product_acceptance'}
        product=report.get('product_acceptance',{})
        allowed_product={'milestone','status','complete','coverage','assertions','unqualified','artifacts',
                         'archive','release_evidence_preservation','release_launcher_startup_failure','error'}
        if not isinstance(product,dict) or set(product)-allowed_product:
            raise ValueError('Unknown retained product acceptance report field')
        if 'release_launcher_startup_failure' in product:
            acceptance.report['release_launcher_startup_failure']=product['release_launcher_startup_failure']
        for assertion in product.get('assertions',[]):
            if (not isinstance(assertion,dict) or set(assertion)-{'name','passed','detail'}
                    or not isinstance(assertion.get('name'),str) or type(assertion.get('passed')) is not bool):
                raise ValueError('Malformed retained acceptance assertion')
            acceptance.report['assertions'].append(assertion)
        if 'release_evidence_preservation' in product:
            receipt=product['release_evidence_preservation']
            allowed_receipt={'fixture_root','fixture_state','installer','installer_sha256','explicit_state_binding_supported',
                             'project_mutated','private_records_moved_or_copied','approvals_or_checks_executed','settings_cleanup',
                             'complete','project_bytes_restored','run_id','log_ref','snapshots','upgrade'}
            if (not isinstance(receipt,dict) or set(receipt)-allowed_receipt
                    or receipt.get('fixture_root')!=str(root) or receipt.get('fixture_state')!=str(state)
                    or receipt.get('private_records_moved_or_copied') is not False
                    or receipt.get('approvals_or_checks_executed') is not False):
                raise ValueError('Retained preservation receipt has an unknown field or changed state binding')
            acceptance.report['release_evidence_preservation']=receipt
    try:
        with tempfile.TemporaryDirectory(prefix='retained-harness-',dir=directory) as temporary:
            harness=Path(temporary)/'harness.py'
            harness.write_text(retained_harness_source(source_buffers,budget))
            acceptance.report['release_evidence_transport_bounds']={
                'harness_sha256':hashlib.sha256(harness.read_bytes()).hexdigest(),
                'helper_sha256':hashes[names[3]],'test_sources':{name:hashes[name] for name in names[:3]},
                'clock':'shared kernel monotonic','work_end':budget.work_end,'cleanup_end':budget.cleanup_end,
                'retained_signed_state_visible':True,'private_records_moved_or_copied':False,
                'no_configured_checks_executed':True}
            try:
                result=helper.qualify(acceptance.options.archive,None,harness,output=output,
                    timeout=budget.remaining(280,cleanup=True),_retained_fixture=(root,state),
                    _retained_deadlines=(budget.work_end,budget.cleanup_end))
            except Exception as error:
                acceptance.report['release_evidence_transport_failure']={
                    'error':str(error),'returncode':getattr(error,'returncode',None),
                    'stderr_tail':getattr(error,'stderr_tail',None)}
                if (output/'report.json').exists():merge_report(read_retained_report(output/'report.json'))
                raise
            report=read_retained_report(output/'report.json');merge_report(report)
            caps=report.get('parent_capabilities',{})
            acceptance.check('retained evidence transport has zero capabilities and uses original shared deadlines',
                set(caps)=={'CapEff','CapPrm','CapBnd'} and all(int(value,16)==0 for value in caps.values())
                and report.get('release_deadline',{}).get('work_end')==budget.work_end
                and report.get('release_deadline',{}).get('cleanup_end')==budget.cleanup_end)
            acceptance.report['release_evidence_transport_inventory']=result['inventory']
            product=report['product_acceptance']
            acceptance.check('retained transport result has consistent preservation assertions',
                all(assertion['passed'] for assertion in product['assertions'])
                and type(product.get('complete')) is bool
                and isinstance(product.get('unqualified'),list)
                and all(isinstance(value,str) for value in product['unqualified'])
                and product['complete']==(not product['unqualified']))
            if product['complete']:
                receipt=product.get('release_evidence_preservation',{})
                acceptance.check('retained transport binds complete preservation of the original signed run and log',
                    receipt.get('complete') is True and receipt.get('project_bytes_restored') is True
                    and isinstance(receipt.get('run_id'),str) and bool(receipt['run_id'])
                    and isinstance(receipt.get('log_ref'),str) and bool(receipt['log_ref'])
                    and receipt.get('snapshots')==['before-install','after-install','after-update','after-remove'])
            return product['unqualified']
    finally:
        with budget.operation(budget.remaining(cleanup=True),cleanup=True):
            fixture.guard()
            if any(hashlib.sha256(read_release_source(ROOT/'scripts'/name)).hexdigest()!=hashes[name] for name in names):
                raise RuntimeError('Retained acceptance source or helper changed during transport')


def packaging_transport_limit(report, preservation, archive_sha256):
    """Classify one measured fixture limit without weakening release criteria.

    The original release criterion covers source-free installation, upgrade,
    and removal. Configured execution belongs to the evidence and pilot gates.
    This classification supplies no execution or general-availability proof.
    """
    recipient=report.get('recipient',{})
    environment=report.get('environment',{})
    inventory=report.get('nested_inventory',{})
    namespace=recipient.get('recipient_namespace',{})
    expected_probe={'probe_exit_code':1,'stderr':'bwrap: setting up uid map: Operation not permitted\n',
                    'configured_check_executed':False}
    expected_caps={name:'0000000000000000' for name in ('CapEff','CapPrm','CapBnd')}
    if not (
        report.get('status')=='partial' and recipient.get('status')=='passed'
        and bool(report.get('assertions')) and report['assertions']==recipient.get('assertions')
        and all(isinstance(name,str) for name in report['assertions'])
        and report.get('archive_sha256')==archive_sha256
        and recipient.get('upgrade_archive_sha256')==archive_sha256
        and PACKAGING_EXECUTION_LIMIT in report.get('unqualified',[])
        and PACKAGING_EXECUTION_LIMIT in recipient.get('limitations',[])
        and environment.get('transport')=='fresh rootless mapped-root namespace'
        and environment.get('guest_euid')==0 and environment.get('invoker_euid')==1000
        and environment.get('privileged') is False and environment.get('product_source_visible') is False
        and environment.get('host_home_visible') is False
        and inventory.get('worktree_visible') is False and inventory.get('host_home_visible') is False
        and recipient.get('recipient_capabilities')==expected_caps
        and namespace.get('euid')==0 and namespace.get('uid_map')==[[0,1000,1]]
        and namespace.get('gid_map')==[[0,1000,1]]
        and recipient.get('nested_sandbox')==expected_probe
        and recipient.get('no_configured_checks_executed') is True
        and preservation.get('complete') is True and preservation.get('project_bytes_restored') is True
        and preservation.get('private_records_moved_or_copied') is False
        and preservation.get('approvals_or_checks_executed') is False
        and preservation.get('snapshots')==['before-install','after-install','after-update','after-remove']
        and isinstance(preservation.get('run_id'),str) and bool(preservation['run_id'])
        and isinstance(preservation.get('log_ref'),str) and bool(preservation['log_ref'])
    ):
        return None
    return {'limitation':PACKAGING_EXECUTION_LIMIT,
            'scope':'source-free packaging fixture only; original release acceptance criteria unchanged',
            'nested_sandbox':recipient['nested_sandbox'],
            'required_execution_gates':['evidence-integrity','standard-codex-pilot'],
            'does_not_qualify_configured_execution':True,
            'does_not_qualify_ordinary_uid1000_recipient_execution':True,
            'does_not_qualify_general_availability':True}


def release_distribution(acceptance, directory: Path):
    """Main runner behavioral interface; never turns partial coverage green."""
    budget=Deadline(getattr(acceptance,'started_at',None))
    acceptance.report['release_deadline']={'work_seconds':210,'total_seconds':295,'cleanup_reserve_seconds':85}
    archive = acceptance.options.archive
    if archive is None:
        acceptance.report['unqualified'] = ['Release distribution requires an exact --archive input; source-only development does not qualify a release.']
        return
    acceptance.artifact('release_recipient_harness',ROOT/'scripts/plugin-recipient-qualify.py')
    acceptance.artifact('release_nested_recipient_module',ROOT/'scripts/plugin-sandbox-recipient.py')
    old_archive=getattr(acceptance.options,'recipient_old_archive',None)
    if old_archive is not None:acceptance.artifact('release_old_archive',old_archive)
    report = qualify(archive, directory / 'release-recipient',budget=budget,old_archive=old_archive)
    acceptance.report['release_recipient'] = report
    for name in report['assertions']:
        acceptance.check('recipient: ' + name, True)
    remaining=list(report['unqualified'])
    if report['status']=='partial' and report['assertions']:
        preservation=mapped_in_place_evidence_preservation(
            acceptance,directory/'release-evidence-preservation',
            getattr(acceptance.options,'evidence_fixture_root',None),
            getattr(acceptance.options,'evidence_fixture_state',None),budget=budget)
        if not preservation:
            # These limitations describe the clean fixture, which deliberately
            # receives no approvals/evidence copies. The separate live retained
            # fixture provides the missing preservation proof.
            remaining=[reason for reason in remaining if reason not in EVIDENCE_PRESERVATION_LIMITS]
            transport_limit=packaging_transport_limit(report,
                acceptance.report.get('release_evidence_preservation',{}),acceptance.report['archive']['sha256'])
            if transport_limit is not None:
                # Keep the original recipient report, probe and limitations
                # intact. Only this measured transport limitation is outside
                # the release criterion; unknown limits remain unmet gates.
                acceptance.report['release_transport_limits']=[transport_limit]
                remaining=[reason for reason in remaining if reason!=PACKAGING_EXECUTION_LIMIT]
        remaining.extend(preservation)
    acceptance.report['unqualified']=remaining


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--container', default=CONTAINER)
    options = parser.parse_args()
    try:
        report = qualify(options.archive, options.output_directory, options.container)
    except Exception as error:
        report = {'status': 'failed', 'complete': False, 'error': str(error)}
    payload = json.dumps(report, indent=2) + '\n'
    (options.output_directory / 'report.json').write_text(payload)
    print(payload, end='')
    return 1 if report['status'] == 'failed' else (0 if report['complete'] else 2)


if __name__ == '__main__':
    raise SystemExit(main())
