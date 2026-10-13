#!/usr/bin/env python3
"""Fresh source-free recipient qualification usable inside the fixed checker sandbox.

Only the selected archives, standalone harness, native Codex ELF, and whitelisted
system runtime are visible in the nested namespace. No approval or configured
check is performed. This is a development qualification helper, not a grant.
The separate fixed-retained-demo mode exposes that signed state in place and
does not claim to be a fresh source-free recipient.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import tempfile
import time

CODEX = Path('/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex')
OLD_SHA256 = 'fbf12375255af78ff30b042a9f9938ecccec5e03d7e8504042dac1872b0f646a'
RETAINED_DEMO = (Path('/home/luis/progress-checker/.local/checker-demo/session-c5c6vsyz/project'),
                 Path('/home/luis/progress-checker/.local/checker-demo/session-c5c6vsyz/state'))


def digest(path: Path, limit: int = 64 * 1024 * 1024) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError(f'Expected bounded regular input: {path}')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dynamic_libraries(executables: list[Path], *, deadline: float | None = None) -> dict[str, Path]:
    """Resolve the dynamic dependencies of the fixed system runtime only."""
    libraries = {}
    pending = list(executables)
    visited = set()
    while pending:
        executable = pending.pop()
        resolved = executable.resolve(strict=True)
        if resolved in visited:
            continue
        visited.add(resolved)
        remaining = 10 if deadline is None else min(10, deadline - time.monotonic())
        if remaining <= 0:
            raise TimeoutError('Fresh recipient bootstrap deadline exceeded')
        result = subprocess.run(['/usr/bin/ldd', str(resolved)], capture_output=True, text=True, timeout=remaining)
        if result.returncode:
            if 'not a dynamic executable' in result.stderr or 'statically linked' in result.stdout:
                continue
            raise RuntimeError(f'Cannot inventory runtime dependencies: {resolved}: {result.stderr}')
        if 'not found' in result.stdout:
            raise RuntimeError(f'Missing runtime dependency: {result.stdout}')
        for value in re.findall(r'(?:=>\s+)?(/[^\s()]+)', result.stdout):
            source = Path(value).resolve(strict=True)
            if not source.is_relative_to('/usr/lib64'):
                raise RuntimeError(f'Unexpected system library: {source}')
            target = value.replace('/lib64/', '/usr/lib64/', 1) if value.startswith('/lib64/') else value
            libraries[target] = source
            pending.append(source)
    return libraries


def qualify(archive: Path, old_archive: Path | None, harness: Path, *, output: Path | None = None,
            codex: Path = CODEX, timeout: int = 240, _public_fixture: tuple[Path, Path] | None = None,
            _retained_fixture: tuple[Path, Path] | None = None,
            _retained_deadlines: tuple[float, float] | None = None) -> dict:
    """Run the actual fresh old→new native recipient workflow; return its report.

    Caller passes immutable fingerprinted archive inputs. Reports are generated
    by the current run; cached qualification reports are never consumed.
    """
    if not 0 < timeout <= 280:
        raise ValueError('Recipient timeout must be positive and at most 280 seconds including bootstrap')
    deadline = time.monotonic() + timeout
    work_deadline = deadline
    if _retained_fixture is not None:
        if _public_fixture is not None or _retained_deadlines is None:
            raise ValueError('Retained demo transport requires its original deadlines and excludes public fixtures')
        if (len(_retained_deadlines) != 2
                or any(type(value) not in (float, int) or not math.isfinite(value) for value in _retained_deadlines)):
            raise ValueError('Retained demo deadlines must be finite monotonic endpoints')
        work_end, cleanup_end = _retained_deadlines
        if not time.monotonic() < work_end < cleanup_end or cleanup_end-work_end != 85:
            raise ValueError('Retained demo transport cannot reset or extend the release deadline')
        work_deadline = min(deadline, work_end)
        deadline = min(deadline, cleanup_end)
        selected = tuple(Path(path) for path in _retained_fixture)
        if selected != RETAINED_DEMO or any(path.resolve(strict=True) != path for path in selected):
            raise ValueError('Retained transport accepts only the exact canonical previously approved demo paths')
        for path in selected:
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise ValueError('Retained demo paths must be real invoking-user-owned directories')
        if stat.S_IMODE(selected[1].lstat().st_mode) != 0o700:
            raise ValueError('Retained demo state must remain private mode0700')
        _retained_fixture = selected
    elif _retained_deadlines is not None:
        raise ValueError('Retained deadlines require the exact retained fixture')
    def check_deadline(*, cleanup=False):
        if time.monotonic() >= (deadline if cleanup else work_deadline):
            raise TimeoutError('Fresh recipient qualification deadline exceeded (including bootstrap)')
    check_deadline()
    if _public_fixture is not None:
        root, state = (Path(p).resolve(strict=True) for p in _public_fixture)
        if root == state or root.is_relative_to(state) or state.is_relative_to(root):
            raise ValueError('Selected fixture and private state must be separate')
        if not state.is_dir() or state.stat().st_uid != os.getuid() or stat.S_IMODE(state.stat().st_mode) != 0o700:
            raise ValueError('Selected public fixture state must be invoking-user-owned mode0700 directory')
        if not (root/'.public-runtime-fixture').is_file() or any(state.iterdir()):
            raise ValueError('Opt-in functional wrapper accepts only a marked public fixture and initially empty state')
        _public_fixture = root, state
    archive, harness, codex = map(Path, (archive, harness, codex))
    old_archive = None if old_archive is None else Path(old_archive)
    sha = digest(archive)
    if old_archive is None and _public_fixture is None and _retained_fixture is None:
        raise ValueError('Source-free recipient upgrade qualification requires the pinned older archive')
    if old_archive is not None and digest(old_archive) != OLD_SHA256:
        raise ValueError('Older archive does not match the pinned genuine package')
    harness_sha = digest(harness)
    codex_sha = digest(codex, 512 * 1024 * 1024)
    if not codex.resolve().is_relative_to('/usr'):
        raise ValueError('Native Codex must be a system /usr runtime')
    if os.getuid() != 1000:
        raise RuntimeError('Fedora recipient qualification currently requires unprivileged uid 1000')
    output = Path(output) if output is not None else Path(tempfile.mkdtemp(prefix='pc-sandbox-report-'))
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or any(output.iterdir()):
        raise ValueError('Output must be an empty dedicated report directory')
    output = output.resolve(strict=True)
    check_deadline()
    # Short paths keep the ordinary Unix socket endpoint within its documented
    # limit. The fixed outer sandbox intentionally provides no host /tmp mount.
    with tempfile.TemporaryDirectory(prefix='pc-recipient-input-') as temporary:
        inputs = Path(temporary)
        (inputs/'passwd').write_text('recipient:x:0:0:Rootless namespace recipient:/r:/bin/bash\n')
        (inputs/'group').write_text('recipient:x:0:\n')
        attestation = {'invoker_euid': os.geteuid(), 'invoker_egid': os.getegid(),
                       'invoker_uid_map': Path('/proc/self/uid_map').read_text(),
                       'invoker_gid_map': Path('/proc/self/gid_map').read_text(),
                       'copied_read_only_executables': True, 'product_source_visible': False,
                       'product_checkout_visible': False, 'selected_fixture_source_visible': False,
                       'host_home_visible': False}
        if _public_fixture is not None:
            attestation.update(test_mode='public mapped-root functional fixture',
                               selected_fixture_root=str(_public_fixture[0]),
                               selected_fixture_state=str(_public_fixture[1]),
                               selected_fixture_source_visible=True,
                               capability_scope='sole CAP_SETFCAP in parent and child namespace; not zero-cap payload equivalence')
        if _retained_fixture is not None:
            attestation.update(test_mode='fixed retained demo evidence preservation in place',
                               selected_fixture_root=str(_retained_fixture[0]),
                               selected_fixture_state=str(_retained_fixture[1]),
                               selected_fixture_source_visible=True,
                               retained_signed_state_visible=True,
                               private_records_moved_or_copied=False,
                               host_home_visible=True,unselected_host_home_visible=False,
                               capability_scope='all capabilities dropped; no configured checks executed',
                               host_home_visibility_scope='only the two explicitly selected retained demo paths are mounted')
        rpm_snapshot = inputs/'rpmdb'
        rpm_snapshot.mkdir(mode=0o755)
        rpm_source = Path('/usr/lib/sysimage/rpm/rpmdb.sqlite')
        if rpm_source.is_symlink() or not stat.S_ISREG(rpm_source.stat().st_mode) or rpm_source.stat().st_size > 512 * 1024 * 1024:
            raise RuntimeError('System RPM database is not bounded regular input')
        rpm_metadata = rpm_source.stat()
        rpm_wal = rpm_source.with_name('rpmdb.sqlite-wal')
        wal_before = rpm_wal.stat() if rpm_wal.exists() else None
        if wal_before is not None and (rpm_wal.is_symlink() or not stat.S_ISREG(wal_before.st_mode) or wal_before.st_size):
            raise RuntimeError('OS RPM WAL contains pending changes; stable readonly snapshot unavailable')
        backup_deadline = min(work_deadline, time.monotonic() + 20)
        def backup_progress(status, remaining, total):
            if time.monotonic() > backup_deadline:
                raise TimeoutError('System RPM snapshot deadline exceeded')
        with sqlite3.connect(rpm_source.as_uri()+'?mode=ro&immutable=1', uri=True) as original:
            with sqlite3.connect(rpm_snapshot/'rpmdb.sqlite') as snapshot:
                original.backup(snapshot, pages=4096, progress=backup_progress)
                if snapshot.execute('PRAGMA quick_check').fetchone() != ('ok',):
                    raise RuntimeError('System RPM snapshot integrity check failed')
        def stamp(info):
            return None if info is None else (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        after = rpm_source.stat()
        wal_after = rpm_wal.stat() if rpm_wal.exists() else None
        if stamp(rpm_metadata) != stamp(after) or stamp(wal_before) != stamp(wal_after):
            raise RuntimeError('Actual OS RPM database changed during its readonly backup')
        (rpm_snapshot/'rpmdb.sqlite').chmod(0o644)
        attestation['rpm_snapshot'] = {'origin':str(rpm_source), 'method':'SQLite readonly immutable-source backup, empty WAL and unchanged metadata confirmed',
                                       'sha256': digest(rpm_snapshot/'rpmdb.sqlite', 512*1024*1024),
                                       'snapshot_time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                       'source_metadata': {'inode':rpm_metadata.st_ino,'device':rpm_metadata.st_dev,
                                                           'uid_in_invoking_namespace':rpm_metadata.st_uid,
                                                           'size':rpm_metadata.st_size,'mtime_ns':rpm_metadata.st_mtime_ns,'ctime_ns':rpm_metadata.st_ctime_ns},
                                       'scope':'actual committed OS package inventory snapshot; not live host immutability'}
        (inputs/'invoker.json').write_text(json.dumps(attestation)+'\n')
        command = ['/usr/bin/bwrap', '--unshare-all', '--uid', '0', '--gid', '0', '--cap-drop', 'ALL', '--die-with-parent', '--new-session',
                   '--clearenv', '--setenv', 'PATH', '/usr/local/bin:/usr/bin:/bin',
                   '--setenv', 'HOME', '/r', '--setenv', 'LANG', 'C.UTF-8',
                   '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
                   '--dir', '/usr', '--dir', '/usr/bin', '--dir', '/usr/lib64',
                   '--dir', '/usr/lib64/python3.14', '--dir', '/usr/local/bin',
                   '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib64', '/lib64',
                   '--symlink', 'usr/lib', '/lib', '--proc', '/proc', '--dev', '/dev',
                   '--perms', '1777', '--tmpfs', '/tmp', '--dir', '/r', '--dir', '/d', '--dir', '/inputs']
        if _public_fixture is not None:
            command += ['--cap-add', 'CAP_SETFCAP']
        binaries = [Path('/usr/bin')/name for name in ('python3.14', 'git', 'bash', 'env', 'true', 'false', 'bwrap', 'rpm')]
        attestation['runtime_executable_sha256'] = {}
        for path in binaries:
            check_deadline()
            source = path.resolve(strict=True)
            if not source.is_relative_to('/usr') or source.stat().st_size > 64 * 1024 * 1024:
                raise ValueError('Unexpected or oversized system executable')
            copied = inputs/path.name
            shutil.copyfile(source, copied)
            copied.chmod(0o755)
            source_sha = digest(source)
            if digest(copied) != source_sha or copied.stat().st_uid != os.getuid():
                raise RuntimeError('Copied system executable bytes or owner changed')
            attestation['runtime_executable_sha256'][str(path)] = source_sha
            command += ['--ro-bind', str(copied), str(path)]
        (inputs/'invoker.json').write_text(json.dumps(attestation)+'\n')
        command += ['--symlink', 'python3.14', '/usr/bin/python3', '--symlink', 'bash', '/usr/bin/sh']
        stdlib = Path('/usr/lib64/python3.14')
        for entry in sorted(stdlib.iterdir()):
            if entry.name not in ('site-packages', '__pycache__'):
                command += ['--ro-bind', str(entry), str(entry)]
        libraries = dynamic_libraries(binaries + list((stdlib/'lib-dynload').glob('*.so')), deadline=work_deadline)
        check_deadline()
        for target, source in sorted(libraries.items()):
            command += ['--ro-bind', str(source), target]
        for source, target in [(Path('/usr/libexec/git-core'), '/usr/libexec/git-core'),
                               (Path('/usr/share/git-core'), '/usr/share/git-core'),
                               (Path('/usr/share/terminfo'), '/usr/share/terminfo'),
                               (Path('/usr/lib/rpm'), '/usr/lib/rpm'),
                               (rpm_snapshot, '/usr/lib/sysimage/rpm'),
                               (Path('/usr/lib/os-release'), '/etc/os-release'),
                               (inputs/'passwd', '/etc/passwd'), (inputs/'group', '/etc/group'),
                               (inputs/'invoker.json', '/inputs/invoker.json'),
                               (codex, '/usr/local/bin/codex'), (archive, '/inputs/new.tar.gz'),
                               (old_archive, '/inputs/old.tar.gz'), (harness, '/inputs/qualify.py')]:
            if source is None and target == '/inputs/old.tar.gz' and (_public_fixture is not None or _retained_fixture is not None):
                continue
            command += ['--ro-bind', str(source.resolve(strict=True)), target]
        if _public_fixture is not None:
            for selected in _public_fixture:
                command += ['--bind', str(selected), str(selected)]
        if _retained_fixture is not None:
            for selected in _retained_fixture:
                command += ['--bind', str(selected), str(selected)]
        command += ['--bind', str(output), '/results', '--chdir', '/r', '--', '/usr/bin/python3',
                    '/inputs/qualify.py', '--archive', '/inputs/new.tar.gz', '--sha256', sha,
                    '--base-dir', '/r',
                    '--data-home', '/d', '--output-dir', '/results',
                    '--namespace-mapped-root', '--invoker-attestation', '/inputs/invoker.json']
        if old_archive is not None:
            command += ['--old-archive', '/inputs/old.tar.gz']
        if _public_fixture is not None:
            command += ['--fixture-root', str(_public_fixture[0]), '--fixture-state', str(_public_fixture[1])]
        if _retained_fixture is not None:
            command += ['--fixture-root', str(_retained_fixture[0]), '--fixture-state', str(_retained_fixture[1])]
        inventory = {'archive_sha256': sha, 'old_archive_sha256': OLD_SHA256 if old_archive is not None else None,
                     'harness_sha256': harness_sha, 'codex_sha256': codex_sha,
                     'namespace': 'nested rootless bwrap --unshare-all; guest UID0 maps invoking UID1000',
                     'invoker_attestation': attestation, 'host_home_visible': False,
                     'worktree_visible': _public_fixture is not None or _retained_fixture is not None, 'runtime_mounts': 'curated read-only host OS runtime and immutable actual RPM inventory snapshot; fresh output directory writable', 'system_binaries': [str(p) for p in binaries],
                     'system_library_count': len(libraries), 'no_configured_checks_executed': True}
        if _public_fixture is not None:
            inventory['qualification_scope'] = 'public product-behavior fixture; source-free recipient qualification remains separate'
        if _retained_fixture is not None:
            inventory.update(qualification_scope='fixed retained demo signed-evidence preservation in place; separate from source-free recipient qualification',
                             retained_signed_state_visible=True, private_records_moved_or_copied=False,
                             host_home_visible=True,unselected_host_home_visible=False,
                             selected_fixture_root=str(_retained_fixture[0]), selected_fixture_state=str(_retained_fixture[1]),
                             host_home_visibility_scope=attestation['host_home_visibility_scope'],
                             release_deadlines={'clock':'shared kernel monotonic', 'work_end':work_deadline, 'cleanup_end':deadline})
        (output/'sandbox-inventory.json').write_text(json.dumps(inventory, indent=2)+'\n')
        stdout_path, stderr_path = output/'qualification.stdout', output/'qualification.stderr'
        check_deadline()
        # Retained transport must finish namespace teardown and its caller's
        # fixture/source guards inside the original shared cleanup endpoint.
        supervisor_end = deadline-12 if _retained_fixture is not None else deadline
        with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                       env={'PATH': '/usr/bin:/bin', 'HOME': '/tmp', 'LANG': 'C.UTF-8'},
                                       start_new_session=True)
            try:
                while process.poll() is None:
                    if time.monotonic() >= supervisor_end:
                        raise TimeoutError('Fresh recipient qualification deadline exceeded')
                    if max(stdout_path.stat().st_size, stderr_path.stat().st_size) > 8 * 1024 * 1024:
                        raise RuntimeError('Fresh recipient qualification output limit exceeded')
                    time.sleep(0.1)
            finally:
                if process.poll() is None:
                    # Killing the bwrap PID-namespace supervisor also reaps
                    # descendants that detached into different process groups.
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        remaining = 5 if _retained_fixture is None else min(5,deadline-time.monotonic()-1)
                        if remaining<=0:raise subprocess.TimeoutExpired(command,0)
                        process.wait(timeout=remaining)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        remaining = 5 if _retained_fixture is None else min(5,deadline-time.monotonic()-1)
                        if remaining<=0:raise TimeoutError('Retained namespace teardown shared deadline exceeded')
                        process.wait(timeout=remaining)
                for path in (stdout_path, stderr_path):
                    if path.stat().st_size > 8 * 1024 * 1024:
                        with path.open('r+b') as captured:
                            captured.truncate(8 * 1024 * 1024)
        check_deadline(cleanup=_retained_fixture is not None)
        if process.returncode:
            if _retained_fixture is not None:
                with stderr_path.open('rb') as stderr:
                    stderr.seek(0,os.SEEK_END);stderr.seek(max(0,stderr.tell()-8192))
                    tail=stderr.read(8192).decode('utf-8','replace')
                error=RuntimeError(f'Retained demo transport failed (exit {process.returncode}); stderr: {tail}; logs: {output}')
                error.returncode,error.stderr_tail=process.returncode,tail
                raise error
            raise RuntimeError(f'Fresh source-free recipient failed (exit {process.returncode}); logs: {output}')
        report_path = output/'report.json'
        if report_path.is_symlink() or report_path.stat().st_size > 1024 * 1024:
            raise RuntimeError('Fresh recipient report is not bounded regular output')
        def strict_pairs(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError('Duplicate retained transport report field: '+key)
                value[key] = item
            return value
        report = json.loads(report_path.read_text(), object_pairs_hook=strict_pairs if _retained_fixture is not None else None)
        if report.get('status') != 'passed' or report.get('upgrade_archive_sha256') != sha:
            raise RuntimeError('Fresh recipient report did not qualify the exact supplied archive')
        if old_archive is not None and digest(old_archive) != OLD_SHA256:
            raise RuntimeError('Older qualification package changed during execution')
        if digest(archive) != sha or digest(harness) != harness_sha or digest(codex, 512 * 1024 * 1024) != codex_sha:
            raise RuntimeError('Qualification inputs changed during execution')
        check_deadline(cleanup=_retained_fixture is not None)
        return {'report': report, 'inventory': inventory, 'output_directory': str(output)}


def run_public_fixture(archive: Path, old_archive: Path | None, harness: Path, root: Path, state: Path, *, output: Path) -> dict:
    """Explicit TEST-only mapped-root fixture with namespace-local SETFCAP.

    Requires a newly marked public fixture and empty selected state. Does not
    accept retained approvals or imply zero-cap/nonroot payload equivalence.
    """
    return qualify(archive, old_archive, harness, output=output, _public_fixture=(root,state))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--old-archive', type=Path, required=True)
    parser.add_argument('--harness', type=Path, default=Path(__file__).with_name('plugin-recipient-qualify.py'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--codex', type=Path, default=CODEX)
    args = parser.parse_args()
    print(json.dumps(qualify(args.archive, args.old_archive, args.harness, output=args.output, codex=args.codex), indent=2))


if __name__ == '__main__':
    main()
