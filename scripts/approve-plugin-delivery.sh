#!/usr/bin/env bash
# Human-only approval helper; never supplies a confirmation or runs a check.
set -euo pipefail
project_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ ! -t 0 || ! -t 1 ]]; then
    printf 'Run this helper yourself in an interactive terminal.\n' >&2
    exit 1
fi
if [[ $# -ne 1 ]]; then
    printf 'Usage: bash scripts/approve-plugin-delivery.sh CHECK_ID\n' >&2
    printf 'Idle exact project plugin launchers will disconnect; review and approve one exact check.\n' >&2
    exit 1
fi
case "$1" in
    plan-definition|plugin-package|service-lifecycle|plan-submission|agent-workflow|evidence-integrity|release-distribution|standard-codex-pilot) ;;
    *) printf 'Unknown delivery check: %s\n' "$1" >&2; exit 1 ;;
esac
exec /usr/bin/python3 - "$project_directory" "$1" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import time

root = Path(sys.argv[1]).resolve(strict=True)
check_id = sys.argv[2]
if root != Path('/home/luis/progress-checker'):
    raise SystemExit('This development helper is bound to the reviewed primary repository.')
selector = hashlib.sha256(os.fsencode(root)).hexdigest()[:12]
codex_home = Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex')))
if codex_home != Path('/home/luis/.codex'):
    raise SystemExit('Use the reviewed primary Codex profile for delivery approval.')
checker = codex_home / 'plugins/cache' / f'progress-local-{selector}' / 'progress-checker/0.2.1-dev/bin/progress-checker'

def opened(path, limit):
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = next_fd
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_size > limit or before.st_mode & 0o022:
        os.close(fd)
        raise SystemExit('Expected a bounded owned installed file.')
    data = bytearray()
    while len(data) <= limit:
        chunk = os.read(fd, min(65536, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    after = os.fstat(fd)
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if len(data) > limit or identity(before) != identity(after):
        os.close(fd)
        raise SystemExit('Installed file changed during bounded validation.')
    return fd, bytes(data)

def process_info(pid):
    proc = Path('/proc') / str(pid)
    try:
        owner = proc.stat().st_uid
        if owner != os.getuid():
            return None
        before = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        argv = (proc / 'cmdline').read_bytes().decode().split('\0')[:-1]
        after = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        if before[19] != after[19] or int(before[1]) != int(after[1]):
            raise SystemExit('Process identity changed during public census.')
        return {'pid':pid, 'uid':owner, 'starttime':before[19], 'ppid':int(before[1]),
                'state':after[0], 'argv':argv}
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, IndexError, ValueError) as error:
        raise SystemExit('Cannot establish owned public process identity: '+str(error))

def census():
    return [info for proc in Path('/proc').iterdir() if proc.name.isdecimal()
            and (info := process_info(int(proc.name))) is not None
            and info['state'] not in {'Z','X','x'}]

def bound_actor(info, root, state):
    argv = info['argv']
    try:
        return argv[argv.index('--root')+1] == str(root) and argv[argv.index('--state-dir')+1] == str(state)
    except (ValueError, IndexError):
        return False

def exact_launcher(info, launcher, root, state):
    return info['uid'] == os.getuid() and info['state'] not in {'Z','X','x'} and info['argv'] == [
        '/usr/bin/python3',str(launcher),'--root',str(root),'--state-dir',str(state)]

def idle_status(binary_fd, checker, root, state, deadline):
    remaining = deadline-time.monotonic()
    if remaining <= 0:
        raise SystemExit('Idle disconnect deadline expired.')
    try:
        result = subprocess.run([str(checker),'--root',str(root),'--state-dir',str(state),'status'],
            executable='/proc/self/fd/'+str(binary_fd), pass_fds=(binary_fd,),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=min(5,remaining), check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SystemExit('Public status unavailable or timed out; nothing will be disconnected: '+str(error))
    if len(result.stdout)+len(result.stderr) > 4*1024*1024:
        raise SystemExit('Public status exceeds the finite bound.')
    if result.returncode != 0:
        error = result.stderr.decode(errors='replace').strip()
        unavailable = error.startswith('SERVICE_UNAVAILABLE:') or (
            error.startswith('Shared service unavailable:') and
            any(reason in error for reason in ('No such file or directory (os error 2)', 'Connection refused (os error 111)')))
        live_service = any(bound_actor(info,root,state) and 'serve' in info['argv'] for info in census())
        if unavailable and not result.stdout.strip() and not live_service:
            return
        raise SystemExit('Unknown public status or live unavailable service; refuse disconnect.')
    def pairs(items):
        value = {}
        for key,item in items:
            if key in value:raise ValueError('Duplicate status field')
            value[key] = item
        return value
    try:
        status = json.loads(result.stdout,object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite status')))
        latest = status['latest']
        if type(status) is not dict or type(latest) is not dict or any(
            type(value) is not dict or value.get('execution_state') != 'finished' for value in latest.values()):
            raise ValueError('Queued, running or unknown latest execution state')
    except (ValueError, KeyError, TypeError) as error:
        raise SystemExit('Public status is not safely idle; refuse disconnect: '+str(error))

def disconnect_idle(binary_fd, checker, launcher, root, state):
    deadline = time.monotonic()+15
    idle_status(binary_fd,checker,root,state,deadline)
    owned = {info['pid']:info for info in census() if exact_launcher(info,launcher,root,state)}
    handles = {}
    try:
        for pid, before in owned.items():
            handles[pid] = os.pidfd_open(pid,0)
            current = process_info(pid)
            if current is None or not exact_launcher(current,launcher,root,state) or any(
                current[key] != before[key] for key in ('pid','uid','starttime','ppid','argv')):
                raise SystemExit('Launcher identity raced or was reused; refuse disconnect.')
        idle_status(binary_fd,checker,root,state,deadline)
        current = {info['pid']:info for info in census() if exact_launcher(info,launcher,root,state)}
        if set(current) != set(owned) or any(current[pid]['starttime'] != owned[pid]['starttime'] for pid in current):
            raise SystemExit('New or changed launcher raced approval; refuse disconnect.')
        print('Gracefully disconnecting '+str(len(handles))+' idle exact project launcher(s); keeping parent Codex running.',flush=True)
        poll = select.poll()
        for pid,handle in handles.items():
            info = process_info(pid)
            if info is None or not exact_launcher(info,launcher,root,state) or any(
                info[key] != owned[pid][key] for key in ('pid','uid','starttime','ppid','argv')):
                raise SystemExit('Launcher identity changed before PIDfd signal.')
            live = select.poll();live.register(handle,select.POLLIN|select.POLLHUP|select.POLLERR)
            if live.poll(0) or time.monotonic() >= deadline:
                raise SystemExit('Exact launcher exited or disconnect deadline expired before signal.')
            signal.pidfd_send_signal(handle,signal.SIGTERM,None,0)
            poll.register(handle,select.POLLIN|select.POLLHUP|select.POLLERR)
        pending = set(handles.values())
        while pending and time.monotonic() < deadline:
            for handle,events in poll.poll(max(1,int(min(.2,deadline-time.monotonic())*1000))):
                if events & select.POLLERR:raise SystemExit('Unknown launcher PIDfd drain error.')
                if events & select.POLLIN:pending.discard(handle)
        while time.monotonic() < deadline:
            actors = [info for info in census() if bound_actor(info,root,state)]
            if time.monotonic() >= deadline:
                break
            if not pending and not actors:
                print('Disconnected '+str(len(handles))+' idle exact project plugin launcher(s); parent Codex remains running.',flush=True)
                return
            if any(exact_launcher(info,launcher,root,state) and info['pid'] not in owned for info in actors):
                raise SystemExit('New launcher raced graceful cleanup; refuse approval.')
            time.sleep(min(.1,max(0,deadline-time.monotonic())))
        raise SystemExit('Graceful disconnect is incomplete or unknown; no forced kill or approval.')
    finally:
        for handle in handles.values():os.close(handle)

binary_fd, binary_bytes = opened(checker, 32 * 1024 * 1024)
binary_info = os.fstat(binary_fd)
if not binary_info.st_mode & stat.S_IXUSR:
    raise SystemExit('Reviewed installed checker must be executable by its owner.')
if hashlib.sha256(binary_bytes).hexdigest() != '9ece1092eba4232a3c66c745d90c7d62df5aaa25a3587a9363c6fe142c830d99':
    raise SystemExit('Installed checker differs from the reviewed delivery candidate; finish the package update first.')
launcher = checker.parent / 'checker-plugin'
launcher_fd, launcher_bytes = opened(launcher, 1024*1024)
if hashlib.sha256(launcher_bytes).hexdigest() != '82fb1e7cef3172e465f33fec54d4d7be4f799c66193b5dd8f9b989689009fcaa':
    os.close(launcher_fd)
    raise SystemExit('Installed launcher differs from the reviewed candidate; refuse disconnect.')
os.close(launcher_fd)
binding_path = checker.parent.parent / 'mcp.json'
binding_fd, binding_bytes = opened(binding_path, 65536)
os.close(binding_fd)
binding = json.loads(binding_bytes)['mcpServers']['progress_checker']
args = binding['args']
if args != ['--root', str(root), '--state-dir', '/home/luis/.local/share/progress-checker'] or binding['command'] != './bin/checker-plugin':
    raise SystemExit('Installed repository binding differs; review installation before approval.')
state = Path(args[3]).resolve(strict=True)
if state != Path('/home/luis/.local/share/progress-checker'):
    raise SystemExit('Resolved checker state differs from the reviewed primary state.')
# Reject directory aliases and shared/unowned state before opening approval CLI.
state_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
try:
    for component in state.parts[1:]:
        next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state_fd)
        os.close(state_fd)
        state_fd = next_fd
    state_info = os.fstat(state_fd)
    if state_info.st_uid != os.getuid() or stat.S_IMODE(state_info.st_mode) != 0o700:
        raise SystemExit('Reviewed checker state must be owned and private (0700).')
finally:
    os.close(state_fd)
if state == root or root in state.parents or state in root.parents:
    raise SystemExit('Checker state must be outside the worktree.')
disconnect_idle(binary_fd,checker,launcher,root,state)
print('The checker will display the exact command and ask for your confirmation. This helper does not answer it or run the check.', flush=True)
# Restore the human terminal: Python source arrived through stdin, not a prompt.
terminal = os.open('/dev/tty', os.O_RDONLY)
os.dup2(terminal, 0)
os.close(terminal)
if os.execve not in os.supports_fd:
    raise SystemExit('Verified-descriptor execution is unavailable; refusing approval.')
current_binary = os.fstat(binary_fd)
identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
if identity(current_binary) != identity(binary_info) or current_binary.st_mode != binary_info.st_mode:
    raise SystemExit('Verified checker descriptor changed before execution.')
os.execve(binary_fd, [str(checker), '--root', str(root), '--state-dir', str(state), 'approve', check_id], os.environ.copy())
PY
