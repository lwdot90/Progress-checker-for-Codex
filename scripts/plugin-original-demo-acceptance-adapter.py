#!/usr/bin/python3
"""OFF-default standalone evidence observer; no preparation or host selector.

Binding this command changes the exact evidence-integrity check definition and
requires separate CAS plan reconciliation and human CLI approval. Those binder
and validator changes are not implemented here. All eight criteria stay intact;
release preservation, primary pilot and dedicated plan coverage are separate.
"""
import argparse
import contextlib
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import tarfile
import time
import types

ROOT = Path(__file__).resolve().parent.parent
ARCHIVE_ARG = '.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz'
ARCHIVE_SHA = '404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
TRUST = 'explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime'
PREFIX = 'progress-checker-0.2.1-dev-linux-x86_64'
SOURCES = {
    'plugin-original-demo-collector.py': '54847b3acd43a8a87199d5e1f0793f1c6b8a731e2464d14e42f11352439cdb82',
    'plugin-original-demo-activate.py': 'b87d9ea01917745b15dad663afa67e126f70a574764d648b1e8ab856b45f2bac',
    'plugin-original-demo-observer.py': '304ac026a10d2290cbc12fed922456a3ac61de3449a3d03d9b948d151d44793d',
    'plugin-original-demo-raw.py': 'e61a08643d6c3cb37941c3a328f6d460277d2df23e8ab682d2ca4188dad9dac8',
    'plugin-original-demo-lifecycle.py': '1aa5036b06bb3c2cf54afccbc3065c67b51ca830b1d3e45ccc83e3129da3631d',
    'plugin-evidence-acceptance.py': 'bb4b6e9e761836bc33f4c42e70c5a7c7b204558783e5ebdd9b2a56d5077d6aeb',
    'plugin-acceptance.py': 'ad1fc66caa841211d6f485832be4a602ac5c1a00743b5c42aefdbdd6f6ff1d99',
}
RUNTIME = {
    'checker-plugin': '82fb1e7cef3172e465f33fec54d4d7be4f799c66193b5dd8f9b989689009fcaa',
    'progress-checker': '9ece1092eba4232a3c66c745d90c7d62df5aaa25a3587a9363c6fe142c830d99',
    'progress-checker-mcp': '6be43b4c12d46555d6443d2619bd15e1dd1754f297781f0fa5c0059bf5c79e7a',
}
FLAGS = ('--archive', '--demo-attestation', '--demo-attestation-sha256', '--demo-readiness')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    def floating(value):
        result = float(value)
        require(math.isfinite(result), 'Nonfinite JSON')
        return result
    return json.loads(data, object_pairs_hook=pairs, parse_float=floating,
                      parse_constant=lambda _: require(False, 'Nonfinite JSON'))


def bounded(path, limit, private=False):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and path.resolve(strict=True) == path,
            'Canonical absolute input required')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                    and before.st_nlink == 1 and not before.st_mode & 0o022
                    and before.st_size <= limit, 'Unsafe bounded regular input')
            if private:
                directory = os.fstat(parent)
                require(path.is_relative_to(ROOT / '.local') and directory.st_uid == os.getuid()
                        and stat.S_IMODE(directory.st_mode) == 0o700
                        and stat.S_IMODE(before.st_mode) == 0o600, 'Private public registration required')
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
                             s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            require(len(data) == before.st_size and key(before) == key(after) == key(current),
                    'Input changed during read')
            return data
    finally:
        os.close(parent)


def argv_for(attestation, digest, readiness):
    return ['/usr/bin/python3', 'scripts/plugin-original-demo-acceptance-adapter.py',
            '--archive', ARCHIVE_ARG, '--demo-attestation', str(attestation),
            '--demo-attestation-sha256', digest, '--demo-readiness', str(readiness)]


def definition_guard(config, expected):
    checks = config.get('checks')
    require(type(checks) is list, 'Configured checks required')
    selected = [value for value in checks if value.get('id') == 'evidence-integrity']
    require(len(selected) == 1, 'Exactly one evidence-integrity definition required')
    check = selected[0]
    require(check.get('argv') == expected and check.get('cwd') == '.'
            and check.get('kind') == 'test' and type(check.get('timeout_seconds')) is int
            and check['timeout_seconds'] == 300
            and type(config.get('execution', {}).get('max_parallel')) is int
            and config['execution']['max_parallel'] == 1,
            'Exact approved evidence observer command/execution shape differs')


def archive_guard(data):
    require(sha(data) == ARCHIVE_SHA, 'Exact404 archive required')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = archive.getmembers()
        require(len(members) <= 4096 and len({m.name for m in members}) == len(members),
                'Bounded unique archive inventory required')
        for name, expected in RUNTIME.items():
            selected = [m for m in members if m.name == PREFIX + '/plugin/bin/' + name]
            require(len(selected) == 1 and selected[0].isfile()
                    and 0 < selected[0].size <= 32 * 1024 * 1024, 'Exact regular archived runtime required')
            with archive.extractfile(selected[0]) as stream:
                content = stream.read(32 * 1024 * 1024 + 1)
            require(len(content) == selected[0].size and sha(content) == expected,
                    'Actual archive runtime bytes differ')


def registration_guard(meta, path):
    require(meta.get('mode') == 'original-demo' and meta.get('trust_policy') == TRUST
            and meta.get('root') == str(ROOT / '.local/checker-demo/session-c5c6vsyz/project')
            and meta.get('state') == str(ROOT / '.local/checker-demo/session-c5c6vsyz/state')
            and meta.get('archive_sha256') == ARCHIVE_SHA, 'Fixed reviewed registration differs')
    require(meta.get('module_hashes') == {str(ROOT / 'scripts' / n): h for n, h in SOURCES.items()},
            'Exact reviewed seven-source roster differs')
    prefix = path.parent / 'extracted' / PREFIX / 'plugin/bin'
    require(meta.get('runtime_files') == {str(prefix / n): h for n, h in RUNTIME.items()},
            'Exact registered runtime/archive inventory differs')


def result_guard(result):
    require(type(result) is dict and result.get('complete') is True
            and result.get('qualification_possible') is True and result.get('status') == 'passed'
            and type(result.get('remaining_unqualified')) is list and not result['remaining_unqualified'],
            'Fresh observer remains failed or unqualified')
    identity = result.get('live_identity', {})
    require(identity.get('policy') == TRUST
            and identity.get('hidden_pid_source_independently_verified') is False
            and identity.get('kernel_peer_lifetime_live') is True, 'Reviewed trust disclosure missing')


@contextlib.contextmanager
def deadline(seconds=120):
    """Absolute adapter budget, including archive/roster reads and consumption."""
    started = time.monotonic()
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    def expired(_signum, _frame):
        raise TimeoutError('Standalone evidence observer absolute budget expired')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(seconds, previous_timer[0]) if previous_timer[0] else seconds)
    try:
        yield lambda: require(time.monotonic() - started < seconds, 'Adapter deadline expired')
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0]:
            signal.setitimer(signal.ITIMER_REAL, max(.000001, previous_timer[0] - (time.monotonic() - started)), previous_timer[1])


def run(options):
    path, readiness = Path(options.demo_attestation), Path(options.demo_readiness)
    require(re.fullmatch('[0-9a-f]{64}', options.demo_attestation_sha256) is not None,
            'Exact lowercase immutable SHA required')
    require(str(options.archive) == ARCHIVE_ARG and path != readiness
            and path.parent == readiness.parent and path.name == 'attestation.json'
            and readiness.name == 'readiness.json', 'Exact archive/registration arguments required')
    with deadline() as clock:
        adapter_path = ROOT / 'scripts/plugin-original-demo-acceptance-adapter.py'
        adapter_bytes = bounded(adapter_path, 8 * 1024 * 1024)
        archive_path = ROOT / ARCHIVE_ARG
        archive_bytes = bounded(archive_path, 64 * 1024 * 1024)
        archive_guard(archive_bytes)
        original = bounded(path, 1024 * 1024, True)
        require(sha(original) == options.demo_attestation_sha256, 'Literal immutable SHA differs')
        registration_guard(strict(original), path)
        config_path = ROOT / '.progress-checker/config.json'
        config_bytes = bounded(config_path, 1024 * 1024)
        job = getattr(options, 'live_job', None)
        if job is not None:
            config = strict(config_bytes)
            definitions = [check for check in config['checks'] if check['id'] == 'evidence-integrity']
            require(len(definitions) == 1, 'Single stable evidence definition required')
            job.definition(definitions[0])
            require(job.value['attestation_path'] == str(path)
                    and job.value['sha256'] == options.demo_attestation_sha256
                    and job.value['readiness_path'] == str(readiness), 'Actual evidence job differs from stable selection')
            definition_guard(config, definitions[0]['argv'])
        else:
            definition_guard(strict(config_bytes), argv_for(path, options.demo_attestation_sha256, readiness))
        buffers = {name: bounded(ROOT / 'scripts' / name, 8 * 1024 * 1024) for name in SOURCES}
        require(all(sha(buffers[n]) == h for n, h in SOURCES.items()), 'Reviewed source buffers changed')
        module_path = ROOT / 'scripts/plugin-original-demo-observer.py'
        observer = types.ModuleType('fresh_original_demo_observer')
        observer.__file__ = str(module_path)
        exec(compile(buffers[module_path.name], str(module_path), 'exec'), observer.__dict__)
        clock()
        result = observer.consume(path, options.demo_attestation_sha256, readiness)
        result_guard(result)
        require(result['live_identity'].get('approved_attestation_sha256') == options.demo_attestation_sha256,
                'Fresh observer immutable binding differs')
        require(bounded(config_path, 1024 * 1024) == config_bytes
                and bounded(path, 1024 * 1024, True) == original
                and bounded(adapter_path, 8 * 1024 * 1024) == adapter_bytes
                and sha(bounded(archive_path, 64 * 1024 * 1024)) == ARCHIVE_SHA
                and all(sha(bounded(ROOT / 'scripts' / n, 8 * 1024 * 1024)) == h for n, h in SOURCES.items()),
                'Accepted command/source/archive changed after fresh consumption')
        clock()
        return {'status': 'passed', 'complete': True, 'milestone': 'evidence-integrity',
                'observation': result, 'archive_sha256': ARCHIVE_SHA,
                'source_hashes': SOURCES, 'approval_created': False,
                'artifacts': {str(adapter_path): sha(adapter_bytes), str(path): sha(original),
                              str(archive_path): ARCHIVE_SHA},
                'host_work_started_or_activated': False,
                'coverage': 'Fresh original demo18 only; release preservation, primary pilot and dedicated plan remain separate.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in FLAGS:
        parser.add_argument(flag, required=True)
    tokens = list(argv) if argv is not None else __import__('sys').argv[1:]
    require(len(tokens) == 8 and all(tokens[i] in FLAGS for i in range(0, 8, 2))
            and {tokens[i] for i in range(0, 8, 2)} == set(FLAGS), 'Exact nonduplicate flag/value argv required')
    options = parser.parse_args(tokens)
    try:
        result = run(options)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except Exception as exc:
        print(json.dumps({'status': 'failed', 'complete': False, 'error': type(exc).__name__ + ': ' + str(exc),
                          'approval_created': False, 'host_work_started_or_activated': False}, indent=2))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
