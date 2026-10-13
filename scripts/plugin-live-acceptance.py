#!/usr/bin/python3
"""Stable acceptance command selecting a freshly reviewed, one-use live job.

Never prepares or activates a producer, grants approval, or replaces a missing
stream with a saved report. Job manifests select identity, not program behavior.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

ROOT = Path(__file__).resolve().parent.parent
ARCHIVE = '.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz'
OLD_ARCHIVE = '.progress-checker/acceptance-inputs/progress-checker-0.2.0-dev-linux-x86_64-fbf12375255a.tar.gz'
KINDS = {'plan': 'plan-submission', 'pilot': 'standard-codex-pilot', 'evidence': 'evidence-integrity'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate manifest field')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'Nonfinite JSON'))


def bounded(path, limit, private=False):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and path.resolve(strict=True) == path,
            'Canonical nonsymlink path required')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        if private:
            info = os.fstat(parent)
            require(path.is_relative_to(ROOT/'.local') and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o700, 'Private public-job directory required')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                    and before.st_nlink == 1 and not before.st_mode & 0o022
                    and before.st_size <= limit, 'Bounded owned regular file required')
            if private:
                require(stat.S_IMODE(before.st_mode) == 0o600, 'Public-job file mode must be 0600')
            data = stream.read(limit+1)
            after = os.fstat(stream.fileno())
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            require(len(data) <= limit and identity(before) == identity(after), 'Input changed during read')
            return data
    finally:
        os.close(parent)


def command(kind):
    require(kind in KINDS, 'Unknown live job kind')
    result = ['/usr/bin/python3', 'scripts/plugin-live-acceptance.py', '--kind', kind,
              '--job-manifest', '.local/acceptance-jobs/'+kind+'.json', '--archive', ARCHIVE]
    if kind == 'pilot':
        result += ['--recipient-old-archive', OLD_ARCHIVE]
    return result


class Job:
    def __init__(self, kind, manifest):
        self.kind = kind
        expected = ROOT/'.local/acceptance-jobs'/ (kind+'.json')
        self.path = Path(manifest)
        if not self.path.is_absolute():
            self.path = ROOT/self.path
        require(self.path == expected, 'Fixed manifest location required')
        self.bytes = bounded(self.path, 65536, True)
        self.value = strict(self.bytes)
        final = 'output_path' if kind == 'plan' else 'readiness_path'
        require(type(self.value) is dict and set(self.value) == {
            'schema_version', 'kind', 'attestation_path', 'sha256', final}, 'Exact manifest schema required')
        require(type(self.value['schema_version']) is int and self.value['schema_version'] == 1
                and self.value['kind'] == kind and type(self.value['sha256']) is str
                and re.fullmatch('[0-9a-f]{64}', self.value['sha256']), 'Typed fixed job identity required')
        for key in ('attestation_path', final):
            path = Path(self.value[key])
            require(type(self.value[key]) is str and path.is_absolute()
                    and path.is_relative_to(ROOT/'.local') and '..' not in path.parts
                    and path.parent.resolve(strict=True) == path.parent, 'Canonical local job paths required')
        self.attestation = Path(self.value['attestation_path'])
        require(self.attestation.name == 'attestation.json', 'Fixed attestation filename required')
        self.immutable = bounded(self.attestation, 1024*1024, True)
        require(digest(self.immutable) == self.value['sha256'], 'Immutable registration digest differs')
        self.metadata = strict(self.immutable)
        require(self.metadata['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'Registration belongs to another boot; prepare and review a fresh job')
        if kind != 'plan':
            require(Path(self.value[final]) == self.attestation.with_name('readiness.json'),
                    'Fixed paired readiness required')

    def stable(self):
        require(bounded(self.path, 65536, True) == self.bytes
                and bounded(self.attestation, 1024*1024, True) == self.immutable,
                'Job selection or immutable registration changed during execution')

    def definition(self, definition):
        require(definition['id'] == KINDS[self.kind] and definition['argv'] == command(self.kind)
                and definition['cwd'] == '.' and definition['kind'] == 'test'
                and definition['timeout_seconds'] == (720 if self.kind == 'plan' else 300),
                'Accepted stable command definition differs')
        self.stable()

    def receipt(self):
        return {'manifest_path': str(self.path), 'manifest_sha256': digest(self.bytes),
                'attestation_sha256': self.value['sha256'],
                'nonce': self.metadata['nonce'], 'boot_id': self.metadata['boot_id'],
                'activation_created': False, 'approval_created': False}


def load(name):
    path = ROOT/'scripts'/name
    data = bounded(path, 8*1024*1024)
    module = types.ModuleType(name.replace('-', '_'))
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module, data


def dispatch(job):
    value = job.value
    if job.kind == 'plan':
        module, source = load('plugin-dedicated-plan-acceptance.py')
        previous_argv = sys.argv
        try:
            sys.argv = [module.__file__, '--run-live', '--archive', ARCHIVE,
                        '--attestation', value['attestation_path'], '--sha256', value['sha256'],
                        '--output', value['output_path']]
            code = module.main()
        finally:
            sys.argv = previous_argv
    elif job.kind == 'evidence':
        module, source = load('plugin-original-demo-acceptance-adapter.py')
        result = module.run(types.SimpleNamespace(archive=ARCHIVE, demo_attestation=value['attestation_path'],
            demo_attestation_sha256=value['sha256'], demo_readiness=value['readiness_path'], live_job=job))
        print(json.dumps(result))
        code = 0 if result.get('complete') is True else 2
    else:
        module, source = load('plugin-acceptance.py')
        options = module.parse_options(['--milestone', 'standard-codex-pilot', '--archive', ARCHIVE,
            '--recipient-old-archive', OLD_ARCHIVE, '--primary-attestation', value['attestation_path'],
            '--primary-attestation-sha256', value['sha256'], '--primary-readiness', value['readiness_path']])
        options.live_job = job
        module.parse_options = lambda: options
        code = module.main()
    require(bounded(Path(module.__file__), 8*1024*1024) == source, 'Loaded acceptance source changed')
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', required=True, choices=KINDS)
    parser.add_argument('--job-manifest', required=True)
    parser.add_argument('--archive', required=True)
    parser.add_argument('--recipient-old-archive')
    options = parser.parse_args(argv)
    try:
        require(options.archive == ARCHIVE and options.recipient_old_archive ==
                (OLD_ARCHIVE if options.kind == 'pilot' else None), 'Fixed archive inputs required')
        job = Job(options.kind, options.job_manifest)
        config = strict(bounded(ROOT/'.progress-checker/config.json', 1024*1024))
        definitions = [item for item in config['checks'] if item['id'] == KINDS[options.kind]]
        require(len(definitions) == 1 and config['execution']['max_parallel'] == 1,
                'Exactly one serial configured live definition required')
        job.definition(definitions[0])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = dispatch(job)
        require(len(output.getvalue().encode()) <= 8*1024*1024, 'Acceptance report bound exceeded')
        result = strict(output.getvalue())
        job.stable()
        result['live_job_selection'] = job.receipt()
        require(code != 0 or result.get('complete') is True, 'Incomplete live acceptance cannot pass')
        print(json.dumps(result, indent=2))
        return code
    except Exception as error:
        print(json.dumps({'status': 'failed', 'complete': False, 'error': str(error),
                          'approval_created': False, 'activation_created': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
