#!/usr/bin/env python3
"""Run public behavioral acceptance in a separately attested test runtime.

This test-only runtime uses a rootless mapped-root namespace with sole
namespace-local CAP_SETFCAP, retained by its nested check payload. It does not
claim zero-capability or nonroot payload equivalence. Production sandbox code,
command definitions, and packaged executable bytes remain unchanged.

Only acceptance-test source buffers, the exact archive, curated OS runtime,
and fresh public fixtures are visible. No retained approvals or project state
are accepted. Original acceptance results and qualification gaps are preserved.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
MAX_TEST_SOURCE_BYTES = 2 * 1024 * 1024
PUBLIC_MILESTONES = ('service-lifecycle', 'agent-workflow', 'plan-submission', 'plugin-package')


def read_test_source(path: Path) -> bytes:
    """Bounded regular-file, no-follow read of a hardcoded public test source."""
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        before=os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size>MAX_TEST_SOURCE_BYTES:
            raise ValueError('Acceptance test source is not bounded regular input')
        data=source.read(MAX_TEST_SOURCE_BYTES+1)
        after=os.fstat(source.fileno())
        if len(data)>MAX_TEST_SOURCE_BYTES or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            raise RuntimeError('Acceptance test source changed while reading')
        return data


def load_helper():
    path = ROOT/'scripts/plugin-sandbox-recipient.py'
    specification = importlib.util.spec_from_file_location('sandbox_recipient_runtime', path)
    module = importlib.util.module_from_spec(specification)
    source = read_test_source(path)
    exec(compile(source, str(path), 'exec'), module.__dict__)
    return module, hashlib.sha256(source).hexdigest()


def harness_source(sources: dict[str, str], milestone: str) -> str:
    # Exact current public acceptance code is a test input, never product runtime.
    # It is materialized only inside the isolated guest; no checkout is mounted.
    return '''import argparse,base64,hashlib,importlib.util,json,os,sys,traceback
from pathlib import Path
p=argparse.ArgumentParser()
for name in ['archive','old-archive','base-dir','data-home','output-dir','invoker-attestation','fixture-root','fixture-state']:p.add_argument('--'+name,type=Path)
p.add_argument('--sha256');p.add_argument('--namespace-mapped-root',action='store_true')
a=p.parse_args()
report={'status':'failed','upgrade_archive_sha256':a.sha256,'no_approvals_created':True,
        'qualification_scope':'test runtime transport only; original product result is preserved',
        'no_retained_state_exposed':True,'test_sources':{}}
try:
    att=json.loads(a.invoker_attestation.read_text())
    caps={line.split(':')[0]:line.split(':')[1].strip() for line in Path('/proc/self/status').read_text().splitlines() if line.startswith(('CapEff:','CapPrm:','CapBnd:'))}
    if os.getuid()!=0 or any(int(value,16)!=1<<31 for value in caps.values()):raise RuntimeError('Expected solely namespace-local SETFCAP')
    if Path('/proc/self/uid_map').read_text().split()!=['0','1000','1']:raise RuntimeError('Unexpected UID mapping')
    if Path('/home/luis/.codex').exists() or Path('/home/luis/.local/share/progress-checker').exists():raise RuntimeError('Host private home exposed')
    report.update(parent_capabilities=caps,invoker_attestation=att)
    source_directory=Path('/r/acceptance-harness/scripts');source_directory.mkdir(parents=True)
    sources=SOURCE_BUFFERS
    for name,value in sources.items():
        data=base64.b64decode(value,validate=True)
        (source_directory/name).write_bytes(data)
        report['test_sources'][name]=hashlib.sha256(data).hexdigest()
    path=source_directory/'plugin-acceptance.py'
    spec=importlib.util.spec_from_file_location('current_public_acceptance',path)
    module=importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
    product_output=a.output_dir/'product-acceptance.json'
    sys.argv=[str(path),'--milestone',__SELECTED_PUBLIC_MILESTONE__,'--archive',str(a.archive),
              '--codex-binary','/usr/local/bin/codex','--output',str(product_output)]
    if __SELECTED_PUBLIC_MILESTONE__=='plugin-package':sys.argv.append('--native-package-only')
    code=module.main()
    product=json.loads(product_output.read_text())
    if product.get('archive',{}).get('sha256')!=a.sha256:raise RuntimeError('Product report archive mismatch')
    report.update(status='passed',product_exit_code=code,product_acceptance=product)
except Exception as error:
    report.update(error=str(error),traceback=traceback.format_exc())
finally:
    (a.output_dir/'report.json').write_text(json.dumps(report,indent=2)+'\\n')
    print(json.dumps(report,indent=2))
    sys.exit(0 if report['status']=='passed' else 1)
'''.replace('__SELECTED_PUBLIC_MILESTONE__', repr(milestone)).replace('SOURCE_BUFFERS', repr(sources))


def run_acceptance(archive: Path, milestone: str, output: Path, *, timeout: int = 260) -> tuple[dict, int]:
    if milestone not in PUBLIC_MILESTONES:
        raise ValueError('This runtime currently accepts only public fixture behavior milestones')
    runtime_hash=hashlib.sha256(read_test_source(Path(__file__))).hexdigest()
    helper, helper_hash = load_helper()
    path = ROOT/'scripts/plugin-acceptance.py'
    source = read_test_source(path)
    sources = {path.name: base64.b64encode(source).decode('ascii')}
    output = output.resolve()
    with tempfile.TemporaryDirectory(prefix='pc-acceptance-runtime-') as temporary:
        directory = Path(temporary)
        root, state = directory/'public-fixture', directory/'state'
        root.mkdir(); state.mkdir(mode=0o700)
        (root/'.public-runtime-fixture').write_text('Fresh public acceptance runtime; no retained state.\n')
        harness = directory/'harness.py'
        harness.write_text(harness_source(sources, milestone))
        result = helper.qualify(archive, None, harness, output=output,
                                timeout=timeout, _public_fixture=(root,state))
    if hashlib.sha256(read_test_source(path)).hexdigest() != hashlib.sha256(source).hexdigest():
        raise RuntimeError('Public acceptance source changed during execution')
    if hashlib.sha256(read_test_source(ROOT/'scripts/plugin-sandbox-recipient.py')).hexdigest() != helper_hash:
        raise RuntimeError('Test runtime helper changed during execution')
    if hashlib.sha256(read_test_source(Path(__file__))).hexdigest()!=runtime_hash:
        raise RuntimeError('Acceptance runtime source changed during execution')
    envelope = result['report']
    product = envelope['product_acceptance']
    product['test_runtime'] = {'scope':envelope['qualification_scope'],
                              'parent_capabilities':envelope['parent_capabilities'],
                              'namespace_invoker':envelope['invoker_attestation'],
                              'runtime_sha256':runtime_hash,'helper_sha256':helper_hash,'test_sources':envelope['test_sources'],
                              'transport_report':str(output/'report.json'),
                              'limitation':'Namespace-local SETFCAP is retained by nested payload; not zero-cap or nonroot equivalence. No retained state exposed.'}
    return product, envelope['product_exit_code']


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--milestone',choices=PUBLIC_MILESTONES,required=True)
    parser.add_argument('--output',type=Path,required=True,help='Fresh dedicated report directory')
    parser.add_argument('--timeout',type=int,default=260)
    options=parser.parse_args()
    report,code=run_acceptance(options.archive,options.milestone,options.output,timeout=options.timeout)
    (options.output/'runtime-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return code


if __name__=='__main__':
    raise SystemExit(main())
