#!/usr/bin/env python3
"""Measure the actual Rust fingerprint on owned fixtures; no metadata-only cache."""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'schema_version':1,'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'coverage':'synthetic production-fingerprint measurements; not end-to-end status latency',
              'host':{'kernel':platform.release(),'architecture':platform.machine(),'cpu_count':os.cpu_count()},
              'build':'Cargo debug profile; optimized sha2 compression; full-content hashing',
              'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
              'sources':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in
                         ('Cargo.toml','Cargo.lock','checker-core/src/fingerprint.rs')},'fixtures':[]}
    for count in (1000, 10000):
        with tempfile.TemporaryDirectory(prefix='fingerprint-', dir=output.parent) as temporary:
            root = Path(temporary)
            files = root/'files'; files.mkdir()
            content = b'A'*4096
            for index in range(count):
                (files/f'input-{index:05}.txt').write_bytes(content)
            subprocess.run(['/usr/bin/git','init','-q',str(root)],check=True)
            subprocess.run(['/usr/bin/git','-C',str(root),'add','files'],check=True)
            def measure(samples):
                return json.loads(subprocess.run([str(binary),str(root),str(samples)],check=True,capture_output=True,text=True,timeout=120).stdout)
            before = measure(5)
            assert len({v['digest'] for v in before['samples']}) == 1
            assert all(v['input_count']==count for v in before['samples'])
            path=files/'input-00000.txt'; stamp=path.stat();path.write_bytes(b'B'*4096)
            os.utime(path,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
            after = measure(1)
            assert path.stat().st_size == stamp.st_size and path.stat().st_mtime_ns == stamp.st_mtime_ns
            assert before['samples'][0]['digest'] != after['samples'][0]['digest'], 'Same-size/restored-mtime edit was missed'
            times=sorted(v['elapsed_ms'] for v in before['samples'])
            report['fixtures'].append({'files':count,'content_bytes':count*len(content),'samples':before['samples'],
                'first_read_ms':before['samples'][0]['elapsed_ms'],'median_ms':statistics.median(times),
                'p95_ms':times[math.ceil(.95*len(times))-1], 'sample_count':len(times),
                'same_size_restored_mtime_edit_detected':True,'after_edit':after['samples'][0]})
    output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
