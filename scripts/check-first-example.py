#!/usr/bin/env python3
"""Exercise good/broken example behavior in an isolated copy, not the user's files."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
example = root / 'examples/first-check'
config = json.loads((example / '.progress-checker/config.json').read_text())
check = config['checks'][0]
assert check['argv'] == ['/usr/bin/python3','-m','unittest','-v','test_greeting']
assert config['milestones'][0]['criteria'][0]['check_id'] == check['id']
with tempfile.TemporaryDirectory() as temporary:
    project = Path(temporary) / 'project'
    shutil.copytree(example, project, ignore=shutil.ignore_patterns('__pycache__'))
    passing = subprocess.run(check['argv'],cwd=project,capture_output=True,text=True,timeout=10)
    assert passing.returncode == 0 and 'OK' in passing.stderr, passing.stderr
    (project/'greeting.py').write_text('def greet(name):\n    return "Hi!"\n')
    # Remove interpreter bytecode so the failing case exercises the rewritten code.
    shutil.rmtree(project/'__pycache__',ignore_errors=True)
    failing = subprocess.run(check['argv'],cwd=project,capture_output=True,text=True,timeout=10)
    assert failing.returncode != 0 and 'FAIL' in failing.stderr, failing.stderr
print('PASS: real example passes correct code and fails broken code')
