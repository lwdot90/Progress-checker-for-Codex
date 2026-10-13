#!/usr/bin/env bash
# Run by a human in an interactive terminal; never supplies confirmation.
set -euo pipefail
project_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
fixture_directory="$project_directory/.local/plugin-acceptance/plan-invalidation-human-fixture-v2"
checker_binary="$fixture_directory/runtime/progress-checker-0.2.1-dev-linux-x86_64/plugin/bin/progress-checker"
if [[ $# -gt 1 || (${1-} != '' && ${1-} != '--verify-only') ]]; then
    printf 'Usage: %s [--verify-only]\n' "$0" >&2
    exit 1
fi
if [[ ${1-} != '--verify-only' && (! -t 0 || ! -t 1) ]]; then
    printf 'Run this script yourself in an interactive terminal.\n' >&2
    exit 1
fi
if [[ "$project_directory" != '/home/luis/progress-checker' ]]; then
    printf 'Refusing a different development repository.\n' >&2
    exit 1
fi
verify_public_file() {
    local file_path="$1" expected_hash="$2" actual_hash
    if [[ ! -f "$file_path" || "$(realpath -e -- "$file_path")" != "$file_path" ]]; then
        printf 'Refusing a missing or redirected input: %s\n' "$file_path" >&2
        exit 1
    fi
    actual_hash="$(sha256sum -- "$file_path")"
    if [[ "${actual_hash%% *}" != "$expected_hash" ]]; then
        printf 'Refusing changed input: %s\n' "$file_path" >&2
        exit 1
    fi
}
verify_public_file "$checker_binary" '9ece1092eba4232a3c66c745d90c7d62df5aaa25a3587a9363c6fe142c830d99'
# Repeated invalidation trials change only Alpha's title. Validate the entire
# fixed fixture structure, then let the human CLI show its current exact hash.
/usr/bin/python3 - "$fixture_directory/project/.progress-checker/config.json" <<'PY'
import json, os, stat, sys
from pathlib import Path
p=Path(sys.argv[1])
assert p.resolve(strict=True)==p
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as stream:
    before=os.fstat(stream.fileno())
    assert stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and before.st_nlink==1 and not before.st_mode&0o022 and before.st_size<=65536
    raw=stream.read(65537);after=os.fstat(stream.fileno())
    assert (before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
def pairs(items):
    result={}
    for key,value in items:
        assert key not in result
        result[key]=value
    return result
config=json.loads(raw,object_pairs_hook=pairs)
expected={'schema_version':1,'project_id':'isolated-plan-invalidation','enabled':True,
    'panel':{'show_on_start':True},'execution':{'max_parallel':1,'default_timeout_seconds':10},
    'fingerprint':{'extra_inputs':[],'exclude_outputs':[]},
    'checks':[{'id':'plan-check','argv':['/usr/bin/python3','plan-check.py'],'cwd':'.','kind':'test','timeout_seconds':10}],
    'milestones':[]}
for name,deps in [('alpha',[]),('beta',['alpha']),('stable',[])]:
    expected['milestones'].append({'id':name,'title':name.title(),'in_scope':True,'depends_on':deps,
        'criteria':[{'id':'acceptance','description':'Dedicated fixture check passes','check_id':'plan-check','required':True}]})
title=config['milestones'][0]['title']
assert type(title) is str and title.startswith('Alpha') and len(title)<=1024
config['milestones'][0]['title']='Alpha'
assert json.dumps(config,sort_keys=True)==json.dumps(expected,sort_keys=True), 'Fixture structure differs; review instead of approving'
PY
verify_public_file "$fixture_directory/project/plan-check.py" '59e958d9d74ed5358548ee5600b925e92d828ae0d9c3480b6ea5a716374b8d45'
verify_public_file "$fixture_directory/project/feature.txt" '56940225cff82e45e757fbbe0b9eb7275086767314fd64e5bc3856ae861ab6a2'
for directory_path in "$fixture_directory/project" "$fixture_directory/state"; do
    if [[ ! -d "$directory_path" || "$(realpath -e -- "$directory_path")" != "$directory_path" ]]; then
        printf 'Refusing a missing or redirected fixture directory.\n' >&2
        exit 1
    fi
done
if [[ ${1-} == '--verify-only' ]]; then
    printf 'Pinned fixture and checker inputs match. No approval or execution requested.\n'
    exit 0
fi
printf 'Review the fixture script before approving its exact command:\n'
cat -- "$fixture_directory/project/plan-check.py"
exec "$checker_binary" --root "$fixture_directory/project" \
    --state-dir "$fixture_directory/state" approve plan-check
