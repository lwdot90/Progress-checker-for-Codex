#!/usr/bin/python3
"""OFF-default pure public/assertion/tool semantics; supplied data is unqualified.

No filesystem, process, socket, service, check or approval capability. Reviewed
capture source is executed only from exact caller-supplied pinned source bytes.
"""
import ast
import base64
import hashlib
import json
import types

BODY_SHA = 'ad1fc66caa841211d6f485832be4a602ac5c1a00743b5c42aefdbdd6f6ff1d99'
CAPTURE_SHA = 'a19413a48ca9f6fcd6b91344d21e66f0f6679aacad01cfc5d7359dcffc5d122c'
SCRIPT = (b'from pathlib import Path\n'
          b'assert Path("feature.txt").read_text() == "plan acceptance implemented\\n"\n'
          b'print("Dedicated plan invalidation fixture passed")\n')
FEATURE = b'plan acceptance implemented\n'
STAT_KEYS = {'device','inode','mode','uid','nlink','size','mtime_ns','ctime_ns','regular'}
DIRECTORY_KEYS = {'path','device','inode','uid','mode','directory','symlink'}
INIT = 'actual MCP advertises all ten tools and no approval tool'


class PublicError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PublicError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source_inventory(source):
    require(type(source) is bytes and len(source) <= 8*1024*1024 and digest(source) == BODY_SHA,
            'Exact original acceptance source required')
    tree = ast.parse(source)
    body = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'plan_invalidation')
    checks = sorted([n for n in ast.walk(body) if isinstance(n, ast.Call)
                     and isinstance(n.func, ast.Attribute) and n.func.attr == 'check'
                     and isinstance(n.func.value, ast.Name) and n.func.value.id == 'acceptance'],
                    key=lambda n:n.lineno)
    require(len(checks) == 14, 'Original static assertion scope differs')
    labels = []
    for call in checks:
        arg = call.args[0]
        if isinstance(arg, ast.Constant) and type(arg.value) is str:
            labels.append(arg.value)
        else:
            require(isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add)
                    and isinstance(arg.left, ast.Constant) and type(arg.left.value) is str
                    and isinstance(arg.right, ast.Name) and arg.right.id == 'label',
                    'Unexpected original dynamic assertion expression')
            labels.append(arg.left.value)
    expected_tools = next(ast.literal_eval(n.value) for n in tree.body
                          if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name)
                          and t.id == 'EXPECTED_TOOLS' for t in n.targets))
    acceptance = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'Acceptance')
    check = next(n for n in acceptance.body if isinstance(n, ast.FunctionDef) and n.name == 'check')
    require(any(isinstance(n, ast.Raise) and isinstance(n.exc, ast.Call)
                and isinstance(n.exc.func, ast.Name) and n.exc.func.id == 'RuntimeError'
                and len(n.exc.args) == 1 and isinstance(n.exc.args[0], ast.Name)
                and n.exc.args[0].id == 'name' for n in ast.walk(check)),
            'Original failed assertion RuntimeError behavior missing')
    # The two helper sites execute twice; both packaged initializations retain
    # their ten-tool assertion. Ordering comes from this exact original body.
    success = [labels[0], labels[1], INIT, labels[4], labels[5], labels[6],
               labels[7], labels[8], labels[9], labels[2]+'after-submit',
               labels[3]+'after-submit', labels[10], INIT, labels[11],
               labels[2]+'after-restart', labels[3]+'after-restart',
               labels[12], labels[13]]
    blocked = [labels[0], labels[1], INIT, labels[4], labels[5], labels[13]]
    return {'static_count':len(checks),'success_names':success,'blocked_names':blocked,
            'expected_tools':expected_tools,'failure_type':'RuntimeError'}


def capture_module(source):
    require(type(source) is bytes and len(source) <= 8*1024*1024 and digest(source) == CAPTURE_SHA,
            'Exact reviewed pure capture buffer required')
    module = types.ModuleType('reviewed_dedicated_capture')
    exec(compile(source, 'reviewed_dedicated_capture', 'exec'), module.__dict__)
    return module


def file_snapshot(payload, capture, expected_config):
    require(type(payload) is dict and set(payload) == {'role','root','state','files','directories'}
            and payload['role'] in {'initial','final'} and payload['root'] == capture.ROOT
            and payload['state'] == capture.STATE, 'Exact public snapshot scope required')
    files = payload['files']
    require(type(files) is list and len(files) == 3, 'Exact three public files required')
    decoded = {}
    for value in files:
        require(type(value) is dict and set(value) == {'role','bytes_base64','before_stat','after_stat','path_lstat'}
                and type(value['role']) is str and value['role'] in {'config','script','feature'}
                and value['role'] not in decoded, 'Public file schema/role differs')
        info = value['before_stat']
        require(type(info) is dict and set(info) == STAT_KEYS
                and all(type(info[key]) is int for key in STAT_KEYS-{'regular'})
                and info['regular'] is True and info['uid'] == 1000 and info['nlink'] == 1
                and info['device'] >= 0 and info['inode'] > 0 and info['size'] >= 0
                and 0 <= info['mode'] <= 0o777 and not info['mode'] & 0o022
                and info['mtime_ns'] >= 0 and info['ctime_ns'] >= 0
                and value['after_stat'] == info and value['path_lstat'] == info,
                'Regular owned anchored immutable file facts required')
        try:
            raw = base64.b64decode(value['bytes_base64'], validate=True)
        except (ValueError, TypeError) as exc:
            raise PublicError('Invalid public bytes base64') from exc
        require(len(raw) == info['size'] and len(raw) <= 65536, 'Public file byte bound/size differs')
        if value['role'] == 'config':
            require(capture.strict(raw) == expected_config, 'Public config/API configuration mismatch')
        else:
            require(raw == {'script':SCRIPT,'feature':FEATURE}[value['role']], 'Literal public bytes differ')
        decoded[value['role']] = {'bytes':raw,'stat':info}
    directories = payload['directories']
    expected_paths = {'root':capture.ROOT,'state':capture.STATE,'config':capture.ROOT+'/.progress-checker'}
    require(type(directories) is dict and set(directories) == set(expected_paths), 'Public directory scope differs')
    for role, path in expected_paths.items():
        info = directories[role]
        require(type(info) is dict and set(info) == DIRECTORY_KEYS and info['path'] == path
                and all(type(info[key]) is int for key in ('device','inode','uid','mode'))
                and info['device'] >= 0 and info['inode'] > 0 and info['uid'] == 1000
                and 0 <= info['mode'] <= 0o777 and not info['mode'] & 0o022
                and info['directory'] is True and info['symlink'] is False
                and (role != 'state' or info['mode'] == 0o700), 'Anchored public directory facts differ')
    return decoded


def evaluate(lines, job_id, nonce, acceptance_source, capture_source):
    inventory = source_inventory(acceptance_source)
    capture = capture_module(capture_source)
    classified = capture.classify_serialized(lines, job_id, nonce)
    frames = [item['frame'] for item in classified['classified_frames']]
    assertions = [f for f in frames if f['kind'] == 'original-assertion']
    terminal = frames[-1]['payload']
    require(type(terminal.get('body_exit')) is int and terminal['body_exit'] in {0,2}
            and type(terminal.get('cleanup_complete')) is bool,
            'Explicit original body exit/cleanup facts required')
    names, failed = [], []
    for frame in assertions:
        value = frame['payload']
        require(set(value) == {'name','passed','exception_type'} and type(value['name']) is str
                and type(value['passed']) is bool
                and value['exception_type'] == (None if value['passed'] else 'RuntimeError'),
                'Original assertion outcome/RuntimeError facts differ')
        names.append(value['name'])
        if not value['passed']:
            failed.append(frame)
    body_phase = classified['body_phase']
    if failed:
        require(terminal['body_exit'] == 2 and terminal.get('error_type') == 'RuntimeError',
                'Failed original assertion must retain RuntimeError failure')
        first = assertions.index(failed[0])
        require(names[:first+1] == inventory['success_names'][:first+1]
                or names[:first+1] == inventory['blocked_names'][:first+1],
                'Failed assertion is not an original ordered prefix')
        require(len(names[first+1:]) <= 1 and all(name == inventory['success_names'][-1]
                for name in names[first+1:]), 'Only original finally close assertion may follow failure')
        status = 'failed-original-assertion-captured-semantics'
    elif body_phase == 'blocked' and terminal['body_exit'] == 0:
        require(names == inventory['blocked_names'] and terminal.get('error') is None
                and terminal.get('error_type') is None, 'Blocked original assertion/error scope differs')
        status = 'blocked-missing-grant-captured-semantics'
    elif body_phase == 'restart-done' and terminal['body_exit'] == 0:
        require(names == inventory['success_names'] and not classified['pending_rpc']
                and terminal['cleanup_complete'] and terminal.get('error') is None
                and terminal.get('error_type') is None, 'Successful full original assertion/error scope differs')
        status = 'full-public-captured-semantics'
    else:
        require(terminal['body_exit'] == 2, 'Partial phase cannot claim successful body exit')
        status = 'partial-failed-captured-semantics'
    tool_lists = [f for f in frames if f['kind'] == 'response'
                  and next((p['frame']['payload']['decoded'].get('method') for p in classified['classified_frames']
                            if p['frame']['sequence'] == f['sequence']-1 and p['frame']['kind'] == 'request'), None) == 'tools/list']
    for frame in tool_lists:
        tools = frame['payload']['decoded']['result'].get('tools')
        require(type(tools) is list and len(tools) == 10
                and all(type(t) is dict and type(t.get('name')) is str for t in tools)
                and {t['name'] for t in tools} == inventory['expected_tools'],
                'Actual raw ten-tool inventory differs')
    if status == 'full-public-captured-semantics':
        require(len(tool_lists) == 2, 'Both packaged ten-tool inventories required')
    elif status == 'blocked-missing-grant-captured-semantics':
        require(len(tool_lists) == 1, 'Blocked packaged ten-tool inventory required')
    for frame in tool_lists:
        following = [a for a in assertions if a['sequence'] > frame['sequence']]
        require(following and following[0]['payload']['name'] == INIT,
                'Actual tool inventory must precede its original initialization assertion')
    projects = [f for item in classified['classified_frames'] if (f := item['frame'])['kind'] == 'response'
                and item['phase'] in {'initial','after-submit','restart-restored'}]
    snapshots = [f for f in frames if f['kind'] == 'public-files']
    initial = [f for f in snapshots if f['payload'].get('role') == 'initial']
    final = [f for f in snapshots if f['payload'].get('role') == 'final']
    require(len(initial) == 1 and len(final) <= 1, 'Exact initial/bounded final public snapshots required')
    if projects:
        first_config = projects[0]['payload']['decoded']['result']['structuredContent']['result']['config']
        milestones = first_config.get('milestones')
        require(type(milestones) is list and len(milestones) == 3
                and {value.get('id') for value in milestones} == {'alpha','beta','stable'}
                and all(criterion.get('check_id') == 'plan-check' for value in milestones
                        for criterion in value.get('criteria', [])), 'Original dedicated milestone scope differs')
        initial_files = file_snapshot(initial[0]['payload'], capture, first_config)
        if status == 'full-public-captured-semantics':
            require(len(final) == 1, 'Full public final snapshot required')
            last_config = projects[-1]['payload']['decoded']['result']['structuredContent']['result']['config']
            final_files = file_snapshot(final[0]['payload'], capture, last_config)
            require(all(initial_files[role] == final_files[role] for role in ('script','feature')),
                    'Public script/feature bytes and identities must persist')
            require(initial[0]['sequence'] < projects[0]['sequence']
                    and final[0]['sequence'] > projects[-1]['sequence'], 'Public snapshot chronology differs')
    if status in {'full-public-captured-semantics','blocked-missing-grant-captured-semantics'}:
        git = [f for f in frames if f['kind'] == 'git-root']
        require(len(git) == 1 and git[0]['payload'] == {
            'argv':['/usr/bin/git','-C',capture.ROOT,'rev-parse','--show-toplevel'],
            'exit_code':0,'stdout_base64':base64.b64encode((capture.ROOT+'\n').encode()).decode(),
            'stderr_base64':''}, 'Literal captured existing Git root required')
        require(initial[0]['sequence'] < assertions[0]['sequence'] < git[0]['sequence']
                < assertions[1]['sequence'], 'Initial file/Git original assertion chronology differs')
    return {'status':status,'complete':False,'qualification_possible':False,
            'semantic_validation_passed':status == 'full-public-captured-semantics',
            'original_assertion_count':len(assertions),'source_static_assertion_count':inventory['static_count'],
            'raw_tool_inventory_count':len(tool_lists),'poll_count':classified['poll_count'],
            'frame_count':len(frames),'approval_created':False,
            'unqualified':['Supplied public/assertion data does not prove live execution or a real human grant.',
                           'Independent registration, connected-peer provenance and actual lifecycle drain remain required.',
                           'Separate installed plan-interruption recovery coverage remains required.']}


if __name__ == '__main__':
    print('OFF: pure public/assertion source staging only; no host or backend operation.')
