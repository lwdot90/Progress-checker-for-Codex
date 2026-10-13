#!/usr/bin/python3
"""Explicit evidence-only CAS binding. Never grants, prepares or runs checks.

Call only after separate source review. Backend acceptance and machine sidecar
are two commits: any failure requires explicit reconciliation, never silent retry.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import stat
import subprocess
import time
import types

ROOT = Path(__file__).resolve().parent.parent
ADAPTER_SHA = '19e8787aac3a9d120063517b8b53a12ac6aaa58787c0404c692f82c4177e8e05'
MCP = Path('/home/luis/.codex/plugins/cache/progress-local-8b5742430514/progress-checker/0.2.1-dev/bin/progress-checker-mcp')
MCP_SHA = '6be43b4c12d46555d6443d2619bd15e1dd1754f297781f0fa5c0059bf5c79e7a'
STATE = Path('/home/luis/.local/share/progress-checker')
INPUTS = tuple('scripts/' + name for name in (
    'plugin-original-demo-acceptance-adapter.py', 'bind-original-demo-acceptance.py',
    'check-plugin-plan.py', 'plugin-original-demo-collector.py',
    'plugin-original-demo-activate.py', 'plugin-original-demo-observer.py',
    'plugin-original-demo-raw.py', 'plugin-original-demo-lifecycle.py',
    'plugin-evidence-acceptance.py', 'plugin-acceptance.py'))


def require(value, message):
    if not value:
        raise RuntimeError(message)


def load_adapter():
    path = ROOT / 'scripts/plugin-original-demo-acceptance-adapter.py'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and not info.st_mode & 0o022 and info.st_size <= 8*1024*1024,
                'Unsafe adapter bootstrap source')
        source = stream.read(8*1024*1024+1)
    require(hashlib.sha256(source).hexdigest() == ADAPTER_SHA, 'Reviewed adapter buffer changed')
    module = types.ModuleType('reviewed_demo_binding_adapter'); module.__file__ = str(path)
    exec(compile(source, str(path), 'exec'), module.__dict__)
    return module


def binding_guard(adapter, a, h, r):
    require(a.parent == r.parent and a.name == 'attestation.json' and r.name == 'readiness.json',
            'Exact registration layout required')
    immutable = adapter.bounded(a, 1024*1024, True)
    require(adapter.sha(immutable) == h, 'Exact reviewed immutable H required')
    meta = adapter.strict(immutable); adapter.registration_guard(meta, a)
    producer = meta.get('producer')
    require(type(producer) is dict and set(producer)=={'pid','starttime','uid','state','ppid','argv'}
            and type(producer['pid']) is int and producer['pid']>0
            and type(producer['uid']) is int and producer['uid']==1000
            and type(producer['ppid']) is int and producer['ppid']>=0
            and type(producer['starttime']) is str and producer['starttime'].isascii() and producer['starttime'].isdecimal()
            and type(producer['argv']) is list and all(type(v) is str for v in producer['argv']), 'Typed registered producer required')
    endpoint = Path(meta['endpoint'])
    require(endpoint == a.parent/'observe.sock' and endpoint.resolve(strict=True)==endpoint, 'Exact owned endpoint required')
    info = endpoint.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid==os.getuid()
            and stat.S_IMODE(info.st_mode)==0o600
            and meta['socket']=={'dev':info.st_dev,'ino':info.st_ino,'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}, 'Registered socket identity changed')
    ready = adapter.strict(adapter.bounded(r, 1024*1024, True))
    require(ready.get('awaiting_activation') is True and ready.get('ready') is False
            and ready.get('consumed') is False and ready.get('attestation_path') == str(a)
            and ready.get('attestation_sha256') == h, 'Producer must still await independent activation')
    require(meta.get('boot_id') == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            and type(meta.get('prepared_ns')) is int and type(meta.get('activation_expires_ns')) is int
            and meta['prepared_ns'] <= time.monotonic_ns() < meta['activation_expires_ns']
            and meta['activation_expires_ns']-meta['prepared_ns'] == 1800_000_000_000,
            'Registration expired or different boot')
    for key in ('schema_version','job_id','nonce','producer','endpoint','socket'):
        require(ready.get(key) == meta.get(key), 'Readiness immutable crosspin differs')
    return {'attestation_path':str(a), 'sha256':h, 'readiness_path':str(r), 'trust_policy':adapter.TRUST}


def transform(adapter, config, plan, binding):
    require(config['project_id'] == plan['project_id'] == 'progress-checker-plugin'
            and len(config['milestones']) == len(plan['milestones']) == 8,
            'All eight accepted milestones required')
    require(len({v['id'] for v in plan['milestones']}) == 8
            and len({v['id'] for v in config['milestones']}) == 8, 'Unique accepted milestone IDs required')
    require(len({c['id'] for c in config['checks']}) == len(config['checks']) == 8,
            'All eight unique check definitions required')
    require({c['id'] for c in config['checks']} == {v['check_id'] for v in plan['milestones']},
            'Existing checks must exactly match eight accepted requirements')
    for check in config['checks']:
        if check['id'] != 'evidence-integrity':
            require(not any(flag in check['argv'] for flag in adapter.FLAGS[1:])
                    and 'scripts/plugin-original-demo-acceptance-adapter.py' not in check['argv'],
                    'Demo observer route belongs only to evidence-integrity')
    for expected, actual in zip(plan['milestones'], config['milestones']):
        require(actual['id'] == expected['id'] and actual['title'] == expected['title']
                and actual['depends_on'] == expected['depends_on'] and actual['in_scope'] is True
                and len(actual['criteria']) == 1 and actual['criteria'][0]['required'] is True
                and actual['criteria'][0]['description'] == expected['acceptance']
                and actual['criteria'][0]['check_id'] == expected['check_id'], 'Existing scope/config differs')
    require(plan['acceptance_archive'] == {'path':adapter.ARCHIVE_ARG,'sha256':adapter.ARCHIVE_SHA}
            and adapter.ARCHIVE_ARG in config['fingerprint']['extra_inputs'], 'Previously accepted archive binding required')
    require(plan['evidence_fixture'] == {'root':str(ROOT/'.local/checker-demo/session-c5c6vsyz/project'),
            'state':str(ROOT/'.local/checker-demo/session-c5c6vsyz/state')}, 'Original retained fixture metadata differs')
    result = copy.deepcopy(config)
    matches = [v for v in result['checks'] if v['id'] == 'evidence-integrity']
    require(len(matches) == 1, 'Exactly one existing evidence definition required')
    check = matches[0]
    old = ['/usr/bin/python3','scripts/plugin-acceptance.py','--milestone','evidence-integrity',
           '--archive',adapter.ARCHIVE_ARG,'--evidence-fixture-root',plan['evidence_fixture']['root'],
           '--evidence-fixture-state',plan['evidence_fixture']['state']]
    prior = plan.get('evidence_observer')
    if prior is not None:
        require(set(prior) == {'attestation_path','sha256','readiness_path','trust_policy'}
                and prior['trust_policy'] == adapter.TRUST, 'Prior evidence metadata needs explicit reconciliation')
        old = adapter.argv_for(prior['attestation_path'], prior['sha256'], prior['readiness_path'])
    adapter.definition_guard(result, old)
    check['argv'] = adapter.argv_for(binding['attestation_path'], binding['sha256'], binding['readiness_path'])
    inputs = result['fingerprint']['extra_inputs']
    require(type(inputs) is list and len(set(inputs)) == len(inputs), 'Unique stable fingerprint inputs required')
    for path in INPUTS:
        if path not in inputs:
            inputs.append(path)
    return result


class Client:
    def __init__(self):
        self.process = None
        try:
            self.process = subprocess.Popen([str(MCP),'--root',str(ROOT),'--state-dir',str(STATE)],
                                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
            os.set_blocking(self.process.stdin.fileno(), False)
            self.buffer = b''; self.sequence = 0
        except BaseException as error:
            cleanup_errors = []
            if self.process is not None:
                try:
                    self.process.stdin.close()
                except BaseException as close_error:
                    cleanup_errors.append('EOF: '+str(close_error))
                try:
                    require(self.process.wait(timeout=10)==0, 'Returned reader nonzero exit')
                except BaseException as wait_error:
                    cleanup_errors.append('bounded wait: '+str(wait_error))
                finally:
                    for stream in (self.process.stdin,self.process.stdout,self.process.stderr):
                        if stream is not None:
                            try:stream.close()
                            except BaseException as close_error:cleanup_errors.append('handle: '+str(close_error))
            suffix = '; returned reader cleanup uncertain: '+repr(cleanup_errors) if cleanup_errors else '; returned reader EOF/reaped or no returned child'
            raise RuntimeError('Native reader construction failed before any RPC; backend outcome unmodified by this client: '+type(error).__name__+': '+str(error)+suffix) from error
    def send(self, data, until):
        offset = 0
        while offset < len(data):
            remaining = until-time.monotonic()
            require(remaining > 0 and select.select([], [self.process.stdin], [], remaining)[1],
                    'Binding pipe write deadline expired')
            try:
                count = os.write(self.process.stdin.fileno(), data[offset:])
            except BlockingIOError:
                continue
            require(count > 0, 'Binding pipe write closed')
            offset += count
    def call(self, method, params):
        self.sequence += 1
        until = time.monotonic()+30
        self.send(json.dumps({'jsonrpc':'2.0','id':self.sequence,'method':method,'params':params}).encode()+b'\n', until)
        while b'\n' not in self.buffer:
            remaining = until-time.monotonic()
            require(remaining > 0 and select.select([self.process.stdout],[],[],remaining)[0], 'Binding RPC deadline expired')
            chunk = os.read(self.process.stdout.fileno(),16384)
            require(chunk, 'Binding MCP closed')
            self.buffer += chunk; require(len(self.buffer) <= 512*1024, 'Bounded RPC required')
        line, self.buffer = self.buffer.split(b'\n',1)
        reply = self.strict(line)
        require(type(reply) is dict and reply.get('jsonrpc') == '2.0'
                and type(reply.get('id')) is int and reply['id'] == self.sequence
                and 'error' not in reply and type(reply.get('result')) is dict, 'Correlated RPC result required')
        return reply['result']
    def tool(self, name, args=None):
        value = self.call('tools/call',{'name':name,'arguments':args or {}})
        require(value.get('isError') is False, 'Binding backend refused: '+str(value))
        require(type(value.get('structuredContent')) is dict
                and type(value.get('content')) is list and value['content']
                and value['content'][0].get('type')=='text'
                and self.strict(value['content'][0]['text'])==value['structuredContent'], 'Binding structured/text mismatch')
        return value['structuredContent']
    def close(self):
        try:
            self.process.stdin.close()
            require(self.process.wait(timeout=10) == 0, 'Owned binding reader did not shut down cleanly')
        finally:
            self.process.stdout.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('--demo-attestation','--demo-attestation-sha256','--demo-readiness','--state-dir'):
        parser.add_argument(name, required=True)
    args = parser.parse_args(argv)
    require(Path(args.state_dir) == STATE, 'Explicit existing root state required; never infer it')
    adapter = load_adapter()
    # 200 seconds of work, followed by at most ten seconds of normal EOF wait.
    # No TERM/KILL path exists: an unresolved reader remains an explicit failure.
    with adapter.deadline(seconds=200):
        bind(adapter, args)


def bind(adapter, args):
    a,r = Path(args.demo_attestation),Path(args.demo_readiness)
    require(type(args.demo_attestation_sha256) is str and len(args.demo_attestation_sha256)==64
            and all(c in '0123456789abcdef' for c in args.demo_attestation_sha256), 'Exact immutable H required')
    plan_path = ROOT/'.progress-checker/plugin-plan.json'; config_path = ROOT/'.progress-checker/config.json'
    before = adapter.bounded(plan_path,1024*1024); plan = adapter.strict(before)
    public_config = adapter.bounded(config_path,1024*1024)
    binding = binding_guard(adapter,a,args.demo_attestation_sha256,r)
    captured = {p:adapter.sha(adapter.bounded(ROOT/p,8*1024*1024)) for p in INPUTS}
    require(all(captured['scripts/'+n] == h for n,h in adapter.SOURCES.items()), 'Prepared source roster changed')
    adapter.archive_guard(adapter.bounded(ROOT/adapter.ARCHIVE_ARG,64*1024*1024))
    require(adapter.sha(adapter.bounded(MCP,32*1024*1024)) == MCP_SHA, 'Exact installed404 MCP required')
    def stable():
        require(adapter.bounded(plan_path,1024*1024) == before and adapter.bounded(config_path,1024*1024) == public_config,
                'Public plan/config changed; explicit reconciliation required')
        require(all(adapter.sha(adapter.bounded(ROOT/p,8*1024*1024)) == h for p,h in captured.items()), 'Binding sources changed')
        binding_guard(adapter,a,args.demo_attestation_sha256,r)
    client = Client(); client.strict = adapter.strict; backend_committed = False; failure = None; result = None
    try:
        client.call('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'evidence-observer-binding','version':'1'}})
        client.send(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n', time.monotonic()+30)
        snapshot = client.tool('checker_get_project')
        require(type(snapshot.get('revision')) is int, 'Exact current revision required')
        require(snapshot['result']['canonical_root'] == str(ROOT) and snapshot['result']['config'] == adapter.strict(public_config), 'Live/public config binding differs')
        updated = transform(adapter,snapshot['result']['config'],plan,binding); stable()
        submission = client.tool('checker_submit_plan',{'config':updated,'reason':'Change ONLY evidence-integrity command to fresh reviewed original-demo standalone observer A/H/readiness; add missing stable source fingerprint inputs. Preserve all eight requirements, criteria, dependencies and other checks. No execution approval is granted.', 'expected_revision':snapshot['revision'],'expected_config_hash':snapshot['result']['status']['source']['config_hash']})
        backend_committed = True
        final = client.tool('checker_get_project')
        require(final['result']['config'] == updated, 'Accepted backend differs; stop and reconcile')
        change = submission['result']['change']
        if updated == snapshot['result']['config']:
            require(change is None, 'Unexpected history for unchanged config; stop and reconcile')
        else:
            require(type(change) is dict and not change['added'] and not change['removed']
                    and set(change['changed']) <= {'evidence-integrity'}, 'Unexpected accepted scope change; stop and reconcile')
        history = client.tool('checker_get_plan_history',{'offset':0,'limit':5})
        require(type(history['result']['total']) is int and history['result']['total'] >= 0, 'Typed scope history total required')
        if change is not None:
            history = client.tool('checker_get_plan_history',{'offset':max(0,history['result']['total']-5),'limit':5})
            require(sum(entry == change for entry in history['result']['entries']) == 1,
                    'Accepted exact scope history entry missing; stop and reconcile')
        require(adapter.bounded(plan_path,1024*1024) == before, 'Machine plan concurrently changed; preserve it and reconcile backend')
        require(all(adapter.sha(adapter.bounded(ROOT/p,8*1024*1024)) == h for p,h in captured.items()), 'Postsubmit source changed')
        binding_guard(adapter,a,args.demo_attestation_sha256,r)
        new_plan = copy.deepcopy(plan); new_plan['evidence_observer'] = binding
        directory = os.open(plan_path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        directory_info = os.fstat(directory); temporary = '.evidence-plan-'+secrets.token_hex(16)+'.tmp'; temporary_identity = None
        try:
            fd = os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644,dir_fd=directory)
            temporary_identity = os.fstat(fd)
            with os.fdopen(fd,'wb') as stream:
                stream.write((json.dumps(new_plan,indent=2)+'\n').encode());stream.flush();os.fsync(stream.fileno())
            require(adapter.bounded(plan_path,1024*1024)==before
                    and (plan_path.parent.stat().st_dev,plan_path.parent.stat().st_ino)==(directory_info.st_dev,directory_info.st_ino), 'Machine plan CAS/parent changed; stop and reconcile')
            os.replace(temporary,plan_path.name,src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
        finally:
            if temporary_identity is not None:
                try:
                    current = os.stat(temporary,dir_fd=directory,follow_symlinks=False)
                    require((current.st_dev,current.st_ino)==(temporary_identity.st_dev,temporary_identity.st_ino), 'Foreign replacement temporary preserved; reconcile')
                    os.unlink(temporary,dir_fd=directory)
                except FileNotFoundError:pass
            os.close(directory)
        require(adapter.strict(adapter.bounded(plan_path,1024*1024))==new_plan
                and client.tool('checker_get_project')['result']['config']==updated, 'Final sidecar/backend reconciliation failed')
        result = {'status':'bound-not-approved','backend':submission,'history':history,'evidence_observer':binding}
    except Exception as error:
        failure = RuntimeError(('Backend committed; explicit machine-plan/backend reconciliation required. ' if backend_committed else 'No successful backend commit observed; verify backend before retry. ')+type(error).__name__+': '+str(error))
    finally:
        try:
            client.close()
        except Exception as close_error:
            prior = str(failure) if failure is not None else ('Backend committed; reconcile before approval. ' if backend_committed else 'Backend outcome uncertain; verify before retry. ')
            failure = RuntimeError(prior+'; owned reader normal-EOF cleanup failed: '+type(close_error).__name__+': '+str(close_error))
    if failure is not None:
        raise failure
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    main()
