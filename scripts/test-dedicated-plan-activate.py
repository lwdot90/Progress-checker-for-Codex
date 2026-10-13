#!/usr/bin/python3
"""Pure activation tests; all filesystem/proc/PIDfd/signal operations mocked."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import types
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).parent
SOURCE=(HERE/'plugin-dedicated-plan-activate.py').read_bytes()
SHA='f03b72cec92e3b3035c3d4b8b39eba8bee4ce53b6002e3e2351eb5994ce6ec01'
assert hashlib.sha256(SOURCE).hexdigest()==SHA
m=types.ModuleType('activation_frozen');m.__file__=str(HERE/'plugin-dedicated-plan-activate.py')
exec(compile(SOURCE,m.__file__,'exec'),m.__dict__)
h=types.ModuleType('host_frozen');h.__file__=str(HERE/'plugin-dedicated-plan-host.py')
hostbytes=(HERE/'plugin-dedicated-plan-host.py').read_bytes();assert m.sha(hostbytes)==m.HOST_SHA
exec(compile(hostbytes,h.__file__,'exec'),h.__dict__)
raw=h.load('plugin-dedicated-plan-capture.py',(HERE/'plugin-dedicated-plan-capture.py').read_bytes())
life=h.load('plugin-dedicated-plan-lifecycle.py',(HERE/'plugin-dedicated-plan-lifecycle.py').read_bytes())
DIRECTORY=m.ROOT/'.local/dedicated-activation-pure';PATH=DIRECTORY/'attestation.json'


def setup():
    buffers={n:(HERE/n).read_bytes() if n in h.PINS or n in ('plugin-dedicated-plan-host.py','plugin-dedicated-plan-activate.py') else b'# future synthetic source\n' for n in h.NAMES}
    argv=['scripts/plugin-dedicated-plan-host.py','--prepare-live','--output-dir',str(DIRECTORY)]
    producer={'pid':78,'uid':1000,'ppid':77,'starttime':'1234','state':'S','argv':['/usr/bin/python3']+argv}
    config={'project_id':'isolated-plan-invalidation','checks':[raw.CHECK]}
    snapshot={'role':'initial','files':[{'role':role,'bytes_base64':base64.b64encode(data).decode()} for role,data in [('config',json.dumps(config).encode()),('script',b'script'),('feature',b'feature')]]}
    socket={'dev':1,'ino':2,'uid':1000,'mode':0o600,'mtime_ns':3,'ctime_ns':4}
    meta={'schema_version':1,'mode':'dedicated-plan','trust_policy':h.TRUST,'job_id':'a'*32,'nonce':'b'*64,
          'root':str(h.FIXTURE),'state':str(h.STATE),'producer':producer,'producer_argv':argv,
          'python_exe_sha256':m.sha(b'python'),'boot_id':'boot','body_sha256':h.PINS['plugin-acceptance.py'],
          'archive_sha256':h.ARCHIVE_SHA,'budget_seconds':h.BUDGETS,'prepared_ns':0,'activation_expires_ns':1_800_000_000_000,
          'module_hashes':{str(m.ROOT/'scripts'/n):m.sha(data) for n,data in buffers.items()},
          'runtime_files':{str(DIRECTORY/'extracted/progress-checker-0.2.1-dev-linux-x86_64/plugin/bin'/n):v for n,v in life.HASHES.items()},
          'initial_public_snapshot':snapshot,'fixture_files':{v['role']:{'sha256':m.sha(base64.b64decode(v['bytes_base64']))} for v in snapshot['files']},
          'check_definition':raw.CHECK,'endpoint':str(DIRECTORY/'observe.sock'),'socket':socket}
    actor=types.SimpleNamespace(RUNTIME_HASHES=life.HASHES,process_identity=Mock(return_value=copy.deepcopy(producer)),
        socket_identity=Mock(return_value=socket),FixedAdapter=types.SimpleNamespace(public_snapshot=Mock(return_value=copy.deepcopy(snapshot))),
        Layout=Mock(return_value=types.SimpleNamespace(absent=Mock())))
    public=types.SimpleNamespace(file_snapshot=Mock())
    modules={'plugin-dedicated-plan-adapter.py':actor,'plugin-dedicated-plan-capture.py':raw,'plugin-dedicated-plan-public.py':public,'plugin-dedicated-plan-lifecycle.py':life}
    return meta,buffers,actor,modules


def run(meta,buffers,actor,modules,mutation=None,poll_events=None):
    original=json.dumps(meta).encode();ready={k:meta[k] for k in ('schema_version','job_id','nonce','producer','endpoint','socket')}
    ready.update(attestation_path=str(PATH),attestation_sha256=m.sha(original),awaiting_activation=True,ready=False,consumed=False)
    activation=m.Activation(PATH,m.sha(original),h);calls=[]
    def read(path,limit,coordination=False):
        if path==PATH:return original
        if path==DIRECTORY/'readiness.json':return json.dumps(ready).encode()
        if path.parent==m.ROOT/'scripts':return buffers[path.name]
        if path==h.ARCHIVE:return b'archive'
        return b'runtime'
    digests={b'archive':h.ARCHIVE_SHA,b'runtime':None}
    originalsha=m.sha
    def digest(data):
        if data==b'archive':return h.ARCHIVE_SHA
        return originalsha(data)
    # Distinct runtime bytes for each fixed hash, without opening any runtime.
    def bounded(path,limit,coordination=False):
        if str(path) in meta['runtime_files']:return meta['runtime_files'][str(path)].encode()
        return read(path,limit,coordination)
    def digest(data):
        if data==b'archive':return h.ARCHIVE_SHA
        if data.decode(errors='ignore') in life.HASHES.values():return data.decode()
        return originalsha(data)
    def signal(handle,*args):calls.append(('signal',handle));assert activation.handle==handle
    poller=types.SimpleNamespace(register=lambda *args:None,poll=lambda delay:poll_events or [])
    with (patch.object(m,'bounded',side_effect=bounded),patch.object(m,'sha',side_effect=digest),
          patch.object(h,'load',side_effect=lambda name,data:modules[name]),patch.object(m.os,'getuid',return_value=1000),
          patch.object(Path,'resolve',lambda path,strict=False:path),patch.object(m.os,'pidfd_open',side_effect=lambda pid,flags:calls.append(('open',pid)) or 55),
          patch.object(m.os,'close',side_effect=lambda fd:calls.append(('close',fd))),patch.object(m.select,'poll',return_value=poller),
          patch.object(m.time,'monotonic_ns',return_value=1),patch.object(Path,'read_text',return_value='boot\n'),
          patch.object(Path,'read_bytes',return_value=b'python'),patch.object(m.os,'readlink',return_value=str(m.ROOT)),
          patch.object(m.os.path,'lexists',return_value=False),patch.object(m.signal,'pidfd_send_signal',side_effect=signal)):
        if mutation:mutation(activation,ready,calls)
        try:result=activation.activate()
        except BaseException:
            assert not any(event[0]=='signal' for event in calls)
            if any(event[0]=='open' for event in calls):assert calls[-1]==('close',55)
            raise
        return result,activation,calls


class Tests(unittest.TestCase):
    def test_fixed_pidfd_once_held_through_signal(self):
        result,a,calls=run(*setup())
        self.assertEqual(calls,[('open',78),('signal',55),('close',55)])
        self.assertTrue(a.sent);self.assertFalse(result['qualification_possible']);self.assertIsNone(a.handle)
        with self.assertRaisesRegex(m.ActivationError,'one-shot'):a.activate()
    def test_pidfd_death_and_error_never_signal_closes(self):
        for event in (1,17,8):
            with self.subTest(event=event),self.assertRaisesRegex(m.ActivationError,'PIDfd'):run(*setup(),poll_events=[(55,event)])
    def test_reused_partial_or_foreign_producer(self):
        for change in ({'starttime':'999'},{'uid':1001},{'ppid':88},{'state':'Z'},{'argv':['/usr/bin/python3','other']}):
            meta,buffers,actor,modules=setup();actor.process_identity.return_value.update(change)
            with self.subTest(change=change),self.assertRaises((m.ActivationError,life.LifecycleError)):run(meta,buffers,actor,modules)
        args=setup();args[2].process_identity.return_value={'pid':78}
        with self.assertRaises(life.LifecycleError):run(*args)
    def test_pending_or_failed_readiness_never_signal(self):
        for change in ({'ready':True},{'consumed':True},{'awaiting_activation':False},{'failed':True},{'activation_invalid':True},{'activated_ns':1},{'schema_version':True}):
            with self.subTest(change=change),self.assertRaises(m.ActivationError):
                run(*setup(),mutation=lambda a,r,c:r.update(change))
    def test_snapshot_bytes_identity_and_socket_changes(self):
        args=setup();args[2].FixedAdapter.public_snapshot.return_value['directories']={'changed':True}
        with self.assertRaisesRegex(m.ActivationError,'Public file'):run(*args)
        args=setup();args[2].socket_identity.return_value={**args[0]['socket'],'ino':99}
        with self.assertRaisesRegex(m.ActivationError,'inode'):run(*args)
    def test_wrong_scope_clock_or_controls(self):
        for change in ({'root':'/other'},{'prepared_ns':True},{'activation_expires_ns':1800},{'producer_argv':['x']},{'budget_seconds':{}},{'endpoint':'/other'},{'socket':None}):
            args=setup();args[0].update(change)
            with self.subTest(change=change),self.assertRaises(m.ActivationError):run(*args)
    def test_source_change_rejected_before_pidfd(self):
        args=setup();args[1]['plugin-dedicated-plan-capture.py']+=b'\n'
        with self.assertRaisesRegex(m.ActivationError,'source changed'):run(*args)
    def test_parser_duplicate_and_nonfinite(self):
        for data in (b'{"x":1,"x":2}',b'{"x":NaN}'):
            with self.assertRaises(m.ActivationError):m.parse(data)
    def test_default_off_without_loading_or_signaling(self):
        with patch.object(m,'load_host') as load,patch.object(m.signal,'pidfd_send_signal') as send,patch('sys.argv',['activate']):
            self.assertEqual(m.main(),0);load.assert_not_called();send.assert_not_called()
    def test_boot_executable_cwd_expiry_guards(self):
        # Direct guard failures still have activate's finally close.
        for kind in ('boot','executable','cwd','expiry'):
            def mutation(a,r,c):
                original=a.guard
                def guard():
                    if kind=='boot':a.meta['boot_id']='other'
                    elif kind=='executable':a.meta['python_exe_sha256']='f'*64
                    elif kind=='cwd':
                        with patch.object(m.os,'readlink',return_value='/other'):return original()
                    else:a.meta['activation_expires_ns']=0
                    return original()
                a.guard=guard
            with self.subTest(kind=kind),self.assertRaises(m.ActivationError):run(*setup(),mutation=mutation)


if __name__=='__main__':unittest.main(verbosity=2)
