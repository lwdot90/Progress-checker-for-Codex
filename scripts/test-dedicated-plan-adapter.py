#!/usr/bin/python3
"""Frozen actual-body integration with entirely fake pipe/process/filesystem I/O.

No dedicated fixture, backend, service, PIDfd, command check, grant or approval
is accessed. Original plan_invalidation and LauncherSession methods execute;
the fake RPC peer supplies invented development responses, not verification.
"""
import ast
import base64
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
from pathlib import Path
import threading
import types
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).parent
SHA = 'd8b02f2b3cb6ac45d0daf0d9753479ed7001a9dea1433f8b3a428b5a791fd646'
def load(name, sha):
    path = HERE/name; source = path.read_bytes()
    assert hashlib.sha256(source).hexdigest() == sha
    module = types.ModuleType(name.replace('-','_')); module.__file__ = str(path)
    exec(compile(source,str(path),'exec'),module.__dict__)
    return module,source
a, ADAPTER_SOURCE = load('plugin-dedicated-plan-adapter.py',SHA)
p, _ = load('test-dedicated-plan-public.py','c86b34e5b17aa936ac325d208ed9a4d4263ca9dc590c23c0287e109200eb796e')
BUFFERS = {'plugin-acceptance.py':p.SOURCE,'plugin-dedicated-plan-capture.py':p.CAPTURE}
COLLECTION = '/home/luis/progress-checker/.local/dedicated-adapter-public-synthetic'


class Pipe:
    def __init__(self,fd): self.fd,self.closed = fd,False
    def fileno(self): return self.fd
    def close(self): self.closed = True
    def __enter__(self): return self
    def __exit__(self,*args): self.close()


class Child:
    def __init__(self,pid):
        self.pid,self.returncode,self.waits,self.terms = pid,None,0,0
        self.stdin,self.stdout = Pipe(pid+1000),Pipe(pid+2000)
    def poll(self): return self.returncode
    def wait(self,timeout=None): self.waits += 1; self.returncode = 0; return 0
    def terminate(self): self.terms += 1; raise AssertionError('No actual actor signaling allowed')


class FakeLayout:
    def __init__(self):
        self.remains,self.absence_calls = False,0
        self.last_census = None
        self.endpoint = types.SimpleNamespace(exists=lambda:False)
    def metadata(self): return None,{}
    def matches(self,info): return '--root' in info['argv'] and str(a.FIXTURE) in info['argv']
    def absent(self):
        self.absence_calls += 1
        self.last_census = {'service_record':{'pid':999,'starttime':'1'} if self.remains else None,
                           'lease_snapshot':{},'endpoint_identity':None,'fixture_processes':[]}
        a.require(not self.remains,'Synthetic remaining backend runtime')
        return self.last_census


class FakeOwned:
    """Ownership dependency is fake here; separate tests execute real cleanup."""
    fail = None
    instances = []
    def __init__(self,adapter,process,session):
        self.adapter,self.process,self.session = adapter,process,session
        self.stop,self.owned = threading.Event(),{}
        self.resource_state = {'synthetic_only':True}
        self.shutdowns,self.operations = 0,[]
        self.instances.append(self)
    def start(self):
        if self.fail == 'start': raise a.AdapterError('synthetic start failure')
        self.owned[self.process.pid] = {'synthetic_only':True}
    def flush(self):
        if self.fail == 'flush': raise a.AdapterError('synthetic flush failure')
    def sample(self): pass
    def operation(self,name,returncode=None):
        self.operations.append((name,returncode))
        if self.fail == 'EOF-capture' and name == 'EOF': raise a.AdapterError('synthetic EOF capture failure')
    def shutdown(self): self.shutdowns += 1; self.stop.set(); return True
    def drain(self): self.shutdown()
    def term_client(self): raise AssertionError('No synthetic TERM fallback expected')


class Peer:
    def __init__(self,blocked=False,fail_initial=False):
        self.config = copy.deepcopy(p.t.Synthetic().config)
        self.claims,self.latest,self.revision,self.config_hash = {},{},1,'hash-1'
        self.blocked,self.fail_initial,self.submitted,self.started = blocked,fail_initial,False,False
        self.polls,self.buffers,self.children,self.requests = 0,{},[],[]
    def popen(self,argv,**kwargs):
        child = Child(200+100*len(self.children)); self.children.append(child)
        self.buffers[child.stdout.fd] = bytearray()
        return child
    def write(self,fd,data):
        child = next(c for c in self.children if c.stdin.fd == fd)
        request = json.loads(data); self.requests.append(request)
        if request['method']=='notifications/initialized': return len(data)
        result = self.reply(request)
        raw = json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result},indent=None).encode()+b'\n'
        self.buffers[child.stdout.fd].extend(raw)
        return len(data)
    def read(self,fd,size):
        available = self.buffers[fd]; count = min(size,len(available),37)
        data = bytes(available[:count]); del available[:count]; return data
    def select(self,read,write,error,timeout=None):
        return ([value for value in read if self.buffers.get(value.fileno())],write,[])
    def receipt(self,result=None,error=None):
        receipt = {'revision':self.revision,'result':result} if error is None else {'error':{'code':error}}
        return {'isError':error is not None,'structuredContent':copy.deepcopy(receipt),
                'content':[{'type':'text','text':json.dumps(receipt)}]}
    def reply(self,q):
        if q['method']=='initialize': return {}
        if q['method']=='tools/list': return {'tools':[{'name':name} for name in sorted(p.p.source_inventory(p.SOURCE)['expected_tools'])]}
        assert q['method']=='tools/call'
        name,args = q['params']['name'],q['params']['arguments']
        if name=='checker_get_project':
            verified,running = 0,[]
            if self.started and not self.submitted:
                self.polls += 1
                if self.polls == 1: running = ['child']
                else:
                    self.latest = {'plan-check':{'run_id':'child','execution_state':'finished','outcome':'passed','freshness':'current'}}
                    verified = 3
            if self.fail_initial: verified = 1
            return self.receipt({'canonical_root':str(a.FIXTURE),'running':running,'config':self.config,
                'claims':self.claims,'status':{'source':{'config_hash':self.config_hash},
                'latest':self.latest,'progress':{'verified':verified}}})
        if name=='checker_get_plan_history': return self.receipt({'total':2,'items':[]})
        assert type(args['expected_revision']) is int and args['expected_revision']==self.revision
        if name=='checker_set_claim':
            self.claims[args['milestone_id']] = args['claim']; self.revision += 1
            return self.receipt({})
        assert args['expected_config_hash']==self.config_hash
        if name=='checker_run_checks':
            if self.blocked or self.submitted: return self.receipt(error='PERMISSION_REQUIRED')
            self.started = True; self.revision += 1
            return self.receipt({'run_ids':['child'],'run_id':'batch'})
        assert name=='checker_submit_plan'
        self.config = copy.deepcopy(args['config']); self.submitted = True; self.revision += 1
        self.config_hash = 'hash-2'; self.latest['plan-check']['freshness'] = 'stale'
        return self.receipt({})


def integration(blocked=False,fail_initial=False,eof=False):
    adapter = a.FixedAdapter(BUFFERS,COLLECTION,p.JOB,p.NONCE,'c'*64)
    peer = Peer(blocked,fail_initial); adapter.layout = FakeLayout()
    real_sha = hashlib.sha256
    def read_bytes(path):
        text = str(path)
        if text==str(a.FIXTURE/'.progress-checker/config.json'): return p.m.encode(peer.config)
        if text==str(a.FIXTURE/'plan-check.py'): return p.p.SCRIPT
        if text==str(a.FIXTURE/'feature.txt'): return p.p.FEATURE
        if text==str(a.ARCHIVE): return b'ARCHIVE'
        if text=='/proc/self/exe': return b'PYTHON'
        for name in a.RUNTIME_HASHES:
            if text==str(adapter.plugin/'bin'/name): return name.encode()
        raise AssertionError('Unmocked filesystem read: '+text)
    def sha(data):
        values = {b'ARCHIVE':a.ARCHIVE_SHA,b'PYTHON':'c'*64,
                  **{name.encode():value for name,value in a.RUNTIME_HASHES.items()}}
        if data in values: return types.SimpleNamespace(hexdigest=lambda:values[data])
        return real_sha(data)
    def anchored(path,limit):
        data = read_bytes(path)
        info = {'device':1,'inode':1,'mode':0o644,'uid':1000,'nlink':1,'size':len(data),
                'mtime_ns':1,'ctime_ns':1,'regular':True}
        return data,info,copy.deepcopy(info),copy.deepcopy(info)
    def directory(path):
        return {'path':str(path),'device':1,'inode':20,'uid':1000,'mode':0o700,
                'directory':True,'symlink':False}
    FakeOwned.fail=None; FakeOwned.instances=[]
    with ExitStack() as stack:
        for target,attribute,value in [(a,'Ownership',FakeOwned),(a,'anchored',anchored),(a,'directory_record',directory),
          (Path,'read_bytes',read_bytes),(Path,'resolve',lambda path,strict=False:path),
          (Path,'is_file',lambda path:True),(Path,'is_symlink',lambda path:False),
          (Path,'exists',lambda path:False),(Path,'mkdir',lambda path,**kwargs:None),
          (Path,'open',lambda path,*args,**kwargs:Pipe(-1)),(a.os,'getuid',lambda:1000),(a.os,'getpid',lambda:100),
          (a.os,'set_blocking',lambda *args:None),(a.os,'write',peer.write),(a.os,'read',lambda fd,size:b'' if eof else peer.read(fd,size)),
          (a.select,'select',peer.select),(a.subprocess,'Popen',peer.popen),
          (a.subprocess,'run',lambda argv,**kwargs:types.SimpleNamespace(returncode=0,stdout=(str(a.FIXTURE)+'\n').encode(),stderr=b'')),
          (a.time,'sleep',lambda duration:None),(a.hashlib,'sha256',sha)]:
            stack.enter_context(patch.object(target,attribute,value))
        result = adapter.run_once()
    return adapter,peer,result


class DummyThread:
    def __init__(self,alive=False): self.ident=1; self.alive=alive; self.joins=[]; self.started=False
    def join(self,timeout=None): self.joins.append(timeout)
    def is_alive(self): return self.alive
    def start(self): self.started=True


class Tests(unittest.TestCase):
    def test_actual_body_full18(self):
        adapter,peer,result = integration()
        self.assertEqual(result['body_exit'],0)
        self.assertEqual(len(result['original_report']['assertions']),18)
        self.assertTrue(all(value['passed'] for value in result['original_report']['assertions']))
        self.assertEqual(peer.polls,2)
        self.assertEqual(len(peer.children),2)
        self.assertTrue(all(child.waits==1 and child.stdin.closed and child.stdout.closed for child in peer.children))
        observed = p.p.evaluate(result['lines'],p.JOB,p.NONCE,p.SOURCE,p.CAPTURE)
        self.assertEqual(observed['status'],'full-public-captured-semantics')
        self.assertFalse(result['qualification_possible']); self.assertFalse(observed['qualification_possible'])
        with self.assertRaises(a.AdapterError): adapter.run_once()
    def test_actual_body_blocked6(self):
        adapter,peer,result = integration(blocked=True)
        self.assertEqual(result['body_exit'],0)
        self.assertEqual(len(result['original_report']['assertions']),6)
        self.assertEqual(result['original_report']['plan_invalidation_probe']['status'],'blocked')
        self.assertEqual(len(peer.children),1); self.assertFalse(peer.submitted)
        self.assertEqual(p.p.evaluate(result['lines'],p.JOB,p.NONCE,p.SOURCE,p.CAPTURE)['status'],
                         'blocked-missing-grant-captured-semantics')
    def test_real_assertion_RuntimeError_finally(self):
        adapter,peer,result = integration(fail_initial=True)
        self.assertEqual(result['body_exit'],2)
        frames = [p.m.strict(line) for line in result['lines']]
        assertions = [frame['payload'] for frame in frames if frame['kind']=='original-assertion']
        self.assertEqual([value['passed'] for value in assertions],[True,True,True,False,True])
        self.assertEqual(assertions[-2]['exception_type'],'RuntimeError')
        self.assertEqual(frames[-1]['payload']['error_type'],'RuntimeError')
        self.assertTrue(peer.children[0].stdin.closed); self.assertEqual(peer.children[0].waits,1)
    def test_original_receive_EOF_RuntimeError_preserved(self):
        adapter,peer,result=integration(eof=True)
        self.assertEqual(result['body_exit'],2)
        terminal=p.m.strict(result['lines'][-1])['payload']
        self.assertEqual(terminal['error_type'],'RuntimeError')
        self.assertEqual(terminal['error'],'MCP closed before a complete response')
        self.assertTrue(adapter.capture.pending)
        self.assertEqual(len(terminal['uncorrelated_closes']),1)
        self.assertFalse(terminal['uncorrelated_closes'][0]['qualification_possible'])
        self.assertFalse(result['qualification_possible'])
        self.assertTrue(peer.children[0].stdin.closed); self.assertEqual(peer.children[0].waits,1)
    def test_original_body_AST_boundary(self):
        tree = ast.parse(ADAPTER_SOURCE)
        calls = [n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
                 and n.func.attr=='plan_invalidation']
        self.assertEqual(len(calls),1)
        self.assertEqual(hashlib.sha256(BUFFERS['plugin-acceptance.py']).hexdigest(),a.SOURCE_HASHES['plugin-acceptance.py'])
    def startup(self,fail=None,setblocking_error=False,backend=False,capture_error=False):
        adapter = a.FixedAdapter(BUFFERS,COLLECTION,p.JOB,p.NONCE,'c'*64)
        adapter.budget=a.Budget(); adapter.layout=FakeLayout()
        adapter.layout.remains=backend
        child=Child(200)
        session=types.SimpleNamespace(label='initial',closed=False,raw_buffer=bytearray(),adapter=adapter)
        adapter.creating=session
        FakeOwned.fail=fail; FakeOwned.instances=[]
        def setblocking(*args):
            if setblocking_error: raise OSError('synthetic setblocking failure')
        with (patch.object(a,'Ownership',FakeOwned),patch.object(a.subprocess,'Popen',lambda *args,**kwargs:child),
             patch.object(a.os,'set_blocking',setblocking)):
            facade=a.SubprocessFacade(adapter)
            if capture_error:
                FakeOwned.fail='EOF-capture'
                # Qualified fake startup followed by a nonblocking setup failure.
                setblocking_error=True
            with self.assertRaises((a.AdapterError,OSError)):
                facade.Popen([str(adapter.plugin/'bin/checker-plugin'),'--root',str(a.FIXTURE),'--state-dir',str(a.STATE)],
                             stdin=-1,stdout=-1)
        return adapter,session,child
    def test_start_flush_setblocking_failure_ownEOFwait(self):
        for failure,setblocking in [('start',False),('flush',False),(None,True)]:
            adapter,session,child=self.startup(failure,setblocking)
            self.assertTrue(child.stdin.closed); self.assertTrue(child.stdout.closed)
            self.assertEqual(child.waits,1); self.assertEqual(child.terms,0)
            self.assertTrue(session.owned.stop.is_set()); self.assertTrue(session.closed)
            self.assertTrue(session.abort_facts['runtime_absent'])
    def test_capture_failure_cannot_skip_wait(self):
        adapter,session,child=self.startup(capture_error=True)
        self.assertEqual(child.waits,1); self.assertTrue(child.stdin.closed)
        self.assertTrue(adapter.cleanup_errors)
    def test_live_backend_after_parent_wait_quarantined(self):
        adapter,session,child=self.startup(setblocking_error=True,backend=True)
        self.assertEqual(child.waits,1); self.assertFalse(session.closed)
        self.assertFalse(session.abort_facts['runtime_absent'])
        self.assertEqual(session.abort_facts['public_census']['service_record']['pid'],999)
        self.assertTrue(adapter.cleanup_errors); self.assertEqual(child.terms,0)
    def ownership(self,alive=False):
        adapter=types.SimpleNamespace(layout=FakeLayout(),budget=a.Budget(),cleanup_errors=[],bootstrap_diagnostics=[],
                                      plugin=Path(COLLECTION)/'extracted/progress-checker-0.2.1-dev-linux-x86_64/plugin',
                                      python_sha='c'*64,capture=types.SimpleNamespace(pending=None),emit=Mock())
        owned=a.Ownership(adapter,Child(200),'initial'); owned.thread=DummyThread(alive)
        owned.owned={200:{'pidfd':70,'role':'client'}}
        return adapter,owned
    def test_monitor_alive_retainsFDs(self):
        adapter,owned=self.ownership(True)
        with patch.object(a.os,'close') as close:
            self.assertFalse(owned.shutdown()); close.assert_not_called()
        self.assertTrue(owned.stop.is_set()); self.assertEqual(owned.resource_state['pidfds_retained'],[70])
        self.assertTrue(adapter.cleanup_errors)
    def test_drain_failure_always_stops_joins_closes(self):
        adapter,owned=self.ownership()
        with (patch.object(owned,'observe_drain',side_effect=a.AdapterError('synthetic drain failure')),
             patch.object(a.os,'close') as close):
            with self.assertRaisesRegex(a.AdapterError,'synthetic drain failure'): owned.drain()
            close.assert_called_once_with(70)
            self.assertTrue(owned.stop.is_set()); self.assertTrue(owned.thread.joins)
            with self.assertRaises(a.AdapterError): owned.drain()
            close.assert_called_once_with(70)
    def test_exact_returnedPIDfd_bootstrap_empty_then_full(self):
        adapter,owned=self.ownership()
        owned.owned={}
        argv=['/usr/bin/python3',str(adapter.plugin/'bin/checker-plugin'),'--root',str(a.FIXTURE),'--state-dir',str(a.STATE)]
        empty={'pid':200,'starttime':'20','uid':0,'state':'R','ppid':100,'argv':[]}
        full=dict(empty,uid=1000,argv=argv)
        poll=types.SimpleNamespace(register=lambda *args:None,poll=lambda *args:[])
        with (patch.object(a.os,'pidfd_open',return_value=70) as opened,
              patch.object(a.os,'getpid',return_value=100),
              patch.object(a,'process_identity',side_effect=[empty,full]),
              patch.object(a.select,'poll',return_value=poll),
              patch.object(Path,'read_bytes',return_value=b'FAKEPYTHON'),
              patch.object(a,'digest',return_value='c'*64),patch.object(a.time,'sleep',return_value=None),
              patch.object(a.os,'close') as closed):
            owned.start(); opened.assert_called_once_with(200,0)
            self.assertEqual(owned.owned[200]['identity'],full)
            self.assertTrue(owned.thread.started); self.assertFalse(adapter.bootstrap_diagnostics[0]['qualification_possible'])
            owned.shutdown(); closed.assert_called_once_with(70)
    def test_bootstrap_rejects_foreignargv_or_identity_change(self):
        for changed in ('argv','starttime'):
            adapter,owned=self.ownership(); owned.owned={}
            empty={'pid':200,'starttime':'20','uid':0,'state':'R','ppid':100,'argv':[]}
            foreign=dict(empty,uid=1000)
            foreign[changed]=['foreign'] if changed=='argv' else '21'
            poll=types.SimpleNamespace(register=lambda *args:None,poll=lambda *args:[])
            with (patch.object(a.os,'pidfd_open',return_value=70) as opened,
                  patch.object(a.os,'getpid',return_value=100),
                  patch.object(a,'process_identity',side_effect=[empty,foreign]),
                  patch.object(a.select,'poll',return_value=poll),patch.object(a.time,'sleep',return_value=None),
                  patch.object(a.os,'close') as closed):
                with self.assertRaises(a.AdapterError): owned.start()
                opened.assert_called_once_with(200,0); closed.assert_not_called()
                self.assertFalse(owned.thread.started)
                owned.shutdown(); closed.assert_called_once_with(70)


if __name__ == '__main__':
    unittest.main(verbosity=2)
