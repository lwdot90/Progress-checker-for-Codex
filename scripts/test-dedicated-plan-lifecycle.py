#!/usr/bin/python3
"""Pure synthetic lifecycle facts; no real process, PIDfd, fixture or state."""
import copy
from pathlib import Path
import unittest

HERE = Path(__file__).parent
# Existing bounded loader imports reviewed pure synthetic helpers only.
import importlib.util
import hashlib
def load(name, sha):
    path = HERE/name; data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == sha
    spec = importlib.util.spec_from_file_location(name.replace('-','_'),path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(data,str(path),'exec'),module.__dict__)
    return module
l = load('plugin-dedicated-plan-lifecycle.py','1a52ba75e8b230dff8bf548b302084c759899de90a0a2bc8fc599ec90028d30e')
p = load('test-dedicated-plan-public.py','c86b34e5b17aa936ac325d208ed9a4d4263ca9dc590c23c0287e109200eb796e')
m, t = p.m, p.t
PREFIX = '/home/luis/progress-checker/.local/dedicated-synthetic/extracted/progress-checker-0.2.1-dev-linux-x86_64/plugin/bin'
META = {'root':l.ROOT,'state':l.STATE,'archive_sha256':l.ARCHIVE,'job_id':p.JOB,'nonce':p.NONCE,
        'producer':{'pid':100,'starttime':'10','uid':1000,'state':'S','ppid':1,
                    'argv':['/usr/bin/python3','fixed-collector']},'python_exe_sha256':'c'*64,
        'endpoint':'/home/luis/progress-checker/.local/dedicated-synthetic/observe.sock',
        'runtime_files':{PREFIX+'/'+name:value for name,value in l.HASHES.items()}}


def process_set(session):
    offset = 200 if session == 'initial' else 300
    args = ['--root',l.ROOT,'--state-dir',l.STATE]
    records = {}
    for role, delta in [('client',0),('backend',1),('adapter',2),('watchdog',3),('health-probe',4)]:
        argv = {'client':['/usr/bin/python3',PREFIX+'/checker-plugin']+args,
                'backend':[PREFIX+'/progress-checker']+args+['serve'],
                'adapter':[PREFIX+'/progress-checker-mcp']+args,
                'watchdog':['/usr/bin/python3',PREFIX+'/checker-plugin']+args+['--watch-service',str(offset+1),'20'],
                'health-probe':[PREFIX+'/progress-checker']+args+['status']}[role]
        info = {'pid':offset+delta,'starttime':'20','uid':1000,'state':'S',
                'ppid':100 if role=='client' else offset,'argv':argv}
        native = 'progress-checker-mcp' if role=='adapter' else 'progress-checker'
        records[role] = {'session':session,'role':role,'operation':'start','pid_identity':info,
          'executable_sha256':META['python_exe_sha256'] if role in {'client','watchdog'} else l.HASHES[native],
          'argv':argv,'root':l.ROOT,'state':l.STATE,'returncode':None,
          'endpoint_identity':{'dev':1,'ino':offset,'uid':1000,'mode':0o600,'mtime_ns':1,'ctime_ns':1},
          'lease_snapshot':{'owned.json':{'pid':offset,'starttime':'20'}},
          'service_record':{'pid':offset+1,'starttime':'20'}}
    return records


def transcript(blocked=False):
    frames = []
    records = {}
    def event(payload):
        frames.append({'schema_version':1,'sequence':0,'job_id':p.JOB,'nonce':p.NONCE,
                       'monotonic_ns':0,'kind':'process','payload':copy.deepcopy(payload)})
    for frame in [m.strict(line) for line in p.enrich(blocked)]:
        if frame['kind']=='session-close':
            session = frame['payload']['session']; selected = records[session]
            eof = copy.deepcopy(selected['client']); eof['operation'] = 'EOF'; event(eof)
            exited = copy.deepcopy(eof); exited.update(operation='exit',returncode=0); event(exited)
            for record in selected.values():
                drained = copy.deepcopy(record)
                drained.update(operation='drain',returncode=0 if record['role']=='client' else None,
                               endpoint_identity=None,lease_snapshot={},service_record=None,
                               pidfd_poll_revents=17,current_identity=None,fixture_processes=[])
                event(drained)
        frames.append(frame)
        if frame['kind']=='session-open':
            session = frame['payload']['session']; records[session] = process_set(session)
            for record in records[session].values(): event(record)
    return p.serialize(frames)


def evaluate(lines, meta=META, source=p.CAPTURE):
    return l.evaluate(lines,meta,source)


def selected(role, operation='drain', session='initial'):
    return lambda f:f['kind']=='process' and f['payload']['role']==role and f['payload']['operation']==operation and f['payload']['session']==session


class Tests(unittest.TestCase):
    def test_full_reaped17(self):
        lines = transcript(); result = evaluate(lines)
        self.assertTrue(result['captured_lifecycle_semantics_passed'])
        self.assertEqual(set(result['sessions']),{'initial','restart'})
        self.assertEqual(result['full_transcript_frame_count'],len(lines))
        self.assertFalse(result['qualification_possible']); self.assertFalse(result['complete'])
    def test_blocked_initial_only(self):
        result = evaluate(transcript(True))
        self.assertEqual(result['body_phase'],'blocked'); self.assertEqual(set(result['sessions']),{'initial'})
        self.assertFalse(result['qualification_possible'])
    def test_zombie_empty_argv(self):
        def change(f):
            info = copy.deepcopy(f['payload']['pid_identity']); info.update(state='Z',argv=[])
            f['payload'].update(current_identity=info,pidfd_poll_revents=1)
        self.assertTrue(evaluate(t.mutate(transcript(),selected('backend'),change))['captured_lifecycle_semantics_passed'])
    def test_reused_nonfixture_pid(self):
        def change(f):
            info = copy.deepcopy(f['payload']['pid_identity']); info.update(starttime='21',argv=['unrelated-public-process'])
            f['payload']['current_identity'] = info
        self.assertTrue(evaluate(t.mutate(transcript(),selected('backend'),change))['captured_lifecycle_semantics_passed'])
    def test_foreign_live_fixture_pid(self):
        def change(f):
            info = copy.deepcopy(f['payload']['pid_identity']); info['starttime'] = '21'
            f['payload']['current_identity'] = info
        with self.assertRaises(l.LifecycleError): evaluate(t.mutate(transcript(),selected('backend'),change))
    def test_malformed_death_and_runtime(self):
        changes = [lambda f:f['payload'].update(current_identity={'pid':201}),
                   lambda f:f['payload'].update(current_identity=copy.deepcopy(f['payload']['pid_identity'])),
                   lambda f:f['payload'].update(pidfd_poll_revents=True),
                   lambda f:f['payload'].update(pidfd_poll_revents=16),
                   lambda f:f['payload'].update(pidfd_poll_revents=33),
                   lambda f:f['payload'].update(fixture_processes=[{'pid':999}]),
                   lambda f:f['payload'].update(lease_snapshot={'foreign.json':{'pid':999,'starttime':'20'}}),
                   lambda f:f['payload'].update(service_record={'pid':201,'starttime':'20'}),
                   lambda f:f['payload'].update(endpoint_identity={'dev':1,'ino':200,'uid':1000,'mode':0o600,'mtime_ns':1,'ctime_ns':1})]
        for index,change in enumerate(changes):
            with self.subTest(case=index), self.assertRaises(l.LifecycleError): evaluate(t.mutate(transcript(),selected('backend'),change))
    def test_child_status_and_ancestry(self):
        cases = [(selected('client','exit'),lambda f:f['payload'].update(returncode=1)),
                 (selected('client','exit'),lambda f:f['payload'].update(returncode=True)),
                 (selected('adapter','start'),lambda f:f['payload']['pid_identity'].update(ppid=999)),
                 (selected('backend','start'),lambda f:f['payload'].update(executable_sha256='d'*64)),
                 (selected('backend','start'),lambda f:f['payload'].update(lease_snapshot={'foreign.json':{'pid':999,'starttime':'20'}})),
                 (selected('backend','start'),lambda f:f['payload'].update(service_record={'pid':201,'starttime':'21'})),
                 (selected('backend','start'),lambda f:f['payload']['pid_identity'].update(uid=True)),
                 (selected('backend','start'),lambda f:f['payload'].update(passed=True))]
        for index,(predicate,change) in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(l.LifecycleError): evaluate(t.mutate(transcript(),predicate,change))
    def test_drain_before_restart(self):
        frames = [m.strict(line) for line in transcript()]
        index = next(i for i,f in enumerate(frames) if selected('backend')(f))
        moved = frames.pop(index)
        target = next(i for i,f in enumerate(frames) if selected('client','start','restart')(f))
        frames.insert(target+1,moved)
        with self.assertRaises(l.LifecycleError): evaluate(p.serialize(frames))
    def test_pid_reuse_within_session(self):
        frames = [m.strict(line) for line in transcript()]
        record = next(copy.deepcopy(f) for f in frames if selected('health-probe','start')(f))
        record['payload']['pid_identity']['starttime'] = '21'
        index = next(i for i,f in enumerate(frames) if selected('health-probe','start')(f))
        frames.insert(index+1,record)
        with self.assertRaises(l.LifecycleError): evaluate(p.serialize(frames))
    def test_restart_backend_must_differ(self):
        frames = [m.strict(line) for line in transcript()]
        for frame in frames:
            if frame['kind'] != 'process' or frame['payload']['session'] != 'restart': continue
            payload = frame['payload']
            if payload['role'] == 'backend': payload['pid_identity']['pid'] = 201
            if payload['service_record'] is not None: payload['service_record']['pid'] = 201
            if payload['role'] == 'watchdog':
                payload['argv'][-2] = '201'; payload['pid_identity']['argv'][-2] = '201'
        with self.assertRaisesRegex(l.LifecycleError,'different actual backend identity'): evaluate(p.serialize(frames))
    def test_required_role_cannot_be_omitted(self):
        frames = [m.strict(line) for line in transcript()]
        frames = [f for f in frames if not (f['kind']=='process' and f['payload']['role']=='watchdog')]
        with self.assertRaises(l.LifecycleError): evaluate(p.serialize(frames))
    def test_registration_and_source_pins(self):
        for change in [lambda meta:meta.update(root='/other'),lambda meta:meta.update(archive_sha256='d'*64),
                       lambda meta:meta['producer'].update(argv=[]),lambda meta:meta['producer'].update(state='Z')]:
            meta = copy.deepcopy(META); change(meta)
            with self.assertRaises(l.LifecycleError): evaluate(transcript(),meta)
        with self.assertRaises(l.LifecycleError): evaluate(transcript(),source=p.CAPTURE+b'\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
