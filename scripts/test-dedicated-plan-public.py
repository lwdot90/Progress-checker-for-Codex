#!/usr/bin/python3
"""Frozen-source public synthetic tests; no actual fixture or host actions."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent
PUBLIC_SHA = '977ce1b54f9b73386d0db90e59b7ae0a3b9189ff7ee95967ca884d32c98531b2'
def load(name, sha):
    path = HERE/name; data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == sha
    spec = importlib.util.spec_from_file_location(name.replace('-','_'),path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(data,str(path),'exec'),module.__dict__)
    return module
p = load('plugin-dedicated-plan-public.py',PUBLIC_SHA)
t = load('test-dedicated-plan-capture.py','dfc2ce354ca3b356c42312a15ddb6948ed476a681fd4bc33cf6cd42f6fcba894')
SOURCE = (HERE/'plugin-acceptance.py').read_bytes()
CAPTURE = (HERE/'plugin-dedicated-plan-capture.py').read_bytes()
m, JOB, NONCE = t.m, t.JOB, t.NONCE


def snapshot(role, config):
    files = []
    for index, (name, raw) in enumerate([('config',m.encode(config)),('script',p.SCRIPT),('feature',p.FEATURE)],1):
        stat = {'device':1,'inode':index,'mode':0o644,'uid':1000,'nlink':1,'size':len(raw),
                'mtime_ns':1,'ctime_ns':1,'regular':True}
        files.append({'role':name,'bytes_base64':base64.b64encode(raw).decode(),
                      'before_stat':stat,'after_stat':copy.deepcopy(stat),'path_lstat':copy.deepcopy(stat)})
    directories = {}
    for name, path in [('root',m.ROOT),('state',m.STATE),('config',m.ROOT+'/.progress-checker')]:
        directories[name] = {'path':path,'device':1,'inode':20,'uid':1000,
                             'mode':0o700 if name=='state' else 0o755,'directory':True,'symlink':False}
    return {'role':role,'root':m.ROOT,'state':m.STATE,'files':files,'directories':directories}


def enrich(blocked=False):
    lines = t.Synthetic().blocked() if blocked else t.Synthetic().success()
    classified = m.classify_serialized(lines,JOB,NONCE)['classified_frames']
    inventory = p.source_inventory(SOURCE)
    names = inventory['blocked_names'] if blocked else inventory['success_names']
    frames = []
    def add(kind,payload): frames.append({'schema_version':1,'sequence':0,'job_id':JOB,'nonce':NONCE,
                                         'monotonic_ns':0,'kind':kind,'payload':payload})
    def assertion(name, passed=True): add('original-assertion',{'name':name,'passed':passed,'exception_type':None if passed else 'RuntimeError'})
    initial_config = next(item['frame']['payload']['decoded']['result']['structuredContent']['result']['config']
                          for item in classified if item['frame']['kind']=='response' and item['phase']=='initial')
    add('public-files',snapshot('initial',initial_config)); assertion(names[0])
    add('git-root',{'argv':['/usr/bin/git','-C',m.ROOT,'rev-parse','--show-toplevel'],'exit_code':0,
                    'stdout_base64':base64.b64encode((m.ROOT+'\n').encode()).decode(),'stderr_base64':''})
    assertion(names[1])
    last_config = initial_config
    for item in classified:
        frame, phase = copy.deepcopy(item['frame']), item['phase']
        if frame['kind']=='response' and phase=='tools/list':
            frame['payload']['decoded']['result']['tools'] = [{'name':name} for name in sorted(inventory['expected_tools'])]
            frame['payload']['line_base64'] = base64.b64encode(m.encode(frame['payload']['decoded'])).decode()
        if frame['kind']=='terminal':
            frame['payload'].update(body_exit=0,error=None,error_type=None)
        if not blocked and frame['kind']=='session-close' and frame['payload']['session']=='restart':
            add('public-files',snapshot('final',last_config)); assertion(names[16])
        frames.append(frame)
        if frame['kind']=='response':
            if phase == 'tools/list': assertion(p.INIT)
            phase_to_name = {'initial':names[3],'claimed':names[4]}
            if not blocked:
                phase_to_name.update({'prior-grant':names[5],'poll-2':names[6],'submit':names[7],
                 'after-submit':names[8],'after-submit-refusal':names[9],'after-refusal':names[10],
                 'restart-history-after':names[13],'restart-refusal':names[14],'restart-refusal-state':names[15]})
            if phase in phase_to_name: assertion(phase_to_name[phase])
            if phase == 'restart-restored':
                last_config = frame['payload']['decoded']['result']['structuredContent']['result']['config']
        if frame['kind']=='session-close':
            if not blocked and frame['payload']['session']=='initial': assertion(names[11])
            else: assertion(names[-1])
    return serialize(frames)


def serialize(frames):
    for index,frame in enumerate(frames,1): frame.update(sequence=index,monotonic_ns=index)
    return [m.encode(frame) for frame in frames]


def evaluate(lines, body=SOURCE, capture=CAPTURE):
    return p.evaluate(lines,JOB,NONCE,body,capture)


class Tests(unittest.TestCase):
    def test_full(self):
        result = evaluate(enrich())
        self.assertEqual(result['status'],'full-public-captured-semantics')
        self.assertEqual(result['original_assertion_count'],18)
        self.assertEqual(result['raw_tool_inventory_count'],2)
        self.assertEqual(result['poll_count'],2)
        self.assertTrue(result['semantic_validation_passed'])
        self.assertFalse(result['complete']); self.assertFalse(result['qualification_possible'])
    def test_blocked(self):
        result = evaluate(enrich(True))
        self.assertEqual(result['status'],'blocked-missing-grant-captured-semantics')
        self.assertEqual(result['original_assertion_count'],6)
        self.assertFalse(result['semantic_validation_passed']); self.assertFalse(result['qualification_possible'])
    def test_failed_assertion_finally(self):
        frames = [m.strict(line) for line in enrich()]
        index = next(i for i,f in enumerate(frames) if f['kind']=='original-assertion'
                     and f['payload']['name']=='dedicated plan fixture initially has no evidence-derived verification')
        frames = frames[:index+1]
        frames[-1]['payload'].update(passed=False,exception_type='RuntimeError')
        final = copy.deepcopy(frames[-1]); final['payload'] = {'name':'dedicated plan invalidation packaged session closes cleanly',
                                                               'passed':True,'exception_type':None}
        terminal = copy.deepcopy(final); terminal.update(kind='terminal',payload={'body_exit':2,
                     'cleanup_complete':True,'error':'original failed assertion','error_type':'RuntimeError'})
        result = evaluate(serialize(frames+[final,terminal]))
        self.assertEqual(result['status'],'failed-original-assertion-captured-semantics')
        self.assertFalse(result['semantic_validation_passed'])
    def test_terminal_error_never_success(self):
        for blocked in (False,True):
            for key,value in [('error','nonempty failure'),('error_type','RuntimeError')]:
                lines = t.mutate(enrich(blocked),lambda f:f['kind']=='terminal',lambda f:f['payload'].update({key:value}))
                with self.subTest(blocked=blocked,key=key), self.assertRaises(p.PublicError): evaluate(lines)
    def test_missing_inventory_and_assertion(self):
        lines = enrich()
        def change(f): f['payload']['decoded']['result']['tools'] = []
        altered = t.mutate(lines,lambda f:f['kind']=='response' and 'tools' in f['payload']['decoded'].get('result',{}),change,True)
        with self.assertRaises(p.PublicError): evaluate(altered)
        frames = [m.strict(line) for line in lines]
        index = next(i for i,f in enumerate(frames) if f['kind']=='original-assertion' and f['payload']['name']==p.INIT)
        del frames[index]
        with self.assertRaises(p.PublicError): evaluate(serialize(frames))
    def test_public_identity_and_bytes(self):
        lines = enrich()
        changes = [lambda f:f['payload']['files'][1]['path_lstat'].update(inode=999),
                   lambda f:f['payload']['files'][1].update(bytes_base64=base64.b64encode(b'wrong').decode()),
                   lambda f:f['payload']['files'][2]['before_stat'].update(regular=False),
                   lambda f:f['payload']['directories']['state'].update(mode=0o755)]
        for index,change in enumerate(changes):
            altered = t.mutate(lines,lambda f:f['kind']=='public-files',change)
            with self.subTest(case=index), self.assertRaises(p.PublicError): evaluate(altered)
    def test_source_hash_mismatch(self):
        for body,capture in [(SOURCE+b'\n',CAPTURE),(SOURCE,CAPTURE+b'\n')]:
            with self.assertRaises(p.PublicError): evaluate(enrich(),body,capture)
    def test_cas_mutation_full_transcript(self):
        altered = t.mutate(enrich(),lambda f:t.tool(f,'checker_submit_plan'),
                          lambda f:f['payload']['decoded']['params']['arguments'].update(expected_revision=True),True)
        with self.assertRaisesRegex(ValueError,'Mutation revision differs'): evaluate(altered)
    def test_failed_assertion_not_rewritten(self):
        altered = t.mutate(enrich(),lambda f:f['kind']=='original-assertion',
                          lambda f:f['payload'].update(passed=False,exception_type='RuntimeError'))
        with self.assertRaises(p.PublicError): evaluate(altered)


if __name__ == '__main__':
    unittest.main(verbosity=2)
