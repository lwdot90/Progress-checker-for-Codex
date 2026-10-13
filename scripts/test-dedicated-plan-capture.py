#!/usr/bin/python3
"""Public synthetic tests only; no fixture, process, service or approval access."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

SOURCE = Path(__file__).with_name('plugin-dedicated-plan-capture.py')
FROZEN = 'a19413a48ca9f6fcd6b91344d21e66f0f6679aacad01cfc5d7359dcffc5d122c'
data = SOURCE.read_bytes()
assert hashlib.sha256(data).hexdigest() == FROZEN, 'Reviewed source freeze changed'
spec = importlib.util.spec_from_file_location('dedicated_capture', SOURCE)
m = importlib.util.module_from_spec(spec)
exec(compile(data, str(SOURCE), 'exec'), m.__dict__)
JOB, NONCE = 'a'*32, 'b'*64


class Synthetic:
    def __init__(self):
        self.capture = m.Capture(JOB, NONCE)
        self.ns, self.id, self.session, self.rev = 0, 0, 'initial', 1
        self.config = {'project_id':'isolated-plan-invalidation','checks':[m.CHECK],
                       'milestones':[{'id':x,'title':x,'criteria':[{'check_id':'plan-check'}]}
                                     for x in ('alpha','beta','stable')]}
        self.claims, self.latest, self.verified, self.running = {}, {}, 0, []
    def stamp(self):
        self.ns += 1
        return self.ns
    def event(self, kind, payload):
        self.capture.event(kind, payload, self.stamp())
    def rpc(self, method, params, result):
        self.id += 1
        self.capture.request(self.session, m.encode({'jsonrpc':'2.0','id':self.id,
                              'method':method,'params':params}), self.stamp())
        self.capture.response(self.session, m.encode({'jsonrpc':'2.0','id':self.id,
                               'result':result}), self.stamp())
    def open(self, session):
        self.session, self.id = session, 0
        self.event('session-open', {'session':session})
        self.rpc('initialize', {}, {})
        self.capture.request(session, m.encode({'jsonrpc':'2.0',
                             'method':'notifications/initialized'}), self.stamp())
        self.rpc('tools/list', {}, {'tools':[]})
    def tool(self, name, args, result=None, error=None):
        receipt = {'revision':self.rev, 'result':result} if error is None else {'error':{'code':error}}
        wrapper = {'isError':error is not None,'structuredContent':receipt,
                   'content':[{'type':'text','text':json.dumps(receipt)}]}
        self.rpc('tools/call', {'name':name,'arguments':args}, wrapper)
    def project(self):
        self.tool('checker_get_project', {}, {'canonical_root':m.ROOT,'running':self.running,
                  'config':self.config,'claims':self.claims,
                  'status':{'source':{'config_hash':'hash-'+str(self.rev)},
                            'progress':{'verified':self.verified},'latest':self.latest}})
    def cas(self):
        return {'expected_revision':self.rev,'expected_config_hash':'hash-'+str(self.rev)}
    def run(self, error=None):
        self.project()
        self.tool('checker_run_checks', dict(self.cas(),check_ids=['plan-check'],
                  idempotency_key='synthetic-'+str(self.id)), {'run_ids':['child'],'run_id':'batch'}, error)
    def initial(self):
        self.open('initial'); self.project()
        for milestone in ('alpha','beta','stable'):
            self.project()
            self.tool('checker_set_claim', {'expected_revision':self.rev,'milestone_id':milestone,
                      'claim':'implemented','note':'Fixture implementation claim only'}, {})
            self.claims[milestone] = 'implemented'
        self.project()
    def finish(self):
        self.event('session-close', {'session':self.session,'exit_code':0})
        self.event('terminal', {'status':'synthetic','cleanup_complete':True})
        return self.capture.serialized()
    def blocked(self):
        self.initial(); self.run('PERMISSION_REQUIRED')
        return self.finish()
    def success(self):
        self.initial(); self.run()
        self.running = ['child']; self.project()
        self.running = []; self.latest = {'plan-check':{'run_id':'child','execution_state':'finished',
                                    'outcome':'passed','freshness':'current'}}
        self.verified = 3; self.project()
        revised = copy.deepcopy(self.config)
        revised['milestones'][0]['title'] += ' explicit invalidation revision'
        self.tool('checker_submit_plan', dict(self.cas(),config=revised,
                  reason='Acceptance: prove installed plan revision invalidates genuine prior evidence and exact approval'), {})
        self.config = revised; self.rev += 1; self.latest['plan-check']['freshness'] = 'stale'
        self.verified = 0; self.project(); self.run('PERMISSION_REQUIRED'); self.project()
        self.tool('checker_get_plan_history', {'offset':0,'limit':5}, {'total':2,'items':[{'revision':2}]})
        self.event('session-close', {'session':'initial','exit_code':0})
        self.open('restart'); self.project()
        self.tool('checker_get_plan_history', {'offset':0,'limit':5}, {'total':2,'items':[{'revision':2}]})
        self.run('PERMISSION_REQUIRED'); self.project()
        return self.finish()


def classify(lines):
    return m.classify_serialized(lines, JOB, NONCE)


def mutate(lines, predicate, change, raw=False):
    output = list(lines)
    for index, line in enumerate(output):
        frame = m.strict(line)
        if predicate(frame):
            change(frame)
            if raw and frame['kind'] in {'request','response'}:
                frame['payload']['line_base64'] = base64.b64encode(m.encode(frame['payload']['decoded'])).decode()
            output[index] = m.encode(frame)
            return output
    raise AssertionError('Mutation target not found')


def tool(frame, name):
    return frame['kind'] == 'request' and frame['payload']['decoded'].get('method') == 'tools/call' and frame['payload']['decoded']['params']['name'] == name


class Tests(unittest.TestCase):
    def test_blocked(self):
        lines = Synthetic().blocked(); result = classify(lines)
        self.assertEqual(result['body_phase'], 'blocked')
        self.assertFalse(result['complete']); self.assertFalse(result['qualification_possible'])
        self.assertEqual(len(result['classified_frames']), len(lines))
    def test_full_success_is_still_unqualified(self):
        lines = Synthetic().success(); result = classify(lines)
        self.assertEqual(result['body_phase'], 'restart-done')
        self.assertEqual(result['poll_count'], 2)
        self.assertEqual(len(result['classified_frames']), len(lines))
        self.assertFalse(result['complete']); self.assertFalse(result['qualification_possible'])
        self.assertEqual(sum(f['phase'] == 'notifications/initialized' for f in result['classified_frames']), 2)
    def test_pending_terminal_is_partial(self):
        s = Synthetic(); s.open('initial')
        s.capture.request('initial', m.encode({'jsonrpc':'2.0','id':99,'method':'tools/call',
                          'params':{'name':'checker_get_project','arguments':{}}}), s.stamp())
        s.event('terminal', {'status':'failed','error':'read failed'})
        result = classify(s.capture.serialized())
        self.assertTrue(result['pending_rpc']); self.assertFalse(result['complete'])
        self.assertEqual(result['body_phase'], 'initial')
    def test_external_payload_mutation(self):
        c = m.Capture(JOB, NONCE); payload = {'nested':{'value':1}}
        returned = c.event('public-files', payload, 1); original = c.serialized()
        payload['nested']['value'] = 2; returned['payload']['nested']['value'] = 3
        self.assertEqual(c.serialized(), original); self.assertEqual(c.frames[0]['payload']['nested']['value'], 1)
    def test_strict_malformed(self):
        for data in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e999}',b'\xff',b'{'):
            with self.subTest(data=data), self.assertRaises(m.CaptureError): m.strict(data)
    def test_wire_malformed(self):
        for data in (b'[]\n',b'{}\n',b'{"jsonrpc":"2.0"}',b'{}\n{}\n',b'\n'):
            with self.subTest(data=data), self.assertRaises(m.CaptureError): m.wire_line(data)
    def test_envelope_and_wire_mutations(self):
        lines = Synthetic().success()
        cases = [
            (lambda f:True, lambda f:f.update(sequence=True),False),
            (lambda f:True, lambda f:f.update(schema_version=True),False),
            (lambda f:True, lambda f:f.update(monotonic_ns=-1),False),
            (lambda f:True, lambda f:f.update(nonce='wrong'),False),
            (lambda f:True, lambda f:f.update(payload=[]),False),
            (lambda f:True, lambda f:f.update(kind=[]),False),
            (lambda f:f['kind']=='request', lambda f:f['payload'].update(line_base64='!'),False),
            (lambda f:f['kind']=='request', lambda f:f['payload']['decoded'].update(id=999),False),
            (lambda f:f['kind']=='response', lambda f:f['payload']['decoded'].update(id=999),True),
            (lambda f:tool(f,'checker_get_project'), lambda f:f['payload']['decoded'].update(params=[]),True),
            (lambda f:tool(f,'checker_set_claim'), lambda f:f['payload']['decoded']['params']['arguments'].update(expected_revision=99),True),
            (lambda f:tool(f,'checker_set_claim'), lambda f:f['payload']['decoded']['params']['arguments'].update(expected_revision=True),True),
            (lambda f:tool(f,'checker_set_claim'), lambda f:f['payload']['decoded']['params']['arguments'].update(expected_revision=1.0),True),
            (lambda f:tool(f,'checker_run_checks'), lambda f:f['payload']['decoded']['params']['arguments'].update(expected_config_hash='wrong'),True),
            (lambda f:tool(f,'checker_run_checks'), lambda f:f['payload']['decoded']['params']['arguments'].update(expected_config_hash=1),True),
            (lambda f:tool(f,'checker_submit_plan'), lambda f:f['payload']['decoded']['params']['arguments']['config']['checks'][0].update(timeout_seconds=11),True),
            (lambda f:tool(f,'checker_submit_plan'), lambda f:f['payload']['decoded']['params']['arguments'].update(reason='different'),True),
            (lambda f:f['kind']=='session-open' and f['payload']['session']=='restart', lambda f:f['payload'].update(session='initial'),False),
        ]
        for index, (predicate, change, raw) in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(m.CaptureError): classify(mutate(lines,predicate,change,raw))
    def test_history_total(self):
        lines = Synthetic().success()
        def selected(f):
            return f['kind']=='response' and f['payload']['session']=='restart' and f['payload']['decoded'].get('result',{}).get('structuredContent',{}).get('result',{}).get('total') == 2
        def change(f):
            result = f['payload']['decoded']['result']; result['structuredContent']['result']['total'] = 3
            result['content'][0]['text'] = json.dumps(result['structuredContent'])
        with self.assertRaises(m.CaptureError): classify(mutate(lines,selected,change,True))
    def test_missing_immediate_read(self):
        frames = [m.strict(line) for line in Synthetic().success()]
        selected = next(i for i,f in enumerate(frames) if tool(f,'checker_submit_plan'))
        del frames[selected-2:selected]
        for index, frame in enumerate(frames,1): frame['sequence'] = index
        with self.assertRaises(m.CaptureError): classify([m.encode(f) for f in frames])
    def test_terminal_required(self):
        with self.assertRaises(m.CaptureError): classify(Synthetic().blocked()[:-1])
    def test_previous_revision_and_hash_types(self):
        lines = Synthetic().blocked()
        def selected(f):
            return f['kind']=='response' and f['payload']['decoded'].get('result',{}).get('structuredContent',{}).get('result',{}).get('canonical_root') == m.ROOT
        for key, value in [('revision',True),('revision',1.0),('config_hash',3)]:
            def change(f):
                result = f['payload']['decoded']['result']; receipt = result['structuredContent']
                if key == 'revision': receipt['revision'] = value
                else: receipt['result']['status']['source']['config_hash'] = value
                result['content'][0]['text'] = json.dumps(receipt)
            # The first initial project read is not the mutation CAS receipt;
            # alter all public project reads to exercise the subsequent gate.
            frames = [m.strict(line) for line in lines]
            for frame in frames:
                if selected(frame):
                    change(frame)
                    frame['payload']['line_base64'] = base64.b64encode(m.encode(frame['payload']['decoded'])).decode()
            with self.subTest(key=key,value=value), self.assertRaises(m.CaptureError): classify([m.encode(f) for f in frames])


if __name__ == '__main__':
    unittest.main(verbosity=2)
