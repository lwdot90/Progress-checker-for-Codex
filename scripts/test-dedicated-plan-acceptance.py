#!/usr/bin/python3
"""Pure composition: actual source definitions, mocked guest/observer/FS/time."""
import copy
from pathlib import Path
import types
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).parent
SOURCE=(HERE/'plugin-dedicated-plan-acceptance.py').read_bytes()
SHA='ff292261b0ed2ff3f4b8f929807a67e57dc83c6cb6dfb89a89bea11016fc65b8'
m=types.ModuleType('frozen_composition');m.__file__=str(HERE/'plugin-dedicated-plan-acceptance.py')
import hashlib
assert hashlib.sha256(SOURCE).hexdigest()==SHA
exec(compile(SOURCE,m.__file__,'exec'),m.__dict__)
ORIGINAL=(HERE/'plugin-acceptance.py').read_bytes()
BODY_SHA='ad1fc66caa841211d6f485832be4a602ac5c1a00743b5c42aefdbdd6f6ff1d99'
HELPER_SHA='0b976d2d5593a725540c500693228f49b9b793f1a06c4ddfa1edaf362ffe44d3'
ARCHIVE_SHA='404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
PATH=m.ROOT/'.local/mock-job/attestation.json'


def fixture(public_seconds=260,wait_seconds=60,host_seconds=365):
    clock=types.SimpleNamespace(now=0)
    writes=[]
    host=types.SimpleNamespace(PINS={'plugin-acceptance.py':BODY_SHA,'plugin-sandbox-recipient.py':HELPER_SHA},
        ARCHIVE_SHA=ARCHIVE_SHA,ARCHIVE=Path('/literal/archive'),TRUST='explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime',
        write_new=lambda path,data:writes.append((path,data)))
    public={'milestone':'plan-submission','status':'partial','complete':False,'unqualified':[m.GATE],
        'assertions':[{'name':label,'passed':True} for label in m.literal_assertions(ORIGINAL)],
        'interruption_probe':{'status':'passed','private_records_manually_edited':False,'production_failpoint':False,'abrupt_process_kill_injected':False},
        'test_runtime':{'runtime_sha256':m.RUNTIME_SHA,'helper_sha256':HELPER_SHA,'test_sources':{'plugin-acceptance.py':BODY_SHA},'limitation':'SETFCAP actual test policy'},
        'archive':{'sha256':ARCHIVE_SHA}}
    dedicated={'dedicated_handoff_passed':True,'completion_committed':True,'immutable_registration_sha256':'a'*64,
        'kernel_peer_lifetime_live':True,'hidden_host_source_independently_verified':False,'qualification_possible':False,
        'complete':False,'handoff_policy':host.TRUST}
    def consume(*args):clock.now+=host_seconds*1_000_000_000;return dedicated
    observer=types.SimpleNamespace(consume=Mock(side_effect=consume))
    composition=m.Composition(PATH,'a'*64,m.ROOT/'.local/mock-output',host,observer,0)
    composition.meta={'job_id':'b'*32,'nonce':'c'*64,'module_hashes':{'source':'synthetic'}}
    composition.buffers={'plugin-acceptance.py':ORIGINAL,'plugin-acceptance-runtime.py':b'mock-runtime'}
    composition.prepare=Mock();composition.stable=Mock()
    def wait(marker):clock.now+=wait_seconds*1_000_000_000
    composition.wait_ready=Mock(side_effect=wait)
    def public_run(*args,**kwargs):clock.now+=public_seconds*1_000_000_000;return public,2
    runtime=types.SimpleNamespace(run_acceptance=Mock(side_effect=public_run))
    return composition,clock,runtime,public,dedicated,writes


def execute(f):
    c,clock,runtime,*_=f
    with patch.object(m.time,'monotonic_ns',lambda:clock.now),patch.object(m,'compile_buffer',return_value=runtime):return c.run()


class Tests(unittest.TestCase):
    def test_fresh_full_public_then_bound_marker_then_observer(self):
        f=fixture();result=execute(f);c,clock,runtime,p,d,writes=f
        runtime.run_acceptance.assert_called_once_with(c.host.ARCHIVE,'plan-submission',c.output/'public-runtime',timeout=260)
        c.observer.consume.assert_called_once_with(PATH,'a'*64,PATH.parent/'readiness.json')
        self.assertEqual(clock.now,685_000_000_000);self.assertEqual(result['outer_deadline_ns'],720_000_000_000)
        self.assertTrue(result['behavioral_acceptance_passed']);self.assertFalse(result['checker_verification'])
        self.assertIs(result['fresh_public_acceptance'],p);self.assertIs(result['dedicated_handoff'],d)
        self.assertFalse(d['complete']);self.assertFalse(d['qualification_possible']);self.assertFalse(result['hidden_host_source_independently_verified'])
        marker=result['phase_marker'];self.assertEqual(marker['phase_ns'],260_000_000_000)
        self.assertEqual(marker['activation_wait_deadline_ns'],320_000_000_000)
        self.assertEqual(marker['public_report_sha256'],m.digest(m.encoded(p)))
        self.assertEqual([path.name for path,data in writes],['fresh-public.json','phase-marker.json','composed-acceptance.json'])
    def test_public_failure_unknown_or_missing_gate_never_consumes(self):
        for change in ({'status':'failed'},{'unqualified':[]},{'unqualified':[m.GATE,'unknown']},{'error':'actual failure'},{'assertions':[]}):
            f=fixture();f[3].update(change)
            with self.subTest(change=change),self.assertRaises(RuntimeError):execute(f)
            f[0].observer.consume.assert_not_called();self.assertEqual(f[5],[])
            self.assertEqual(f[3].get('unqualified'),change.get('unqualified',[m.GATE]))
    def test_actual_interruption_and_source_attestation_required(self):
        for key in ('interruption_probe','test_runtime','archive'):
            f=fixture();f[3][key]={}
            with self.subTest(key=key),self.assertRaises(RuntimeError):execute(f)
            f[0].observer.consume.assert_not_called()
        f=fixture();f[3]['assertions'].pop()
        with self.assertRaisesRegex(RuntimeError,'coverage'):execute(f)
    def test_cumulative_public_and_total_deadline_no_reset(self):
        for f in (fixture(public_seconds=261),fixture(host_seconds=401)):
            with self.assertRaises(RuntimeError):execute(f)
            self.assertFalse(any(path.name=='composed-acceptance.json' for path,data in f[5]))
    def test_blocked_or_uncommitted_handoff_never_passes(self):
        for change in ({'dedicated_handoff_passed':False},{'completion_committed':False},{'kernel_peer_lifetime_live':False},{'hidden_host_source_independently_verified':True},{'qualification_possible':True},{'immutable_registration_sha256':'other'}):
            f=fixture();f[4].update(change)
            with self.subTest(change=change),self.assertRaises(RuntimeError):execute(f)
            self.assertFalse(any(path.name=='composed-acceptance.json' for path,data in f[5]))
    def test_actual_wait_activation_then_body_uses_absolute_clock(self):
        f=fixture();c,clock,*_=f;c.wait_ready=m.Composition.wait_ready.__get__(c)
        clock.now=260_000_000_000
        values=[{'ready':False},{'ready':False,'activated_ns':260_100_000_000,'hard_deadline_ns':625_100_000_000},
                {'ready':True,'awaiting_activation':False,'activated_ns':260_100_000_000,'hard_deadline_ns':625_100_000_000}]
        c.readiness=Mock(side_effect=values)
        with patch.object(m.time,'monotonic_ns',lambda:clock.now),patch.object(m.time,'sleep',lambda value:setattr(clock,'now',clock.now+int(value*1e9))):
            self.assertTrue(c.wait_ready(260_000_000_000)['ready'])
    def test_actual_wait_early_reused_or_bool_signal_stamp_fails(self):
        for stamp,hard in [(259_999_999_999,624_999_999_999),(320_000_000_001,685_000_000_001),(True,365_000_000_001),(270_000_000_000,635_000_000_001)]:
            f=fixture();c,clock,*_=f;clock.now=260_000_000_000
            c.readiness=Mock(return_value={'ready':True,'awaiting_activation':False,'activated_ns':stamp,'hard_deadline_ns':hard})
            with self.subTest(stamp=stamp),patch.object(m.time,'monotonic_ns',lambda:clock.now),self.assertRaises(RuntimeError):m.Composition.wait_ready(c,clock.now)
    def test_actual_wait_absence_expires_without_activation(self):
        f=fixture();c,clock,*_=f;clock.now=260_000_000_000;c.readiness=Mock(return_value={'ready':False})
        with patch.object(m.time,'monotonic_ns',lambda:clock.now),patch.object(m.time,'sleep',lambda seconds:setattr(clock,'now',clock.now+int(seconds*1e9))):
            with self.assertRaisesRegex(RuntimeError,'wait expired'):m.Composition.wait_ready(c,260_000_000_000)
        self.assertEqual(clock.now,320_000_000_000)
    def test_bad_source_never_compiles(self):
        with self.assertRaisesRegex(RuntimeError,'source buffer'):m.compile_buffer('x',b'raise Exception()', 'f'*64)
    def test_default_off_no_inputs_or_guest(self):
        with patch.object(m,'load_inputs') as inputs,patch('sys.argv',['composition']):
            self.assertEqual(m.main(),0);inputs.assert_not_called()


if __name__=='__main__':unittest.main(verbosity=2)
