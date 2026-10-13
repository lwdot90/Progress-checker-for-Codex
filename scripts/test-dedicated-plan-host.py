#!/usr/bin/python3
"""Frozen host pure tests: fake packets/clocks/signals; no preparation/actions."""
import hashlib
from pathlib import Path
import struct
import types
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).parent
SOURCE=(HERE/'plugin-dedicated-plan-host.py').read_bytes()
SHA='9b97e848bb2f9c2288f9a704592c0ed1f2554a829819d3f686c2e53611d54f6b'
assert hashlib.sha256(SOURCE).hexdigest()==SHA
h=types.ModuleType('frozen_dedicated_host');h.__file__=str(HERE/'plugin-dedicated-plan-host.py')
exec(compile(SOURCE,h.__file__,'exec'),h.__dict__)
CAPTURE=(HERE/'plugin-dedicated-plan-capture.py').read_bytes()
raw=h.load('plugin-dedicated-plan-capture.py',CAPTURE)
JOB,NONCE='a'*32,'b'*64


class Connection:
    def __init__(self,request,followup=b''):
        self.incoming=[request[:13],request[13:],followup]
        self.packets,self.events,self.timeouts=[],[],[]
    def recv(self,count): self.events.append('recv');return self.incoming.pop(0)
    def sendall(self,data): self.events.append('send'+str(len(self.packets)+1));self.packets.append(data)
    def getsockopt(self,*args): return struct.pack('3i',77,1000,1000)
    def settimeout(self,value):self.timeouts.append(value)
    def fileno(self):return 88
    def __enter__(self):return self
    def __exit__(self,*args):self.events.append('connection-close')


class Server:
    def __init__(self,connection):self.connection=connection
    def accept(self):return self.connection,None


def peer(followup=b'',remove_error=False,no_full_close=False,duplicate_packet=None,uid=1000):
    coordinator=h.Coordinator('/home/luis/progress-checker/.local/dedicated-host-pure')
    request=h.encoded({'schema_version':1,'job_id':JOB,'nonce':NONCE,'request':'read-events'})
    connection=Connection(request,followup)
    coordinator.server=Server(connection);coordinator.raw=raw
    coordinator.meta={'job_id':JOB,'nonce':NONCE,'module_hashes':{'source':'synthetic'},'runtime_files':{'binary':'synthetic'}}
    coordinator.ready={'observer_expires_ns':10_000_000_000,'hard_deadline_ns':365_000_000_000,'activated_ns':0,'ready':True,'consumed':False}
    gate=h.ActivationGate();gate.armed=True;gate.activated=True;gate.activated_ns=0;gate.deadline=1_800_000_000_000
    coordinator.gate=gate
    connection.getsockopt=lambda *args:struct.pack('3i',77,uid,uid)
    original_send=connection.sendall
    def send(data):
        original_send(data)
        if len(connection.packets)==duplicate_packet:gate.receive()
    connection.sendall=send
    payload=b'{"synthetic":true}\n';audit={'job_id':JOB,'nonce':NONCE,'raw_exact_bytes_sha256':h.digest(payload)}
    coordinator.audit=Mock(return_value=audit);coordinator.guard=Mock()
    def remove():
        connection.events.append('owned-handoff-removed')
        if remove_error:raise h.HostError('synthetic ownership failure')
    def publish():connection.events.append('consumed-committed')
    coordinator.remove_handoff=remove;coordinator.publish=publish
    clock=types.SimpleNamespace(now=0)
    def poll(timeout):
        connection.events.append('full-close-poll')
        if no_full_close:clock.now=11;return []
        return [(88,h.select.POLLHUP)]
    poller=types.SimpleNamespace(register=lambda *args:None,poll=poll)
    with (patch.object(h.time,'monotonic',lambda:clock.now),patch.object(h.time,'monotonic_ns',lambda:int(clock.now*1e9)),
          patch.object(h.select,'poll',lambda:poller),
          patch.object(h,'bounded',lambda *args,**kwargs:h.encoded(coordinator.ready))):
        coordinator.serve_once(payload)
    return coordinator,connection,payload,h.encoded(audit)


class Tests(unittest.TestCase):
    def test_exact_fixed_request(self):
        data=h.encoded({'schema_version':1,'job_id':JOB,'nonce':NONCE,'request':'read-events'})
        self.assertEqual(h.exact_request(data,JOB,NONCE,raw.strict)['request'],'read-events')
        for value in [data+b'{}\n',data[:-1],data.replace(b'read-events',b'run-check'),
                      data.replace(b'"schema_version":1',b'"schema_version":true'),
                      data.replace(b'"job_id":',b'"job_id":"duplicate","job_id":')]:
            with self.subTest(value=value),self.assertRaises((h.HostError,ValueError)):
                h.exact_request(value,JOB,NONCE,raw.strict)
    def test_cumulative_clocks(self):
        result=h.clock_binding(0,5_000_000_000,125_000_000_000,245_000_000_000,245_000_000_000)
        self.assertEqual(result['hard_deadline_ns'],365_000_000_000)
        for values in [(0,True,120_000_000_000,240_000_000_000,1),
                       (0,6_000_000_000,126_000_000_000,246_000_000_000,246_000_000_000),
                       (0,0,121_000_000_000,240_000_000_000,1),
                       (0,0,120_000_000_000,241_000_000_000,1),
                       (0,0,120_000_000_000,240_000_000_000,366_000_000_000)]:
            with self.subTest(values=values),self.assertRaises(h.HostError):h.clock_binding(*values)
    def test_three_packets_commit_before_ACK_full_close(self):
        coordinator,connection,payload,audit=peer()
        self.assertEqual(len(connection.packets),3)
        def decoded(packet):
            count=struct.unpack('!I',packet[:4])[0];self.assertEqual(count,len(packet)-4);return packet[4:]
        self.assertEqual(decoded(connection.packets[0]),payload)
        self.assertEqual(decoded(connection.packets[1]),audit)
        ack=raw.strict(decoded(connection.packets[2]))
        self.assertEqual(ack['raw_exact_bytes_sha256'],h.digest(payload))
        self.assertEqual(ack['transfer_audit_sha256'],h.digest(audit))
        self.assertEqual(ack['readiness_sha256'],h.digest(h.encoded(coordinator.ready)))
        self.assertIsNone(ack['endpoint_identity']);self.assertIsNone(ack['reservation_identity'])
        self.assertLess(connection.events.index('owned-handoff-removed'),connection.events.index('consumed-committed'))
        self.assertLess(connection.events.index('consumed-committed'),connection.events.index('send3'))
        self.assertLess(connection.events.index('send3'),connection.events.index('full-close-poll'))
        self.assertTrue(coordinator.ready['consumed']);self.assertFalse(coordinator.ready['ready'])
        self.assertTrue(all(0<value<=15 for value in connection.timeouts))
    def test_followup_never_commits(self):
        with self.assertRaisesRegex(h.HostError,'followup'):peer(followup=b'x')
    def test_owned_cleanup_failure_never_ACK(self):
        with self.assertRaisesRegex(h.HostError,'ownership failure'):peer(remove_error=True)
    def test_half_close_is_not_full_close(self):
        with self.assertRaisesRegex(h.HostError,'full close absent'):peer(no_full_close=True)
    def test_activation_gate_only_explicit_fresh(self):
        gate=h.ActivationGate();gate.receive();self.assertTrue(gate.early)
        with patch.object(h.signal,'sigpending',return_value=set()),patch.object(h.signal,'pthread_sigmask'):
            with self.assertRaises(h.HostError):gate.publish(lambda:None,100,set())
        gate=h.ActivationGate();events=[]
        with (patch.object(h.signal,'sigpending',return_value=set()),patch.object(h.signal,'pthread_sigmask'),
              patch.object(h.time,'monotonic_ns',return_value=1)):
            gate.publish(lambda:events.append('inactive-readiness'),100,set())
            gate.receive();gate.wait(None)
            self.assertTrue(gate.activated);self.assertEqual(events,['inactive-readiness'])
            gate.receive()
            with self.assertRaises(h.HostError):gate.wait(None)
    def test_publication_time_pending_signal_rejected_before_arm(self):
        gate=h.ActivationGate();pending=set()
        def callback():pending.add(h.signal.SIGUSR1)
        with (patch.object(h.signal,'sigpending',lambda:pending),
              patch.object(h.signal,'pthread_sigmask') as unmask):
            with self.assertRaisesRegex(h.HostError,'Publication-time'):gate.publish(callback,100,set())
            self.assertFalse(gate.armed);self.assertFalse(gate.activated);unmask.assert_not_called()
    def test_missing_future_source_before_any_creation(self):
        coordinator=h.Coordinator('/home/luis/progress-checker/.local/dedicated-host-pure')
        with (patch.object(h.os,'getuid',return_value=1000),patch.object(Path,'exists',return_value=False),
              patch.object(Path,'resolve',lambda path,strict=False:path),
              patch.object(h,'bounded',side_effect=FileNotFoundError('future helper absent')),
              patch.object(Path,'mkdir') as mkdir):
            with self.assertRaises(FileNotFoundError):coordinator.prepare()
            mkdir.assert_not_called();self.assertFalse(coordinator.created)
    def test_exact_inventory_and_source_refusal(self):
        self.assertEqual(len(h.NAMES),11)
        self.assertFalse(any('original-demo' in name for name in h.NAMES))
        self.assertEqual(h.BUDGETS,{'preparation':1800,'start':5,'work':120,'cleanup':120,'observation':90,'final_margin':30,'hard':365})
        with self.assertRaises(h.HostError):h.load('plugin-dedicated-plan-capture.py',CAPTURE+b'\n')
    def test_actual_signal_stamp_guard_delay_cannot_reset(self):
        coordinator=h.Coordinator('/home/luis/progress-checker/.local/dedicated-host-pure')
        gate=h.ActivationGate();gate.armed=True;gate.deadline=1_800_000_000_000
        clock=types.SimpleNamespace(now=123_000_000_000)
        with patch.object(h.time,'monotonic_ns',lambda:clock.now):
            gate.receive();stamp=gate.activated_ns
            coordinator.ready={'awaiting_activation':True};coordinator.publish=Mock()
            coordinator.guard=lambda: setattr(clock,'now',stamp+6_000_000_000)
            coordinator.adapter=Mock()
            with self.assertRaisesRegex(h.HostError,'delayed adapter start'):coordinator.execute(gate)
            coordinator.adapter.run_once.assert_not_called()
            self.assertFalse(coordinator.workflow_started)
            self.assertEqual(coordinator.ready['activated_ns'],stamp)
            self.assertEqual(coordinator.ready['hard_deadline_ns'],stamp+365_000_000_000)
    def test_duplicate_during_actual_body_invalidates_without_rollback(self):
        coordinator=h.Coordinator('/home/luis/progress-checker/.local/dedicated-host-pure')
        gate=h.ActivationGate();gate.armed=True;gate.deadline=1_800_000_000_000
        with patch.object(h.time,'monotonic_ns',return_value=7):
            gate.receive();coordinator.ready={'awaiting_activation':True}
            coordinator.publish=Mock();coordinator.guard=Mock();effect=[]
            def body():effect.append('actual-body-effect');gate.receive();return {'body_exit':0}
            coordinator.adapter=types.SimpleNamespace(run_once=Mock(side_effect=body))
            with self.assertRaisesRegex(h.HostError,'duplicate'):coordinator.execute(gate)
            self.assertEqual(effect,['actual-body-effect']);self.assertTrue(coordinator.workflow_started)
            coordinator.adapter.run_once.assert_called_once();self.assertNotIn('ready',coordinator.ready)
    def test_duplicate_during_transfer_and_final_close_cannot_qualify(self):
        for packet in (1,2,3):
            with self.subTest(packet=packet),self.assertRaisesRegex(h.HostError,'duplicate'):
                peer(duplicate_packet=packet)
    def test_namespace_peer_contract_kernel_uid_only(self):
        with self.assertRaisesRegex(h.HostError,'kernel UID'):peer(uid=1001)
        # Producer intentionally makes no peer PID/executable claim: synthetic
        # kernel PID77 succeeds. Observer must bind producer's SO_PEERPIDFD.
        self.assertEqual(len(peer()[1].packets),3)
    def test_failure_cannot_write_preexisting_workspace(self):
        coordinator=h.Coordinator('/home/luis/progress-checker/.local/preexisting-public')
        with patch.object(h,'atomic') as atomic:
            coordinator.fail(h.HostError('preflight refused'))
            atomic.assert_not_called()


if __name__=='__main__':unittest.main(verbosity=2)
