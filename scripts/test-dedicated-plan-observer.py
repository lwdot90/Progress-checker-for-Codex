#!/usr/bin/python3
"""Pure frozen observer tests. All socket/clock/coordination reads mocked."""
import base64
import copy
import hashlib
import importlib.util
import json
import io
import stat
from pathlib import Path
import struct
import types
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).parent
SHA='a57250fe51e70264acbc3f1dc1b46262f5f60feac80ea7b426a7256961018edf'
def load(name,sha):
    data=(HERE/name).read_bytes(); assert hashlib.sha256(data).hexdigest()==sha
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),HERE/name)
    module=importlib.util.module_from_spec(spec); exec(compile(data,str(HERE/name),'exec'),module.__dict__); return module

o=load('plugin-dedicated-plan-observer.py',SHA)
t=load('test-dedicated-plan-lifecycle.py','1b8cfe22772e42d05717769b6d22450984e5c7f8f66ca5eaada970498f50f80a')
BUFFERS={n:(HERE/n).read_bytes() for n in o.PINS}
encode=lambda v:json.dumps(v,separators=(',',':')).encode()+b'\n'
PATH=o.ROOT/'.local/dedicated-synthetic/attestation.json'
NOW=1_000_000_000


def fixture():
    lines=t.transcript(); frames=[o.strict(line) for line in lines]
    initial=next(f['payload'] for f in frames if f['kind']=='public-files' and f['payload']['role']=='initial')
    final=next(f['payload'] for f in frames if f['kind']=='public-files' and f['payload']['role']=='final')
    meta=dict(t.META,schema_version=1,mode='dedicated-plan',trust_policy=o.TRUST,
        producer_argv=['fixed-collector'],boot_id='synthetic-boot',body_sha256=o.PINS['plugin-acceptance.py'],
        module_hashes={str(o.ROOT/'scripts'/n):o.PINS.get(n,'c'*64) for n in o.NAMES},
        fixture_files={v['role']:{'sha256':o.digest(base64.b64decode(v['bytes_base64']))} for v in initial['files']},
        initial_public_snapshot=initial,check_definition=t.m.CHECK,
        socket={'dev':1,'ino':2,'uid':1000,'mode':0o600,'mtime_ns':1,'ctime_ns':1},
        prepared_ns=0,activation_expires_ns=1800_000_000_000,budget_seconds=o.BUDGETS)
    meta['module_hashes'][str(o.ROOT/'scripts/plugin-dedicated-plan-host.py')]=o.HOST_SHA
    original=encode(meta); sha=o.digest(original)
    ready={k:meta[k] for k in ('schema_version','job_id','nonce','producer','endpoint','socket')}
    ready.update(attestation_path=str(PATH),attestation_sha256=sha,awaiting_activation=False,ready=True,
        consumed=False,activated_ns=0,hard_deadline_ns=365_000_000_000,body_started_ns=0,
        body_work_deadline_ns=120_000_000_000,body_cleanup_deadline_ns=240_000_000_000,
        cleanup_complete=True,body_exit=0,body_status='full-public-captured-semantics',observer_expires_ns=90_000_000_000)
    raw=b''.join(lines); ready_bytes=encode(ready)
    audit=dict(schema_version=1,job_id=meta['job_id'],nonce=meta['nonce'],connected_ns=NOW,audited_ns=NOW,
        raw_exact_bytes_sha256=o.digest(raw),module_hashes=meta['module_hashes'],runtime_files=meta['runtime_files'],
        final_public_pins={v['role']:{'sha256':o.digest(base64.b64decode(v['bytes_base64']))} for v in final['files']},
        fixture_census={'service_record':None,'lease_snapshot':{},'endpoint_identity':None,'fixture_processes':[]},
        ready_sha256=o.digest(ready_bytes))
    audit_bytes=encode(audit); committed=encode(dict(ready,ready=False,consumed=True))
    ack=dict(schema_version=1,job_id=meta['job_id'],nonce=meta['nonce'],completed_ns=NOW,
        raw_exact_bytes_sha256=o.digest(raw),transfer_audit_sha256=o.digest(audit_bytes),readiness_sha256=o.digest(committed),
        module_hashes=meta['module_hashes'],runtime_files=meta['runtime_files'],endpoint_identity=None,reservation_identity=None)
    return meta,ready,original,sha,raw,frames,audit,audit_bytes,committed,ack


class Wire:
    def __init__(self,payload,uid=1000,unsupported=False,pid=100):
        self.data=payload;self.uid=uid;self.pid=pid;self.unsupported=unsupported;self.halfclosed=False;self.closed=False;self.sent=[]
    def settimeout(self,value):assert 0<value<=15
    def connect(self,path):self.connected=path
    def getsockopt(self,level,option,length):
        if option==77:
            if self.unsupported:raise OSError('unsupported SO_PEERPIDFD')
            return struct.pack('i',88)
        return struct.pack('3i',self.pid,self.uid,1000)
    def recv(self,count):
        value=self.data[:min(count,17)];self.data=self.data[len(value):];return value
    def sendall(self,value):self.sent.append(value)
    def shutdown(self,how):assert how==o.socket.SHUT_WR;self.halfclosed=True
    def __enter__(self):return self
    def __exit__(self,*args):self.closed=True


def consume_mock(uid=1000,pid=100,unsupported=False,change_ack=None,changed_commit=False,late_failure=False,dead=False,source_fail=False,mutate_raw=None):
    meta,ready,original,sha,raw,frames,audit,audit_bytes,committed,ack=fixture()
    if change_ack: change_ack(ack)
    if mutate_raw:raw=mutate_raw(raw)
    ack_bytes=encode(ack)
    wire=Wire(b''.join(struct.pack('!I',len(p))+p for p in (raw,audit_bytes,ack_bytes)),uid,unsupported,pid)
    poll=Mock();poll.poll.return_value=[(88,1)] if dead else []
    def bounded(path,limit,private=False):
        if path==PATH:return original
        assert path==PATH.parent/'readiness.json'
        if wire.halfclosed:return encode(dict(ready,ready=False,consumed=True,failed=True)) if changed_commit else committed
        return encode(ready)
    def lexists(path):return bool(late_failure and wire.halfclosed and str(path).endswith('failure.json'))
    with patch.object(o,'bounded',side_effect=bounded),patch.object(o,'source_runtime_guard',side_effect=RuntimeError('source changed') if source_fail else lambda _:BUFFERS),\
         patch.object(o,'endpoint_identity',return_value=meta['socket']),patch.object(o.socket,'socket',return_value=wire),\
         patch.object(o.select,'poll',return_value=poll),patch.object(o.select,'select',side_effect=lambda r,w,e,timeout:(r,[],[])),\
         patch.object(o.time,'monotonic',return_value=1),patch.object(o.time,'monotonic_ns',return_value=NOW),\
         patch.object(o.os.path,'lexists',side_effect=lexists),patch.object(o.os,'close'),\
         patch.object(o.Path,'read_text',return_value='synthetic-boot'):
        result=o.consume(PATH,sha,PATH.parent/'readiness.json')
    return result,wire


class Tests(unittest.TestCase):
    def test_full_mock_handoff_preserves_false_qualification(self):
        result,wire=consume_mock();self.assertTrue(result['dedicated_handoff_passed'])
        self.assertFalse(result['complete']);self.assertFalse(result['qualification_possible'])
        self.assertFalse(result['hidden_host_source_independently_verified'])
        self.assertTrue(wire.halfclosed and wire.closed);self.assertEqual(len(wire.sent),1)
        self.assertEqual(o.strict(wire.sent[0])['request'],'read-events')
    def test_mutated_ack_pins(self):
        for key in ('job_id','nonce','raw_exact_bytes_sha256','transfer_audit_sha256','readiness_sha256','module_hashes','runtime_files','endpoint_identity','reservation_identity'):
            with self.subTest(key=key),self.assertRaises((RuntimeError,ValueError)):
                consume_mock(change_ack=lambda a:a.update({key:'wrong'}))
    def test_ack_bool_schema_rejected(self):
        with self.assertRaises(RuntimeError):consume_mock(change_ack=lambda a:a.update(schema_version=True))
    def test_expired_or_early_ack(self):
        for stamp in (NOW-1,90_000_000_000):
            with self.subTest(stamp=stamp),self.assertRaises(RuntimeError):consume_mock(change_ack=lambda a:a.update(completed_ns=stamp))
    def test_late_failure_after_ack_rejected(self):
        with self.assertRaises(RuntimeError):consume_mock(late_failure=True)
    def test_changed_consumed_readiness_rejected(self):
        with self.assertRaises(RuntimeError):consume_mock(changed_commit=True)
    def test_dead_connected_peer(self):
        with self.assertRaises(RuntimeError):consume_mock(dead=True)
    def test_wrong_kernel_uid(self):
        with self.assertRaises(RuntimeError):consume_mock(uid=1001)
    def test_visible_correct_and_hidden_peer_pid(self):
        for pid in (100,0):
            with self.subTest(pid=pid):self.assertTrue(consume_mock(pid=pid)[0]['dedicated_handoff_passed'])
    def test_wrong_visible_and_negative_peer_pid(self):
        for pid in (101,-1):
            with self.subTest(pid=pid),self.assertRaises(RuntimeError):consume_mock(pid=pid)
    def test_unsupported_peerpidfd(self):
        with self.assertRaises(OSError):consume_mock(unsupported=True)
    def test_changed_source_rejected(self):
        with self.assertRaises(RuntimeError):consume_mock(source_fail=True)
    def test_raw_unchanged_and_unterminated(self):
        with self.assertRaises(RuntimeError):consume_mock(mutate_raw=lambda b:b[:-1])
    def test_exact_registration_guards(self):
        meta,ready,original,sha,*_=fixture()
        o.validate_registration(meta,ready,PATH,sha,NOW,'synthetic-boot')
        for key,value in [('mode','foreign'),('root','/other'),('state','/other'),('nonce','wrong'),('prepared_ns',True),('boot_id','other'),('budget_seconds',{})]:
            changed=copy.deepcopy(meta);changed[key]=value
            with self.subTest(key=key),self.assertRaises(RuntimeError):o.validate_registration(changed,ready,PATH,sha,NOW,'synthetic-boot')
    def test_registration_extra_key_and_ready_failure(self):
        meta,ready,original,sha,*_=fixture()
        for changed in (dict(ready,failed=True),dict(ready,consumed=True),dict(ready,observer_expires_ns=NOW)):
            with self.assertRaises(RuntimeError):o.validate_registration(meta,changed,PATH,sha,NOW,'synthetic-boot')
    def test_audit_rejects_stale_and_wrong_drain(self):
        meta,ready,_,_,raw,frames,audit,*_=fixture()
        for key,value in [('connected_ns',NOW-1),('audited_ns',NOW+1),('fixture_census',{}),('raw_exact_bytes_sha256','0'*64),('ready_sha256','0'*64)]:
            changed=copy.deepcopy(audit);changed[key]=value
            with self.subTest(key=key),self.assertRaises(RuntimeError):o.verify_audit(changed,meta,ready,encode(ready),raw,frames,NOW,NOW)
    def test_packet_bounds_and_eof(self):
        for packet in (struct.pack('!I',0),struct.pack('!I',o.MAX_PACKET+1),struct.pack('!I',8)+b'abc'):
            wire=Wire(packet)
            with patch.object(o.time,'monotonic',return_value=1),patch.object(o.select,'select',side_effect=lambda r,w,e,t:(r,[],[])),self.assertRaises(RuntimeError):o.packet(wire,o.MAX_PACKET,10)
    def test_per_wait_15_second_cap(self):
        calls=[]
        with patch.object(o.time,'monotonic',return_value=1),patch.object(o.select,'select',side_effect=lambda r,w,e,t:(calls.append(t) or r,[],[])):
            self.assertEqual(o.read_exact(Wire(b'hello'),5,200),b'hello')
        self.assertEqual(calls,[15])
    def test_final_guard_missing_resource_deadline_and_commit(self):
        meta,ready,original,sha,raw,frames,audit,audit_bytes,committed,ack=fixture()
        poll=Mock();poll.poll.return_value=[]
        with patch.object(o.time,'monotonic',return_value=1),patch.object(o.os.path,'lexists',return_value=True),self.assertRaises(RuntimeError):
            o.final_guard(meta,PATH,original,PATH.parent/'readiness.json',committed,Path(meta['endpoint']),poll,10)
    def test_strict_json(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":1e999}'):
            with self.assertRaises(RuntimeError):o.strict(raw)
    def test_anchored_bounded_mocked_filesystem(self):
        class Buffer(io.BytesIO):
            def fileno(self):return 55
        def info(**changes):
            values=dict(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o600,st_uid=1000,st_nlink=1,
                        st_size=3,st_mtime_ns=1,st_ctime_ns=1)
            values.update(changes);return types.SimpleNamespace(**values)
        safe=info(); directory=info(st_mode=stat.S_IFDIR|0o700)
        cases=[({},False),({'st_nlink':2},True),({'st_uid':1001},True),
               {'st_mode':stat.S_IFREG|0o622}, {'st_size':9}, {'st_mode':stat.S_IFLNK|0o600}]
        for case in cases:
            changes,fail=case if type(case) is tuple else (case,True)
            current=info(**changes)
            with patch.object(o.os,'open',return_value=44) as opened,patch.object(o.os,'close'),\
                 patch.object(o.os,'fdopen',return_value=Buffer(b'abc')),\
                 patch.object(o.os,'fstat',side_effect=lambda fd:current if fd==55 else directory),\
                 patch.object(o.os,'stat',return_value=current):
                if fail:
                    with self.assertRaises(RuntimeError):o.bounded(PATH,8,True)
                else:
                    self.assertEqual(o.bounded(PATH,8,True),b'abc')
                    self.assertTrue(all(args.args[1]&o.os.O_NOFOLLOW for args in opened.call_args_list[1:]))
        with patch.object(o.os,'open',return_value=44),patch.object(o.os,'close'),\
             patch.object(o.os,'fdopen',return_value=Buffer(b'abc')),\
             patch.object(o.os,'fstat',side_effect=lambda fd:safe if fd==55 else directory),\
             patch.object(o.os,'stat',return_value=info(st_ino=3)),self.assertRaises(RuntimeError):
            o.bounded(PATH,8,True)
        with self.assertRaises(RuntimeError):o.bounded(Path('/tmp/../alias'),8)

    def test_off_default_does_no_io(self):
        with patch.object(o.argparse.ArgumentParser,'parse_args',return_value=types.SimpleNamespace(attestation=None,sha256=None,readiness=None)),\
             patch.object(o,'consume',side_effect=AssertionError('must remain OFF')),patch('builtins.print'):
            self.assertEqual(o.main(),0)


if __name__=='__main__':unittest.main()
