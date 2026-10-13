#!/usr/bin/env python3
"""Pure mocked-pipe gateway tests; no backend, service or approval storage."""
import ast
import json
from pathlib import Path
import queue
import runpy
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

MODULE = runpy.run_path(str(Path(__file__).resolve().parents[1] /
                           'plugins/progress-checker/bin/checker-global'))
Gateway = MODULE['Gateway']
MAX_FRAME = MODULE['MAX_FRAME']


class Pipe:
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.closed = False

    def fileno(self):
        return self.descriptor

    def close(self):
        self.closed = True


class Child:
    def __init__(self):
        self.stdin, self.stdout = Pipe(123), Pipe(124)
        self.returncode = None
        self.killed = False
        self.terminated = False
        self.release_write = threading.Event()

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        self.returncode = 0
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0
        self.release_write.set()

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.release_write.set()


def gateway():
    value = Gateway.__new__(Gateway)
    value.child = Child()
    value.child_group = None
    value.reader = value.reader_stop = None
    value.writer = value.writer_stop = value.writes = None
    value.responses = queue.Queue(maxsize=4)
    value.buffer = b''
    value.sequence = 0
    return value


class GatewayStdioTests(unittest.TestCase):
    def setUp(self):
        # A future accidental subprocess addition must fail this pure entry.
        self.popen = mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('No subprocess allowed'))
        self.popen.start()
        self.addCleanup(self.popen.stop)

    def test_reader_is_bounded_and_closes_on_eof(self):
        value = gateway()
        with mock.patch.object(MODULE['os'], 'read', side_effect=[b'first\n', b'']):
            value.start_reader()
            value.reader.join(timeout=1)
            self.assertFalse(value.reader.is_alive())
            self.assertEqual(value.responses.get_nowait(), b'first\n')
            self.assertEqual(value.responses.get_nowait(), b'')
            self.assertEqual(value.responses.maxsize, 4)
            value.close()

    def test_reader_backpressure_does_not_grow_queue(self):
        value = gateway()
        fifth_read = threading.Event()
        count = 0

        def read(_descriptor, _size):
            nonlocal count
            count += 1
            if count == 5:
                fifth_read.set()
            return b'x' * 65536

        with mock.patch.object(MODULE['os'], 'read', side_effect=read):
            value.start_reader()
            self.assertTrue(fifth_read.wait(timeout=1))
            self.assertEqual(value.responses.qsize(), 4)
            value.close()

    def test_writer_handles_partial_writes(self):
        value = gateway()
        output = bytearray()

        def write(_descriptor, data):
            count = min(3, len(data))
            output.extend(data[:count])
            return count

        with mock.patch.object(MODULE['os'], 'write', side_effect=write):
            value.start_writer()
            value.send(b'hello world\n', time.monotonic() + 1)
            self.assertEqual(output, b'hello world\n')
            self.assertEqual(value.writes.maxsize, 1)
            value.close()

    def test_stuck_writer_kills_only_owned_child(self):
        value = gateway()
        owned_child = value.child

        def blocked_write(_descriptor, _data):
            if not owned_child.release_write.wait(timeout=2):
                raise AssertionError('Owned child was not killed')
            raise BrokenPipeError('mock pipe closed')

        with mock.patch.object(MODULE['os'], 'write', side_effect=blocked_write):
            value.start_writer()
            writer = value.writer
            with self.assertRaisesRegex(RuntimeError, 'request timed out'):
                value.send(b'request\n', time.monotonic() + .2)
            self.assertTrue(owned_child.killed)
            self.assertIsNone(value.child)
            self.assertFalse(writer.is_alive())
            self.assertTrue(owned_child.stdin.closed)

    def test_oversized_request_is_rejected_before_queueing(self):
        value = gateway()
        with self.assertRaisesRegex(RuntimeError, 'request exceeded frame limit'):
            value.send(b'x' * (MAX_FRAME + 1), time.monotonic() + 1)
        self.assertFalse(value.child.killed)

    def test_exchange_rejects_eof_bad_identity_and_oversized_frame(self):
        cases = [(b'', 'connection closed'),
                 (json.dumps({'id': 99, 'result': {}}).encode() + b'\n', 'identity mismatch'),
                 (b'x' * (MAX_FRAME + 1), 'exceeded frame limit')]
        for response, message in cases:
            with self.subTest(message=message):
                value = gateway()
                value.responses.put(response)
                with mock.patch.object(value, 'send'):
                    with self.assertRaisesRegex(RuntimeError, message):
                        value.exchange('ping', {})

    def test_exchange_response_deadline_includes_send(self):
        value = gateway()
        with mock.patch.object(value, 'send') as send:
            with mock.patch.object(MODULE['time'], 'monotonic', side_effect=[100, 151]):
                with self.assertRaisesRegex(RuntimeError, 'response timed out'):
                    value.exchange('ping', {})
            self.assertEqual(send.call_args.args[1], 150)

    def test_malformed_backend_json_closes_owned_connection(self):
        value = gateway()
        child = value.child
        value.ready = value.initialized = True
        value.names = {'checker_get_project'}
        value.responses.put(b'{not-json}\n')
        with mock.patch.object(value, 'send'):
            with self.assertRaises(json.JSONDecodeError):
                value.dispatch({'jsonrpc': '2.0', 'id': 12, 'method': 'tools/call',
                                'params': {'name': 'checker_get_project'}})
        self.assertIsNone(value.child)
        self.assertTrue(child.stdin.closed)
        self.assertTrue(child.stdout.closed)
        self.assertFalse(child.killed)

    def test_dead_child_cleanup_stops_all_owned_threads(self):
        value = gateway()
        child = value.child
        child.returncode = 0

        def read(_descriptor, _size):
            value.reader_stop.wait(timeout=1)
            return b''

        with mock.patch.object(MODULE['os'], 'read', side_effect=read):
            value.start_reader()
            value.start_writer()
            reader, writer = value.reader, value.writer
            value.close()
            self.assertFalse(reader.is_alive())
            self.assertFalse(writer.is_alive())
            self.assertFalse(child.killed)
            self.assertTrue(child.stdin.closed)
            self.assertTrue(child.stdout.closed)
            self.assertIsNone(value.responses)
            self.assertIsNone(value.writes)

    def test_initializer_uses_manifest_version_without_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory)
            (plugin / 'bin').mkdir()
            (plugin / 'plugin.json').write_text(json.dumps({'version': '9.8.7-dev'}))
            globals_dict = Gateway.__init__.__globals__
            with mock.patch.dict(globals_dict, {'BIN': plugin / 'bin',
                                               'require_supported_runtime': lambda: None}):
                with mock.patch.object(subprocess, 'check_output', return_value=b'{"tools":[]}'):
                    value = Gateway(plugin / 'uncreated-state')
            reply = value.dispatch({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                                    'params': {'protocolVersion': '2025-06-18',
                                               'capabilities': {}, 'clientInfo': {}}})
            self.assertEqual(reply['result']['serverInfo']['version'], '9.8.7-dev')
            value.close()
            self.assertEqual(value.version, '9.8.7-dev')
            self.assertFalse((plugin / 'uncreated-state').exists())

    def test_initialization_notification_uses_bounded_send(self):
        # Inspect the actual track body without invoking setup or lifecycle.
        import inspect
        import textwrap
        tree = ast.parse(textwrap.dedent(inspect.getsource(Gateway.track)))
        sends = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == 'send'
                 and node.args and isinstance(node.args[0], ast.Constant)
                 and isinstance(node.args[0].value, bytes)
                 and b'notifications/initialized' in node.args[0].value]
        self.assertEqual(len(sends), 1)
        self.assertEqual(len(sends[0].args), 2)
        deadline = sends[0].args[1]
        self.assertIsInstance(deadline, ast.BinOp)
        self.assertIsInstance(deadline.op, ast.Add)
        self.assertIsInstance(deadline.left, ast.Call)
        self.assertEqual(deadline.left.func.attr, 'monotonic')
        self.assertEqual(deadline.right.value, 50)

    def test_readonly_tracking_and_unknown_parameters_fail_structurally(self):
        value = gateway()
        value.ready = value.initialized = True
        value.tools, value.names = [], set()
        cases = [({'name': 'checker_track_project', 'arguments': {'project_root': '/fake'},
                   '_meta': {'openai/readOnly': True}}, 'tools/call', 'READ_ONLY_REQUEST'),
                 ({'cursor': 'next'}, 'tools/list', 'INVALID_ARGUMENT'),
                 ({'unexpected': True}, 'tools/list', 'INVALID_ARGUMENT'),
                 ({'name': 'checker_track_project', 'unexpected': True},
                  'tools/call', 'INVALID_ARGUMENT')]
        with mock.patch.object(value, 'track') as track:
            for params, method, code in cases:
                with self.subTest(code=code, params=params):
                    response = value.dispatch({'jsonrpc': '2.0', 'id': 3,
                                               'method': method, 'params': params})
                    self.assertTrue(response['result']['isError'])
                    self.assertEqual(response['result']['structuredContent']['error']['code'], code)
            track.assert_not_called()
        value.close()

    def test_owned_group_is_signalled_before_leader_reaping(self):
        value = gateway()
        child = value.child
        child.pid = value.child_group = 12345
        events = []

        def wait(timeout):
            events.append(('wait', child.pid))
            child.returncode = 0
            return 0

        def killpg(group, signum):
            events.append(('signal', group, signum))

        with mock.patch.object(MODULE['os'], 'killpg', side_effect=killpg):
            with mock.patch.object(MODULE['os'], 'waitid', return_value=object()) as observe:
                with mock.patch.object(child, 'wait', side_effect=wait):
                    value.close()
        self.assertEqual(events, [('signal', 12345, signal.SIGTERM),
                                  ('signal', 12345, signal.SIGKILL), ('wait', 12345)])
        self.assertTrue(observe.call_args.args[2] & MODULE['os'].WNOWAIT)
        self.assertIsNone(value.child_group)
        self.assertIsNone(value.child)

    def test_stuck_group_is_not_signalled_again_after_reap(self):
        value = gateway()
        child = value.child
        child.pid = value.child_group = 12345
        with mock.patch.object(MODULE['os'], 'killpg') as killpg:
            value.abort_stuck_writer()
        killpg.assert_called_once_with(12345, signal.SIGKILL)
        self.assertIsNone(value.child_group)
        self.assertTrue(child.stdin.closed)


if __name__ == '__main__':
    unittest.main()
