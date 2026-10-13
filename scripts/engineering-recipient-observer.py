#!/usr/bin/env python3
"""Read one fresh registered stream with live kernel-peer lifetime checks."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import stat
import struct
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('engineering_observer_gates', ROOT/'scripts/plugin-live-acceptance.py')
GATES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATES)


def exact(wire, count):
    data = bytearray()
    while len(data) < count:
        part = wire.recv(count-len(data))
        GATES.require(bool(part), 'Truncated fresh stream')
        data.extend(part)
    return bytes(data)


def validate_response(result, meta, reviewed_sha, connected_ns, now):
    GATES.require(type(result) is dict and type(result.get('schema_version')) is int and result.get('schema_version') == 1
                  and result.get('job_id') == meta['job_id'] and result.get('nonce') == meta['nonce']
                  and result.get('registration_sha256') == reviewed_sha
                  and type(result.get('generated_ns')) is int
                  and connected_ns <= result['generated_ns'] <= now < meta['expires_ns'],
                  'Fresh exact live job binding required')
    GATES.require(result.get('status') == 'blocked' and result.get('check_executed') is False
                  and result.get('qualification_possible') is False,
                  'Execution claims are unsupported by this observer')
    return result


def consume(path, reviewed_sha):
    raw = GATES.bounded(path, 1024*1024, True)
    GATES.require(hashlib.sha256(raw).hexdigest() == reviewed_sha, 'Literal registration SHA differs')
    meta = GATES.strict(raw)
    GATES.require(meta.get('trust_policy') == 'explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime'
                  and meta.get('mode') == 'engineering-recipient'
                  and meta.get('boot_id') == Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'Exact host registration and boot required')
    endpoint = Path(meta['endpoint'])
    GATES.require(endpoint == path.parent/'observe.sock', 'Paired endpoint required')
    before = endpoint.lstat()
    GATES.require(stat.S_ISSOCK(before.st_mode) and before.st_uid == os.getuid()
                  and stat.S_IMODE(before.st_mode) == 0o600
                  and (before.st_dev, before.st_ino) == (meta['socket_dev'], meta['socket_ino']), 'Registered socket identity differs')
    with socket.socket(socket.AF_UNIX) as wire:
        wire.settimeout(15)
        wire.connect(str(endpoint))
        connected_ns = time.monotonic_ns()
        pid, uid, _ = struct.unpack('3i', wire.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        GATES.require(pid == meta['producer_pid'] and uid == meta['producer_uid'] == os.getuid(), 'Kernel producer identity differs')
        handle = os.pidfd_open(pid, 0)
        try:
            poll = select.poll()
            poll.register(handle, select.POLLIN|select.POLLHUP|select.POLLERR)
            GATES.require(not poll.poll(0), 'Registered producer is dead')
            actual = hashlib.sha256((Path('/proc')/str(pid)/'exe').read_bytes()).hexdigest()
            GATES.require(actual == meta['producer_exe_sha256'], 'Actual live producer executable differs')
            request = json.dumps({'schema_version': 1, 'job_id': meta['job_id'], 'nonce': meta['nonce'], 'request': 'observe'}, separators=(',', ':')).encode()
            wire.sendall(struct.pack('>I', len(request))+request)
            count = struct.unpack('>I', exact(wire, 4))[0]
            GATES.require(0 < count <= 1024*1024, 'Bounded live response required')
            result = GATES.strict(exact(wire, count))
            now = time.monotonic_ns()
            GATES.require(not poll.poll(0), 'Producer exited during observation')
            validate_response(result, meta, reviewed_sha, connected_ns, now)
            after = endpoint.lstat()
            GATES.require((after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
                          and GATES.bounded(path, 1024*1024, True) == raw, 'Registration or endpoint changed')
            # This producer only implements refusal. Never turn a transport
            # diagnostic or a caller-selected report into passing evidence.
            GATES.require(result.get('status') == 'blocked' and result.get('check_executed') is False
                          and result.get('qualification_possible') is False, 'Execution claims are unsupported by this observer')
            return {**result, 'kernel_peer_lifetime_live': True, 'hidden_pid_source_independently_verified': False}
        finally:
            os.close(handle)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registration', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(consume(args.registration, args.sha256), indent=2))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
