#!/usr/bin/env python3
"""Live one-use transport foundation. No recipient runner is enabled yet."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import time
import re

TRUST = 'explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime'
LIMIT = 1024 * 1024


def encode(value):
    return json.dumps(value, separators=(',', ':'), allow_nan=False).encode()


def exact(wire, count):
    data = bytearray()
    while len(data) < count:
        part = wire.recv(count-len(data))
        if not part:
            raise RuntimeError('Truncated live packet')
        data.extend(part)
    return bytes(data)


class Producer:
    """Require reviewed activation externally; reader cannot choose work."""
    def __init__(self, directory: Path, input_binding: dict):
        required = {'source_inputs_sha256', 'preparation_job_sha256', 'image_sha256', 'runtime_files', 'argv'}
        if type(input_binding) is not dict or set(input_binding) != required:
            raise RuntimeError('Exact public input binding required; security metadata is not caller-selected')
        if any(type(input_binding[key]) is not str or re.fullmatch('[0-9a-f]{64}', input_binding[key]) is None
               for key in ('source_inputs_sha256', 'preparation_job_sha256', 'image_sha256')):
            raise RuntimeError('Exact immutable input hashes required')
        if input_binding['argv'] != ['/usr/bin/bash', 'scripts/check-engineering.sh', 'tests']:
            raise RuntimeError('Only the full regression suite is proposed')
        if type(input_binding['runtime_files']) is not dict or not input_binding['runtime_files']:
            raise RuntimeError('Explicit runtime inventory required')
        self.directory = directory
        if directory.exists() or directory.is_symlink():
            raise RuntimeError('Use a new dedicated producer directory')
        directory.mkdir(mode=0o700)
        self.endpoint = directory/'observe.sock'
        self.wire = socket.socket(socket.AF_UNIX)
        self.wire.bind(str(self.endpoint))
        os.chmod(self.endpoint, 0o600)
        self.wire.listen(1)
        self.job_id, self.nonce = secrets.token_hex(16), secrets.token_hex(32)
        self.started_ns = time.monotonic_ns()
        socket_info = self.endpoint.stat()
        self.registration = {
            'schema_version': 1, 'mode': 'engineering-recipient', 'trust_policy': TRUST,
            **input_binding, 'job_id': self.job_id, 'nonce': self.nonce,
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'producer_pid': os.getpid(), 'producer_uid': os.getuid(),
            'producer_exe_sha256': hashlib.sha256(Path('/proc/self/exe').read_bytes()).hexdigest(),
            'endpoint': str(self.endpoint), 'socket_dev': socket_info.st_dev,
            'socket_ino': socket_info.st_ino, 'prepared_ns': self.started_ns,
            'expires_ns': self.started_ns+1800_000_000_000,
            'activation_enabled': False, 'qualification_possible': False,
        }
        raw = encode(self.registration)
        fd = os.open(directory/'attestation.json', os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
        self.registration_sha256 = hashlib.sha256(raw).hexdigest()
        self.consumed = False

    def observe_once(self):
        """Fresh refusal proves transport only. It executes no check or CLI."""
        if self.consumed:
            raise RuntimeError('One-use job was already consumed')
        self.wire.settimeout(15)
        with self.wire.accept()[0] as peer:
            peer.settimeout(15)
            _, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.getuid():
                raise RuntimeError('Foreign observer refused')
            count = struct.unpack('>I', exact(peer, 4))[0]
            if not 0 < count <= 4096:
                raise RuntimeError('Bounded exact reader request required')
            request = exact(peer, count)
            expected = encode({'schema_version': 1, 'job_id': self.job_id,
                               'nonce': self.nonce, 'request': 'observe'})
            if request != expected or time.monotonic_ns() >= self.registration['expires_ns']:
                raise RuntimeError('Unknown, expired or reader-selected work refused')
            self.consumed = True
            response = encode({'schema_version': 1, 'job_id': self.job_id,
                               'nonce': self.nonce, 'registration_sha256': self.registration_sha256,
                               'generated_ns': time.monotonic_ns(), 'status': 'blocked',
                               'check_executed': False, 'qualification_possible': False,
                               'reason': 'Fixed independently human-approved isolated recipient runner is not implemented.'})
            peer.sendall(struct.pack('>I', len(response))+response)

    def close(self):
        self.wire.close()
        # Preserve socket path and attestation identities for review; never
        # delete an unverified replacement endpoint or public registration.


if __name__ == '__main__':
    print('OFF: producer transport library only; no preparation, activation, approval or execution.')
