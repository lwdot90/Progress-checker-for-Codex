#!/usr/bin/env python3
"""Pure metadata/input regressions; no services, approvals or check execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT/'scripts'/name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ADAPTER = load('engineering-recipient-adapter.py')
OBSERVER = load('engineering-recipient-observer.py')
PRODUCER = load('engineering-recipient-producer.py')
PREPARE = load('prepare-engineering-recipient.py')


def digest(data):
    return hashlib.sha256(data).hexdigest()


class InputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.jobdir = self.root/'.local'/'recipient'
        (self.jobdir/'source').mkdir(parents=True)
        (self.root/'scripts').mkdir()
        self.source = self.root/'scripts'/'fixture.py'
        self.source.write_bytes(b'print("public")\n')
        (self.jobdir/'source'/'scripts').mkdir()
        self.snapshot = self.jobdir/'source'/'scripts'/'fixture.py'
        self.snapshot.write_bytes(self.source.read_bytes())
        inventory = json.dumps({'scripts/fixture.py': digest(self.source.read_bytes())}).encode()
        (self.jobdir/'inputs.json').write_bytes(inventory)
        self.job = {'schema_version': 1, 'purpose': 'engineering-recipient-preparation-only',
                    'source': 'source', 'proposed_job_argv': ['/usr/bin/bash', 'scripts/check-engineering.sh', 'tests'],
                    'approval_created': False, 'check_executed': False, 'qualification_possible': False,
                    'inputs_sha256': digest(inventory)}
        self.path = self.jobdir/'job.json'
        self.write_job()

    def write_job(self):
        raw = json.dumps(self.job).encode()
        self.path.write_bytes(raw)
        self.sha = digest(raw)

    def validate(self):
        with patch.object(ADAPTER, 'ROOT', self.root):
            return ADAPTER.preparation(self.path, self.sha)

    def test_public_snapshot_validates(self):
        self.assertEqual(self.validate()['input_count'], 1)

    def test_changed_current_source_refused(self):
        self.source.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'Current source differs'):
            self.validate()

    def test_changed_snapshot_refused(self):
        self.snapshot.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'Snapshot source changed'):
            self.validate()

    def test_extra_snapshot_file_refused(self):
        (self.jobdir/'source'/'extra.py').write_bytes(b'public')
        with self.assertRaisesRegex(RuntimeError, 'unregistered'):
            self.validate()

    def test_symlink_snapshot_refused(self):
        self.snapshot.unlink()
        self.snapshot.symlink_to(self.source)
        with self.assertRaisesRegex(RuntimeError, 'symlinks'):
            self.validate()

    def test_caller_claimed_execution_refused(self):
        self.job['check_executed'] = True
        self.write_job()
        with self.assertRaisesRegex(RuntimeError, 'non-executing'):
            self.validate()

    def test_private_inventory_refused_before_current_read(self):
        inventory = json.dumps({'.progress-checker/grants.json': 'a'*64}).encode()
        (self.jobdir/'inputs.json').write_bytes(inventory)
        self.job['inputs_sha256'] = digest(inventory)
        self.write_job()
        with self.assertRaisesRegex(RuntimeError, 'outside explicit public'):
            self.validate()

    def test_excluded_nested_inventory_refused(self):
        inventory = json.dumps({'scripts/.local/private.json': 'a'*64}).encode()
        (self.jobdir/'inputs.json').write_bytes(inventory)
        self.job['inputs_sha256'] = digest(inventory)
        self.write_job()
        with self.assertRaisesRegex(RuntimeError, 'Unsafe source'):
            self.validate()

    def test_modified_during_final_read_refused(self):
        original = ADAPTER.GATES.bounded
        reads = 0
        def bounded(path, *args, **kwargs):
            nonlocal reads
            data = original(path, *args, **kwargs)
            if Path(path) == self.path:
                reads += 1
                if reads == 2:
                    return data+b' '
            return data
        with patch.object(ADAPTER.GATES, 'bounded', bounded):
            with self.assertRaisesRegex(RuntimeError, 'changed during validation'):
                self.validate()


class SourceRosterTests(unittest.TestCase):
    def test_workspace_and_static_source_inputs_preserved(self):
        for name in ('checker-global', 'rust-toolchain.toml', 'NOTICE', 'schemas', '.github',
                     '.progress-checker/plugin-plan.json'):
            with self.subTest(name=name):
                self.assertIn(name, PREPARE.INPUTS)

    def test_hidden_state_is_explicit_public_files_only(self):
        for name in PREPARE.INPUTS:
            if name.startswith('.progress-checker'):
                self.assertTrue(name == '.progress-checker/plugin-plan.json' or
                                name.startswith('.progress-checker/acceptance-inputs/') and name.endswith('.tar.gz'))
        self.assertNotIn('.progress-checker', PREPARE.INPUTS)
        self.assertNotIn('.progress-checker/config.json', PREPARE.INPUTS)


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.meta = {'job_id': 'a'*32, 'nonce': 'b'*64, 'expires_ns': 30}
        self.sha = 'c'*64
        self.result = {'schema_version': 1, 'job_id': self.meta['job_id'], 'nonce': self.meta['nonce'],
                       'registration_sha256': self.sha, 'generated_ns': 15, 'status': 'blocked',
                       'check_executed': False, 'qualification_possible': False}

    def validate(self):
        return OBSERVER.validate_response(self.result, self.meta, self.sha, 10, 20)

    def test_fresh_refusal_is_not_qualification(self):
        self.assertFalse(self.validate()['qualification_possible'])

    def test_wrong_identity_nonce_and_old_clock_refused(self):
        for key, value in [('job_id', 'x'), ('nonce', 'x'), ('registration_sha256', 'x'),
                           ('generated_ns', 9), ('generated_ns', True)]:
            with self.subTest(key=key, value=value):
                original = self.result[key]
                self.result[key] = value
                with self.assertRaises(RuntimeError):
                    self.validate()
                self.result[key] = original

    def test_agent_written_passing_claim_refused(self):
        self.result.update(status='passed', check_executed=True, qualification_possible=True)
        with self.assertRaisesRegex(RuntimeError, 'unsupported'):
            self.validate()

    def test_user_boolean_cannot_override_producer_metadata(self):
        for key in ('trust_policy', 'activation_enabled', 'qualification_possible', 'producer_pid'):
            with self.subTest(key=key):
                with self.assertRaisesRegex(RuntimeError, 'security metadata'):
                    PRODUCER.Producer(Path('/not-created'), {key: True})


if __name__ == '__main__':
    unittest.main()
