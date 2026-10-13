#!/usr/bin/env python3
"""Test live-service freshness with synthetic worktrees and explicit fixture approvals."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
import time

from importlib.util import module_from_spec, spec_from_file_location

_spec = spec_from_file_location('service_acceptance', Path(__file__).with_name('smoke-service.py'))
_service = module_from_spec(_spec)
_spec.loader.exec_module(_service)


class Freshness(_service.Acceptance):
    def execute(self):
        self.report.pop('mcp_binary_sha256', None)
        self.report['baseline'].pop('samples', None)
        self.report['harness'] = 'live-service-freshness'
        self.save()
        with tempfile.TemporaryDirectory(prefix='service-freshness-') as temporary:
            directory = Path(temporary)
            self.root, config = _service._phase1.fixture(directory)
            check = self.root / 'check.py'
            check.write_text(check.read_text().replace(
                'sys.exit(1 if', 'if mode=="delayed": time.sleep(1)\nsys.exit(1 if'))
            (self.root / 'mode.txt').write_text('delayed\n')
            self.state = directory / 'state'
            self.state.mkdir(mode=0o700)
            home = directory / 'home'
            home.mkdir(mode=0o700)
            self.environment.update(HOME=str(home), XDG_CONFIG_HOME=str(home / 'config'))
            digest = _service.hashlib.sha256(_service.os.fsencode(self.root.resolve())).hexdigest()[:24]
            self.socket = self.state / f'ipc-{digest}.sock'
            approval = _service._phase1.Harness(self.binary, self.output / 'approval')
            approval.state_dir, approval.environment = self.state, self.environment
            approval.approve(self.root, 'check', 'approve check')
            service = self.start()
            client = _service.IPC(self.socket)
            for milestone in ('feature', 'dependent'):
                status = self.snapshot(client)
                self.request(client, 'set_claim', milestone_id=milestone, claim='implemented',
                             note='Synthetic freshness claim', expected_revision=status['revision'])
            status = self.snapshot(client)
            accepted = self.run(client, 'edit-revert', status)
            source = self.root / 'source.txt'
            original = source.read_text()
            time.sleep(0.1)
            source.write_text('transient edit during execution\n')
            time.sleep(0.15)
            source.write_text(original)
            status = self.finished(client, accepted['run_id'])
            evidence = status['latest']['check']
            self.check('passing edit-revert run never produces current green',
                       evidence['outcome'] == 'passed' and evidence['freshness'] == 'stale' and
                       status['progress']['verified'] == 0)
            accepted = self.run(client, 'clean-followup', status)
            status = self.finished(client, accepted['run_id'])
            self.check('clean subsequent run restores current verification',
                       status['progress']['verified'] == 2 and
                       status['latest']['check']['freshness'] == 'current')
            old_config_hash = status['source']['config_hash']
            config_path = self.root / '.progress-checker/config.json'
            original_config = config_path.read_text()
            config['milestones'][0]['title'] = 'Changed acceptance configuration'
            config_path.write_text(json.dumps(config, indent=2) + '\n')
            status = self.wait_for(client, lambda snapshot:
                                   snapshot['source']['config_hash'] != old_config_hash)
            self.check('live configuration change invalidates passing evidence',
                       status['progress']['verified'] == 0 and
                       status['latest']['check']['freshness'] == 'stale')
            self.request(client, 'run_checks', expected_error='PERMISSION_REQUIRED', check_ids=['check'],
                         idempotency_key='changed-config-denied',
                         expected_config_hash=status['source']['config_hash'],
                         expected_revision=status['revision'])
            self.check('changed configuration cannot reuse old command approval',
                       self.snapshot(client)['latest']['check']['run_id'] == accepted['run_ids'][0])
            config_path.write_text(original_config)
            status = self.wait_for(client, lambda snapshot:
                                   snapshot['source']['config_hash'] == old_config_hash)
            old_commit = status['source']['git_commit']
            _service.subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Smoke',
                                     '-c', 'user.email=smoke@example.invalid', 'commit',
                                     '--allow-empty', '-qm', 'synthetic HEAD change'], check=True)
            status = self.wait_for(client, lambda snapshot:
                                   snapshot['source']['git_commit'] != old_commit)
            self.check('live HEAD change invalidates passing evidence',
                       status['progress']['verified'] == 0 and
                       status['latest']['check']['freshness'] == 'stale')
            self.check('freshness refresh executes no additional check',
                       status['latest']['check']['run_id'] == accepted['run_ids'][0])
            self.stop(service)
        self.report['complete'] = True
        self.save()

    def wait_for(self, client, condition):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status = self.snapshot(client)
            if condition(status):
                return status
            time.sleep(0.03)
        raise AssertionError('Live service did not refresh the mutated source identity')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('.local/service-freshness'))
    options = parser.parse_args()
    options.mcp_binary, options.samples = options.binary, 20
    harness = Freshness(options)
    try:
        harness.execute()
    except Exception as error:
        harness.report['failure'] = {'type': type(error).__name__, 'message': str(error)}
        harness.save()
        raise
    finally:
        harness.cleanup()
    print(f'Live-service freshness evidence: {harness.output / "report.json"}')


if __name__ == '__main__':
    main()
