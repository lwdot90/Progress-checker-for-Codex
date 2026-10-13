#!/usr/bin/env python3
"""Check plan/config agreement; this does not verify the plugin product."""
import json
import hashlib
import re
from pathlib import Path

EVIDENCE_SOURCES = tuple('scripts/' + name for name in (
    'plugin-original-demo-acceptance-adapter.py', 'bind-original-demo-acceptance.py',
    'check-plugin-plan.py', 'plugin-original-demo-collector.py',
    'plugin-original-demo-activate.py', 'plugin-original-demo-observer.py',
    'plugin-original-demo-raw.py', 'plugin-original-demo-lifecycle.py',
    'plugin-evidence-acceptance.py', 'plugin-acceptance.py'))

DEDICATED_PLAN_SOURCES = tuple('scripts/' + name for name in (
    'plugin-acceptance.py', 'plugin-dedicated-plan-capture.py',
    'plugin-dedicated-plan-public.py', 'plugin-dedicated-plan-lifecycle.py',
    'plugin-dedicated-plan-adapter.py', 'plugin-acceptance-runtime.py',
    'plugin-sandbox-recipient.py', 'plugin-dedicated-plan-host.py',
    'plugin-dedicated-plan-activate.py', 'plugin-dedicated-plan-observer.py',
    'plugin-dedicated-plan-acceptance.py'))


def validate_dedicated_plan_metadata(plan, config, root):
    script = 'scripts/plugin-dedicated-plan-acceptance.py'
    flags = ('--run-live', '--attestation', '--sha256', '--output')
    selected = []
    for check in config['checks']:
        assert 'dedicated_plan_observer' not in check, 'Dedicated binding belongs only in machine plan metadata'
        if check['id'] == 'plan-submission':
            selected.append(check)
        else:
            # --sha256 is also the legitimate frozen global-archive pin.
            # Dedicated-only controls identify orphan composition, while the
            # selected plan check below still requires its exact full argv.
            assert script not in check['argv'] and not any(flag in check['argv'] for flag in flags if flag != '--sha256'), 'Orphan dedicated composite controls'
    assert len(selected) == 1
    check = selected[0]
    if 'dedicated_plan_observer' not in plan:
        assert script not in check['argv'] and not any(flag in check['argv'] for flag in flags), 'Dedicated composite argv has no machine binding'
        return
    binding = plan['dedicated_plan_observer']
    assert type(binding) is dict and set(binding) == {'attestation_path', 'sha256', 'output_path', 'trust_policy'}
    assert binding['trust_policy'] == 'explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime'
    assert type(binding['sha256']) is str and re.fullmatch('[0-9a-f]{64}', binding['sha256'])
    for key in ('attestation_path', 'output_path'):
        value = binding[key]
        assert type(value) is str
        path = Path(value)
        assert str(path) == value and path.is_absolute() and path.is_relative_to(root/'.local') and '..' not in path.parts
        assert path != root/'.local'
    attestation, output = Path(binding['attestation_path']), Path(binding['output_path'])
    assert attestation.name == 'attestation.json'
    assert output != attestation.parent and not output.is_relative_to(attestation.parent) and not attestation.parent.is_relative_to(output), 'Producer and output workspaces must be separate'
    assert attestation.resolve(strict=True) == attestation and attestation.is_file() and not attestation.is_symlink()
    assert output.parent.resolve(strict=True) == output.parent and not output.is_symlink(), 'Canonical nonsymlink output required'
    if output.exists():
        assert output.is_dir() and output.resolve(strict=True) == output, 'Existing output must be a canonical directory'
    before = attestation.stat()
    assert before.st_size <= 1024*1024
    data = attestation.read_bytes()
    after = attestation.stat()
    identity = lambda info: (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    assert identity(before) == identity(after) and len(data) == before.st_size
    assert hashlib.sha256(data).hexdigest() == binding['sha256'], 'Immutable current attestation SHA differs'
    archive = plan['acceptance_archive']
    assert archive == {'path':'.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz', 'sha256':'404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'}
    assert check['argv'] == ['/usr/bin/python3',script,'--run-live','--archive',archive['path'],'--attestation',str(attestation),'--sha256',binding['sha256'],'--output',str(output)]
    assert check['cwd'] == '.' and check['kind'] == 'test'
    assert type(check['timeout_seconds']) is int and check['timeout_seconds'] == 720
    assert type(config['execution']['max_parallel']) is int and config['execution']['max_parallel'] == 1
    assert all(path in config['fingerprint']['extra_inputs'] for path in DEDICATED_PLAN_SOURCES)
    assert str(attestation) not in config['fingerprint']['extra_inputs'] and str(attestation.relative_to(root)) not in config['fingerprint']['extra_inputs'], 'Attestation binds through literal SHA, not excluded fingerprint input'


def validate_evidence_metadata(plan, config, root):
    flags = ('--demo-attestation', '--demo-attestation-sha256', '--demo-readiness')
    for other in config['checks']:
        if other['id'] != 'evidence-integrity':
            assert not any(flag in other['argv'] for flag in flags)
            assert 'scripts/plugin-original-demo-acceptance-adapter.py' not in other['argv']
    selected = [value for value in config['checks'] if value['id'] == 'evidence-integrity']
    assert len(selected) == 1
    check = selected[0]
    binding = plan.get('evidence_observer')
    if binding is None:
        assert not any(flag in check['argv'] for flag in flags)
        assert 'scripts/plugin-original-demo-acceptance-adapter.py' not in check['argv']
        return
    assert type(binding) is dict and set(binding) == {'attestation_path','sha256','readiness_path','trust_policy'}
    assert binding['trust_policy'] == 'explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime'
    assert type(binding['sha256']) is str and re.fullmatch('[0-9a-f]{64}', binding['sha256'])
    a, r = Path(binding['attestation_path']), Path(binding['readiness_path'])
    assert a.parent == r.parent and a.name == 'attestation.json' and r.name == 'readiness.json'
    for path in (a, r):
        assert path.is_absolute() and path.is_relative_to(root/'.local') and '..' not in path.parts
    archive = plan['acceptance_archive']
    assert archive == {'path':'.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz', 'sha256':'404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'}
    assert check['argv'] == ['/usr/bin/python3','scripts/plugin-original-demo-acceptance-adapter.py','--archive',archive['path'],flags[0],str(a),flags[1],binding['sha256'],flags[2],str(r)]
    assert check['cwd'] == '.' and check['kind'] == 'test'
    assert type(check['timeout_seconds']) is int and check['timeout_seconds'] == 300
    assert type(config['execution']['max_parallel']) is int and config['execution']['max_parallel'] == 1
    assert all(path in config['fingerprint']['extra_inputs'] for path in EVIDENCE_SOURCES)
    assert plan['evidence_fixture'] == {'root':str(root/'.local/checker-demo/session-c5c6vsyz/project'), 'state':str(root/'.local/checker-demo/session-c5c6vsyz/state')}

def validate_live_jobs(plan, config, root):
    jobs = plan.get('live_acceptance_jobs')
    checks = {check['id']: check for check in config['checks']}
    kinds = {'plan': 'plan-submission', 'pilot': 'standard-codex-pilot', 'evidence': 'evidence-integrity'}
    if jobs is None:
        assert all('scripts/plugin-live-acceptance.py' not in check['argv']
                   and '--job-manifest' not in check['argv'] for check in checks.values())
        return
    assert type(jobs) is dict and set(jobs) == set(kinds)
    assert not any(key in plan for key in ('dedicated_plan_observer', 'primary_observer', 'evidence_observer'))
    assert config['execution']['max_parallel'] == 1
    assert plan['acceptance_archive'] == {'path':'.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz', 'sha256':'404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'}
    assert plan['acceptance_old_archive'] == {'path':'.progress-checker/acceptance-inputs/progress-checker-0.2.0-dev-linux-x86_64-fbf12375255a.tar.gz', 'sha256':'fbf12375255af78ff30b042a9f9938ecccec5e03d7e8504042dac1872b0f646a'}
    required = {
        'plugin-live-acceptance.py', 'plugin-acceptance.py', 'plugin-acceptance-runtime.py',
        'plugin-sandbox-recipient.py', 'plugin-dedicated-plan-capture.py', 'plugin-dedicated-plan-public.py',
        'plugin-dedicated-plan-lifecycle.py', 'plugin-dedicated-plan-adapter.py', 'plugin-dedicated-plan-host.py',
        'plugin-dedicated-plan-activate.py', 'plugin-dedicated-plan-observer.py', 'plugin-dedicated-plan-acceptance.py',
        'plugin-primary-acceptance.py', 'plugin-primary-observer.py', 'plugin-primary-pilot-producer.py',
        'plugin-primary-pilot-activate.py', 'plugin-primary-upgrade.py', 'plugin-pilot-acceptance.py',
        'plugin-original-demo-acceptance-adapter.py', 'plugin-original-demo-collector.py', 'plugin-original-demo-raw.py',
        'plugin-original-demo-lifecycle.py', 'plugin-original-demo-observer.py', 'plugin-original-demo-activate.py',
        'plugin-evidence-acceptance.py', 'plugin-release-acceptance.py', 'plugin-recipient-qualify.py'}
    assert {'scripts/'+name for name in required} <= set(config['fingerprint']['extra_inputs'])
    for check_id, check in checks.items():
        if check_id not in kinds.values():
            assert 'scripts/plugin-live-acceptance.py' not in check['argv'] and '--job-manifest' not in check['argv']
    for kind, check_id in kinds.items():
        binding = jobs[kind]
        assert type(binding) is dict and set(binding) == {'manifest_path', 'trust_policy'}
        assert binding['trust_policy'] == 'explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime'
        assert binding['manifest_path'] == '.local/acceptance-jobs/'+kind+'.json'
        argv = ['/usr/bin/python3', 'scripts/plugin-live-acceptance.py', '--kind', kind,
                '--job-manifest', binding['manifest_path'], '--archive', plan['acceptance_archive']['path']]
        if kind == 'pilot':
            argv += ['--recipient-old-archive', plan['acceptance_old_archive']['path']]
        check = checks[check_id]
        assert check['argv'] == argv
        assert (check['cwd'], check['kind'], check['timeout_seconds']) == ('.', 'test', 720 if kind == 'plan' else 300)
    workflow = next(item for item in config['milestones'] if item['id'] == 'agent-workflow')
    assert workflow['criteria'][0]['check_id'] == 'standard-codex-pilot'


def validate_primary_metadata(plan, config, root):
    flags = ('--primary-attestation','--primary-attestation-sha256','--primary-readiness')
    checks = {item['id']:item for item in config['checks']}
    argv = checks['standard-codex-pilot']['argv']
    binding = plan.get('primary_observer')
    if not binding:
        assert not any(flag in argv for flag in flags), 'Primary argv has no matching machine metadata'
        return
    assert set(binding) == {'attestation_path','sha256','readiness_path','trust_policy'}
    assert binding['trust_policy'] == 'explicit-reviewed-host-registration-with-kernel-peer-pidfd-lifetime'
    assert re.fullmatch('[0-9a-f]{64}', binding['sha256'])
    attestation, readiness = Path(binding['attestation_path']), Path(binding['readiness_path'])
    for path in (attestation, readiness):
        assert path.is_absolute() and path.is_relative_to(root/'.local') and '..' not in path.parts
    assert attestation.parent == readiness.parent and attestation != readiness
    current, prior = plan['acceptance_archive'], plan['acceptance_old_archive']
    assert current['sha256'] == '404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
    assert prior['sha256'] == 'fbf12375255af78ff30b042a9f9938ecccec5e03d7e8504042dac1872b0f646a'
    assert argv == ['/usr/bin/python3','scripts/plugin-acceptance.py','--milestone','standard-codex-pilot','--archive',current['path'],'--recipient-old-archive',prior['path'],flags[0],binding['attestation_path'],flags[1],binding['sha256'],flags[2],binding['readiness_path']]
    check = checks['standard-codex-pilot']
    assert (check['cwd'],check['kind'],check['timeout_seconds']) == ('.','test',300)
    assert config['execution']['max_parallel'] == 1


NATIVE_ONBOARDING_CHECKS = ('native-browser-install', 'live-service-approval', 'onboarding-release')


def validate_native_onboarding_metadata(plan, config, root):
    """Pending artifacts establish plan structure only, never product success."""
    artifact = plan['native_onboarding_release']
    assert type(artifact) is dict and set(artifact) == {'status', 'version', 'archive_path', 'sha256', 'reason'}
    assert artifact['version'] == '0.4.0-dev'
    assert type(artifact['reason']) is str and artifact['reason'].strip()
    assert artifact['status'] in {'pending', 'frozen'}
    manifest_path = root / '.progress-checker/native-onboarding-release.json'
    assert manifest_path.is_file() and not manifest_path.is_symlink()
    manifest = json.loads(manifest_path.read_text())
    assert type(manifest) is dict and type(manifest.get('schema_version')) is int and manifest['schema_version'] == 1
    assert all(manifest.get(key) == artifact[key] for key in ('status', 'version', 'archive_path', 'sha256')), 'Release manifest and machine plan archive pins differ'
    if artifact['status'] == 'pending':
        assert artifact['archive_path'] is None and artifact['sha256'] is None, 'Pending artifact must not invent a path or digest'
    else:
        assert type(artifact['archive_path']) is str and type(artifact['sha256']) is str
        assert re.fullmatch('[0-9a-f]{64}', artifact['sha256'])
        relative = Path(artifact['archive_path'])
        assert not relative.is_absolute() and '..' not in relative.parts
        assert relative.parent == Path('.progress-checker/acceptance-inputs')
        assert relative.name.startswith('progress-checker-0.4.0-dev-linux-x86_64-') and relative.name.endswith('.tar.gz')
        archive = root / relative
        assert archive.resolve().is_relative_to(root) and archive.is_file() and not archive.is_symlink()
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == artifact['sha256']
        assert artifact['archive_path'] in config['fingerprint']['extra_inputs']
    checks = {item['id']: item for item in config['checks']}
    for check_id in NATIVE_ONBOARDING_CHECKS:
        check = checks[check_id]
        assert check['argv'] == ['/usr/bin/python3', 'scripts/test-native-onboarding.py', '--case', check_id,
                                 '--release-manifest', '.progress-checker/native-onboarding-release.json']
        assert (check['cwd'], check['kind'], check['timeout_seconds']) == ('.', 'test', 300)
    assert {'scripts/test-native-onboarding.py', '.progress-checker/native-onboarding-release.json',
            'scripts/check-plugin-plan.py'} <= set(config['fingerprint']['extra_inputs'])
    expected_dependencies = {'native-browser-install': ['global-install'],
                             'live-service-approval': ['global-isolation', 'native-browser-install'],
                             'onboarding-release': ['native-browser-install', 'live-service-approval', 'release-distribution']}
    for item in plan['milestones']:
        if item['id'] in expected_dependencies:
            assert item['depends_on'] == expected_dependencies[item['id']]
    # Keep the established global package independent of the new artifact.
    assert plan['global_archive'] == {
        'path': '.progress-checker/acceptance-inputs/progress-checker-0.3.0-dev-linux-x86_64-0169944a4289.tar.gz',
        'sha256': '0169944a42895eb37a1b279316052fbf566e6a7d436ce53eef95d55060176d9b'}


root = Path(__file__).resolve().parent.parent
plan = json.loads((root / '.progress-checker/plugin-plan.json').read_text())
config = json.loads((root / '.progress-checker/config.json').read_text())
document = (root / 'PLUGIN_PLAN.md').read_text()
instructions = (root / 'AGENTS.md').read_text()
validate_live_jobs(plan, config, root)
assert plan['project_id'] == config['project_id'] == 'progress-checker-plugin'
USER_READINESS_IDS = {'first-use-workflow', 'user-quickstart-demo', 'repository-discovery', 'ubuntu-portability-assessment', 'user-doc-navigation', 'independent-user-trial'}
USER_READINESS_CHECKS = USER_READINESS_IDS - {'first-use-workflow'}
ENGINEERING_IDS = {'version-alignment', 'log-privacy', 'command-compatibility-policy', 'runnable-check-example', 'fingerprint-performance', 'service-architecture-review'}
ENGINEERING_CHECKS = {'engineering-unit-tests', 'engineering-fingerprint-benchmark', 'platform-development-tests'}
PLATFORM_IDS = {'ubuntu-native-support','native-windows-support','native-macos-support','wsl2-support','native-platform-builds','native-platform-packaging','recipient-regression','safe-fingerprint-buffer-reuse','portable-gateway'}
PLATFORM_CHECKS = {target+'-platform-qualification' for target in ('ubuntu','windows','macos','wsl2')}
expected_ids = {'delivery-plan', 'plugin-package', 'service-lifecycle', 'plan-submission', 'agent-workflow', 'evidence-integrity', 'release-distribution', 'standard-codex-pilot', 'global-install', 'project-activation', 'global-isolation', *NATIVE_ONBOARDING_CHECKS, *USER_READINESS_IDS, *ENGINEERING_IDS, *PLATFORM_IDS}
assert len(plan['milestones']) == len(config['milestones']) == len(expected_ids)
assert {item['id'] for item in plan['milestones']} == expected_ids
assert len({item['id'] for item in plan['milestones']}) == len(expected_ids)
assert 'Progress Checker project planning' in instructions
assert 'implementation claims' in instructions
checks = {item['id']: item for item in config['checks']}
for item, tracked in zip(plan['milestones'], config['milestones']):
    assert item['id'] == tracked['id']
    assert item['title'] == tracked['title']
    assert item['depends_on'] == tracked['depends_on']
    assert item['acceptance'].strip()
    assert f"### {item['id']} —" in document
    assert tracked['in_scope'] is True
    assert len(tracked['criteria']) == 1
    criterion = tracked['criteria'][0]
    assert criterion['required'] is True
    assert criterion['description'] == item['acceptance']
    assert criterion['check_id'] == item['check_id']
    assert item['check_id'] in checks
if artifact := plan.get('acceptance_archive'):
    archive = root / artifact['path']
    assert archive.resolve().is_relative_to(root)
    assert archive.is_file() and not archive.is_symlink()
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == artifact['sha256']
    assert artifact['path'] in config['fingerprint']['extra_inputs']
    for check in config['checks']:
        if check['id'] not in ('plan-definition', 'global-onboarding', *NATIVE_ONBOARDING_CHECKS, *USER_READINESS_CHECKS, *ENGINEERING_CHECKS, *PLATFORM_CHECKS):
            index = check['argv'].index('--archive')
            assert check['argv'][index + 1] == artifact['path']
if artifact := plan.get('acceptance_old_archive'):
    archive = root / artifact['path']
    assert archive.resolve().is_relative_to(root)
    assert archive.is_file() and not archive.is_symlink()
    assert artifact['sha256'] == 'fbf12375255af78ff30b042a9f9938ecccec5e03d7e8504042dac1872b0f646a'
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == artifact['sha256']
    assert artifact['path'] in config['fingerprint']['extra_inputs']
    for check_id in ('plugin-package', 'release-distribution'):
        argv = checks[check_id]['argv']
        index = argv.index('--recipient-old-archive')
        assert argv[index + 1] == artifact['path']
if runtime := plan.get('public_test_runtime'):
    assert runtime['mode'] == 'public-namespace'
    assert set(runtime['checks']) == {'plugin-package', 'service-lifecycle', 'agent-workflow'}
    for check_id in runtime['checks']:
        argv = checks[check_id]['argv']
        index = argv.index('--test-runtime')
        assert argv[index + 1] == runtime['mode']
        assert not any(flag in argv for flag in ('--evidence-fixture-root', '--plan-fixture-root', '--pilot-fixture-root'))
validate_primary_metadata(plan, config, root)
validate_evidence_metadata(plan, config, root)
validate_dedicated_plan_metadata(plan, config, root)
global_artifact = plan['global_archive']
archive = root / global_artifact['path']
assert archive.resolve().is_relative_to(root) and archive.is_file() and not archive.is_symlink()
assert hashlib.sha256(archive.read_bytes()).hexdigest() == global_artifact['sha256']
assert global_artifact['path'] in config['fingerprint']['extra_inputs']
argv = checks['global-onboarding']['argv']
assert argv[argv.index('--archive') + 1] == global_artifact['path']
assert argv[argv.index('--sha256') + 1] == global_artifact['sha256']
validate_native_onboarding_metadata(plan, config, root)
assert set(plan['user_readiness_extension']['scope_added']) == USER_READINESS_IDS
assert plan['user_readiness_extension']['scope_removed'] == []
assert plan['user_readiness_extension']['scope_changed'] == []
for check_id in USER_READINESS_CHECKS:
    assert checks[check_id]['argv'] == ['/usr/bin/python3', 'scripts/check-user-readiness.py', '--case', check_id]
assert set(plan['engineering_extension']['scope_added']) == ENGINEERING_IDS
assert plan['engineering_extension']['scope_removed'] == []
assert plan['engineering_extension']['scope_changed'] == []
assert checks['engineering-unit-tests']['argv'] == ['/usr/bin/bash','scripts/check-engineering.sh','tests']
assert checks['engineering-fingerprint-benchmark']['argv'] == ['/usr/bin/bash','scripts/check-engineering.sh','benchmark']
assert set(plan['native_platform_extension']['scope_added']) == PLATFORM_IDS
assert plan['native_platform_extension']['scope_removed'] == []
assert plan['native_platform_extension']['scope_changed'] == []
for target in ('ubuntu','windows','macos','wsl2'):
    assert checks[target+'-platform-qualification']['argv'] == ['/usr/bin/python3','scripts/check-platform-support.py','--platform',target]
assert checks['platform-development-tests']['argv'] == ['/usr/bin/bash','scripts/check-platform-development.sh']
print('PASS: all thirty-five milestones match the delivery plan and checker configuration.')
if plan['native_onboarding_release']['status'] == 'pending':
    print('PENDING: the 0.4 onboarding archive is not frozen; structure agreement does not qualify its behavior.')
print('Coverage: plan structure only; plugin implementation is not verified by this check.')
