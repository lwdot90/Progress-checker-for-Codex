#!/usr/bin/env python3
"""Fresh authenticated native pilot probes; never issue command approval.

Prepare runs accepted planning/readiness only. Verify requires an explicitly
selected prior human-granted check; the backend remains the authority. Missing
host authentication is a qualification gap, never a reason to copy credentials
or expose a host home to an acceptance sandbox.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import select
import signal
import stat
import subprocess
import time
import tomllib
import types

ROOT = Path(__file__).resolve().parent.parent
ACTIVE = 'progress-checker@progress-local-8b5742430514'
GAPS = ['Authenticated existing-project verification, source staleness and restart need the explicit prior human-granted exact check.',
        'Actual failed MCP startup normal prompt handling; configured disabled-server proof is narrower.',
        'Fresh clean recipient qualification.',
        'Primary repository authenticated local-development trial remains separate from isolated fixture coverage.']


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _files(path):
    if not path.exists():
        return None
    if path.is_file():
        return {'sha256': _hash(path.read_bytes()), 'mode': stat.S_IMODE(path.stat().st_mode)}
    result = {}
    for file in path.rglob('*'):
        if file.is_symlink():
            result[str(file.relative_to(path))] = {'symlink': os.readlink(file)}
        elif file.is_file():
            result[str(file.relative_to(path))] = _files(file)
    return result


def _public(root):
    values = {}
    for path in root.rglob('*'):
        if '.git' in path.relative_to(root).parts:
            continue
        if path.is_symlink():
            raise RuntimeError('Pilot public fixture may not contain symlinks')
        if path.is_file():
            info = path.stat()
            if info.st_size > 1024 * 1024 or info.st_uid != os.geteuid():
                raise RuntimeError('Pilot fixture file must be bounded and owned')
            values[str(path.relative_to(root))] = (path.read_bytes(), stat.S_IMODE(info.st_mode))
    if len(values) > 128:
        raise RuntimeError('Pilot fixture exceeds bounded public inventory')
    return values


def _public_hashes(values):
    return {name: {'sha256': _hash(value[0]), 'mode': value[1]} for name, value in values.items()}


def _group_members(process):
    result = []
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit():
            continue
        try:
            info = directory.stat()
            fields = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) == process.pid and int(fields[3]) == process.pid and fields[0] != 'Z':
                if info.st_uid != os.geteuid():
                    raise RuntimeError('Native process group contains a differently owned process')
                result.append(int(directory.name))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return result


def _stop_group(process):
    """Stop the owned new session even when its leader exited before children."""
    # A group ID remains reserved while members exist. Requiring both session
    # and group IDs to match our new-session leader excludes unrelated groups.
    members = _group_members(process)
    if members:
        os.killpg(process.pid, signal.SIGTERM)
    deadline = time.monotonic() + 2
    while _group_members(process) and time.monotonic() < deadline:
        time.sleep(.025)
    if _group_members(process):
        # Checker writers/watchdogs are detached into distinct sessions; this
        # escalation reaches only our native invocation group.
        os.killpg(process.pid, signal.SIGKILL)
        deadline = time.monotonic() + 3
        while _group_members(process) and time.monotonic() < deadline:
            time.sleep(.025)
        if _group_members(process):
            raise RuntimeError('Owned native group did not exit after bounded escalation')
    process.wait(timeout=3)


def _run(directory, label, argv, env, root, timeout=180, deadline=None):
    cutoff = min(time.monotonic() + timeout, deadline if deadline is not None else float('inf'))
    if time.monotonic() >= cutoff:
        raise RuntimeError('Shared pilot work deadline expired before ' + label)
    process = subprocess.Popen([str(value) for value in argv], cwd=root, env=env,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    streams = {process.stdout: (directory / (label + '.stdout')).open('wb'),
               process.stderr: (directory / (label + '.stderr')).open('wb')}
    counts = {stream: 0 for stream in streams}
    try:
        pending = set(streams)
        while pending:
            remaining = cutoff - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('Bounded native invocation timed out; no restart was attempted')
            ready, _, _ = select.select(list(pending), [], [], min(.1, remaining))
            for stream in ready:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    pending.remove(stream)
                    continue
                counts[stream] += len(chunk)
                if counts[stream] > 8 * 1024 * 1024:
                    raise RuntimeError('Native live output exceeded bounded 8 MiB per stream')
                streams[stream].write(chunk)
                streams[stream].flush()
        process.wait(timeout=max(.001, cutoff - time.monotonic()))
        if process.returncode:
            raise RuntimeError(label + ' failed with exit ' + str(process.returncode))
    except BaseException:
        _stop_group(process)
        raise
    finally:
        for stream, output in streams.items():
            output.close()
            stream.close()
    return ((directory / (label + '.stdout')).read_text(),
            (directory / (label + '.stderr')).read_text())


def _native_receive(self, timeout=15):
    deadline = min(time.monotonic() + timeout, getattr(self, 'pilot_deadline', float('inf')))
    while b'\n' not in self.buffer:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([self.wire.stdout], [], [], remaining)[0]:
            raise RuntimeError('Native diagnostic response deadline exceeded')
        chunk = os.read(self.wire.stdout.fileno(), 65536)
        if not chunk:
            raise RuntimeError('Native diagnostic closed before complete response')
        self.buffer.extend(chunk)
        if len(self.buffer) > 8 * 1024 * 1024:
            raise RuntimeError('Native diagnostic frame exceeds 8 MiB')
    line, _, rest = self.buffer.partition(b'\n')
    self.buffer[:] = rest
    return json.loads(line)


def standard_codex_pilot(acceptance, directory, fixture_root, fixture_state,
                         codex_home, accepted_plan, phase='prepare', check_id=None):
    report = acceptance.report['authenticated_pilot'] = {
        'phase': phase, 'status': 'blocked', 'credentials_copied': False,
        'approval_created': False, 'configured_checks_executed': False,
        'full_primary_project_trial_complete': False, 'model_invocations': [],
        'coverage': 'Fresh authenticated installed-fixture behavior only; no saved report reuse.'}
    missing = []
    for name, value in [('fixture root', fixture_root), ('fixture state', fixture_state),
                        ('Codex authentication home', codex_home), ('accepted public plan', accepted_plan)]:
        if value is None:
            missing.append('Explicit pilot ' + name + ' is required.')
    if missing:
        return missing + GAPS
    if not acceptance.options.archive or not acceptance.report.get('archive'):
        return ['Authenticated pilot requires the exact validated --archive.'] + GAPS
    home = Path(codex_home)
    if not home.is_dir() or not (home / 'config.toml').is_file():
        return ['Explicit authenticated Codex home is unavailable in this environment; no host-home exposure or credential copying is attempted.'] + GAPS
    if phase not in ('prepare', 'verify'):
        raise RuntimeError('Unknown pilot phase')
    if phase == 'verify' and check_id != 'demo-check':
        return ['Verification requires explicit --pilot-approved-check demo-check and its prior genuine human grant.'] + GAPS
    # Load exact current implementation sources, without timestamp-cached pyc.
    import importlib.util
    source = acceptance.artifact('pilot_runner_source', ROOT / 'scripts/plugin-acceptance.py')
    specification = importlib.util.spec_from_file_location('pilot_runner', source)
    runner = importlib.util.module_from_spec(specification)
    exec(compile(source.read_bytes(), str(source), 'exec'), runner.__dict__)
    release = runner.behavioral_module(acceptance, 'plugin_release_acceptance')
    evidence = runner.behavioral_module(acceptance, 'plugin_evidence_acceptance')
    root, state = Path(fixture_root).resolve(strict=True), Path(fixture_state).resolve(strict=True)
    if (root == ROOT or root in state.parents or state in root.parents
            or not (root / '.git').exists() or not state.is_dir()):
        raise RuntimeError('Pilot needs a separate existing Git fixture and external retained state')
    if 'plan-invalidation-human-fixture' in str(root):
        raise RuntimeError('Pending dedicated plan approval fixture is not a pilot fixture')
    expected_bytes, _ = evidence._bounded_file(Path(accepted_plan), 64 * 1024)
    expected = json.loads(expected_bytes)
    original = _public(root)
    original_config = json.loads(original['.progress-checker/config.json'][0])
    if expected.get('project_id') != original_config.get('project_id'):
        raise RuntimeError('Accepted pilot plan must preserve the selected project identity')
    approved_fixture = evidence._Fixture(root, state) if phase == 'verify' else None
    if phase == 'verify' and expected != original_config:
        return ['Verify requires the already accepted exact config; a changed plan would invalidate its human grant.'] + GAPS
    directory.mkdir(parents=True, exist_ok=True)
    started = getattr(acceptance, 'started_at', time.monotonic())
    work_deadline, hard_deadline = started + 210, started + 295
    report['shared_budget_seconds'] = {'work': 210, 'hard_with_cleanup': 295}
    plugin = acceptance.options.plugin_directory.resolve(strict=True)
    installer = plugin.parent / 'install.py'
    codex = acceptance.artifact('pilot_native_codex', acceptance.options.codex_binary)
    if not codex.is_file() or not os.access(codex, os.X_OK):
        return ['Native standard Codex is unavailable.'] + GAPS
    env = os.environ.copy()
    env['CODEX_HOME'] = str(home)
    # Explicit direct profile authentication rather than an inherited API key.
    env.pop('OPENAI_API_KEY', None); env.pop('CODEX_API_KEY', None)
    report['frontend_environment_presence'] = {name: True for name in sorted(env)
        if any(word in name.upper() for word in ('CODEX', 'PROXY', 'AGENT', 'SANDBOX', 'MCP'))}
    selector = 'progress-checker@progress-local-' + _hash(os.fsencode(root))[:12]
    market = selector.split('@')[1]
    cache = home / 'plugins/cache' / market / 'progress-checker' / acceptance.report['archive']['version']
    runtime = state / ('plugin-' + _hash(os.fsencode(root))[:24])
    settings = home / 'config.toml'
    before_settings = settings.read_bytes()
    before_toml = tomllib.loads(before_settings.decode())
    active_paths = {'cache': home / 'plugins/cache/progress-local-8b5742430514/progress-checker/0.2.1-dev',
                    'source': Path('/home/luis/.local/share/progress-checker-plugins/8b5742430514/plugins/progress-checker'),
                    'project_config': ROOT / '.codex/config.toml'}
    active_before = {name: _files(path) for name, path in active_paths.items()}
    if (selector in before_toml.get('plugins', {}) or market in before_toml.get('marketplaces', {})
            or (home / 'plugins/cache' / market).exists()):
        raise RuntimeError('Selected pilot namespace already exists; refusing unrelated installation mutation')
    report['before_audit'] = {'active_root': active_before, 'profile_sha256': _hash(before_settings),
                              'fixture_public': _public_hashes(original)}
    (directory / 'before-audit.json').write_text(json.dumps(report['before_audit'], indent=2) + '\n')
    directory_created = not (root / '.codex').exists()
    owned_file = release.settings_snapshot(root / '.codex/config.toml')
    owned_directory = release.directory_identity(root / '.codex')
    installed = False
    log = (directory / 'public-native.stderr').open('ab')
    args = ['--project', str(root), '--codex', str(codex), '--codex-home', str(home),
            '--data-home', str(directory / 'installer-data'), '--state-dir', str(state), '--skip-agent-instructions']
    overrides = ['plugins.' + ACTIVE + '.enabled=false', 'plugins.' + selector + '.enabled=true']
    report['source_configapply_facts'] = {
        'key_parser': 'utils/cli/src/config_override.rs preserves key text',
        'apply': 'config/src/overrides.rs splits literal dotted path without stripping quotes',
        'native_policy': 'PluginConfig.mcp_servers per-tool host policy; AppToolApproval::Approve skips only native MCP prompt',
        'unchanged_plan': 'checker-core/src/plan.rs config==self.config returns Ok(None) before approval clearing'}

    def run(label, argv, timeout=180, cleanup=False):
        return _run(directory, label, argv, env, root, timeout,
                    hard_deadline if cleanup else work_deadline)

    def snapshot(label):
        client = runner.LauncherSession(acceptance, plugin / 'bin/checker-plugin', root, state,
                                       runner.environment(directory), plugin, log)
        try:
            client.initialize()
            current = client.current()['result']
            value = {key: current[key] for key in ('config', 'claims', 'running')}
            value['latest'] = current['status']['latest']
            value['progress'] = current['status']['progress']
            value['history'] = client.history()
            (directory / (label + '-public.json')).write_text(json.dumps(value, indent=2) + '\n')
            return value
        finally:
            client.close()

    def inventory(disabled=False, failed=False):
        native = runner.NativeCodex.__new__(runner.NativeCodex)
        native.sequence, native.buffer, native.notifications = 0, bytearray(), []
        native.thread_id = native.shutdown_probe = None
        native.pilot_deadline = work_deadline
        native.receive = types.MethodType(_native_receive, native)
        flags = overrides + (['plugins.' + selector + '.mcp_servers.progress_checker.enabled=false'] if disabled else [])
        argv = [codex, '--no-daemon'] + [value for item in flags for value in ('-c', item)] + ['app-server', '--listen', 'stdio://']
        native.wire = subprocess.Popen([str(value) for value in argv], cwd=root, env=env,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, start_new_session=True)
        try:
            result = native.call('initialize', {'clientInfo': {'name': 'pilot-acceptance', 'version': '1'},
                                                'capabilities': {'experimentalApi': True}})
            native.send({'method': 'initialized'})
            acceptance.check('authenticated native profile is exactly explicitly selected', result['codexHome'] == str(home))
            skills = native.call('skills/list', {'cwds': [str(root)], 'forceReload': False})
            available = [skill for item in skills.get('data', []) for skill in item.get('skills', [])
                         if skill.get('pluginId') == selector and skill.get('enabled')]
            acceptance.check('exact owned installed pilot skill is enabled', len(available) == 1)
            started = native.call('thread/start', {'cwd': str(root), 'ephemeral': True,
                                                 'approvalPolicy': 'never', 'sandbox': 'read-only'})
            native.thread_id = started['thread']['id']
            report['model'] = {key: started.get(key) for key in ('model', 'modelProvider')}
            deadline = min(time.monotonic() + 45, work_deadline)
            while True:
                result = native.call('mcpServerStatus/list', {'threadId': native.thread_id})
                servers = [server for server in result['data'] if server['name'] == 'progress_checker']
                if servers and servers[0].get('runtimeStatus') in ('connected', 'disabled', 'failed') or time.monotonic() > deadline:
                    break
                time.sleep(.1)
            acceptance.check('native installed checker inventory matches selected availability',
                len(servers) == 1 and servers[0].get('pluginId') == selector
                and (servers[0].get('runtimeStatus') == 'failed' and not servers[0]['tools'] if failed
                     else servers[0].get('runtimeStatus') == 'disabled' and not servers[0]['tools'] if disabled
                     else servers[0].get('runtimeStatus') == 'connected' and set(servers[0]['tools']) == runner.EXPECTED_TOOLS))
            return {'disabled': disabled, 'failed_startup': failed, 'server': {'runtimeStatus': servers[0]['runtimeStatus'],
                                                    'tools': sorted(servers[0]['tools'])}, 'skill': available[0]}
        finally:
            acceptance.check('native no-model discovery closes cleanly', native.close() == 0)

    def model(label, prompt, allowed, permissions=(), disabled=False):
        skill = str(cache / 'skills/progress-checker/SKILL.md')
        prefix = 'Apply the installed Progress Checker skill; only cat of its exact file ' + skill + ' is an allowed shell command. '
        suffix = ' Never approve commands or change files through shell. Invoke only the explicitly requested tools. Then answer what is2+3.'
        flags = overrides + list(permissions) + (['plugins.' + selector + '.mcp_servers.progress_checker.enabled=false'] if disabled else [])
        argv = [codex, '--no-daemon', '-a', 'never', '-s', 'read-only', '-C', root]
        argv += [value for item in flags for value in ('-c', item)] + ['exec', '--json', '--ephemeral', prefix + prompt + suffix]
        text, _ = run(label, argv)
        events = [json.loads(line) for line in text.splitlines() if line.strip()]
        calls = [event['item'] for event in events if event.get('type') == 'item.completed'
                 and event.get('item', {}).get('type') == 'mcp_tool_call']
        messages = [event['item']['text'] for event in events if event.get('type') == 'item.completed'
                    and event.get('item', {}).get('type') == 'agent_message']
        commands = [event['item'].get('command', '') for event in events if event.get('type') == 'item.completed'
                    and event.get('item', {}).get('type') == 'command_execution']
        receipt = {'label': label, 'argv': list(map(str, argv)), 'calls': calls,
                   'normal_answer': '\n'.join(messages), 'shell_commands': commands}
        report['model_invocations'].append(receipt)
        (directory / (label + '.jsonl')).write_text(text)
        acceptance.check(label + ': only authorized checker calls', all(call.get('server') == 'progress_checker'
                         and call.get('tool') in allowed for call in calls))
        acceptance.check(label + ': only exact installed skill read', all(command in (
            'cat ' + skill, "/bin/bash -lc 'cat " + skill + "'", "/bin/bash -lc 'cat -- " + skill + "'") for command in commands))
        acceptance.check(label + ': no shell file edits', not any(event.get('item', {}).get('type') == 'file_change' for event in events))
        acceptance.check(label + ': arithmetic answer completes normally', bool(re.search(r'\b5\b', receipt['normal_answer'])))
        return receipt

    def permission(tool):
        return 'plugins.' + selector + '.mcp_servers.progress_checker.tools.' + tool + '.approval_mode="approve"'

    try:
        baseline = snapshot('before')
        acceptance.check('pilot startup has no active configured checks', baseline['running'] == [])
        auth_out, auth_error = run('native-login-status', [codex, 'login', 'status'], 30)
        report['authentication_status'] = auth_out.strip() or auth_error.strip()
        report['codex_version'] = run('native-version', [codex, '--version'], 20)[0].strip()
        installed = True
        report['installation_attempted'] = True
        run('install', ['/usr/bin/python3', installer, 'install', *args], 90)
        owned_file, owned_directory = release.settings_snapshot(root / '.codex/config.toml'), release.directory_identity(root / '.codex')
        checksums = json.loads((plugin.parent / 'checksums.json').read_text())
        acceptance.check('authenticated installed cache exact archive runtime inventory', all(
            (cache / name.removeprefix('plugin/')).is_file()
            and _hash((cache / name.removeprefix('plugin/')).read_bytes()) == digest
            for name, digest in checksums.items() if name.startswith('plugin/') and name != 'plugin/mcp.json'))
        report['installed_runtime_hashes'] = {name: _files(cache / name) for name in
            ('bin/checker-plugin', 'bin/progress-checker', 'bin/progress-checker-mcp', 'skills/progress-checker/SKILL.md')}
        acceptance.check('exact pilot retains explicit root/state binding', json.loads((cache / 'mcp.json').read_text())['mcpServers']['progress_checker']['args'] == ['--root', str(root), '--state-dir', str(state)])
        report['native_ready'] = inventory()
        plan_permissions = (permission('checker_submit_plan'),) + ((permission('checker_set_claim'),) if phase == 'prepare' else ())
        prompt = 'Read checker_get_project and submit this exact accepted complete config using current revision/config hash with reason "Accepted existing project pilot plan": ' + json.dumps(expected)
        prompt += '. Read checker_get_plan_history with limit5 and checker_get_progress. Do not execute checks.'
        if phase == 'prepare':
            prompt += ' Record implementation claims only where current fixture source already implements the criterion, reading current revision for each; claims are separate from verification.'
        allowed = {'checker_get_project', 'checker_submit_plan', 'checker_get_plan_history', 'checker_get_progress', 'checker_list_milestones'}
        if phase == 'prepare': allowed.add('checker_set_claim')
        result = model('accepted-planning', prompt, allowed, plan_permissions)
        acceptance.check('actual authenticated model submits accepted plan and reads progress',
                         {'checker_submit_plan', 'checker_get_project', 'checker_get_progress', 'checker_get_plan_history'} <=
                         {call['tool'] for call in result['calls'] if call['status'] == 'completed'})
        after_plan = snapshot('after-plan')
        acceptance.check('native model commits exactly explicitly accepted plan', after_plan['config'] == expected)
        report['accepted_plan_committed'] = True
        if phase == 'verify':
            acceptance.check('same-config native submission preserves exact config and scope history',
                             (root / '.progress-checker/config.json').read_bytes() == original['.progress-checker/config.json'][0]
                             and after_plan['history'] == baseline['history'])
            approved_fixture.cas_feature(approved_fixture.original, evidence.EXPECTED_FEATURE)
            try:
                result = model('authorized-exact-check',
                    'Read checker_get_project; request ONLY checker_run_checks check_ids=["demo-check"] with current revision/config hash and a unique idempotency key. This exact existing demo-check already has human approval; never approve or change its definition. If PERMISSION_REQUIRED, stop and report the missing grant without retry or workaround. Otherwise poll checker_get_run/get_progress until finished, report current verification separately from claims.',
                    {'checker_get_project', 'checker_run_checks', 'checker_get_run', 'checker_get_progress', 'checker_get_log'},
                    (permission('checker_run_checks'),))
                refused = any('PERMISSION_REQUIRED' in json.dumps(call.get('result')) for call in result['calls'])
                report['configured_checks_executed'] = any(call['tool'] == 'checker_run_checks' and call['status'] == 'completed' for call in result['calls'])
                if refused:
                    report['configured_checks_executed'] = False
                    report['verification'] = 'blocked: backend prior human grant refused'
                    missing.append('Exact prior human approval was refused by the backend; no workaround or new grant attempted.')
                else:
                    live = snapshot('current-verification')
                    latest = live['latest'].get('demo-check', {})
                    report['configured_checks_executed'] = latest.get('run_id') != baseline['latest'].get('demo-check', {}).get('run_id')
                    acceptance.check('fresh authenticated exact check executes and derives passing verification',
                        any(call['tool'] == 'checker_run_checks' and call['status'] == 'completed' for call in result['calls'])
                        and latest.get('run_id') != baseline['latest'].get('demo-check', {}).get('run_id')
                        and latest.get('outcome') == 'passed' and latest.get('freshness') == 'current'
                        and live['progress']['verified'] == 2)
                    report['configured_checks_executed'] = True
                    report['current_verified_snapshot'] = live
            finally:
                approved_fixture.cas_feature(approved_fixture.feature_owned, approved_fixture.original)
            if not missing:
                stale = snapshot('source-stale')
                acceptance.check('restoring original source derives stale zero verification', stale['progress']['verified'] == 0
                                 and stale['latest']['demo-check']['freshness'] == 'stale')
                first = model('after-source-stale', 'Read checker_get_project/checker_get_progress and explain current stale evidence, claims and blockers. Do not submit plans, claims or execute checks.', {'checker_get_project', 'checker_get_progress'})
                # Native exec is ephemeral and completely exits; a second native
                # process is the actual installed restart, not cached status.
                second = model('after-native-restart', 'Read checker_get_project/checker_get_progress, confirm retained accepted plan, implementation claims and stale evidence. Do not submit plans, claims or execute checks.', {'checker_get_project', 'checker_get_progress'})
                restarted = snapshot('after-restart')
                acceptance.check('native restart retains accepted scope claims and stale evidence', restarted['config'] == expected
                                 and restarted['claims'] == baseline['claims'] and restarted['progress']['verified'] == 0
                                 and restarted['latest']['demo-check']['freshness'] == 'stale')
                acceptance.check('both stale and restarted authenticated sessions actually read checker progress', all(
                    {'checker_get_project', 'checker_get_progress'} <= {call['tool'] for call in receipt['calls'] if call['status'] == 'completed'}
                    for receipt in (first, second)))
        report['native_disabled'] = inventory(disabled=True)
        report['unavailable_limitation'] = 'Configured disabled-checker prompt handling only; not arbitrary crashing or slow startup.'
        # Actual startup failure is scoped to the newly owned installed cache.
        # The archive/extracted observer remain executable and unchanged.
        owned_launcher = cache / 'bin/checker-plugin'
        launcher_data, launcher_identity = evidence._bounded_file(owned_launcher, 64 * 1024)
        initial_mode = launcher_identity[2]
        probe_mode = initial_mode & ~0o111
        owned_launcher.chmod(probe_mode)
        report['failed_startup_mode'] = {'sha256': _hash(launcher_data),
                                         'initial_mode': initial_mode, 'probe_mode': probe_mode}
        try:
            report['native_failed_startup'] = inventory(failed=True)
            model('failed-startup-normal-math',
                  'The owned checker launcher intentionally has no executable mode bits, so its MCP startup fails. Do not invoke any MCP tools, submit plans, claims or execute checks. Answer the normal arithmetic prompt.', set())
            report['failed_startup_normal_prompt_proven'] = True
        finally:
            current_data, current_identity = evidence._bounded_file(owned_launcher, 64 * 1024)
            if (current_data != launcher_data or current_identity[:2] != launcher_identity[:2]
                    or current_identity[2] != probe_mode):
                raise RuntimeError('Owned failed-startup launcher restoration refused concurrent changes')
            owned_launcher.chmod(initial_mode)
            report['failed_startup_mode_restored'] = True

        if phase == 'verify' and not missing:
            try:
                recipient = release.qualify(acceptance.options.archive, directory / 'fresh-pilot-recipient',
                                            budget=release.Deadline(started))
                report['fresh_recipient'] = recipient
                requirements = recipient.get('recipient', {}).get('recipient_requirements', {})
                exact = (recipient.get('archive_sha256') == acceptance.report['archive']['sha256']
                         and recipient.get('recipient', {}).get('upgrade_archive_sha256') == acceptance.report['archive']['sha256'])
                qualified = (recipient.get('recipient', {}).get('status') == 'passed' and exact
                             and requirements.get('toolchain_installed') is False)
                report['fresh_recipient_exact_runtime_passed'] = qualified
                # Recipient limitations remain explicit, including transport
                # identity/clean-environment gaps. Never import saved receipts.
                missing.extend(recipient.get('unqualified', []))
            except RuntimeError as error:
                report['fresh_recipient_blocker'] = str(error)
                missing.append('Fresh clean recipient qualification blocked within the shared deadline: ' + str(error))
        report['status'] = 'passed' if not missing else 'partial'
    except BaseException as error:
        report['probe_error'] = str(error)
        raise
    finally:
        cleanup_errors = []
        if approved_fixture and approved_fixture.feature_owned != approved_fixture.original:
            try:
                approved_fixture.cas_feature(approved_fixture.feature_owned, approved_fixture.original)
            except Exception as error:
                cleanup_errors.append('Source CAS restoration: ' + str(error))
        if installed:
            try:
                run('remove', ['/usr/bin/python3', installer, 'remove', *args], 90, cleanup=True)
            except Exception as error:
                cleanup_errors.append('Owned native uninstall: ' + str(error))
            try:
                owned_file = release.settings_snapshot(root / '.codex/config.toml')
                owned_directory = release.directory_identity(root / '.codex')
            except Exception as error:
                cleanup_errors.append('Owned settings observation: ' + str(error))
        try:
            report['settings_cleanup'] = release.cleanup_owned_empty_settings(
                root, original, owned_file, owned_directory, directory_created)
        except Exception as error:
            cleanup_errors.append('Owned settings cleanup: ' + str(error))
        namespace = home / 'plugins/cache' / market
        try:
            if namespace.is_dir() and not list(namespace.iterdir()):
                namespace.rmdir()
        except Exception as error:
            cleanup_errors.append('Owned empty namespace cleanup: ' + str(error))
        # Complete every audit before asserting, so failure of one guard does
        # not skip unrelated owner cleanup or hide the original profile state.
        try:
            after_settings = settings.read_bytes()
            active_after = {name: _files(path) for name, path in active_paths.items()}
            public_after = _public(root)
            report['final_audit'] = {
                'active_root_unchanged': active_after == active_before,
                'profile_exact_bytes_preserved': after_settings == before_settings,
                'profile_unrelated_values_preserved': tomllib.loads(after_settings.decode()) == before_toml,
                'profile_sha256': _hash(after_settings),
                'fixture_public': _public_hashes(public_after),
                'pilot_namespace_removed': not namespace.exists(),
                'public_except_accepted_config_preserved':
                    {name: value for name, value in public_after.items() if name != '.progress-checker/config.json'} ==
                    {name: value for name, value in original.items() if name != '.progress-checker/config.json'},
                'accepted_config_exact': json.loads(public_after['.progress-checker/config.json'][0]) == (expected if report.get('accepted_plan_committed') else original_config)}
        except Exception as error:
            cleanup_errors.append('Final artifact audit: ' + str(error))
        deadline = min(time.monotonic() + 15, hard_deadline)
        while time.monotonic() < deadline and ((runtime / 'service.json').exists()
                or list((runtime / 'leases').glob('*.json'))):
            time.sleep(.05)
        report['native_cleanup'] = {'owned_service_record_absent': not (runtime / 'service.json').exists(),
                                    'leases': list(map(str, (runtime / 'leases').glob('*.json')))}
        report['elapsed_seconds'] = time.monotonic() - started
        report['cleanup_errors'] = cleanup_errors
        log.close()
        if cleanup_errors:
            raise RuntimeError('Pilot owner cleanup or audit failed: ' + '; '.join(cleanup_errors))
        audit = report['final_audit']
        for name, key in [('actual root cache source projectconfig remain unchanged', 'active_root_unchanged'),
                          ('actual profile unrelated configuration preserved', 'profile_unrelated_values_preserved'),
                          ('owned pilot namespace removed', 'pilot_namespace_removed'),
                          ('fixture public files except accepted plan preserve exact bytes/modes', 'public_except_accepted_config_preserved'),
                          ('fixture config remains exact accepted plan', 'accepted_config_exact')]:
            acceptance.check(name, audit[key])
        acceptance.check('last native pilot session leaves no owned writer record or leases',
                         report['native_cleanup']['owned_service_record_absent'] and not report['native_cleanup']['leases'])
    remaining = GAPS.copy() if phase == 'prepare' else GAPS[1:].copy()
    if report.get('failed_startup_normal_prompt_proven') and report.get('failed_startup_mode_restored'):
        remaining = [gap for gap in remaining if not gap.startswith('Actual failed MCP startup')]
    fresh = report.get('fresh_recipient', {})
    if report.get('fresh_recipient_exact_runtime_passed') and not fresh.get('unqualified'):
        remaining = [gap for gap in remaining if gap != 'Fresh clean recipient qualification.']
    return missing + remaining
