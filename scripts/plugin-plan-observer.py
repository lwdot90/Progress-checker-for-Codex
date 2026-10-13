#!/usr/bin/env python3
"""OFF-default pure dedicated-plan semantic evaluator; performs no I/O/actions.

Supplied frames remain development inputs. The serialized entrypoint validates
bounded UTF-8 bytes and strict JSON before semantic evaluation; neither entrypoint
establishes authoritative live attestation or actual command execution.
Registration, live transport/process provenance and interruption remain pending.
"""
import copy
import json
import math

MAX_LINE_BYTES = 262144
MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_FRAMES = 512

FIXTURE_ROOT = '/home/luis/progress-checker/.local/plugin-acceptance/plan-invalidation-human-fixture-v2/project'
FIXTURE_STATE = '/home/luis/progress-checker/.local/plugin-acceptance/plan-invalidation-human-fixture-v2/state'
CHECK = {'id': 'plan-check', 'argv': ['/usr/bin/python3', 'plan-check.py'], 'cwd': '.', 'kind': 'test', 'timeout_seconds': 10}
SCRIPT = 'from pathlib import Path\nassert Path("feature.txt").read_text() == "plan acceptance implemented\\n"\nprint("Dedicated plan invalidation fixture passed")\n'
FEATURE = 'plan acceptance implemented\n'
PENDING = ['Fresh live schema/nonce/expiry/registration and connected-peer process provenance are not integrated.',
           'Supplied development frames cannot establish actual human-approved host execution.',
           'Separate installed plan-interruption recovery gate remains required.']


class PlanObservationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PlanObservationError(message)


def strict_json(value, limit=MAX_LINE_BYTES):
    """Validate one bounded JSON buffer without lossy duplicate-key parsing."""
    require(type(value) in (str, bytes), 'JSON buffer must be text or bytes')
    try:
        wire = value.encode('utf-8') if isinstance(value, str) else value
        require(len(wire) <= limit, 'JSON byte bound exceeded')
        text = wire.decode('utf-8')
        def pairs(items):
            result = {}
            for key, item in items:
                require(key not in result, 'Duplicate JSON key')
                result[key] = item
            return result
        def constant(_):
            raise PlanObservationError('Nonfinite JSON value')
        def floating(value):
            result = float(value)
            require(math.isfinite(result), 'Nonfinite JSON number')
            return result
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant,
                          parse_float=floating)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PlanObservationError('Invalid bounded JSON buffer') from exc


def evaluate_plan_invalidation_raw(lines):
    """Pure bounded serialized-frame validation; no process or filesystem access."""
    require(type(lines) is list and 0 < len(lines) <= MAX_FRAMES, 'Bounded raw frames required')
    frames, total = [], 0
    for line in lines:
        require(type(line) is bytes and line.endswith(b'\n') and b'\n' not in line[:-1],
                'Exactly one LF-terminated byte frame required')
        total += len(line)
        require(total <= MAX_STREAM_BYTES, 'Serialized stream byte bound exceeded')
        frames.append(strict_json(line))
    result = evaluate_plan_invalidation(frames)
    result['serialized_input_validated'] = True
    return result


def raw_calls(frames):
    """Correlate development-parsed MCP inputs; consume no producer PASS flags."""
    require(isinstance(frames, list) and 0 < len(frames) <= MAX_FRAMES, 'Bounded frames required')
    calls, pending, events = [], None, []
    previous = 0
    for frame in frames:
        require(type(frame) is dict and set(frame) == {'seq', 'type', 'phase', 'data'}, 'Unexpected pure frame schema')
        require(type(frame['seq']) is int and frame['seq'] == previous+1, 'Frame sequence differs')
        previous = frame['seq']
        if frame['type'] in {'api_request', 'api_response'}:
            data = frame['data']
            require(type(data) is dict and set(data) == {'raw_line', 'event'}
                    and strict_json(data['raw_line']) == data['event'], 'Raw API bytes differ')
            event = data['event']
            if frame['type'] == 'api_request':
                require(pending is None and event.get('method') == 'tools/call', 'Unexpected API request')
                pending = (frame, event)
            else:
                require(pending is not None and event.get('id') == pending[1]['id'] and frame['phase'] == pending[0]['phase'], 'API response identity differs')
                require('error' not in event and 'result' in event, 'Transport RPC failed')
                result = event['result']; structured = result.get('structuredContent')
                require(isinstance(structured, dict) and type(result.get('isError')) is bool, 'Tool response shape differs')
                content = result.get('content', [])
                require(content and content[0].get('type') == 'text' and strict_json(content[0]['text']) == structured, 'Tool text/structured mismatch')
                require(result['isError'] == ('error' in structured), 'Tool success/error disagreement')
                calls.append({'seq': frame['seq'], 'phase': frame['phase'], 'name': pending[1]['params']['name'], 'arguments': pending[1]['params']['arguments'], 'receipt': structured, 'is_error': result['isError']})
                pending = None
        else:
            require(pending is None and frame['type'] in {'public_files', 'git_root', 'launcher_close', 'launcher_connect'}, 'Unreviewed event/overlapping request')
            events.append(frame)
    require(pending is None, 'Unfinished raw RPC')
    return calls, events


def evaluate_plan_invalidation(frames):
    """Validate literal plan_invalidation semantics; never return full completion."""
    calls, events = raw_calls(frames)
    allowed = {'checker_get_project', 'checker_set_claim', 'checker_run_checks', 'checker_submit_plan', 'checker_get_plan_history'}
    require(all(c['name'] in allowed for c in calls), 'Unexpected API operation')
    def one(phase, name):
        selected = [c for c in calls if c['phase'] == phase and c['name'] == name]
        require(len(selected) == 1, 'Exact API phase required: '+phase+'/'+name)
        return selected[0]
    def success(call):
        require(not call['is_error'] and 'result' in call['receipt'], 'Required tool failed')
        return call['receipt']['result']
    def project(phase):
        call = one(phase, 'checker_get_project'); require(call['arguments'] == {}, 'Project arguments differ')
        value = success(call)
        require(value['canonical_root'] == FIXTURE_ROOT and value['running'] == [], 'Exact idle dedicated root required')
        return call, value
    def event(kind, phase):
        found = [e for e in events if e['type'] == kind and e['phase'] == phase]
        require(len(found) == 1, 'Exact lifecycle/public phase required')
        return found[0]
    def files(phase):
        value = event('public_files', phase)['data']
        require(value == {'root': FIXTURE_ROOT, 'state': FIXTURE_STATE, 'script': SCRIPT, 'feature': FEATURE, 'script_regular_no_symlink': True, 'feature_regular_no_symlink': True}, 'Literal public fixture bytes/type differ')
    files('initial'); files('final')
    git = event('git_root', 'initial')['data']
    require(git == {'argv': ['/usr/bin/git', '-C', FIXTURE_ROOT, 'rev-parse', '--show-toplevel'], 'exit_code': 0, 'stdout': FIXTURE_ROOT+'\n'}, 'Canonical existing Git root differs')
    initial_call, initial = project('initial'); original = initial['config']
    require(original['project_id'] == 'isolated-plan-invalidation' and original['checks'] == [CHECK], 'Exact dedicated configuration required')
    milestones = original['milestones']
    require({m['id'] for m in milestones} == {'alpha', 'beta', 'stable'} and len(milestones) == 3 and all(c['check_id'] == 'plan-check' for m in milestones for c in m['criteria']), 'Dedicated milestone scope differs')
    require(initial['status']['progress']['verified'] == 0, 'Initial verified count must be zero')
    previous = None
    for call in calls:
        if call['name'] in {'checker_set_claim', 'checker_run_checks', 'checker_submit_plan'}:
            require(previous is not None and previous['name'] == 'checker_get_project', 'Mutation needs immediate fresh project read')
            current = success(previous)
            require(call['arguments'].get('expected_revision') == previous['receipt']['revision'], 'Mutation revision differs')
            if call['name'] != 'checker_set_claim':
                require(call['arguments'].get('expected_config_hash') == current['status']['source']['config_hash'], 'Mutation config hash differs')
        previous = call
    for milestone in ('alpha', 'beta', 'stable'):
        call = one('claim-'+milestone, 'checker_set_claim')
        require(call['arguments'].get('milestone_id') == milestone and call['arguments'].get('claim') == 'implemented' and call['arguments'].get('note') == 'Fixture implementation claim only', 'Literal claim differs')
        success(call)
    claimed_call, claimed = project('claimed')
    require(claimed['config'] == original and claimed['claims'] == {m: 'implemented' for m in ('alpha', 'beta', 'stable')} and claimed['status']['progress']['verified'] == 0, 'Claims must remain distinct from verification')
    prior = one('prior-grant', 'checker_run_checks')
    require(prior['arguments'].get('check_ids') == ['plan-check'] and isinstance(prior['arguments'].get('idempotency_key'), str) and prior['arguments']['idempotency_key'], 'Exact check request required')
    if prior['is_error']:
        require(prior['receipt']['error']['code'] == 'PERMISSION_REQUIRED', 'Unexpected prior grant failure')
        require(not any(c['name'] == 'checker_submit_plan' for c in calls), 'No plan revision after missing grant')
        return {'status': 'blocked', 'complete': False, 'semantic_validation_passed': False, 'approval_created': False, 'unqualified': ['Dedicated fixture usable exact human grant is missing.']+PENDING}
    acceptance = success(prior)
    require(len(acceptance['run_ids']) == 1 and acceptance['run_id'], 'Exact accepted child required')
    child = acceptance['run_ids'][0]
    verified_call, verified = project('verified'); evidence = verified['status']['latest']['plan-check']
    require(evidence['run_id'] == child and evidence['execution_state'] == 'finished' and evidence['outcome'] == 'passed' and evidence['freshness'] == 'current' and verified['status']['progress']['verified'] == 3, 'Actual current passing three-milestone evidence required')
    revised = copy.deepcopy(verified['config']); revised['milestones'][0]['title'] += ' explicit invalidation revision'
    submit = one('submit', 'checker_submit_plan')
    require(submit['arguments']['config'] == revised and submit['arguments']['reason'] == 'Acceptance: prove installed plan revision invalidates genuine prior evidence and exact approval', 'Exact title-only plan revision required')
    success(submit)
    after_call, after = project('after-submit'); latest = after['status']['latest']
    require(after['config'] == revised and latest['plan-check']['run_id'] == child and latest['plan-check']['outcome'] == 'passed' and latest['plan-check']['freshness'] == 'stale' and after['status']['progress']['verified'] == 0, 'Revision must retain passing child stale and unverified')
    def refusal(phase, following):
        call = one(phase, 'checker_run_checks')
        require(call['arguments']['check_ids'] == ['plan-check'] and call['is_error'] and call['receipt']['error']['code'] == 'PERMISSION_REQUIRED', 'Revised exact grant must be refused')
        next_call, current = project(following)
        require(current['status']['latest'] == latest and current['running'] == [], 'Refusal must create no replacement attempts')
        return call, next_call
    first_refused, first_after = refusal('after-submit-refusal', 'after-refusal')
    history_before = one('history-before', 'checker_get_plan_history'); history_after = one('history-after', 'checker_get_plan_history')
    require(history_before['arguments'] == history_after['arguments'] == {'offset': 0, 'limit': 5}, 'Exact bounded history arguments required')
    before_history, after_history = success(history_before), success(history_after)
    require(before_history['total'] == after_history['total'], 'Restart history total differs')
    close = event('launcher_close', 'before-restart'); reconnect = event('launcher_connect', 'after-restart'); final_close = event('launcher_close', 'final')
    require(close['data'].get('exit_code') == 0 and reconnect['data'].get('initialized') is True and final_close['data'].get('exit_code') in (0, None), 'Literal packaged lifecycle required')
    restored_call, restored = project('restored')
    require(restored['config'] == revised and restored['status']['latest'] == latest and restored['status']['progress']['verified'] == 0, 'Packaged reconnect must retain revised plan and stale evidence')
    second_refused, second_after = refusal('after-restart-refusal', 'after-restart-refusal-state')
    chronology = [initial_call['seq'], claimed_call['seq'], prior['seq'], verified_call['seq'], submit['seq'], after_call['seq'], first_refused['seq'], first_after['seq'], history_before['seq'], close['seq'], reconnect['seq'], restored_call['seq'], history_after['seq'], second_refused['seq'], second_after['seq'], event('public_files', 'final')['seq'], final_close['seq']]
    require(chronology == sorted(chronology) and len(set(chronology)) == len(chronology), 'Literal invalidation phase chronology differs')
    require(len([c for c in calls if c['name'] == 'checker_set_claim']) == 3 and len([c for c in calls if c['name'] == 'checker_submit_plan']) == 1 and len([c for c in calls if c['name'] == 'checker_run_checks']) == 3, 'Unexpected extra mutation/run requests')
    return {'status': 'semantic-only', 'complete': False, 'semantic_validation_passed': True, 'genuine_prior_child_run_id': child, 'approval_created': False, 'fixture_plan_left_at_explicit_new_revision': True, 'unqualified': list(PENDING)}
