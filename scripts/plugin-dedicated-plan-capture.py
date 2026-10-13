#!/usr/bin/python3
"""OFF-default pure dedicated-plan byte recorder. No host or backend capability.

Capture inputs remain supplied development data. This module proves neither
human approval nor process provenance. It never executes the acceptance body.
"""
import base64
import copy
import hashlib
import json
import math

MAX_LINE = 262144
MAX_STREAM = 8 * 1024 * 1024
MAX_FRAMES = 2048
BODY_SHA256 = 'ad1fc66caa841211d6f485832be4a602ac5c1a00743b5c42aefdbdd6f6ff1d99'
ROOT = '/home/luis/progress-checker/.local/plugin-acceptance/plan-invalidation-human-fixture-v2/project'
STATE = '/home/luis/progress-checker/.local/plugin-acceptance/plan-invalidation-human-fixture-v2/state'
CHECK = {'id': 'plan-check', 'argv': ['/usr/bin/python3', 'plan-check.py'],
         'cwd': '.', 'kind': 'test', 'timeout_seconds': 10}
TOOLS = {'checker_get_project', 'checker_set_claim', 'checker_run_checks',
         'checker_submit_plan', 'checker_get_plan_history'}
EVENTS = {'public-files', 'git-root', 'process', 'session-open', 'session-close',
          'original-assertion', 'terminal'}


class CaptureError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CaptureError(message)


def strict(data):
    require(type(data) is bytes and 0 < len(data) <= MAX_LINE, 'Bounded bytes required')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key')
            result[key] = value
        return result
    def floating(value):
        result = float(value)
        require(math.isfinite(result), 'Nonfinite JSON number')
        return result
    def constant(_):
        raise CaptureError('Nonfinite JSON value')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                          parse_float=floating, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CaptureError('Invalid bounded JSON') from exc


def wire_line(data):
    require(type(data) is bytes and data.endswith(b'\n') and b'\n' not in data[:-1],
            'Exactly one LF-terminated raw line required')
    value = strict(data)
    require(type(value) is dict and value.get('jsonrpc') == '2.0', 'JSON-RPC object required')
    return value


def encode(value):
    try:
        return json.dumps(value, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False).encode('utf-8') + b'\n'
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise CaptureError('Unserializable frame') from exc


class PhaseAdapter:
    """Pure full-transcript classifier, with no reduced semantic projection.

    Every initialize/notification/tools-list/poll record stays in output. The
    host must separately capture lifecycle and original assertions. Successful
    classification alone cannot qualify semantics, process facts or approval.
    """
    def __init__(self):
        self.stage = 'initial'
        self.previous = None
        self.child = None
        self.polls = 0
        self.original_config = None
        self.latest = None
        self.history = None
        self.revised = None

    def paired_tool(self, request, response, session):
        params = request.get('params')
        require(type(params) is dict and set(params) == {'name','arguments'}
                and type(params['name']) is str and params['name'] in TOOLS
                and type(params['arguments']) is dict, 'Exact ordinary tool parameters required')
        name = request['params']['name']
        args = request['params']['arguments']
        result = response.get('result')
        require(type(result) is dict and type(result.get('isError')) is bool,
                'Tool response shape differs')
        receipt = result.get('structuredContent')
        require(type(receipt) is dict and result['isError'] == ('error' in receipt),
                'Tool structured success/error mismatch')
        content = result.get('content')
        require(type(content) is list and content and content[0].get('type') == 'text'
                and strict(content[0]['text'].encode('utf-8')) == receipt,
                'Tool text/structured mismatch')
        mutation = name in {'checker_set_claim', 'checker_run_checks', 'checker_submit_plan'}
        if mutation:
            require(self.previous is not None and self.previous['name'] == 'checker_get_project',
                    'Mutation lacks immediate full-transcript project read')
            previous = self.previous['receipt']
            require(type(previous.get('revision')) is int
                    and type(args.get('expected_revision')) is int
                    and args['expected_revision'] == previous['revision'], 'Mutation revision differs')
            if name != 'checker_set_claim':
                config_hash = previous['result']['status']['source']['config_hash']
                require(type(config_hash) is str and type(args.get('expected_config_hash')) is str
                        and args['expected_config_hash'] == config_hash,
                        'Mutation config hash differs')
        require(session == ('restart' if self.stage.startswith('restart-') else 'initial'),
                'Unexpected session for fixed phase')
        stage = self.stage
        if name == 'checker_get_project':
            require(args == {} and not result['isError'], 'Exact project read required')
            project = receipt['result']
            require(project['canonical_root'] == ROOT
                    and (stage == 'poll' or project['running'] == []), 'Literal root/idle phase required')
            if stage == 'initial':
                self.original_config = copy.deepcopy(project['config'])
                require(project['config']['project_id'] == 'isolated-plan-invalidation'
                        and project['config']['checks'] == [CHECK]
                        and project['status']['progress']['verified'] == 0, 'Initial fixed fixture differs')
                self.stage = 'claim-alpha-current'
            elif stage in {'claim-alpha-current','claim-beta-current','claim-stable-current'}:
                self.stage = stage.removesuffix('-current')
            elif stage == 'claimed':
                require(project['claims'] == {m:'implemented' for m in ('alpha','beta','stable')}
                        and project['status']['progress']['verified'] == 0, 'Claims are not verification')
                self.stage = 'prior-grant-current'
            elif stage in {'prior-grant-current','after-submit-refusal-current','restart-refusal-current'}:
                self.stage = stage.removesuffix('-current')
            elif stage == 'poll':
                self.polls += 1
                stage = 'poll-'+str(self.polls)
                evidence = project['status']['latest'].get('plan-check', {})
                if evidence.get('run_id') == self.child and evidence.get('execution_state') == 'finished':
                    require(evidence['outcome'] == 'passed' and evidence['freshness'] == 'current'
                            and project['status']['progress']['verified'] == 3, 'Genuine current child differs')
                    self.stage = 'submit'
            elif stage == 'after-submit':
                require(project['config'] == self.revised, 'Accepted revised public config differs')
                self.latest = copy.deepcopy(project['status']['latest'])
                require(self.latest['plan-check']['run_id'] == self.child
                        and self.latest['plan-check']['outcome'] == 'passed'
                        and self.latest['plan-check']['freshness'] == 'stale'
                        and project['status']['progress']['verified'] == 0, 'Revised passing child must be stale')
                self.stage = 'after-submit-refusal-current'
            elif stage in {'after-refusal','restart-restored','restart-refusal-state'}:
                require(project['config'] == self.revised and project['status']['latest'] == self.latest
                        and project['status']['progress']['verified'] == 0, 'Public no-attempt/stale state differs')
                self.stage = {'after-refusal':'history-before','restart-restored':'restart-history-after',
                              'restart-refusal-state':'restart-done'}[stage]
            else:
                raise CaptureError('Unexpected project read at '+stage)
        elif name == 'checker_set_claim':
            require(stage in {'claim-alpha','claim-beta','claim-stable'} and not result['isError'],
                    'Unexpected or failed claim')
            require(args.get('milestone_id') == stage.removeprefix('claim-')
                    and args.get('claim') == 'implemented'
                    and args.get('note') == 'Fixture implementation claim only', 'Literal original claim differs')
            self.stage = {'claim-alpha':'claim-beta-current','claim-beta':'claim-stable-current',
                          'claim-stable':'claimed'}[stage]
        elif name == 'checker_run_checks':
            require(stage in {'prior-grant','after-submit-refusal','restart-refusal'}, 'Unexpected run phase')
            require(args.get('check_ids') == ['plan-check'] and type(args.get('idempotency_key')) is str
                    and args['idempotency_key'], 'Literal run request differs')
            if result['isError']:
                require(receipt['error']['code'] == 'PERMISSION_REQUIRED', 'Unexpected run refusal')
                self.stage = {'prior-grant':'blocked','after-submit-refusal':'after-refusal',
                              'restart-refusal':'restart-refusal-state'}[stage]
            else:
                require(stage == 'prior-grant' and len(receipt['result']['run_ids']) == 1,
                        'Unexpected accepted run')
                self.child = receipt['result']['run_ids'][0]
                require(type(self.child) is str and self.child, 'Actual child ID required')
                self.stage = 'poll'
        elif name == 'checker_submit_plan':
            require(stage == 'submit' and not result['isError'], 'Unexpected or failed revision')
            revised = copy.deepcopy(self.previous['receipt']['result']['config'])
            revised['milestones'][0]['title'] += ' explicit invalidation revision'
            require(args.get('config') == revised and args.get('reason') ==
                    'Acceptance: prove installed plan revision invalidates genuine prior evidence and exact approval',
                    'Literal title-only original revision differs')
            self.revised = copy.deepcopy(revised)
            self.stage = 'after-submit'
        elif name == 'checker_get_plan_history':
            require(stage in {'history-before','restart-history-after'} and not result['isError']
                    and args == {'offset':0,'limit':5}, 'Unexpected bounded history')
            if stage == 'history-before':
                self.history = copy.deepcopy(receipt['result'])
                self.stage = 'await-restart'
            else:
                require(receipt['result']['total'] == self.history['total'], 'Durable public history total differs')
                self.stage = 'restart-refusal-current'
        else:
            raise CaptureError('Unreviewed tool')
        self.previous = {'name':name, 'receipt':copy.deepcopy(receipt)}
        return stage

    def restart(self):
        require(self.stage == 'await-restart', 'Restart at unexpected body phase')
        self.stage = 'restart-restored'
        self.previous = None


def classify_serialized(lines, job_id, nonce):
    """Validate/classify every supplied serialized record, retaining all polls.

    Public events remain unqualified data. No lifecycle/pass inference is made
    from a caller-supplied session-open/close or assertion event.
    """
    require(type(lines) is list and 0 < len(lines) <= MAX_FRAMES, 'Bounded frame list required')
    adapter = PhaseAdapter()
    classified, pending = [], None
    total, last_ns = 0, -1
    opened, protocols = set(), {}
    terminal = False
    for index, line in enumerate(lines, 1):
        require(type(line) is bytes and line.endswith(b'\n') and b'\n' not in line[:-1],
                'Exactly one serialized LF frame required')
        total += len(line)
        require(total <= MAX_STREAM and not terminal, 'Stream bound/terminal differs')
        frame = strict(line)
        require(type(frame) is dict and set(frame) == {'schema_version','sequence','job_id',
                'nonce','monotonic_ns','kind','payload'}, 'Exact capture frame schema required')
        require(type(frame['schema_version']) is int and frame['schema_version'] == 1
                and type(frame['sequence']) is int and frame['sequence'] == index
                and frame['job_id'] == job_id and frame['nonce'] == nonce,
                'Serialized job identity/order differs')
        require(type(frame['monotonic_ns']) is int and frame['monotonic_ns'] >= 0
                and frame['monotonic_ns'] >= last_ns, 'Serialized clock order differs')
        last_ns = frame['monotonic_ns']
        kind, payload, phase = frame['kind'], frame['payload'], None
        require(type(kind) is str, 'Serialized event kind string required')
        require(type(payload) is dict, 'Serialized payload object required')
        if kind in {'request','response'}:
            require(set(payload) == {'session','line_base64','decoded'}, 'Exact wire payload required')
            try:
                data = base64.b64decode(payload['line_base64'], validate=True)
            except (ValueError, TypeError) as exc:
                raise CaptureError('Invalid raw line base64') from exc
            value = wire_line(data)
            require(value == payload['decoded'] and payload['session'] in opened,
                    'Raw/decoded bytes or session differ')
            session = payload['session']
            if kind == 'request':
                require(pending is None, 'Overlapping raw RPC')
                method = value.get('method')
                step = protocols[session]
                expected = {0:'initialize',1:'notifications/initialized',2:'tools/list'}.get(step,'tools/call')
                require(method == expected, 'Full initialization/RPC order differs')
                if method == 'notifications/initialized':
                    require('id' not in value and 'params' not in value, 'Notification differs')
                    protocols[session] += 1
                else:
                    require(type(value.get('id')) is int and value['id'] > 0, 'Exact raw request ID required')
                    pending = (session, value)
                phase = method
            else:
                require(pending is not None and pending[0] == session
                        and type(value.get('id')) is int and value['id'] == pending[1]['id'],
                        'Raw response correlation differs')
                request = pending[1]
                require('error' not in value and 'result' in value, 'Original transport RPC failed')
                if request['method'] == 'tools/call':
                    phase = adapter.paired_tool(request, value, session)
                else:
                    phase = request['method']
                    protocols[session] += 1
                pending = None
        else:
            require(kind in EVENTS and (pending is None or kind == 'terminal'), 'Unreviewed/overlapping event')
            if kind == 'session-open':
                session = payload.get('session')
                require(session in {'initial','restart'} and session not in opened,
                        'Fixed once-only session required')
                if session == 'restart':
                    require('initial' in opened, 'Restart without initial session')
                    adapter.restart()
                opened.add(session)
                protocols[session] = 0
            terminal = kind == 'terminal'
        classified.append({'frame':frame,'phase':phase})
    require(terminal, 'Terminal capture required')
    return {'status':'development-full-transcript-only','complete':False,
            'qualification_possible':False,'classified_frames':classified,
            'body_phase':adapter.stage,'poll_count':adapter.polls,
            'genuine_prior_child_candidate':adapter.child,
            'transcript_sha256':hashlib.sha256(b''.join(lines)).hexdigest(),
            'pending_rpc':pending is not None,'approval_created':False,
            'unqualified':['Supplied records establish no host provenance or real grant.',
                           'Original assertion/lifecycle/public file gates remain required.',
                           'Separate plan-interruption coverage remains required.']}


class Capture:
    """Pure recorder; callers supply actual pipe bytes and monotonic timestamps.

    Request bytes are recorded only after the whole pipe write succeeds; actual
    read bytes are supplied only after one full LF line arrives. A host adapter
    must preserve failed writes/reads as terminal failures rather than forge a
    complete pair. This class owns no files, sockets, processes or approvals.
    """
    def __init__(self, job_id, nonce):
        require(type(job_id) is str and len(job_id) == 32
                and all(c in '0123456789abcdef' for c in job_id), 'Exact job ID required')
        require(type(nonce) is str and len(nonce) == 64
                and all(c in '0123456789abcdef' for c in nonce), 'Exact nonce required')
        self.job_id, self.nonce = job_id, nonce
        self.frames, self.lines = [], []
        self.pending = None
        self.total = 0
        self.last_ns = -1
        self.closed = False

    def event(self, kind, payload, monotonic_ns):
        require(kind in EVENTS, 'Unreviewed event')
        require(kind == 'terminal' or self.pending is None,
                'Nonterminal event overlaps pending RPC')
        return self._append(kind, payload, monotonic_ns)

    def _append(self, kind, payload, monotonic_ns):
        require(not self.closed, 'Capture already terminal')
        require(type(monotonic_ns) is int and monotonic_ns >= 0
                and monotonic_ns >= self.last_ns, 'Monotonic integer ordering required')
        require(type(payload) is dict, 'Object payload required')
        frame = {'schema_version': 1, 'sequence': len(self.frames)+1,
                 'job_id': self.job_id, 'nonce': self.nonce,
                 'monotonic_ns': monotonic_ns, 'kind': kind, 'payload': payload}
        line = encode(frame)
        require(len(line) <= MAX_LINE and self.total+len(line) <= MAX_STREAM
                and len(self.frames) < MAX_FRAMES, 'Capture bounds exceeded')
        # Decode our immutable serialized copy; external payload mutation must
        # not retrospectively modify the recorded transcript.
        self.frames.append(strict(line))
        self.lines.append(line)
        self.total += len(line)
        self.last_ns = monotonic_ns
        self.closed = kind == 'terminal'
        return strict(line)

    def request(self, session, data, monotonic_ns):
        require(session in {'initial', 'restart'}, 'Fixed session required')
        require(self.pending is None, 'Concurrent RPC forbidden')
        value = wire_line(data)
        method = value.get('method')
        require(method in {'initialize', 'notifications/initialized', 'tools/list',
                           'tools/call'}, 'Unreviewed RPC method')
        if method == 'notifications/initialized':
            require('id' not in value and 'params' not in value,
                    'Literal initialized notification required')
        else:
            require(type(value.get('id')) is int and value['id'] > 0,
                    'Positive integer request ID required')
        if method == 'tools/call':
            params = value.get('params')
            require(type(params) is dict and set(params) == {'name', 'arguments'}
                    and params['name'] in TOOLS and type(params['arguments']) is dict,
                    'Fixed ordinary tool request required')
            args = params['arguments']
            if params['name'] == 'checker_run_checks':
                require(args.get('check_ids') == ['plan-check'], 'Literal plan check required')
            if params['name'] == 'checker_get_plan_history':
                require(args == {'offset': 0, 'limit': 5}, 'Literal bounded history required')
        frame = self._append('request', {'session': session,
            'line_base64': base64.b64encode(data).decode('ascii'), 'decoded': value}, monotonic_ns)
        if method != 'notifications/initialized':
            self.pending = (session, value['id'])
        return frame

    def response(self, session, data, monotonic_ns):
        value = wire_line(data)
        require(self.pending == (session, value.get('id')), 'Response identity differs')
        require(type(value.get('id')) is int and ('result' in value) != ('error' in value),
                'Exact result/error response required')
        frame = self._append('response', {'session': session,
            'line_base64': base64.b64encode(data).decode('ascii'), 'decoded': value}, monotonic_ns)
        self.pending = None
        return frame

    def serialized(self):
        return list(self.lines)

    def public_summary(self):
        return {'status': 'development-capture-only', 'complete': False,
                'qualification_possible': False, 'frame_count': len(self.lines),
                'transcript_sha256': hashlib.sha256(b''.join(self.lines)).hexdigest(),
                'terminal': self.closed, 'pending_rpc': self.pending is not None,
                'approval_created': False, 'unqualified': [
                    'No independent live host registration or process provenance.',
                    'Genuine dedicated fixture human-granted trial remains required.',
                    'Separate installed plan-interruption coverage remains required.']}


if __name__ == '__main__':
    print('OFF: pure source staging only; no fixture, process, check, approval or stream operation.')
