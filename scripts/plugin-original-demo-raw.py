#!/usr/bin/python3
"""OFF-default pure original-demo raw capture/evaluator staging; no host execution."""
from __future__ import annotations
import argparse,base64,hashlib,json,math,re,time
from pathlib import Path
MAX_LINE=256*1024;MAX_FRAME=1024*1024;MAX_STREAM=8*1024*1024;MAX_FRAMES=4096
KINDS={'rpc','rpc-notification','public-command','public-files','feature-cas','process','terminal'}
PHASES=['fixture-preflight','unapproved-open','unapproved-before','unapproved-request','unapproved-after','unapproved-close','approved-open','initial','fail-request','fail-finished','feature-to-expected','pass-request','pass-finished','feature-to-original','stale','approved-close','restart-open','restored','readonly-run','readonly-claim','readonly-plan','after-readonly','fixture-final','restart-close','terminal']
ROOT='/home/luis/progress-checker/.local/checker-demo/session-c5c6vsyz/project';STATE='/home/luis/progress-checker/.local/checker-demo/session-c5c6vsyz/state'
ORIGINAL=b'demo implemented\nchanged\n';EXPECTED=b'demo implemented\n'
SCRIPT=b'from pathlib import Path\nassert Path("feature.txt").read_text() == "demo implemented\\n"\nprint("Feature fixture and content checks passed")\n'

class Refusal(ValueError):pass

def pairs(values):
    d={}
    for k,v in values:
        if k in d:raise Refusal('Duplicate JSON key: '+k)
        d[k]=v
    return d

def strict(data):
    def floating(value):
        result=float(value)
        if not math.isfinite(result):raise Refusal('Nonfinite JSON number')
        return result
    try:return json.loads(data,object_pairs_hook=pairs,parse_float=floating,parse_constant=lambda x:(_ for _ in ()).throw(Refusal('Nonfinite JSON')))
    except (UnicodeError,json.JSONDecodeError,RecursionError) as e:raise Refusal('Invalid strict JSON') from e

def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def decoded(v):
    if not isinstance(v,str):raise Refusal('Expected base64 string')
    try:return base64.b64decode(v,validate=True)
    except ValueError as e:raise Refusal('Invalid base64') from e

def raw_line(value):
    b=decoded(value)
    if not 0<len(b)<=MAX_LINE or not b.endswith(b'\n') or b'\n' in b[:-1]:raise Refusal('Raw JSONRPC line framing/bound')
    o=strict(b)
    if not isinstance(o,dict):raise Refusal('JSONRPC object required')
    return o

class Capture:
    """Pure byte recorder; no process/socket/file/check capability or activation."""
    def __init__(self,job_id,nonce):self.job_id=job_id;self.nonce=nonce;self.frames=[]
    def event(self,phase,kind,payload,stamp=None):
        frame={'schema_version':1,'job_id':self.job_id,'nonce':self.nonce,'sequence':len(self.frames)+1,'phase':phase,'kind':kind,'monotonic_ns':time.monotonic_ns() if stamp is None else stamp,'payload':payload}
        self.frames.append(frame);return frame
    def rpc(self,phase,session,ordinal,request_line,response_line,sent,received):
        req=base64.b64encode(request_line).decode();res=base64.b64encode(response_line).decode()
        return self.event(phase,'rpc',{'session':session,'ordinal':ordinal,'request_line_base64':req,'response_line_base64':res,'request':raw_line(req),'response':raw_line(res),'sent_monotonic_ns':sent,'received_monotonic_ns':received},received)
    def notification(self,phase,session,line,sent):
        b=base64.b64encode(line).decode()
        return self.event(phase,'rpc-notification',{'session':session,'request_line_base64':b,'request':raw_line(b),'sent_monotonic_ns':sent},sent)

def validate(frames,job_id,nonce):
    if not isinstance(frames,list) or len(frames)>MAX_FRAMES:raise Refusal('Stream count bound')
    total=0;last=-1;phase_index=-1;ordinals={};terminal=False
    for i,f in enumerate(frames,1):
        if set(f)!={'schema_version','job_id','nonce','sequence','phase','kind','monotonic_ns','payload'}:raise Refusal('Envelope schema')
        if type(f['schema_version']) is not int or f['schema_version']!=1 or f['job_id']!=job_id or f['nonce']!=nonce or type(f['sequence']) is not int or f['sequence']!=i or type(f['monotonic_ns']) is not int:raise Refusal('Envelope identity/sequence/time')
        if terminal:raise Refusal('Bytes after terminal')
        if f['kind'] not in KINDS or f['phase'] not in PHASES+['cleanup']:raise Refusal('Unknown kind/phase')
        if f['monotonic_ns']<last:raise Refusal('Time regression')
        last=f['monotonic_ns'];n=len(canonical(f));total+=n
        if n>MAX_FRAME or total>MAX_STREAM:raise Refusal('Stream byte bound')
        if f['phase']!='cleanup':
            index=PHASES.index(f['phase'])
            if index<phase_index:raise Refusal('Phase regression')
            phase_index=index
        p=f['payload']
        if not isinstance(p,dict):raise Refusal('Payload object')
        if f['kind']=='rpc':
            if set(p)!={'session','ordinal','request_line_base64','response_line_base64','request','response','sent_monotonic_ns','received_monotonic_ns'}:raise Refusal('RPC schema')
            req=raw_line(p['request_line_base64']);res=raw_line(p['response_line_base64'])
            if req!=p['request'] or res!=p['response']:raise Refusal('Parsed/raw mismatch')
            if type(p['ordinal']) is not int or p['ordinal']!=ordinals.get(p['session'],0)+1:raise Refusal('Session ordinal')
            ordinals[p['session']]=p['ordinal']
            if type(req.get('id')) is not int or type(res.get('id')) is not int or req['id']!=p['ordinal'] or res['id']!=p['ordinal'] or req.get('jsonrpc')!='2.0' or res.get('jsonrpc')!='2.0' or 'error' in res:raise Refusal('JSONRPC framing')
            if any(type(p[k]) is not int for k in ('sent_monotonic_ns','received_monotonic_ns')) or not p['sent_monotonic_ns']<=p['received_monotonic_ns']==f['monotonic_ns'] or p['received_monotonic_ns']-p['sent_monotonic_ns']>55_000_000_000:raise Refusal('RPC deadline')
            if req.get('method')=='tools/call':
                reply=res.get('result',{})
                if strict(reply['content'][0]['text'])!=reply['structuredContent']:raise Refusal('Text/structured mismatch')
        if f['kind']=='rpc-notification':
            if set(p)!={'session','request_line_base64','request','sent_monotonic_ns'}:raise Refusal('Notification schema')
            req=raw_line(p['request_line_base64'])
            if req!=p['request'] or req!={'jsonrpc':'2.0','method':'notifications/initialized','params':{}}:raise Refusal('Notification identity/no fabricated response')
            if type(p['sent_monotonic_ns']) is not int or p['sent_monotonic_ns']!=f['monotonic_ns']:raise Refusal('Notification timestamp')
        if f['kind']=='terminal':terminal=True
    return frames

def evaluate(frames,job_id,nonce,*,_raw_gate=False,_deadline_gate=False):
    """Recompute all18 predicates; fail closed on staged host provenance/gates.

    No host attestation verifier is integrated yet, so even synthetic all-true
    assertions cannot qualify retained evidence through this staged module.
    """
    validate(frames,job_id,nonce);checks=[];errors=[]
    def check(label,fn):
        try:ok=bool(fn())
        except (KeyError,IndexError,TypeError,ValueError):ok=False
        checks.append({'label':label,'passed':ok})
    def events(phase,kind):return [f['payload'] for f in frames if f['phase']==phase and f['kind']==kind]
    def rpc(phase,method='tools/call',name=None):
        values=[p for p in events(phase,'rpc') if p['request']['method']==method and (name is None or p['request']['params'].get('name')==name)]
        return values[-1]
    def reply(phase,name='checker_get_progress'):return rpc(phase,name=name)['response']['result']
    def current(phase):
        r=reply(phase)
        if r['isError']:raise Refusal('Current unsuccessful')
        return r['structuredContent']
    def status(phase):return current(phase)['result']['status']
    def tools(phase):
        t=rpc(phase,'tools/list')['response']['result']['tools'];return len(t)==10 and not any('approve' in x['name'] for x in t)
    def closed(phase):return any(x.get('operation')=='exit' and x.get('role')=='client' and x.get('returncode')==0 for x in events(phase,'process'))
    def refusal(phase,code):
        r=reply(phase,'checker_run_checks' if phase=='unapproved-request' else {'readonly-run':'checker_run_checks','readonly-claim':'checker_set_claim','readonly-plan':'checker_submit_plan'}[phase]);return r['isError'] and r['structuredContent']['error']['code']==code
    check('exact Git worktree',lambda:any(decoded(x['stdout_base64']).decode().strip()==ROOT and x['returncode']==0 for x in events('fixture-preflight','public-command')))
    check('unapproved ten tools/no approval',lambda:tools('unapproved-open'))
    check('unapproved refused',lambda:refusal('unapproved-request','PERMISSION_REQUIRED'))
    check('unapproved no attempt/marker',lambda:current('unapproved-before')['revision']==current('unapproved-after')['revision'] and status('unapproved-after')['latest']=={} and current('unapproved-after')['result']['running']==[] and any(x.get('role')=='sentinel-marker' and x.get('exists') is False for x in events('unapproved-after','public-files')))
    check('unapproved close0',lambda:closed('unapproved-close'))
    check('approved ten tools/no approval',lambda:tools('approved-open'))
    check('failing check unverified',lambda:status('fail-finished')['latest']['demo-check']['outcome']=='failed' and status('fail-finished')['progress']['verified']==0)
    check('pass accepted',lambda:not reply('pass-request','checker_run_checks')['isError'] and bool(current('pass-finished')))
    check('current pass2/2',lambda:status('pass-finished')['latest']['demo-check']['outcome']=='passed' and status('pass-finished')['latest']['demo-check']['freshness']=='current' and status('pass-finished')['progress']['verified']==status('pass-finished')['progress']['scoped']==2)
    check('restored source stale/dependency blocked',lambda:status('stale')['latest']['demo-check']['freshness']=='stale' and status('stale')['progress']['verified']==0 and any('dependency fixture is unverified' in x for x in status('stale')['progress']['milestones'][1]['blockers']))
    check('approved close0',lambda:closed('approved-close'))
    check('restart ten tools/no approval',lambda:tools('restart-open'))
    check('restart claims/stale pass',lambda:current('restored')['result']['claims']==current('initial')['result']['claims'] and status('restored')['latest']['demo-check']['outcome']=='passed' and status('restored')['latest']['demo-check']['freshness']=='stale')
    for p in ['readonly-run','readonly-claim','readonly-plan']:check(p+' refused',lambda p=p:refusal(p,'READ_ONLY_REQUEST') and rpc(p)['request']['params']['_meta']=={'openai/readOnly':True})
    check('readonly preserved',lambda:current('after-readonly')['revision']==current('restored')['revision'] and all(current('after-readonly')['result'][k]==current('restored')['result'][k] for k in ['claims','config']) and status('after-readonly')['latest']==status('restored')['latest'])
    check('restart close0',lambda:closed('restart-close'))
    gates={}
    for prefix in ['fail','pass']:
        try:
            q=rpc(prefix+'-request',name='checker_run_checks');req=q['request']['params']['arguments'];accepted=q['response']['result'];finished=current(prefix+'-finished');latest=finished['result']['status']['latest']['demo-check']
            gates[prefix+'_new_accepted_finished']=not accepted['isError'] and latest['run_id'] in accepted['structuredContent']['result']['run_ids'] and latest['execution_state']=='finished' and req['check_ids']==['demo-check'] and req['idempotency_key'].startswith('evidence-'+prefix+'-')
        except (KeyError,IndexError,TypeError,ValueError):gates[prefix+'_new_accepted_finished']=False
    terminals=events('terminal','terminal');terminal=terminals[-1] if terminals else {}
    # Preserve actual pass-refusal body failure, rather than converting to partial.
    pass_refused=not checks[7]['passed'] and bool(events('pass-request','rpc'))
    outcome='failed' if pass_refused or terminal.get('body_exit') not in (0,None) else 'partial'
    remaining=terminal.get('remaining_unqualified',[])
    if not isinstance(remaining,list) or any(not isinstance(x,str) for x in remaining):raise Refusal('Terminal remaining_unqualified must preserve a string list')
    body_remaining=list(remaining)
    prerequisite_gates=fixture_cas_gates(frames)
    session_gates=session_run_gates(frames)
    unqualified=list(body_remaining)
    unqualified.extend(['OFF-default staged: independent host provenance verifier not integrated','Owned backend/watchdog/lease/socket drain verifier not integrated','Immutable registration and independent activation verifier not integrated'])
    if not _raw_gate:unqualified.append('Actual serialized envelope byte/duplicatekey bounds unavailable')
    if not _deadline_gate:unqualified.append('Shared absolute raw stream deadline unavailable')
    for group in (gates,prerequisite_gates,session_gates):
        unqualified.extend('Unsatisfied raw predicate: '+k for k,v in group.items() if not v)
    if any(not x['passed'] for x in checks) and terminal.get('body_exit')==0 and not body_remaining:outcome='failed'
    return {'status':outcome,'assertions':checks,'assertion_count':len(checks),'run_association_gates':gates,'fixture_cas_gates':prerequisite_gates,'session_binding_gates':session_gates,'raw_serialized_gate':_raw_gate,'absolute_deadline_gate':_deadline_gate,'body_remaining_unqualified':body_remaining,'remaining_unqualified':unqualified,'body_exit':terminal.get('body_exit'),'body_error':terminal.get('error'),'cleanup_complete':terminal.get('cleanup_complete'),'retained_execution':False,'qualification_possible':False}

def decode_frames(lines):
    """Decode original serialized envelopes BEFORE normalized validation."""
    if not isinstance(lines,list) or len(lines)>MAX_FRAMES:raise Refusal('Original frame count')
    frames=[];total=0
    for line in lines:
        if not isinstance(line,bytes) or not 0<len(line)<=MAX_FRAME or not line.endswith(b'\n') or b'\n' in line[:-1]:raise Refusal('Original serialized frame bound/framing')
        total+=len(line)
        if total>MAX_STREAM:raise Refusal('Original serialized stream byte bound')
        f=strict(line)
        if not isinstance(f,dict):raise Refusal('Original envelope object')
        frames.append(f)
    return frames


def evaluate_raw(lines,job_id,nonce,deadline):
    frames=decode_frames(lines)
    expected={'prepared_ns','activated_ns','workflow_deadline_ns','hard_deadline_ns','observer_now_ns'}
    if not isinstance(deadline,dict) or set(deadline)!=expected or any(type(v) is not int for v in deadline.values()):raise Refusal('Absolute deadline metadata required')
    p,a,w,h,n=(deadline[k] for k in ['prepared_ns','activated_ns','workflow_deadline_ns','hard_deadline_ns','observer_now_ns'])
    if not 0<=p<=a<=n<h or not a<w<=h or w-a>480_000_000_000 or h-a>600_000_000_000:raise Refusal('Absolute deadline bound')
    for f in frames:
        end=h if f['phase'] in ('cleanup','terminal') else w
        if not a<=f['monotonic_ns']<=min(n,end):raise Refusal('Frame outside absolute work/cleanup deadline')
    return evaluate(frames,job_id,nonce,_raw_gate=True,_deadline_gate=True)


def public_files(payload):
    """Validate bounded original public file snapshots, never private records."""
    result={}
    for entry in payload['files']:
        role=entry['relative_role']
        if role not in ('config','script','feature') or role in result:raise Refusal('Fixed public file role')
        b=decoded(entry['bytes_base64']);before=entry['before_stat'];after=entry['after_stat'];path=entry['path_lstat']
        fields=['device','inode','mode','uid','nlink','size','mtime_ns','ctime_ns','regular']
        if any(type(before[k]) is not int for k in fields[:-1]) or before['regular'] is not True or before['uid']!=1000 or before['nlink']!=1:raise Refusal('Bounded owned regular singlelink public file')
        if any(before[k]!=after[k] for k in fields) or any(before[k]!=path[k] for k in ('device','inode')):raise Refusal('Public file identity changed')
        if before['size']!=len(b) or len(b)>(65536 if role=='config' else 4096):raise Refusal('Public file byte bound')
        result[role]=(b,(before['device'],before['inode'],before['mode']))
    if set(result)!={'config','script','feature'}:raise Refusal('Complete public snapshot required')
    return result


def config_identity(b):
    c=strict(b);ms=c.get('milestones',[])
    return (c.get('schema_version')==1 and c.get('project_id')=='phase1-human-demo' and c.get('enabled') is True
      and c.get('checks')==[{'id':'demo-check','argv':['/usr/bin/python3','check.py'],'cwd':'.','kind':'test','timeout_seconds':10}]
      and c.get('fingerprint')=={'extra_inputs':[],'exclude_outputs':[]} and c.get('execution')=={'max_parallel':1,'default_timeout_seconds':10}
      and len(ms)==2 and [x.get('id') for x in ms]==['fixture','content'] and [x.get('depends_on') for x in ms]==[[],['fixture']]
      and all(x.get('in_scope') is True and len(x.get('criteria',[]))==1 and x['criteria'][0].get('check_id')=='demo-check' and x['criteria'][0].get('required') is True for x in ms))


def fixture_cas_gates(frames):
    gates={k:False for k in ['fixed_fixture_identity','all_recorded_guards','guards_before_runs_and_polls','feature_cas_to_expected','feature_cas_to_original','final_original_restored']}
    snapshots={};baseline=None
    try:
        initial=[f for f in frames if f['phase']=='fixture-preflight' and f['kind']=='public-files' and f['payload'].get('role')=='fixture'][0]
        p=initial['payload'];baseline=public_files(p);dirs=p['directory_stats']
        if dirs['root']['path']!=ROOT or dirs['state']['path']!=STATE or any(dirs[k]['uid']!=1000 or dirs[k]['directory'] is not True for k in ('root','state','config')) or dirs['state']['mode']!=0o700 or dirs['config']['symlink']:raise Refusal('Literal fixture/state directory identity')
        gates['fixed_fixture_identity']=config_identity(baseline['config'][0]) and baseline['script'][0]==SCRIPT and baseline['feature'][0]==ORIGINAL
        def same(snapshot,feature):return all(snapshot[k]==baseline[k] for k in ('config','script')) and snapshot['feature'][1]==baseline['feature'][1] and snapshot['feature'][0]==feature
        guards=[f for f in frames if f['kind']=='public-files' and f['payload'].get('role') in ('guard','final')]
        for f in guards:snapshots[f['sequence']]=public_files(f['payload'])
        cas_states={'feature-to-expected':(ORIGINAL,EXPECTED),'feature-to-original':(EXPECTED,ORIGINAL)}
        def guard_matches(f):
            stage=f['payload'].get('cas_guard_stage')
            if f['phase'] in cas_states:
                if f['payload']['role']!='guard' or stage not in ('before','after'):return False
                feature=cas_states[f['phase']][stage=='after']
            else:
                if 'cas_guard_stage' in f['payload']:return False
                feature=EXPECTED if f['phase'] in ('pass-request','pass-finished') else ORIGINAL
            return same(snapshots[f['sequence']],feature)
        gates['all_recorded_guards']=bool(guards) and all(guard_matches(f) for f in guards)
        relevant=[f for f in frames if f['kind']=='rpc' and f['phase'] in ('fail-request','fail-finished','pass-request','pass-finished')]
        matches=[]
        for f in relevant:
            preceding=[g for g in guards if g['phase']==f['phase'] and g['sequence']<f['sequence']]
            # Before current+run a single guard suffices; each later polling call must have its own guard.
            prior=preceding[-1] if preceding else None
            prior_calls=[g for g in relevant if g['phase']==f['phase'] and g['sequence']<f['sequence'] and g['payload']['request']['params']['name']=='checker_get_progress']
            is_poll=f['payload']['request']['params']['name']=='checker_get_progress'
            # current() retries pending internally WITHOUT another fixture.guard.
            # Only a new OUTER current/poll boundary needs a fresh guard.
            retry=False
            if is_poll and prior_calls:
                previous=prior_calls[-1]
                prevreply=previous['payload']['response']['result']
                intervening=[g for g in relevant if previous['sequence']<g['sequence']<f['sequence'] and g['phase']==f['phase']]
                retry=not intervening and prevreply['isError'] and prevreply['structuredContent']['error']['code']=='FRESHNESS_PENDING'
            fresh_guard=not is_poll or retry or not prior_calls or prior is not None and prior['sequence']>prior_calls[-1]['sequence']
            matches.append(prior is not None and fresh_guard and same(snapshots[prior['sequence']],EXPECTED if f['phase'].startswith('pass') else ORIGINAL))
        gates['guards_before_runs_and_polls']=bool(relevant) and all(matches)
        for phase,key,expected,replacement in [('feature-to-expected','feature_cas_to_expected',ORIGINAL,EXPECTED),('feature-to-original','feature_cas_to_original',EXPECTED,ORIGINAL)]:
            cas_frames=[f for f in frames if f['phase']==phase and f['kind']=='feature-cas']
            phase_guards=[f for f in guards if f['phase']==phase]
            # The unchanged body guards before opening the feature and again
            # after write/truncate/fsync/close. The collector emits its CAS
            # record only after that original method returns.
            if (len(cas_frames)!=1 or len(phase_guards)!=2
                or [f['payload'].get('cas_guard_stage') for f in phase_guards]!=['before','after']
                or not phase_guards[0]['sequence']<phase_guards[1]['sequence']<cas_frames[0]['sequence']
                or not all(guard_matches(f) for f in phase_guards)):continue
            c=cas_frames[0]['payload']
            opened=c['opened_identity'];pathname=c['pathname_identity'];counts=c['write_counts']
            gates[key]=(decoded(c['expected_base64'])==expected and decoded(c['replacement_base64'])==replacement and tuple(opened[k] for k in ('device','inode','mode'))==baseline['feature'][1] and all(opened[k]==pathname[k] for k in ('device','inode')) and opened['regular'] is True and c['role']==('to-expected' if phase=='feature-to-expected' else 'to-original') and all(c['parent_identity'][k]==dirs['root'][k] for k in ('device','inode')) and opened['uid']==1000 and opened['nlink']==1 and c['lock_acquired'] is True and bool(counts) and all(type(v) is int and v>0 for v in counts) and sum(counts)==len(replacement) and c['truncate_size']==len(replacement) and c['fsync_return']==0 and same(public_files(c['final_public_files']),replacement))
        final=[f for f in guards if f['phase']=='fixture-final'][-1];gates['final_original_restored']=same(snapshots[final['sequence']],ORIGINAL)
    except (KeyError,IndexError,TypeError,ValueError):pass
    return gates


def session_run_gates(frames):
    gates={k:False for k in ['session_initialize_notification_tools_order','fixed_rpc_methods_and_phase_sessions','run_requests_bind_fresh_revision_config','readonly_requests_exact','bounded_freshness_and_run_poll_loops','sentinel_request_exact','public_git_preflight_argv']}
    mapping={p:('unapproved' if p.startswith('unapproved') else 'restart' if p in ('restart-open','restored','readonly-run','readonly-claim','readonly-plan','after-readonly') else 'approved') for p in PHASES}
    rpcframes=[f for f in frames if f['kind']=='rpc']
    try:
        open_ok=[]
        for phase,session in [('unapproved-open','unapproved'),('approved-open','approved'),('restart-open','restart')]:
            group=[f for f in frames if f['phase']==phase and f['kind'] in ('rpc','rpc-notification')]
            open_ok.append(len(group)==3 and group[0]['kind']=='rpc' and group[0]['payload']['request']['method']=='initialize' and group[0]['payload']['request']['params']=={'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'live-evidence-acceptance','version':'1'}} and group[1]['kind']=='rpc-notification' and group[2]['payload']['request']['method']=='tools/list' and group[2]['payload']['request']['params']=={} and all(f['payload']['session']==session for f in group))
        gates['session_initialize_notification_tools_order']=all(open_ok)
        fixed=[]
        for f in rpcframes:
            p=f['payload'];q=p['request'];phase=f['phase'];method=q['method']
            good=p['session']==mapping[phase]
            if phase.endswith('-open'):good=good and method in ('initialize','tools/list')
            else:
                good=good and method=='tools/call'
                allowed='checker_run_checks' if phase in ('unapproved-request','readonly-run') else 'checker_set_claim' if phase=='readonly-claim' else 'checker_submit_plan' if phase=='readonly-plan' else None
                name=q['params']['name']
                good=good and (name in ('checker_get_progress','checker_run_checks') if phase in ('fail-request','pass-request') else name==(allowed or 'checker_get_progress'))
                if name=='checker_get_progress':good=good and q['params']['arguments']=={} and '_meta' not in q['params']
                if not phase.startswith('readonly'):good=good and '_meta' not in q['params']
            fixed.append(good)
        gates['fixed_rpc_methods_and_phase_sessions']=bool(fixed) and all(fixed)
        def success(f):return f['payload']['response']['result']['structuredContent']
        def current_before(f):
            vals=[g for g in rpcframes if g['sequence']<f['sequence'] and g['payload']['session']==f['payload']['session'] and g['payload']['request'].get('method')=='tools/call' and g['payload']['request']['params']['name']=='checker_get_progress' and not g['payload']['response']['result']['isError']]
            return success(vals[-1])
        bindings=[]
        for phase,label in [('fail-request','fail'),('pass-request','pass')]:
            f=[g for g in rpcframes if g['phase']==phase and g['payload']['request']['params']['name']=='checker_run_checks'][0];a=f['payload']['request']['params']['arguments'];v=current_before(f)
            bindings.append(set(a)=={'check_ids','idempotency_key','expected_config_hash','expected_revision'} and a['check_ids']==['demo-check'] and a['expected_revision']==v['revision'] and a['expected_config_hash']==v['result']['status']['source']['config_hash'] and a['idempotency_key'].startswith('evidence-'+label+'-') and re.fullmatch('[0-9a-f]{32}',a['idempotency_key'].split('-')[-1]) is not None)
        gates['run_requests_bind_fresh_revision_config']=all(bindings)
        restored=success([f for f in rpcframes if f['phase']=='restored' and not f['payload']['response']['result']['isError']][-1]);rev=restored['revision'];res=restored['result'];cfg=res['status']['source']['config_hash']
        expected={'readonly-claim':{'milestone_id':'fixture','claim':'planned','note':'Read-only rejection probe','expected_revision':rev},'readonly-plan':{'config':res['config'],'reason':'Read-only rejection probe','expected_revision':rev,'expected_config_hash':cfg}}
        ro=[]
        for phase in ('readonly-run','readonly-claim','readonly-plan'):
            f=[g for g in rpcframes if g['phase']==phase][0];a=f['payload']['request']['params']['arguments']
            ro.append(f['payload']['request']['params']['_meta']=={'openai/readOnly':True} and (a==expected[phase] if phase!='readonly-run' else set(a)=={'check_ids','idempotency_key','expected_revision','expected_config_hash'} and a['check_ids']==['demo-check'] and a['expected_revision']==rev and a['expected_config_hash']==cfg and a['idempotency_key'].startswith('readonly-') and re.fullmatch('[0-9a-f]{32}',a['idempotency_key'].split('-')[-1]) is not None))
        gates['readonly_requests_exact']=all(ro)
        polls=[]
        for phase in ('unapproved-before','unapproved-after','initial','fail-request','fail-finished','pass-request','pass-finished','stale','restored','after-readonly'):
            group=[f for f in rpcframes if f['phase']==phase and f['payload']['request']['params']['name']=='checker_get_progress']
            if not group:polls.append(False);continue
            limit=25_000_000_000 if phase in ('fail-finished','pass-finished') else 20_000_000_000
            valid=group[-1]['monotonic_ns']-group[0]['payload']['sent_monotonic_ns']<=limit and not group[-1]['payload']['response']['result']['isError'] and all(not g['payload']['response']['result']['isError'] or success(g)['error']['code']=='FRESHNESS_PENDING' for g in group)
            boundary=0
            for index,g in enumerate(group):
                if not g['payload']['response']['result']['isError']:
                    valid=valid and g['monotonic_ns']-group[boundary]['payload']['sent_monotonic_ns']<=20_000_000_000
                    boundary=index+1
            polls.append(valid)
        for prefix in ('fail','pass'):
            request=[f for f in rpcframes if f['phase']==prefix+'-request' and f['payload']['request']['params']['name']=='checker_run_checks'][0]
            finished=[f for f in rpcframes if f['phase']==prefix+'-finished'][-1]
            polls.append(finished['monotonic_ns']-request['payload']['received_monotonic_ns']<=25_000_000_000)
        gates['bounded_freshness_and_run_poll_loops']=all(polls)
        sf=[f for f in rpcframes if f['phase']=='unapproved-request'][0];a=sf['payload']['request']['params']['arguments'];v=current_before(sf)
        gates['sentinel_request_exact']=set(a)=={'check_ids','idempotency_key','expected_revision','expected_config_hash'} and a['check_ids']==['sentinel'] and a['expected_revision']==v['revision'] and a['expected_config_hash']==v['result']['status']['source']['config_hash'] and a['idempotency_key'].startswith('unapproved-') and re.fullmatch('[0-9a-f]{32}',a['idempotency_key'].split('-')[-1]) is not None
        cmds=[f['payload'] for f in frames if f['phase']=='fixture-preflight' and f['kind']=='public-command'];gates['public_git_preflight_argv']=len(cmds)==1 and cmds[0]['argv']==['/usr/bin/git','-C',ROOT,'rev-parse','--show-toplevel']
    except (KeyError,IndexError,TypeError,ValueError):pass
    return gates


if __name__=='__main__':
    argparse.ArgumentParser(description=__doc__).parse_args()
    print('OFF: pure capture/evaluator staging only. No preparation, process, socket, retained file, approval or check operation.')
