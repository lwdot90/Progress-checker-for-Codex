#!/usr/bin/python3
"""OFF-default PURE release-preservation raw capture/evaluator; no I/O hooks.

Four public API sessions and five native installer actions are a separate body
from original-demo evidence qualification. Supplied facts never prove live host
provenance, lifecycle ownership or a committed one-use observation by themselves.
"""
import argparse,base64,hashlib,json,math
ROOT='/home/luis/progress-checker/.local/checker-demo/session-c5c6vsyz/project'
STATE='/home/luis/progress-checker/.local/checker-demo/session-c5c6vsyz/state'
ARCHIVE='404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'
RELEASE_SHA='f2c996c6f9a49ba3abb2ea38a715f1e3c774e850d3282efb64a95eee8f4cd2d6'
BODY_SHA='44626dc4e60a623939f1e89dfb24ff5d162222b7dc9b888ef9ae18781951e3e2'
SESSIONS=('before-install','after-install','after-update','after-remove')
PHASES=('preflight','before-install','install','after-install','conflicting-update','update','after-update','list','remove','after-remove','final','cleanup','terminal')
KINDS={'rpc','notification','assertion','public-files','installer','installer-process','cache','cache-chunk','process','terminal'}
# One native action may contain two original 8MiB output streams (base64).
MAX_LINE=256*1024;MAX_FRAME=24*1024*1024;MAX_STREAM=192*1024*1024;MAX_COUNT=4096
CACHE_CHUNK=256*1024;MAX_CACHE_FILE=16*1024*1024;MAX_CACHE_TOTAL=24*1024*1024
PENDING=('Release captured public provenance/installer ownership verifier is not integrated.','Release four-session backend/watchdog/lease/socket drain verifier is not integrated.','Release immutable registration/activation/one-use committed live observation is not integrated.')
class Refusal(ValueError):pass
def require(value,message):
    if not value:raise Refusal(message)
def strict(data):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'Duplicate JSON key');result[key]=value
        return result
    def floating(value):
        result=float(value);require(math.isfinite(result),'Nonfinite JSON number');return result
    return json.loads(data,object_pairs_hook=pairs,parse_float=floating,parse_constant=lambda _:(_ for _ in ()).throw(Refusal('Nonfinite JSON')))
def b64(value,limit):
    require(type(value) is str,'Base64 must be string');data=base64.b64decode(value,validate=True);require(len(data)<=limit,'Decoded byte bound');return data
def encoded(value):return base64.b64encode(value).decode()
def raw_line(value):
    data=b64(value,MAX_LINE);require(data.endswith(b'\n') and b'\n' not in data[:-1],'Raw line framing');return strict(data)
class Capture:
    def __init__(self,job,nonce):self.job,self.nonce,self._lines=job,nonce,[];self.bytes=0
    @property
    def frames(self):return [strict(line) for line in self._lines]
    def event(self,phase,kind,payload,stamp):
        f={'schema_version':1,'job_id':self.job,'nonce':self.nonce,'sequence':len(self._lines)+1,'phase':phase,'kind':kind,'monotonic_ns':stamp,'payload':payload}
        line=json.dumps(f,separators=(',',':'),allow_nan=False).encode()+b'\n'
        require(len(line)<=MAX_FRAME and self.bytes+len(line)<=MAX_STREAM and len(self._lines)<MAX_COUNT,'Capture bound');self.bytes+=len(line);self._lines.append(line);return strict(line)
    def lines(self):return list(self._lines)
def decode(lines,job,nonce):
    require(type(lines) is list and len(lines)<=MAX_COUNT,'Frame count bound');frames=[];size=0;last=-1;phase=-1;terminal=False;ordinals={}
    for seq,line in enumerate(lines,1):
        require(type(line) is bytes and 0<len(line)<=MAX_FRAME and line.endswith(b'\n') and b'\n' not in line[:-1],'Actual serialized frame bound');size+=len(line);require(size<=MAX_STREAM,'Actual stream bound');f=strict(line)
        require(set(f)=={'schema_version','job_id','nonce','sequence','phase','kind','monotonic_ns','payload'} and type(f['schema_version']) is int and f['schema_version']==1 and type(f['sequence']) is int and f['sequence']==seq and f['job_id']==job and f['nonce']==nonce,'Envelope pins/types')
        require(not terminal and type(f['monotonic_ns']) is int and f['monotonic_ns']>=last and f['kind'] in KINDS and f['phase'] in PHASES and type(f['payload']) is dict,'Finite envelope');last=f['monotonic_ns']
        if f['phase']!='cleanup':require(PHASES.index(f['phase'])>=phase,'Phase regression');phase=PHASES.index(f['phase'])
        p=f['payload']
        if f['kind']=='rpc':
            require(set(p)=={'session','request_line_base64','response_line_base64','request','response','sent_ns','received_ns'},'RPC fields');q=raw_line(p['request_line_base64']);r=raw_line(p['response_line_base64']);require(q==p['request'] and r==p['response'],'Normalized/raw difference');ordinal=ordinals.get(p['session'],0)+1
            require(type(q.get('id')) is int and type(r.get('id')) is int and q['id']==r['id']==ordinal and q.get('jsonrpc')==r.get('jsonrpc')=='2.0' and 'error' not in r,'RPC identity');ordinals[p['session']]=ordinal
            require(type(p['sent_ns']) is int and type(p['received_ns']) is int and p['sent_ns']<=p['received_ns']==f['monotonic_ns'] and p['received_ns']-p['sent_ns']<=55_000_000_000,'RPC deadline')
            if q['method']=='tools/call':require(strict(r['result']['content'][0]['text'])==r['result']['structuredContent'],'Text/structured mismatch')
        if f['kind']=='notification':
            require(set(p)=={'session','request_line_base64','sent_ns'} and type(p['sent_ns']) is int and p['sent_ns']==f['monotonic_ns'],'Notification schema/time');require(raw_line(p['request_line_base64'])=={'jsonrpc':'2.0','method':'notifications/initialized','params':{}},'Actual notification params')
        if f['kind']=='terminal':terminal=True
        frames.append(f)
    require(terminal,'Missing actual terminal');return frames
def public_inventory(payload):
    require(set(payload)=={'root','files','directories'} and payload['root']==ROOT and type(payload['files']) is dict,'Public inventory literal root')
    result={}
    for path,item in payload['files'].items():
        require(type(path) is str and not path.startswith('/') and all(part not in ('','.','..','.git') for part in path.split('/')),'Public relative path')
        require(set(item)=={'bytes_base64','mode','stat'} and type(item['mode']) is int and 0<=item['mode']<=0o777,'Public file types');data=b64(item['bytes_base64'],1024*1024);s=item['stat']
        require(s['regular'] is True and type(s['uid']) is int and s['uid']==1000 and type(s['nlink']) is int and s['nlink']==1 and s['size']==len(data),'Public owned file')
        result[path]=(data,item['mode'])
    return result
def cache_valid(p,chunks):
    require(p['archive_sha256']==ARCHIVE and p['root']==ROOT and p['state']==STATE,'Cache fixed inputs');checksums=strict(b64(p['checksums_base64'],1024*1024));expected={path.removeprefix('plugin/'):sha for path,sha in checksums.items() if path.startswith('plugin/') and path!='plugin/mcp.json'}
    require(set(p['files'])==set(expected),'Exact checked cached inventory')
    require(type(p['inventory_id']) is int and 0<=p['inventory_id']<4,'Fixed inventory index');total=0
    ordered=[]
    for path,digest in expected.items():
        item=p['files'][path];size=item['size'];require(type(size) is int and 0<=size<=MAX_CACHE_FILE and item['sha256']==digest and item['regular'] is True and item['symlink'] is False,'Cached file facts');total+=size
        count=max(1,(size+CACHE_CHUNK-1)//CACHE_CHUNK);parts=[q for q in chunks if q.get('inventory_id')==p['inventory_id'] and q.get('path')==path];require(len(parts)==count,'Exact cache chunk count');data=bytearray()
        for index,q in enumerate(parts):
            require(set(q)=={'inventory_id','path','index','count','offset','sha256','bytes_base64'} and type(q['inventory_id']) is int and type(q['index']) is int and type(q['count']) is int and type(q['offset']) is int and q['index']==index and q['count']==count and q['offset']==len(data),'Ordered chunk identity');part=b64(q['bytes_base64'],CACHE_CHUNK);require(len(part)==min(CACHE_CHUNK,size-len(data)) and hashlib.sha256(part).hexdigest()==q['sha256'],'Exact bounded chunk bytes');data.extend(part);ordered.append(q)
        require(len(data)==size and hashlib.sha256(data).hexdigest()==digest,'Reassembled cached bytes')
    require(total<=MAX_CACHE_TOTAL and [q for q in chunks if q.get('inventory_id')==p['inventory_id']]==ordered,'Cache aggregate/order/extra chunks')
    return True
def evaluate(lines,job,nonce,clocks):
    frames=decode(lines,job,nonce);require(set(clocks)=={'activated_ns','work_deadline_ns','hard_deadline_ns'} and all(type(v) is int for v in clocks.values()) and clocks['activated_ns']<clocks['work_deadline_ns']<clocks['hard_deadline_ns'],'Shared clock schema')
    require(all(clocks['activated_ns']<=f['monotonic_ns']<=clocks['hard_deadline_ns'] and (f['phase'] in ('cleanup','terminal') or f['monotonic_ns']<=clocks['work_deadline_ns']) for f in frames),'Shared absolute deadline')
    def events(phase,kind):return [f['payload'] for f in frames if f['phase']==phase and f['kind']==kind]
    snapshots={};derived=[];errors=[]
    def predicate(name,fn):
        try:value=fn() is True
        except (ValueError,KeyError,IndexError,TypeError):value=False
        derived.append({'name':name,'passed':value})
    def session(label):
        group=[f for f in frames if f['phase']==label and f['kind'] in ('rpc','notification')];rpcs=[f['payload'] for f in group if f['kind']=='rpc']
        require(all(p['session']=='release-'+label for p in rpcs),'Fixed session labels');require(len(group)>=7 and group[0]['payload']['request']=={'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'live-evidence-acceptance','version':'1'}}} and group[1]['kind']=='notification' and group[2]['payload']['request']['method']=='tools/list' and group[2]['payload']['request']['params']=={},'Open ordering')
        replies={}
        for p in rpcs[2:]:
            q=p['request'];require(q['method']=='tools/call' and q['params']['name'] in ('checker_get_progress','checker_get_project','checker_get_run','checker_get_log'),'No mutation/approval APIs');name=q['params']['name']
            if name!='checker_get_progress':require(type(q['params'].get('_meta')) is dict and set(q['params']['_meta'])=={'openai/readOnly'} and q['params']['_meta']['openai/readOnly'] is True,'Actual read-only metadata')
            else:require(q['params']['arguments']=={} and '_meta' not in q['params'],'Fixed progress request')
            response=p['response']['result']
            require(type(response['isError']) is bool,'API error must be strict boolean')
            if response['isError']:
                require(name=='checker_get_progress' and response['structuredContent']['error']['code']=='FRESHNESS_PENDING','API refusal is unmet');continue
            require(name=='checker_get_progress' or name not in replies,'Duplicate fixed API');replies[name]=(q['params']['arguments'],response['structuredContent']['result'])
        current=replies['checker_get_progress'][1];latest=current['status']['latest']['demo-check'];runid=latest['run_id']
        require(replies['checker_get_project'][0]=={} and replies['checker_get_run'][0]=={'run_id':runid} and replies['checker_get_log'][0]=={'run_id':runid,'check_id':'demo-check','offset':0,'limit':32768},'Fixed current run/log request')
        run=replies['checker_get_run'][1];log=replies['checker_get_log'][1]
        require(type(runid) is str and bool(runid) and run['run_id']==log['run_id']==runid and run['check_id']==log['check_id']=='demo-check' and run['current_freshness']=='stale' and run['evidence']['outcome']=='passed' and run['evidence']['run_id']==runid and run['evidence']['source']==latest['source'] and run['evidence']['log_ref']==latest['log_ref'] and run['changed_during_run'] is False,'Returned genuine stale child/source binding')
        require(type(log['offset']) is int and log['offset']==0 and type(log['next_offset']) is int and type(log['total_bytes']) is int and 0<=log['next_offset']<=log['total_bytes'] and type(log['text']) is str and len(log['text'].encode())<=32768 and type(log['truncated']) is bool,'Bounded returned log identity/types')
        snapshot={'claims':current['claims'],'latest':latest,'config':replies['checker_get_project'][1]['config'],'run':replies['checker_get_run'][1],'log':replies['checker_get_log'][1]};snapshots[label]=snapshot
        return rpcs[1]['response']['result']['tools'],latest,snapshot
    def snapshot_predicates(label):
        predicate('evidence runtime advertises ten tools without any approval tool',lambda:len(session(label)[0])==10 and not any('approve' in t['name'] for t in session(label)[0]))
        predicate(label+' reads genuine passing stale evidence',lambda:session(label)[1]['outcome']=='passed' and session(label)[1]['freshness']=='stale' and bool(session(label)[1]['run_id']) and bool(session(label)[1]['log_ref']))
        predicate(label+' reads authenticated original run and log',lambda:bool(session(label)[2]))
        predicate('evidence packaged client shuts down cleanly',lambda:any(p.get('role')=='client' and p.get('operation')=='exit' and type(p.get('returncode')) is int and p['returncode']==0 for p in events(label,'process')))
    def installer(phase,action,success):
        p=events(phase,'installer')[0];require(p['action']==action and type(p['returncode']) is int,'Installer action/status');return (p['returncode']==0)==success
    def output(phase,key):
        data=b64(events(phase,'installer')[0]['stdout_base64'],8*1024*1024).decode();decoder=json.JSONDecoder()
        for i,c in enumerate(data):
            if c=='{':
                try:value,_=decoder.raw_decode(data[i:])
                except ValueError:continue
                if type(value) is dict and key in value:return value[key]
        raise Refusal('Missing native installer receipt')
    def cached(phase):
        facts=events(phase,'cache');p=facts[0] if facts else {}
        require(len(facts)==2 and [f.get('inventory_id') for f in facts]==([0,1] if phase=='after-install' else [2,3]),'Four ordered full cache inventories')
        predicate('isolated profile contains exactly one expected plugin',lambda:type(p['manifest_count']) is int and p['manifest_count']==1)
        predicate('native installed configuration binds exact retained state',lambda:strict(b64(p['mcp_base64'],65536))['mcpServers']['progress_checker']['args']==['--root',ROOT,'--state-dir',STATE])
        predicate('native cached package files match checked archive before use',lambda:cache_valid(p,events(phase,'cache-chunk')))
        predicate('native cached package files match checked archive before use',lambda:cache_valid(facts[1],events(phase,'cache-chunk')))
    snapshot_predicates('before-install')
    predicate('retained evidence installer install succeeds',lambda:installer('install','install',True));predicate('installer advertises retained state',lambda:output('install','state_directory')==STATE)
    cached('after-install');snapshot_predicates('after-install');predicate('installation preserves signed public evidence',lambda:snapshots['after-install']==snapshots['before-install'])
    predicate('retained evidence installer update refuses conflicting state',lambda:installer('conflicting-update','update',False));predicate('refused state migration leaves native binding unchanged',lambda:b64(events('conflicting-update','cache')[0]['mcp_before_base64'],65536)==b64(events('conflicting-update','cache')[0]['mcp_after_base64'],65536))
    predicate('retained evidence installer update succeeds',lambda:installer('update','update',True));cached('after-update');snapshot_predicates('after-update');predicate('update without state flag retains signed public evidence',lambda:snapshots['after-update']==snapshots['before-install'])
    predicate('retained evidence installer list succeeds',lambda:installer('list','list',True));predicate('retained evidence installer remove succeeds',lambda:installer('remove','remove',True));predicate('remove explicitly preserves retained state',lambda:output('remove','preserved_state_directory')==STATE)
    snapshot_predicates('after-remove');predicate('removal preserves signed public evidence and readable log',lambda:snapshots['after-remove']==snapshots['before-install']);predicate('retained fixture original file bytes and modes restored',lambda:public_inventory(events('final','public-files')[0])==public_inventory(events('preflight','public-files')[0]))
    actual=[f['payload'] for f in frames if f['kind']=='assertion'];require(len(derived)==36,'Internal fixed body expansion differs')
    terminal=frames[-1]['payload'];remaining=terminal.get('remaining_unqualified',[]);require(type(remaining) is list and all(type(v) is str for v in remaining),'Original unmet string list')
    if len(actual)!=36 or [p.get('name') for p in actual]!=[p['name'] for p in derived]:errors.append('Actual original assertion instances/order are incomplete or different.')
    if any(type(p.get('passed')) is not bool or p['passed'] is not True for p in actual):errors.append('Original caller recorded a failed assertion.')
    if any(not p['passed'] for p in derived):errors.append('One or more independently derived original predicates failed.')
    if terminal.get('error') or type(terminal.get('body_exit')) is not int or terminal.get('body_exit')!=0:errors.append('Original body failed: '+str(terminal.get('error')))
    return {'status':'failed' if errors else 'partial','assertions':derived,'assertion_count':36,'actual_assertion_count':len(actual),'snapshots':snapshots,'body_error':terminal.get('error'),'body_remaining_unqualified':remaining,'remaining_unqualified':list(remaining)+errors+list(PENDING),'raw_serialized_bounds':True,'shared_absolute_deadline':True,'qualification_possible':False,'complete':False}
if __name__=='__main__':
    argparse.ArgumentParser(description=__doc__).parse_args();print('OFF: pure release preservation capture/evaluator only.')
