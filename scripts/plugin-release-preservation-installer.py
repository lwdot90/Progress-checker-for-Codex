#!/usr/bin/python3
"""OFF-default fixed installer ownership capture and pure lifecycle validator.

Only the exact returned Popen child can become the leader. Descendants require
observed parent identity, exact finite argv, executable bytes and the same new
session. No launch/signal interface exists. This cannot prove an unobserved child
that detached and was reparented between samples; live integration stays OFF.
"""
import argparse,hashlib,os,select,threading,time
from pathlib import Path
ROOT=Path('/home/luis/progress-checker');FIXTURE=ROOT/'.local/checker-demo/session-c5c6vsyz/project'
CODEX=Path('/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex')
class Refusal(RuntimeError):pass
def require(condition,message):
    if not condition:raise Refusal(message)
def digest_file(path,limit=512*1024*1024):
    digest=hashlib.sha256();total=0
    with Path(path).open('rb') as stream:
        while block:=stream.read(1024*1024):
            total+=len(block);require(total<=limit,'Executable byte bound');digest.update(block)
    return digest.hexdigest()
def identity(pid):
    try:
        path=Path('/proc')/str(pid);f=(path/'stat').read_text().rsplit(')',1)[1].split()
        return {'pid':pid,'starttime':f[19],'uid':path.stat().st_uid,'state':f[0],'ppid':int(f[1]),'pgid':int(f[2]),'sid':int(f[3]),'argv':(path/'cmdline').read_bytes().decode().split('\0')[:-1]}
    except (FileNotFoundError,ProcessLookupError):return None
def valid_identity(info):
    return type(info) is dict and set(info)=={'pid','starttime','uid','state','ppid','pgid','sid','argv'} and all(type(info[k]) is int for k in ('pid','uid','ppid','pgid','sid')) and info['pid']>0 and info['uid']==1000 and info['ppid']>=0 and info['pgid']>0 and info['sid']>0 and type(info['starttime']) is str and info['starttime'].isascii() and info['starttime'].isdecimal() and type(info['state']) is str and len(info['state'])==1 and type(info['argv']) is list and all(type(arg) is str for arg in info['argv'])
def key(info):return (info['pid'],info['starttime'],info['uid'])
def same_actor(current,pinned):return valid_identity(current) and all(current[k]==pinned[k] for k in ('pid','starttime','uid','ppid','pgid','sid','argv'))
def same_live_actor(current,pinned):return same_actor(current,pinned) and current['state']!='Z'
def allowed_children(directory):
    require(type(directory) is Path or isinstance(directory,Path),'Owned directory type')
    require(directory.is_absolute() and directory.is_relative_to(ROOT/'.local'),'Fixed public trial directory')
    rootkey=hashlib.sha256(os.fsencode(FIXTURE)).hexdigest()[:12];marketplace='progress-local-'+rootkey;selector='progress-checker@'+marketplace;destination=directory/'data/progress-checker-plugins'/rootkey
    return [['/usr/bin/git','-C',str(FIXTURE),'rev-parse','--show-toplevel'],[str(CODEX),'plugin','list','--marketplace',marketplace,'--json'],[str(CODEX),'plugin','remove',selector,'--json'],[str(CODEX),'plugin','marketplace','remove',marketplace,'--json'],[str(CODEX),'plugin','marketplace','add',str(destination),'--json'],[str(CODEX),'plugin','add',selector,'--json']]
def validate_leader_argv(argv,directory):
    common=['--project',str(FIXTURE),'--codex',str(CODEX),'--codex-home',str(directory/'codex-profile'),'--data-home',str(directory/'data'),'--skip-agent-instructions']
    package=directory.parent/'extracted/progress-checker-0.2.1-dev-linux-x86_64';require(type(argv) is list and argv[:2]==['/usr/bin/python3',str(package/'install.py')] and len(argv)>=3,'Exact packaged installer leader argv')
    action=argv[2];extra=argv[3+len(common):];require(action in ('install','update','list','remove') and argv[3:3+len(common)]==common,'Fixed installer action/profile/root')
    require((action=='install' and extra==['--state-dir',str(FIXTURE.parent/'state')]) or (action=='update' and extra in ([],['--state-dir',str(directory/'conflicting-state')])) or (action in ('list','remove') and not extra),'Exact fixed installer extras')
def readiness(fd):
    poll=select.poll();poll.register(fd,select.POLLIN);mask=0
    for _,value in poll.poll(0):mask|=value
    return mask
class ReturnedHandle:
    """Shared single-attempt ledger for exactly the returned child's PIDfd."""
    def __init__(self,pid,fd):self.pid,self.fd,self.transferred,self.uncertain=pid,fd,False,False;self.errors=[]
    def transfer(self,pid,pending):
        require(pid==self.pid and type(pending) is set and self.fd is not None and not self.transferred,'Exact returned-handle transfer')
        fd=self.fd;pending.add(fd);self.fd=None;self.transferred=True;return fd
    def shutdown(self):
        fd=self.fd;self.fd=None
        if fd is not None:
            try:os.close(fd)
            except BaseException as error:self.uncertain=True;self.errors.append(repr(error))
        return not self.uncertain
class OwnedInstaller:
    """No process creation or signals; future integration supplies returned child."""
    def __init__(self,process,argv,directory,budget,emit,expected_hashes,returned_handle=None):
        self.process,self.argv,self.directory,self.budget,self.emit=process,list(argv),directory,budget,emit
        validate_leader_argv(self.argv,directory)
        self.expected=dict(expected_hashes);require(set(self.expected)=={'python','codex','git'} and all(type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value) for value in self.expected.values()),'Exact executable pin roster')
        self.allowed=allowed_children(directory);self.owned={};self.pending=set();self.errors=[];self.stop=threading.Event();self.thread=threading.Thread(target=self.monitor,daemon=True);self.lock=threading.RLock();self.parent_pid=os.getpid();self.leader=None;self.started=False;self.drain_attempted=False;self.drain_failure=None
        if returned_handle is None:fd=os.pidfd_open(process.pid,0);self.pending.add(fd)
        else:
            require(type(returned_handle) is ReturnedHandle,'Pinned returned-handle capsule type');fd=returned_handle.transfer(process.pid,self.pending)
        try:
            until=time.monotonic()+budget.remaining(2);baseline=None
            while time.monotonic()<until:
                require(not readiness(fd),'Returned installer exited before ownership pin');info=identity(process.pid)
                if info is not None:
                    require(info['pid']==process.pid and info['ppid']==self.parent_pid,'Exact returned installer parent/PID')
                    current_key=(info['pid'],info['starttime'],info['ppid'])
                    if baseline is None:baseline=current_key
                    require(current_key==baseline,'Returned installer PID/start/UID changed')
                    if info['argv']:require(info['argv']==self.argv,'Complete returned installer argv differs')
                    if valid_identity(info) and info['state']!='Z' and info['argv']==self.argv:
                        require(info['sid']==info['pgid']==process.pid,'New installer session required')
                        digest=digest_file(Path('/proc')/str(process.pid)/'exe');require(digest==self.expected['python'],'Installer interpreter bytes differ')
                        require(same_actor(identity(process.pid),info) and not readiness(fd),'Returned installer changed before pin')
                        self.leader=info;self.owned[process.pid]={'identity':info,'pidfd':fd,'exe_sha256':digest,'parent_key':None};self.pending.remove(fd);self.emit('installer-process',self.payload(process.pid,'start'));self.thread.start();self.started=True;return
                remaining=min(.025,until-time.monotonic(),budget.remaining(.025))
                if remaining>0:time.sleep(remaining)
            raise Refusal('Returned installer bootstrap expired')
        except BaseException:
            self.shutdown();raise
    def payload(self,pid,operation,**facts):
        item=self.owned[pid]
        return {'operation':operation,'identity':dict(item['identity']),'executable_sha256':item['exe_sha256'],'parent_key':item['parent_key'],'leader_key':list(key(self.leader)),'argv':list(item['identity']['argv']),**facts}
    def sample(self):
        with self.lock:
            census=[]
            for path in Path('/proc').iterdir():
                if not path.name.isascii() or not path.name.isdecimal():continue
                info=identity(int(path.name))
                if info is None or info['state']=='Z':continue
                # Candidate selection is only an observation. Never adopt on
                # UID/session alone: every new actor must have a pinned parent.
                if info['sid']==self.leader['sid'] or info['ppid'] in self.owned:census.append(info)
            require(len(census)<=64,'Installer descendant census bound')
            unresolved=list(census)
            while unresolved:
                progress=False
                for info in list(unresolved):
                    pid=info['pid']
                    if pid in self.owned:
                        require(same_actor(info,self.owned[pid]['identity']),'Observed installer actor changed');unresolved.remove(info);progress=True;continue
                    parent=self.owned.get(info['ppid'])
                    if parent is None:continue
                    require(valid_identity(info) and info['sid']==info['pgid']==self.leader['pid'] and int(info['starttime'])>=int(parent['identity']['starttime']) and info['argv'] in self.allowed,'Descendant exact argv/session/ancestry differs')
                    require(same_live_actor(identity(info['ppid']),parent['identity']),'Descendant parent no longer has pinned live identity')
                    fd=os.pidfd_open(pid,0);self.pending.add(fd);pin_failure=None
                    try:
                        require(same_actor(identity(pid),info) and not readiness(fd),'Observed descendant changed before pin');kind='git' if info['argv'][0]=='/usr/bin/git' else 'codex';digest=digest_file(Path('/proc')/str(pid)/'exe');require(digest==self.expected[kind],'Descendant executable bytes differ')
                        require(same_actor(identity(pid),info) and same_live_actor(identity(info['ppid']),parent['identity']) and not readiness(fd),'Descendant identity changed while hashing')
                        self.owned[pid]={'identity':info,'pidfd':fd,'exe_sha256':digest,'parent_key':list(key(parent['identity']))};self.pending.remove(fd);fd=None;self.emit('installer-process',self.payload(pid,'start'))
                    except BaseException as error:pin_failure=error;raise
                    finally:
                        if fd is not None:
                            self.pending.discard(fd)
                            try:os.close(fd)
                            except BaseException as error:
                                self.resource_release_uncertain=True;self.errors.append('Pending PIDfd close: '+repr(error))
                                if pin_failure is None:raise
                    unresolved.remove(info);progress=True
                require(progress,'Unowned installer-session actor; quarantine')
            return census
    def monitor(self):
        while not self.stop.wait(.025):
            try:self.sample()
            except BaseException as error:self.errors.append(repr(error));return
    def observe_drain(self,returncode):
        require(type(returncode) is int,'Actual installer returncode')
        self.emit('installer-process',self.payload(self.process.pid,'exit',returncode=returncode))
        until=time.monotonic()+self.budget.remaining(15)
        while time.monotonic()<until:
            census=self.sample()
            if not census and all(readiness(item['pidfd'])&select.POLLIN for item in self.owned.values()):break
            time.sleep(.025)
        else:raise Refusal('Installer descendant drain unresolved')
        self.stop.set();self.thread.join(timeout=self.budget.remaining(1));require(not self.thread.is_alive() and not self.errors,'Installer monitor unresolved')
        for pid,item in self.owned.items():
            mask=readiness(item['pidfd']);current=identity(pid);require(mask&select.POLLIN and not mask&~(select.POLLIN|select.POLLHUP),'Bound installer handle did not exit')
            require(current is None or valid_identity(current),'Malformed final process identity')
            require(not self.sample(),'Installer runtime reappeared')
            self.emit('installer-process',self.payload(pid,'drain',pidfd_poll_revents=mask,current_identity=current,descendant_census=[]))
    def drain(self,returncode):
        failure=self.drain_failure;released=False
        try:
            if not self.drain_attempted:
                self.drain_attempted=True
                try:self.observe_drain(returncode)
                except BaseException as error:failure=error;self.drain_failure=error
        finally:
            try:released=self.shutdown()
            except BaseException as error:
                self.errors.append('Final resource shutdown: '+repr(error));failure=failure or error;self.drain_failure=failure
        if failure is not None:raise failure
        require(released,'Installer resource release unresolved; quarantine')
    def shutdown(self):
        issues=[]
        try:self.stop.set()
        except BaseException as error:issues.append(repr(error))
        try:
            if self.thread.ident is not None:self.thread.join(timeout=self.budget.remaining(1))
        except BaseException as error:issues.append(repr(error))
        try:alive=self.thread.is_alive()
        except BaseException as error:issues.append(repr(error));alive=True
        if alive:self.errors.extend(issues+['Monitor live; PIDfds retained']);return False
        for fd in dict.fromkeys(list(self.pending)+[v['pidfd'] for v in self.owned.values() if v['pidfd'] is not None]):
            # Linux close can fail after releasing this number. Remove it from
            # every ledger before the sole attempt; never close a reused fd.
            self.pending.discard(fd)
            for item in self.owned.values():
                if item['pidfd']==fd:item['pidfd']=None
            try:
                os.close(fd)
            except BaseException as error:issues.append(repr(error))
        self.resource_release_uncertain=getattr(self,'resource_release_uncertain',False) or bool(issues)
        self.errors.extend(issues);return not issues and not self.resource_release_uncertain
def evaluate(events,expected_argv,allowed_argv,expected_hashes):
    """PURE: validate fresh captured facts, never a supplied passed flag."""
    require(type(events) is list and 0<len(events)<=256,'Finite installer facts');owned={};digests={};leader=None;exited=False;drained=set()
    for event in events:
        info=event['identity'];require(valid_identity(info),'Complete typed process identity');pid=info['pid'];operation=event['operation'];require(event['argv']==info['argv'],'Actual argv copy')
        if operation=='start':
            require(not exited and pid not in owned and info['state']!='Z','Unique live startup identity before leader exit')
            if leader is None:
                require(info['argv']==expected_argv and info['sid']==info['pgid']==pid and event['parent_key'] is None and event['executable_sha256']==expected_hashes['python'],'Exact returned leader facts');leader=info
            else:
                parent=owned.get(info['ppid']);require(parent is not None and event['parent_key']==list(key(parent)) and info['sid']==info['pgid']==leader['pid'] and int(info['starttime'])>=int(parent['starttime']) and info['argv'] in allowed_argv,'Actual observed descendant ancestry/argv');kind='git' if info['argv'][0]=='/usr/bin/git' else 'codex';require(event['executable_sha256']==expected_hashes[kind],'Descendant bytes')
            owned[pid]=info;digests[pid]=event['executable_sha256']
        elif operation=='exit':
            require(leader is not None and pid==leader['pid'] and info==owned[pid] and not exited and type(event['returncode']) is int,'Actual leader exit');exited=True
        elif operation=='drain':
            require(exited and pid in owned and info==owned[pid] and pid not in drained,'Ordered bound drain');mask=event['pidfd_poll_revents'];require(type(mask) is int and mask&select.POLLIN and not mask&~(select.POLLIN|select.POLLHUP),'Actual bound PIDfd poll');current=event['current_identity'];require(current is None or valid_identity(current),'Strict current identity');require(current is None or key(current)!=key(info) or current['state']=='Z','Original actor still live');require(event['descendant_census']==[],'Fresh empty owned-layout census');drained.add(pid)
        else:raise Refusal('Unknown installer lifecycle operation')
        require(event['executable_sha256']==digests[pid],'Pinned executable hash changed between events')
        require(event['leader_key']==list(key(leader)),'Exact returned leader key')
    require(exited and drained==set(owned),'All observed actor handles drained')
    return {'observed_actor_count':len(owned),'observed_ancestry_and_bound_drain':True,'complete':False,'remaining_unqualified':['Live returned-handle provenance/continuous collector trust and possible unobserved detached children remain unqualified.']}
if __name__=='__main__':
    argparse.ArgumentParser(description=__doc__).parse_args();print('OFF: installer ownership source stage; no process creation, signals or invocation.')
