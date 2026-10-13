#!/usr/bin/python3
"""OFF-default fresh full-plan public acceptance plus fixed dedicated handoff.

Future exact human approval of the concrete checker command remains external.
This source does not grant approval, activate the host or alter plan/config.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
import types

ROOT=Path('/home/luis/progress-checker')
HOST_SHA='c1440e86162097cd3a7d7f65c478a57c42b5817f627f0d91e4802e05ed0a0b38'
ACTIVATE_SHA='886179200c67183f95e3ccfd2bed74c6b662929d74d266f4ecd17b6d2af65fe7'
OBSERVER_SHA='0cb36f2da32d151729d5eb92663d19df1696bcfff6fc522dd34eebdfdb2613b8'
RUNTIME_SHA='a001a978a55d305993b9d55375fe7f65c2c6b2509973e20135ac86e2bd3d4f51'
GATE='Plan changes invalidate previously approved exact commands and previously passing evidence through the installed plugin; this runner grants no approvals.'
BUDGETS={'total':720,'public':260,'activation_wait':60,'host':365,'overhead':35}
ARCHIVE_RELATIVE=Path('.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz')
ARCHIVE_SHA='404759af79cd563d3e1266f686869893727110b22465eeecbbb0cf2c7ba9c029'


def require(condition,message):
    if not condition:raise RuntimeError(message)


def digest(data):return hashlib.sha256(data).hexdigest()
def encoded(value):return json.dumps(value,separators=(',',':'),allow_nan=False).encode()+b'\n'


def select_archive(value):
    require(isinstance(value,Path) and value in {ARCHIVE_RELATIVE,ROOT/ARCHIVE_RELATIVE},
            'Only the exact frozen404 archive path is accepted')
    return ROOT/ARCHIVE_RELATIVE


def validate_archive(value,host):
    selected=select_archive(value)
    require(selected==host.ARCHIVE and host.ARCHIVE_SHA==ARCHIVE_SHA
            and digest(host.bounded(selected,64*1024*1024))==ARCHIVE_SHA,
            'Only the exact frozen404 archive bytes are accepted')
    return selected


def compile_buffer(name,data,pin):
    require(type(data) is bytes and digest(data)==pin,'Frozen source buffer differs')
    module=types.ModuleType(name.replace('-','_'));module.__file__=str(ROOT/'scripts'/name)
    exec(compile(data,module.__file__,'exec'),module.__dict__);return module


def load_inputs():
    # No import-time operations. Bootstrap anchored reader from literal host.
    host_path=ROOT/'scripts/plugin-dedicated-plan-host.py'
    # Reuse reviewed activation's bounded bootstrap only after exact buffer pin.
    fd=os.open(ROOT/'scripts/plugin-dedicated-plan-activate.py',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno());data=stream.read(8*1024*1024+1);after=os.fstat(stream.fileno())
        require(len(data)==before.st_size<=8*1024*1024 and (before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns),'Activation bootstrap changed')
    activation=compile_buffer('plugin-dedicated-plan-activate.py',data,ACTIVATE_SHA)
    host=compile_buffer(host_path.name,activation.bounded(host_path,8*1024*1024),HOST_SHA)
    observer=compile_buffer('plugin-dedicated-plan-observer.py',activation.bounded(ROOT/'scripts/plugin-dedicated-plan-observer.py',8*1024*1024),OBSERVER_SHA)
    return host,observer


def literal_assertions(source):
    tree=ast.parse(source)
    functions={v.name:v for v in tree.body if isinstance(v,ast.FunctionDef)}
    require({'plan_submission','plan_interruption','plan_invalidation'}<=set(functions),'Actual full original body required')
    labels=[]
    for name in ('plan_submission','plan_interruption'):
        for node in ast.walk(functions[name]):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='check' and node.args and isinstance(node.args[0],ast.Constant) and type(node.args[0].value) is str:
                labels.append(node.args[0].value)
    require(labels,'Actual original assertion labels required');return set(labels)


def public_gate(report,code,buffers,host):
    require(type(report) is dict and type(code) is int and code==2
            and report.get('milestone')=='plan-submission' and report.get('status')=='partial'
            and report.get('complete') is False and report.get('error') is None,'Fresh public body must finish partial without failure')
    require(report.get('unqualified')==[GATE],'Unknown or missing public gates preserved; exact invalidation-only prerequisite required')
    assertions=report.get('assertions')
    require(type(assertions) is list and assertions and all(type(a) is dict and a.get('passed') is True and type(a.get('name')) is str for a in assertions),'Fresh original assertions required')
    require(literal_assertions(buffers['plugin-acceptance.py'])<={a['name'] for a in assertions},'Full public original body/interruption assertion coverage missing')
    probe=report.get('interruption_probe',{})
    require(type(probe) is dict and probe.get('status')=='passed' and probe.get('private_records_manually_edited') is False
            and probe.get('production_failpoint') is False and probe.get('abrupt_process_kill_injected') is False,'Actual existing interruption probe required')
    runtime=report.get('test_runtime',{})
    require(type(runtime) is dict and runtime.get('runtime_sha256')==RUNTIME_SHA
            and runtime.get('helper_sha256')==host.PINS['plugin-sandbox-recipient.py']
            and runtime.get('test_sources')=={'plugin-acceptance.py':host.PINS['plugin-acceptance.py']},'Fresh public source/runtime attestation differs')
    require(report.get('archive',{}).get('sha256')==host.ARCHIVE_SHA,'Fresh public archive differs')
    # Capability semantics are the runtime's honest test policy, not zero-cap
    # or nonroot production equivalence. Preserve the entire report unchanged.
    return True


class Composition:
    def __init__(self,path,sha,output,host,observer,started_ns=None):
        self.path,self.sha,self.output,self.host,self.observer=Path(path),sha,Path(output),host,observer
        self.started=time.monotonic_ns() if started_ns is None else started_ns
        require(type(self.started) is int and self.started>=0,'Exact outer invocation start required')
        self.deadline=self.started+720_000_000_000
        self.public_report=None;self.dedicated_result=None;self.created=False
    def remaining(self):
        value=(self.deadline-time.monotonic_ns())/1e9
        require(value>0,'Cumulative720s lifetime expired');return value
    def stable(self):
        self.remaining();h=self.host
        require(h.bounded(self.path,h.MAX_PACKET,True)==self.original,'Immutable registration changed during composition')
        for name,data in self.buffers.items():require(h.bounded(ROOT/'scripts'/name,8*1024*1024)==data,'Full integration source changed')
        require(digest(h.bounded(h.ARCHIVE,64*1024*1024))==h.ARCHIVE_SHA,'Archive changed during composition')
        require(not os.path.lexists(self.path.parent/'failure.json'),'Dedicated producer failed')
    def readiness(self):
        self.stable();ready=self.observer.strict(self.host.bounded(self.path.parent/'readiness.json',self.host.MAX_PACKET,True))
        for key in ('schema_version','job_id','nonce','producer','endpoint','socket'):
            require(type(ready.get(key)) is type(self.meta[key]) and ready.get(key)==self.meta[key],'Phase readiness binding differs')
        require(ready.get('attestation_path')==str(self.path) and ready.get('attestation_sha256')==self.sha
                and ready.get('consumed') is False and not ready.get('failed') and not ready.get('activation_invalid'),'Current unconsumed job required')
        return ready
    def prepare(self):
        h=self.host;o=self.observer
        require(os.getuid()==1000 and self.path.is_absolute() and self.path.name=='attestation.json'
                and self.path.is_relative_to(ROOT/'.local') and '..' not in self.path.parts,'Fixed reviewed registration path required')
        require(o.hextext(self.sha,64),'Reviewed immutable SHA required')
        self.original=h.bounded(self.path,h.MAX_PACKET,True);require(digest(self.original)==self.sha,'Reviewed registration differs')
        self.meta=o.strict(self.original)
        require(type(self.meta) is dict and set(self.meta)==o.META_KEYS and self.meta['mode']=='dedicated-plan'
                and self.meta['trust_policy']==h.TRUST and self.meta['root']==str(h.FIXTURE) and self.meta['state']==str(h.STATE),'Fixed dedicated registration required')
        self.buffers=o.source_runtime_guard(self.meta)
        require(digest(self.buffers['plugin-dedicated-plan-activate.py'])==ACTIVATE_SHA
                and digest(self.buffers['plugin-dedicated-plan-observer.py'])==OBSERVER_SHA,'Integration literal new source pins differ')
        ready=self.readiness()
        require(ready.get('awaiting_activation') is True and ready.get('ready') is False and 'activated_ns' not in ready,'Public phase must precede host activation')
        require(type(self.meta['activation_expires_ns']) is int and time.monotonic_ns()+320_000_000_000<self.meta['activation_expires_ns'],'Registration must cover public+activation phases')
        require(self.output.is_absolute() and self.output.is_relative_to(ROOT/'.local') and '..' not in self.output.parts
                and not self.output.exists() and self.output.parent.resolve(strict=True)==self.output.parent
                and not self.output.is_relative_to(self.path.parent),'New separate canonical public output required')
        self.output.mkdir(mode=0o700);self.created=True
    def wait_ready(self,marker_ns):
        wait_end=min(marker_ns+60_000_000_000,self.deadline-400_000_000_000)
        activated=None
        while True:
            ready=self.readiness();now=time.monotonic_ns()
            stamp=ready.get('activated_ns')
            if stamp is not None:
                require(type(stamp) is int and marker_ns<=stamp<=wait_end,'Actual activation must follow current fresh phase within60s')
                if activated is None:activated=stamp
                require(stamp==activated and ready.get('hard_deadline_ns')==stamp+365_000_000_000,'Actual cumulative host clock changed')
            bound=wait_end if activated is None else min(activated+365_000_000_000,self.deadline-35_000_000_000)
            require(now<bound,'Activation or cumulative host readiness wait expired')
            if ready.get('ready') is True:
                require(activated is not None and ready.get('awaiting_activation') is False,'Unactivated ready stream refused');return ready
            require(ready.get('ready') is False,'Typed readiness required')
            time.sleep(min(.2,(bound-now)/1e9))
    def run(self):
        self.prepare();public_start=time.monotonic_ns()
        runtime=compile_buffer('plugin-acceptance-runtime.py',self.buffers['plugin-acceptance-runtime.py'],RUNTIME_SHA)
        self.public_report,code=runtime.run_acceptance(self.host.ARCHIVE,'plan-submission',self.output/'public-runtime',timeout=min(260,self.remaining()))
        require(time.monotonic_ns()-public_start<=260_000_000_000,'Public260s phase exceeded')
        self.stable();public_gate(self.public_report,code,self.buffers,self.host)
        self.host.write_new(self.output/'fresh-public.json',encoded(self.public_report))
        marker_ns=time.monotonic_ns()
        marker={'schema_version':1,'phase':'fresh-full-public-passed-awaiting-independent-activation','job_id':self.meta['job_id'],
                'nonce':self.meta['nonce'],'trial_nonce':secrets.token_hex(32),'immutable_registration_sha256':self.sha,
                'public_report_sha256':digest(encoded(self.public_report)),'module_hashes':self.meta['module_hashes'],
                'archive_sha256':self.host.ARCHIVE_SHA,'outer_started_ns':self.started,'phase_ns':marker_ns,
                'activation_wait_deadline_ns':min(marker_ns+60_000_000_000,self.deadline-400_000_000_000),
                'outer_deadline_ns':self.deadline,'approval_created':False}
        self.host.write_new(self.output/'phase-marker.json',encoded(marker))
        self.wait_ready(marker_ns);self.remaining()
        self.dedicated_result=self.observer.consume(self.path,self.sha,self.path.parent/'readiness.json')
        self.stable();self.remaining();d=self.dedicated_result
        require(d.get('dedicated_handoff_passed') is True and d.get('completion_committed') is True
                and d.get('immutable_registration_sha256')==self.sha and d.get('kernel_peer_lifetime_live') is True
                and d.get('hidden_host_source_independently_verified') is False and d.get('qualification_possible') is False
                and d.get('complete') is False and d.get('handoff_policy')==self.host.TRUST,'Full dedicated handoff under explicit reviewed trust required')
        # Preserve both raw predicate reports and their false standalone flags.
        # Only the covered gate is resolved; no arbitrary unknown gate removal.
        remaining=[gate for gate in self.public_report['unqualified'] if gate!=GATE]
        result={'milestone':'plan-submission','status':'passed' if not remaining else 'partial','complete':not remaining,
                'unqualified':remaining,'resolved_gate':GATE,'fresh_public_acceptance':self.public_report,'dedicated_handoff':d,
                'phase_marker':marker,'behavioral_acceptance_passed':not remaining,'checker_verification':False,
                'approval_created':False,'trust_policy':self.host.TRUST,'hidden_host_source_independently_verified':False,
                'outer_started_ns':self.started,'finished_ns':time.monotonic_ns(),'outer_deadline_ns':self.deadline}
        self.host.write_new(self.output/'composed-acceptance.json',encoded(result));return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-live',action='store_true');parser.add_argument('--archive',type=Path);parser.add_argument('--attestation',type=Path);parser.add_argument('--sha256');parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if not args.run_live:print('OFF: no public guest, signal, fixture, API, grant or registration operation.');return 0
    if not all((args.archive,args.attestation,args.sha256,args.output)):parser.error('Explicit future approved run requires exact archive, immutable attestation/SHA and fresh public output')
    started=time.monotonic_ns()
    select_archive(args.archive)
    host,observer=load_inputs();validate_archive(args.archive,host)
    composition=Composition(args.attestation,args.sha256,args.output,host,observer,started)
    try:result=composition.run()
    except BaseException as error:
        if composition.created:host.write_new(composition.output/'failed-composition.json',encoded({'status':'failed','complete':False,'error':type(error).__name__+': '+str(error),'fresh_public_acceptance':composition.public_report,'dedicated_handoff':composition.dedicated_result,'checker_verification':False,'approval_created':False}))
        raise
    print(json.dumps(result,indent=2));return 0 if result['complete'] else 2


if __name__=='__main__':raise SystemExit(main())
