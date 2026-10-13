#!/usr/bin/env python3
"""Explicitly reviewed primary-root accepted-plan/no-op claim reaffirmation trial.

No installation, approval or check operation. Explicit accepted-plan no-op and
existing-claim reaffirmation preserve all notes and scope. Authentication stays
in the existing Codex home. Only minimal public snapshots/package hashes are
retained; credentials and private checker state are never read or copied.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import types

ROOT=Path(__file__).resolve().parent.parent
CODEX=Path('/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex')
CODEX_PROFILE=Path('/home/luis/.codex')
STATE=Path('/home/luis/.local/share/progress-checker')
SELECTOR='progress-checker@progress-local-8b5742430514'
CACHE=CODEX_PROFILE/'plugins/cache/progress-local-8b5742430514/progress-checker/0.2.1-dev'
SOURCE=Path('/home/luis/.local/share/progress-checker-plugins/8b5742430514/plugins/progress-checker')
RUNTIME=STATE/'plugin-8b5742430514e5c52baf368b'


def load(path):
    import importlib.util
    spec=importlib.util.spec_from_file_location(path.stem.replace('-','_'),path)
    result=importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(),str(path),'exec'),result.__dict__)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upgrade-report',required=True,type=Path)
    parser.add_argument('--report-dir',required=True,type=Path)
    parser.add_argument('--invoke-model',action='store_true',help='Explicit reviewed accepted-plan no-op and existing claim reaffirmations')
    args=parser.parse_args()
    driver=load(ROOT/'scripts/plugin-primary-upgrade.py');runner=load(ROOT/'scripts/plugin-acceptance.py');pilot=load(ROOT/'scripts/plugin-pilot-acceptance.py')
    driver.RUNNER=runner
    acceptance=runner.Acceptance(types.SimpleNamespace(milestone='service-lifecycle'));driver.ACCEPTANCE=acceptance
    started=time.monotonic();deadline=started+210;hard=started+295
    directory=args.report_dir.absolute();directory.mkdir(mode=0o700,exist_ok=False)
    report={'status':'blocked','model_selected':args.invoke_model,'authentication_copied':False,'approval_created':False,
            'configured_checks_requested':False,'full_primary_pilot_complete':False,'coverage':'Actual primary accepted-plan no-op/existing claims and normal prompt trial; no verification.'}
    clients=[];native=None
    env=os.environ.copy();env['CODEX_HOME']=str(CODEX_PROFILE);env.pop('OPENAI_API_KEY',None);env.pop('CODEX_API_KEY',None)
    try:
        upgrade=json.loads(driver.regular(args.upgrade_report,1024*1024))
        if upgrade['status']!='passed' or not upgrade['protected_files_unchanged']:raise RuntimeError('Reviewed primary upgrade receipt must pass')
        writer=upgrade['current_writer'];leases=upgrade['final_root_runtime_audit']['leases'];legacy=upgrade['legacy_processes']
        hashes=upgrade['cache_current_hashes']
        if driver.writer(RUNTIME/'service.json',CACHE/'bin/progress-checker',ROOT,STATE,hashes['progress-checker'])!=writer:raise RuntimeError('Reviewed primary writer changed')
        for name,value in hashes.items():
            if driver.digest(CACHE/'bin'/name)!=value:raise RuntimeError('Reviewed current cache bytes changed')
        protected_paths=[ROOT/p for p in ['.progress-checker/config.json','AGENTS.md','PLUGIN_PLAN.md','.progress-checker/plugin-plan.json','.codex/config.toml','.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz']]+[CODEX_PROFILE/'config.toml']
        protected={str(p):driver.digest(p) for p in protected_paths}
        packages={'cache':driver.inventory(CACHE),'source':driver.inventory(SOURCE)}
        archive=ROOT/'.progress-checker/acceptance-inputs/progress-checker-0.2.1-dev-linux-x86_64-404759af79cd.tar.gz'
        plugin=runner.extract_archive(acceptance,archive,directory/'extracted')
        if acceptance.report['archive']['sha256']!=driver.ARCHIVE_HASH:raise RuntimeError('Primary archive changed from exact reviewed404')
        expected=driver.inventory(plugin)
        for label,base in [('cache',CACHE),('source',SOURCE)]:
            actual=packages[label]
            if actual.keys()!=expected.keys()|{'mcp.json'}:raise RuntimeError('Installed '+label+' inventory changed')
            if any(actual[name]!=value for name,value in expected.items()):raise RuntimeError('Installed '+label+' differs from exact404 bytes/modes')
            binding=json.loads(driver.regular(base/'mcp.json',65536))['mcpServers']['progress_checker']
            if binding['command']!='./bin/checker-plugin' or binding['args']!=['--root',str(ROOT),'--state-dir',str(STATE)]:raise RuntimeError('Installed '+label+' binding changed')
        report['archive']=acceptance.report['archive']
        report['before_audit']={'public_hashes':protected,'package_inventories':packages,'writer':writer,'legacy_leases':leases}
        report['native_codex']={'sha256':driver.digest(CODEX)}
        driver.capture([CODEX,'--version'],directory,'native-version',min(deadline,time.monotonic()+10),env,ROOT,report)
        report['native_codex']['version']=(directory/'native-version.stdout').read_text().strip()
        with (directory/'native.log').open('ab') as log:
            observer=driver.wire(CACHE/'bin/progress-checker-mcp',ROOT,STATE,env,log,deadline);clients.append(observer)
            before=driver.snapshot(observer);before['claim_notes']=observer.current()['result']['claim_notes'];report['public_before']=before
            if before['running'] or before['canonical_root']!=str(ROOT):raise RuntimeError('Primary root unavailable or checks running')
            reviewed=upgrade['public_after_current_adapter']
            for name in ['config','config_hash','claims','running','latest','history','canonical_root','progress','service_instance_id']:
                if before[name]!=reviewed[name]:raise RuntimeError('Reviewed upgraded public baseline changed: '+name)
            native=runner.NativeCodex.__new__(runner.NativeCodex);native.sequence,native.buffer,native.notifications=0,bytearray(),[]
            native.thread_id=native.shutdown_probe=None;native.pilot_deadline=deadline;native.receive=types.MethodType(pilot._native_receive,native)
            overrides=['-c','plugins.'+SELECTOR+'.enabled=true']
            argv=[str(CODEX),'--no-daemon']+overrides+['app-server','--listen','stdio://'];report['native_discovery_argv']=argv
            native.wire=subprocess.Popen(argv,cwd=ROOT,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,start_new_session=True)
            init=native.call('initialize',{'clientInfo':{'name':'primary-readonly','version':'1'},'capabilities':{'experimentalApi':True}})
            native.send({'method':'initialized'})
            if init['codexHome']!=str(CODEX_PROFILE):raise RuntimeError('Native authentication home differs')
            skills=native.call('skills/list',{'cwds':[str(ROOT)],'forceReload':False})
            available=[skill for item in skills.get('data',[]) for skill in item.get('skills',[]) if skill.get('pluginId')==SELECTOR and skill.get('enabled')]
            if len(available)!=1:raise RuntimeError('Current root installed skill not enabled')
            thread=native.call('thread/start',{'cwd':str(ROOT),'ephemeral':True,'approvalPolicy':'never','sandbox':'read-only'})
            native.thread_id=thread['thread']['id'];report['model_config']={k:thread.get(k) for k in ['model','modelProvider']}
            cutoff=min(deadline,time.monotonic()+45)
            while time.monotonic()<cutoff:
                servers=native.call('mcpServerStatus/list',{'threadId':native.thread_id})
                servers=[s for s in servers['data'] if s.get('name')=='progress_checker' and s.get('pluginId')==SELECTOR]
                if servers and servers[0].get('runtimeStatus') in ['connected','failed','disabled']:break
                time.sleep(.1)
            if len(servers)!=1 or servers[0].get('runtimeStatus')!='connected' or set(servers[0]['tools'])!=runner.EXPECTED_TOOLS:raise RuntimeError('Actual native root tools unavailable')
            report['native_discovery']={'skill_path':available[0]['path'],'tools':sorted(servers[0]['tools']),'runtimeStatus':'connected'}
            if available[0]['path']!=str(CACHE/'skills/progress-checker/SKILL.md'):raise RuntimeError('Native skill path differs')
            live_leases={p.name:json.loads(driver.regular(p,4096)) for p in (RUNTIME/'leases').glob('*.json')}
            new_leases=[value for name,value in live_leases.items() if name not in leases]
            native_images=[]
            def belongs(pid):
                visited=set()
                while pid not in visited and len(visited)<32:
                    if pid==native.wire.pid:return True
                    visited.add(pid);info=runner.fixture_process_snapshot(pid)
                    if info.get('absent') or info.get('owned') is False:return False
                    pid=info['ppid']
                return False
            for owned in new_leases:
                pid=owned['pid']
                if runner.process_identity(pid)!=owned or not belongs(pid):raise RuntimeError('Fresh native launcher ownership not proven')
                info=runner.fixture_process_snapshot(pid)
                expected_args=[str(CACHE/'bin/checker-plugin'),'--root',str(ROOT),'--state-dir',str(STATE)]
                if info['command'][1:-1]!=expected_args:raise RuntimeError('Fresh native launcher command differs')
                children=[runner.fixture_process_snapshot(child) for child in info['children']]
                adapters=[child for child in children if child.get('command')==[str(CACHE/'bin/progress-checker-mcp'),'--root',str(ROOT),'--state-dir',str(STATE),'']]
                if len(adapters)!=1:raise RuntimeError('Fresh native adapter not identified')
                adapter=adapters[0];exe=driver.digest(Path(f'/proc/{adapter["pid"]}/exe'))
                if exe!=hashes['progress-checker-mcp'] or driver.digest(CACHE/'bin/checker-plugin')!=hashes['checker-plugin']:raise RuntimeError('Fresh native process bytes differ')
                native_images.append({'launcher':owned,'launcher_argv':info['command'],'launcher_source_sha256':hashes['checker-plugin'],
                                      'adapter':{'pid':adapter['pid'],'starttime':adapter['starttime']},'adapter_argv':adapter['command'],'adapter_exe_sha256':exe})
            if len(native_images)!=1:raise RuntimeError('Exactly one owned fresh native launcher/adapter required')
            report['native_process_images']=native_images
            # Normal EOF owns only this new native child. Preserve active root sessions.
            native.call('thread/unsubscribe',{'threadId':native.thread_id},timeout=10)
            driver.close_wire(native);native=None
            if args.invoke_model:
                skill=str(CACHE/'skills/progress-checker/SKILL.md')
                accepted={'config':before['config'],'claims':before['claims'],'claim_notes':before['claim_notes']}
                report['accepted_public_input']=accepted
                prompt='Apply the installed Progress Checker skill. The only allowed shell command is /usr/bin/cat '+skill+'. This is the already accepted complete current project configuration and existing claims/notes: '+json.dumps(accepted)+'. Read checker_get_project; submit this IDENTICAL config once via checker_submit_plan with the actual current revision/config hash and reason "Primary accepted plan confirmation; no scope change". Never change scope/config. For each existing implemented claim (and only those seven), read checker_get_project immediately before its checker_set_claim and use that actual current revision, IDENTICAL claim value and EXACT same note from the accepted input. If current config, claim values or notes differ from accepted input, stop without mutation. Read checker_get_plan_history limit5 and checker_get_progress; explain implemented versus verified. Do not execute checks, grant approval, create new claims, or change any file or claim note. Then answer what is 2+3.'
                permissions=[]
                for tool in ['checker_submit_plan','checker_set_claim']:
                    permissions+=['-c','plugins.'+SELECTOR+'.mcp_servers.progress_checker.tools.'+tool+'.approval_mode="approve"']
                report['native_permission_tools']=['checker_submit_plan','checker_set_claim']
                argv=[str(CODEX),'--no-daemon','-a','never','-s','read-only','-C',str(ROOT)]+overrides+permissions+['exec','--json','--ephemeral',prompt]
                driver.capture(argv,directory,'authenticated-planning',min(deadline,time.monotonic()+120),env,ROOT,report)
                text=(directory/'authenticated-planning.stdout').read_text();events=[json.loads(line) for line in text.splitlines() if line.strip()]
                (directory/'authenticated-planning.jsonl').write_text(text)
                items=[e['item'] for e in events if e.get('type')=='item.completed'];calls=[i for i in items if i.get('type')=='mcp_tool_call']
                commands=[i.get('command','') for i in items if i.get('type')=='command_execution'];answer='\n'.join(i['text'] for i in items if i.get('type')=='agent_message')
                report['model_receipt']={'argv':argv,'calls':calls,'normal_answer':answer,'shell_commands':commands}
                if not calls or not {'checker_get_project','checker_get_progress','checker_submit_plan','checker_set_claim','checker_get_plan_history'}<={c.get('tool') for c in calls}:raise RuntimeError('Required actual model reads missing')
                if any(c.get('server')!='progress_checker' or c.get('tool') not in ['checker_get_project','checker_get_progress','checker_submit_plan','checker_set_claim','checker_get_plan_history'] or c.get('status')!='completed' for c in calls):raise RuntimeError('Unexpected model MCP operation')
                submissions=[call for call in calls if call['tool']=='checker_submit_plan']
                reaffirmations=[call for call in calls if call['tool']=='checker_set_claim']
                if len(submissions)!=1 or submissions[0]['arguments']['config']!=before['config']:raise RuntimeError('Model accepted plan submission differs')
                if len(reaffirmations)!=len(before['claims']) or {call['arguments']['milestone_id'] for call in reaffirmations}!=set(before['claims']):raise RuntimeError('Existing claim reaffirmations missing/duplicated')
                for call in submissions+reaffirmations:
                    result=call.get('result') or {};structured=result.get('structured_content') or {}
                    if call.get('error') is not None or 'error' in structured or 'result' not in structured or structured.get('service_instance_id')!=before['service_instance_id']:
                        raise RuntimeError('Actual model plan/claim backend receipt failed')
                for call in reaffirmations:
                    arguments=call['arguments'];mid=arguments['milestone_id']
                    if arguments['claim']!=before['claims'][mid] or arguments['note']!=before['claim_notes'].get(mid,''):raise RuntimeError('Model claim/note differs from accepted existing value')
                allowed=[f'/usr/bin/cat {skill}',f"/bin/bash -lc '/usr/bin/cat {skill}'",f"/bin/bash -lc '/usr/bin/cat -- {skill}'"]
                if any(command not in allowed for command in commands) or any(i.get('type')=='file_change' for i in items):raise RuntimeError('Unexpected model shell/write operation')
                if not re.search(r'\b5\b',answer):raise RuntimeError('Normal arithmetic answer missing')
            after=driver.snapshot(observer);after['claim_notes']=observer.current()['result']['claim_notes'];report['public_after']=after
            for name in ['config','config_hash','claims','running','latest','history','canonical_root','progress','service_instance_id','claim_notes']:
                if after[name]!=before[name]:raise RuntimeError('Primary public state changed: '+name)
            report['status']='passed' if args.invoke_model else 'native-readiness-only'
    except BaseException as exc:report['status']='failed';report['error']=repr(exc)
    finally:
        for client in ([native] if native else [])+list(reversed(clients)):
            try:driver.close_wire(client)
            except BaseException as exc:report.setdefault('cleanup_errors',[]).append(repr(exc));report['status']='failed'
        if 'protected' in locals():
            try:
                final={str(p):driver.digest(p) for p in protected_paths};report['final_public_hashes']=final
                if final!=protected or driver.inventory(CACHE)!=packages['cache'] or driver.inventory(SOURCE)!=packages['source']:raise RuntimeError('Primary public/profile/package bytes changed')
                if driver.writer(RUNTIME/'service.json',CACHE/'bin/progress-checker',ROOT,STATE,hashes['progress-checker'])!=writer:raise RuntimeError('Primary writer changed during native cleanup')
                cutoff=min(hard,time.monotonic()+15)
                while time.monotonic()<cutoff:
                    final_leases={p.name:json.loads(driver.regular(p,4096)) for p in (RUNTIME/'leases').glob('*.json')}
                    if final_leases==leases:break
                    time.sleep(.1)
                if final_leases!=leases:raise RuntimeError('Native cleanup left changed root leases')
                for pid,item in legacy.items():
                    if runner.process_identity(int(pid))!={'pid':int(pid),'starttime':item['starttime']} or driver.digest(Path(f'/proc/{pid}/exe'))!=item['exe_sha256']:raise RuntimeError('Legacy process changed')
                report['final_audit']={'root_public_profile_package_unchanged':True,'writer_preserved':writer,'legacy_leases_preserved':final_leases,'legacy_identities_preserved':True}
            except BaseException as exc:report['status']='failed';report['final_audit_error']=repr(exc)
        report['elapsed_seconds']=time.monotonic()-started
        (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(directory/'report.json')
    return 0 if report['status'] in ['passed','native-readiness-only'] else 2


if __name__=='__main__':raise SystemExit(main())
