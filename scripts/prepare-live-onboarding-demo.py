#!/usr/bin/env python3
"""QA only: prepare a source-free recipient fixture; never approve or run a check."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import tempfile

ROOT = Path('/home/luis/progress-checker')
CONTAINER = 'pc-launch-recipient-20261006'
CONTAINER_ID = '7a1ddcb59f246d42dc97621748a6ee5c71913a857a1e0d90ee8f191fc4a5a7d1'
IMAGE_ID = 'd7e33d71fd7174024da0388b96bfc3ca94d471e89a1f1677d2e0bb120619d8a5'
DESCRIPTOR = ROOT / '.local/native-onboarding-human-demo.json'
PROGRESS_PROBE = r'''
import hashlib,json,os,socket,struct,sys
from pathlib import Path
root,state=map(Path,sys.argv[1:]);key=hashlib.sha256(os.fsencode(root)).hexdigest()[:24]
endpoint=state/('ipc-'+key+'.sock')
if len(os.fsencode(endpoint))>100:
 key=hashlib.sha256(os.fsencode(root)+b'\0'+os.fsencode(state)).hexdigest()[:24]
 endpoint=Path('/tmp')/('progress-checker-ipc-'+str(os.getuid()))/('ipc-'+key+'.sock')
def exact(s,n):
 b=bytearray()
 while len(b)<n:
  c=s.recv(n-len(b))
  if not c:raise RuntimeError('Truncated public response')
  b.extend(c)
 return bytes(b)
with socket.socket(socket.AF_UNIX) as s:
 s.settimeout(5);s.connect(str(endpoint));pid,uid,gid=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
 if uid!=os.getuid():raise RuntimeError('Foreign public service')
 q=json.dumps({'schema_version':1,'request_id':'onboarding-public','operation':{'operation':'progress'}}).encode()
 s.sendall(struct.pack('>I',len(q))+q);n=struct.unpack('>I',exact(s,4))[0]
 if not 0<n<=262144:raise RuntimeError('Public response bound')
 r=json.loads(exact(s,n))
 if r.get('request_id')!='onboarding-public' or r.get('schema_version')!=1 or 'error' in r:raise RuntimeError('Public response refused')
 r['public_peer']={'pid':pid,'uid':uid,'exe_sha256':hashlib.sha256(Path('/proc/'+str(pid)+'/exe').read_bytes()).hexdigest()}
 print(json.dumps(r))
'''
SETUP = r'''
import hashlib,json,os,secrets,subprocess,sys,time
from pathlib import Path
package,base,expected=Path(sys.argv[1]),Path(sys.argv[2]),json.loads(sys.argv[3])
for rel,digest in expected.items():
 if hashlib.sha256((package/rel).read_bytes()).hexdigest()!=digest:raise RuntimeError('Container package checksum differs')
base.mkdir(mode=0o700);root=base/'project';state=base/'state';root.mkdir(mode=0o700);state.mkdir(mode=0o700)
(root/'.progress-checker').mkdir();(root/'feature.txt').write_text('native onboarding ready\n')
(root/'check.py').write_text('from pathlib import Path\nassert Path("feature.txt").read_text() == "native onboarding ready\\n"\nprint("Native onboarding fixture passed")\n')
config={'schema_version':1,'project_id':'native-onboarding-human-demo','enabled':True,'panel':{'show_on_start':True},'execution':{'max_parallel':1,'default_timeout_seconds':10},'fingerprint':{'extra_inputs':[],'exclude_outputs':[]},'checks':[{'id':'live-demo','argv':['/usr/bin/python3','check.py'],'cwd':'.','kind':'test','timeout_seconds':10}],'milestones':[{'id':'onboarding','title':'Recipient approved check','in_scope':True,'depends_on':[],'criteria':[{'id':'acceptance','description':'Exact human-approved fixture passes','check_id':'live-demo','required':True}]}]}
(root/'.progress-checker/config.json').write_text(json.dumps(config,indent=2)+'\n')
subprocess.run(['/usr/bin/git','init','-q',str(root)],stdin=subprocess.DEVNULL,check=True)
cli=package/'plugin/bin/progress-checker'
with (base/'service.stdout').open('xb') as out,(base/'service.stderr').open('xb') as err:
 process=subprocess.Popen([str(cli),'--root',str(root),'--state-dir',str(state),'serve'],stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
print(json.dumps({'root':str(root),'state_dir':str(state),'service_pid':process.pid,'public_log_directory':str(base),'config_file_sha256':hashlib.sha256((root/'.progress-checker/config.json').read_bytes()).hexdigest(),'script_sha256':hashlib.sha256((root/'check.py').read_bytes()).hexdigest(),'feature_sha256':hashlib.sha256((root/'feature.txt').read_bytes()).hexdigest()}))
'''


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def command(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, timeout=30, **kwargs)


def inspect():
    values = json.loads(command(['podman', 'inspect', CONTAINER]).stdout)
    require(len(values) == 1, 'Exact existing recipient container required')
    value = values[0]
    host = value['HostConfig']
    require(value['Id'] == CONTAINER_ID and value['Image'] == IMAGE_ID
        and value['Config']['User'] == '1000:1000' and not value['Mounts']
        and not host.get('Binds') and host['NetworkMode'] == 'none'
        and host['Privileged'] is False and not host['CapAdd']
        and host['SecurityOpt'] == ['label=disable', 'seccomp=unconfined', 'unmask=all']
        and 'CAP_SYS_CHROOT' in host['CapDrop'], 'Existing recipient development policy differs')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    args = parser.parse_args()
    require(not os.path.lexists(DESCRIPTOR), 'Public descriptor exists; preserve the previous fixture')
    package = args.package.resolve(strict=True)
    checksums = json.loads((package / 'checksums.json').read_bytes())
    manifest = json.loads((package / 'plugin/plugin.json').read_bytes())
    require(manifest['version'] == '0.4.0-dev', 'Reviewed 0.4.0-dev package required')
    for relative, digest in checksums.items():
        path = package / relative
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts
                and path.resolve().is_relative_to(package) and not path.is_symlink()
                and stat.S_ISREG(path.stat().st_mode), 'Unsafe package inventory')
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'Package checksum differs: ' + relative)
    package_sha = hashlib.sha256((package / 'checksums.json').read_bytes()).hexdigest()
    target = '/inputs/native-onboarding/' + package_sha[:16]
    value = inspect()
    if not value['State']['Running']:
        command(['podman', 'start', CONTAINER])
    inspect()
    # podman cp copies bytes into existing container storage; it mounts no host path.
    check = command(['podman', 'exec', CONTAINER, '/usr/bin/python3', '-c',
        'import json,os;print(json.dumps([os.path.exists("/inputs/native-onboarding"),os.path.exists(' + repr(target) + ')]))'])
    parent_exists, target_exists = json.loads(check.stdout)
    if not parent_exists:
        with tempfile.TemporaryDirectory(prefix='native-onboarding-inputs-') as temporary:
            command(['podman', 'cp', temporary, CONTAINER + ':/inputs/native-onboarding'])
    require(not target_exists, 'Reviewed package input already exists; no release inputs overwritten')
    command(['podman', 'cp', str(package), CONTAINER + ':' + target])
    nonce = secrets.token_hex(16)
    base = '/home/recipient/live-onboarding-' + nonce
    selected = {relative: checksums[relative] for relative in (
        'plugin/bin/progress-checker', 'plugin/bin/progress-checker-mcp')}
    prepared = json.loads(command(['podman', 'exec', '-i', CONTAINER, '/usr/bin/python3', '-',
        target, base, json.dumps(selected)], input=SETUP.encode()).stdout)
    import time
    until = time.monotonic() + 20
    query = ['podman', 'exec', CONTAINER, '/usr/bin/python3', '-c', PROGRESS_PROBE,
             prepared['root'], prepared['state_dir']]
    while True:
        try:
            progress = json.loads(command(query).stdout)
            break
        except subprocess.CalledProcessError:
            require(time.monotonic() < until, 'Own service public startup deadline; logs retained')
            time.sleep(.1)
    snapshot = progress['result']
    require(snapshot['canonical_root'] == prepared['root'] and not snapshot['running']
            and not snapshot['status']['latest'] and snapshot['status']['progress']['verified'] == 0,
            'Fresh fixture public state differs')
    require(progress['public_peer']['pid'] == prepared['service_pid']
        and progress['public_peer']['exe_sha256'] == selected['plugin/bin/progress-checker'],
        'Actual service peer differs from packaged CLI')
    # Rust Check serializes these exact fields in declaration order.
    check = snapshot['config']['checks'][0]
    definition = {key: check[key] for key in ('id', 'argv', 'cwd', 'kind', 'timeout_seconds')}
    command_hash = 'sha256:' + hashlib.sha256(json.dumps(definition, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    descriptor = {'schema_version': 1, 'purpose': 'isolated-recipient-human-approval-qa',
        'transport': {'kind': 'podman', 'container_id': CONTAINER_ID}, 'container': CONTAINER,
        'image_id': IMAGE_ID, 'package_path': target, 'package_checksums_sha256': package_sha,
        **prepared, 'check_id': 'live-demo', 'check_definition': definition,
        'service_instance_id': progress['service_instance_id'],
        'config_hash': snapshot['status']['source']['config_hash'], 'command_hash': command_hash,
        'cli_sha256': selected['plugin/bin/progress-checker'], 'public_query_argv': query,
        'approval_created': False, 'check_executed': False, 'qualification_possible': False,
        'development_container_policy': 'Existing network-none/no-host-mounts/cap-drop policy retained; seccomp/label development exceptions unchanged.'}
    DESCRIPTOR.parent.mkdir(exist_ok=True)
    with DESCRIPTOR.open('x') as output:
        os.chmod(DESCRIPTOR, 0o600)
        json.dump(descriptor, output, indent=2)
        output.write('\n')
    print(json.dumps(descriptor, indent=2))


if __name__ == '__main__':
    main()
