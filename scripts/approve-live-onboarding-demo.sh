#!/bin/bash
# QA helper only: native human approval in the retained recipient fixture.
set -euo pipefail
if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [public-descriptor.json]" >&2
  exit 2
fi
if [[ ! -t 0 || ! -t 1 ]]; then
  echo "Run this helper yourself in an interactive human terminal." >&2
  exit 1
fi
exec /usr/bin/python3 -c '
import hashlib,json,os,re,runpy,stat,subprocess,sys
from pathlib import Path
module=runpy.run_path("/home/luis/progress-checker/scripts/prepare-live-onboarding-demo.py")
path=Path(sys.argv[1])
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,"rb") as source:
 info=os.fstat(source.fileno())
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_size>32768:raise SystemExit("Expected bounded owned public descriptor")
 demo=json.loads(source.read(32769))
container=module["inspect"]()
if not container["State"]["Running"]:raise SystemExit("Prepared recipient container is not running")
if demo.get("schema_version")!=1 or demo.get("container")!=module["CONTAINER"] or demo.get("transport")!={"kind":"podman","container_id":module["CONTAINER_ID"]}:raise SystemExit("Public descriptor container differs")
root=demo["root"];state=demo["state_dir"];package=demo["package_path"]
if not re.fullmatch("/home/recipient/live-onboarding-[0-9a-f]{32}/project",root) or state!=str(Path(root).parent/"state") or not re.fullmatch("/inputs/native-onboarding/[0-9a-f]{16}",package):raise SystemExit("Unexpected QA fixture selector")
expected={"id":"live-demo","argv":["/usr/bin/python3","check.py"],"cwd":".","kind":"test","timeout_seconds":10}
if demo.get("check_id")!="live-demo" or demo.get("check_definition")!=expected:raise SystemExit("Unexpected QA check definition")
query=["podman","exec",module["CONTAINER_ID"],"/usr/bin/python3","-c",module["PROGRESS_PROBE"],root,state]
public=json.loads(subprocess.run(query,check=True,capture_output=True,timeout=15).stdout)
snapshot=public["result"]
if public["service_instance_id"]!=demo["service_instance_id"] or snapshot["canonical_root"]!=root or snapshot["status"]["source"]["config_hash"]!=demo["config_hash"] or snapshot["config"]["checks"]!=[expected] or snapshot["running"] or public["public_peer"]["pid"]!=demo["service_pid"] or public["public_peer"]["exe_sha256"]!=demo["cli_sha256"]:raise SystemExit("Prepared public service/configuration changed")
verify="import hashlib,json,sys;from pathlib import Path;p=Path(sys.argv[1]);q=Path(sys.argv[2]);print(json.dumps({\"config_file_sha256\":hashlib.sha256((p/\".progress-checker/config.json\").read_bytes()).hexdigest(),\"script_sha256\":hashlib.sha256((p/\"check.py\").read_bytes()).hexdigest(),\"feature_sha256\":hashlib.sha256((p/\"feature.txt\").read_bytes()).hexdigest(),\"cli_sha256\":hashlib.sha256((q/\"plugin/bin/progress-checker\").read_bytes()).hexdigest()}))"
facts=json.loads(subprocess.run(["podman","exec",module["CONTAINER_ID"],"/usr/bin/python3","-c",verify,root,package],check=True,capture_output=True,timeout=15).stdout)
if any(demo.get(key)!=value for key,value in facts.items()):raise SystemExit("Prepared public fixture/package bytes changed")
print("Isolated recipient QA fixture; this requests approval only and runs no check.",flush=True)
print(json.dumps({"project":root,"state_directory":state,"service_instance_id":demo["service_instance_id"],"check":expected,"config_hash":demo["config_hash"],"command_hash":demo["command_hash"]},indent=2),flush=True)
print("Review the native CLI definition and answer its confirmation yourself.",flush=True)
os.execvp("podman",["podman","exec","-it",module["CONTAINER_ID"],package+"/plugin/bin/progress-checker","--root",root,"--state-dir",state,"approve","live-demo"])
' "${1:-/home/luis/progress-checker/.local/native-onboarding-human-demo.json}"
