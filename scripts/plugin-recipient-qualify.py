#!/usr/bin/env python3
import argparse, gzip, io, tempfile, codecs, datetime, errno, fcntl, hashlib, http.server, json, os, pty, select, signal, struct, subprocess, sys, tarfile, termios, threading, time, tomllib, traceback, unicodedata
from pathlib import Path
class Screen:
    """Small VT screen sufficient for crossterm's cursor/erase drawing commands."""

    def __init__(self, width: int, height: int):
        self.width, self.height = width, height
        self.cells = [[" "] * width for _ in range(height)]
        self.row = self.col = 0
        self.saved = (0, 0)
        self.scroll_top, self.scroll_bottom = 0, height - 1
        self.mode, self.sequence = "text", ""
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")

    def resize(self, width: int, height: int):
        old = self.cells
        self.width, self.height = width, height
        self.cells = [
            (old[row][:width] + [" "] * width)[:width]
            if row < len(old)
            else [" "] * width
            for row in range(height)
        ]
        self.row, self.col = min(self.row, height - 1), min(self.col, width - 1)
        self.scroll_top, self.scroll_bottom = 0, height - 1

    def text(self) -> str:
        return "\n".join("".join(row).rstrip() for row in self.cells).rstrip() + "\n"

    def linefeed(self):
        if self.row == self.scroll_bottom:
            self.cells.pop(self.scroll_top)
            self.cells.insert(self.scroll_bottom, [" "] * self.width)
        else:
            self.row += 1

    def feed(self, data: bytes) -> bytes:
        replies = bytearray()
        for char in self.decoder.decode(data):
            if self.mode == "osc":
                if char == "\a":
                    replies.extend(self.finish_osc())
                elif char == "\x1b":
                    self.mode = "osc-escape"
                else:
                    self.sequence += char
                continue
            if self.mode == "osc-escape":
                if char == "\\":
                    replies.extend(self.finish_osc())
                else:
                    self.sequence += char
                    self.mode = "osc"
                continue
            if self.mode == "csi":
                if "@" <= char <= "~":
                    replies.extend(self.csi(char))
                    self.mode, self.sequence = "text", ""
                else:
                    self.sequence += char
                continue
            if self.mode == "charset":
                self.mode = "text"
                continue
            if self.mode == "escape":
                self.mode = "text"
                if char == "[":
                    self.mode, self.sequence = "csi", ""
                elif char == "]":
                    self.mode, self.sequence = "osc", ""
                elif char in "()*+":
                    self.mode = "charset"
                elif char == "7":
                    self.saved = (self.row, self.col)
                elif char == "8":
                    self.row, self.col = self.saved
                elif char in "DE":
                    self.linefeed()
                    if char == "E":
                        self.col = 0
                elif char == "M":
                    if self.row == self.scroll_top:
                        self.cells.pop(self.scroll_bottom)
                        self.cells.insert(self.scroll_top, [" "] * self.width)
                    else:
                        self.row = max(0, self.row - 1)
                continue
            if char == "\x1b":
                self.mode = "escape"
            elif char == "\r":
                self.col = 0
            elif char == "\n":
                self.linefeed()
            elif char == "\b":
                self.col = max(0, self.col - 1)
            elif char == "\t":
                self.col = min(self.width - 1, (self.col // 8 + 1) * 8)
            elif ord(char) >= 32 and char != "\x7f":
                if unicodedata.combining(char):
                    if self.col:
                        self.cells[self.row][self.col - 1] += char
                    continue
                columns = 2 if unicodedata.east_asian_width(char) in "WF" else 1
                if self.col >= self.width:
                    self.col = 0
                    self.linefeed()
                self.cells[self.row][self.col] = char
                if columns == 2 and self.col + 1 < self.width:
                    self.cells[self.row][self.col + 1] = ""
                self.col += columns
        return bytes(replies)

    def finish_osc(self) -> bytes:
        sequence = self.sequence
        self.mode, self.sequence = "text", ""
        if sequence in ("10;?", "11;?"):
            color = "ffff/ffff/ffff" if sequence.startswith("10") else "0000/0000/0000"
            return f"\x1b]{sequence[:2]};rgb:{color}\x1b\\".encode()
        return b""

    def csi(self, command: str) -> bytes:
        if self.sequence.startswith("?"):
            return b""
        try:
            values = [int(value) if value else 0 for value in self.sequence.split(";")]
        except ValueError:
            return b""
        first = values[0] or 1
        if command in "Hf":
            self.row = min(self.height - 1, first - 1)
            self.col = min(self.width - 1, (values[1] or 1) - 1) if len(values) > 1 else 0
        elif command == "A":
            self.row = max(0, self.row - first)
        elif command == "B":
            self.row = min(self.height - 1, self.row + first)
        elif command == "C":
            self.col = min(self.width - 1, self.col + first)
        elif command == "D":
            self.col = max(0, self.col - first)
        elif command in "EF":
            self.row = max(0, min(self.height - 1, self.row + (first if command == "E" else -first)))
            self.col = 0
        elif command == "G":
            self.col = min(self.width - 1, first - 1)
        elif command == "d":
            self.row = min(self.height - 1, first - 1)
        elif command == "J":
            if values[0] in (2, 3):
                self.cells = [[" "] * self.width for _ in range(self.height)]
            elif values[0] == 0:
                self.cells[self.row][self.col:] = [" "] * (self.width - self.col)
                for row in range(self.row + 1, self.height):
                    self.cells[row] = [" "] * self.width
            elif values[0] == 1:
                for row in range(self.row):
                    self.cells[row] = [" "] * self.width
                self.cells[self.row][:self.col + 1] = [" "] * (self.col + 1)
        elif command == "K":
            start, end = (0, self.width) if values[0] == 2 else ((0, self.col + 1) if values[0] == 1 else (self.col, self.width))
            self.cells[self.row][start:end] = [" "] * (end - start)
        elif command == "X":
            end = min(self.width, self.col + first)
            self.cells[self.row][self.col:end] = [" "] * (end - self.col)
        elif command == "P":
            row = self.cells[self.row]
            self.cells[self.row] = (row[:self.col] + row[self.col + first:] + [" "] * first)[:self.width]
        elif command == "@":
            row = self.cells[self.row]
            self.cells[self.row] = (row[:self.col] + [" "] * first + row[self.col:])[:self.width]
        elif command == "s":
            self.saved = (self.row, self.col)
        elif command == "u":
            self.row, self.col = self.saved
        elif command == "n" and values[0] == 6:
            return f"\x1b[{self.row + 1};{min(self.col, self.width - 1) + 1}R".encode()
        elif command == "r":
            self.scroll_top = min(self.height - 1, first - 1)
            self.scroll_bottom = min(self.height - 1, values[1] - 1) if len(values) > 1 and values[1] else self.height - 1
            self.row = self.col = 0
        elif command == "c":
            return b"\x1b[?1;2c"
        return b""



parser=argparse.ArgumentParser(description='Source-free native recipient qualification; never approves or runs configured checks.')
parser.add_argument('--archive',type=Path,required=True)
parser.add_argument('--sha256',required=True)
parser.add_argument('--old-archive',type=Path,required=True)
parser.add_argument('--base-dir',type=Path,default=Path('/home/recipient'))
parser.add_argument('--data-home',type=Path)
parser.add_argument('--output-dir',type=Path)
parser.add_argument('--namespace-mapped-root',action='store_true')
parser.add_argument('--invoker-attestation',type=Path)
options=parser.parse_args()
def extract_package(archive, target):
    """Bound archive expansion and reject duplicate/aliased/special members."""
    with gzip.open(archive,'rb') as source:
        expanded=source.read(144*1024*1024+1)
    if len(expanded)>144*1024*1024: raise ValueError('Archive expansion exceeds limit')
    with tarfile.open(fileobj=io.BytesIO(expanded),mode='r:') as tf:
        members=tf.getmembers()
        if len(members)>4096: raise ValueError('Archive member count exceeds limit')
        seen=set(); total=0
        for member in members:
            name=member.name.rstrip('/') if member.isdir() else member.name
            if not name or name.startswith('/') or '\\' in name or any(part in ('','.','..') for part in name.split('/')) or name in seen:
                raise ValueError('Archive contains duplicate, aliased, or unsafe path')
            seen.add(name)
            if not member.isfile() and not member.isdir(): raise ValueError('Archive special members forbidden')
            total+=member.size
            if member.size>64*1024*1024 or total>128*1024*1024: raise ValueError('Archive payload exceeds limit')
        tf.extractall(target,filter='data')

BASE=Path(tempfile.mkdtemp(prefix='pc-recipient-',dir=options.base_dir))
OUT=options.output_dir or BASE/'results'
OUT.mkdir(exist_ok=True)
PROJECT=BASE/'worktrees/demo'
PROFILE=BASE/'codex-profile'
DATA=options.data_home or BASE/'data'
REPORT={'status':'running','archive_sha256':None,'assertions':[], 'limitations':[], 'no_configured_checks_executed':True}
ENV=os.environ.copy()
for key in list(ENV):
    if any(part in key.upper() for part in ['TOKEN','API_KEY','AUTHORIZATION']): ENV.pop(key)
ENV.update(HOME=str(BASE),CODEX_HOME=str(PROFILE),XDG_DATA_HOME=str(DATA),XDG_CACHE_HOME=str(BASE/'cache'),TERM='xterm-256color',COLORTERM='truecolor',OTEL_SDK_DISABLED='true')
def record(name, value=True):
    assert value, name
    REPORT['assertions'].append(name)
def run(name,args,check=True):
    p=subprocess.run([str(a) for a in args],env=ENV,text=True,capture_output=True,timeout=90)
    (OUT/(name+'.stdout')).write_text(p.stdout)
    (OUT/(name+'.stderr')).write_text(p.stderr)
    record(name+' exit 0',p.returncode==0) if check else None
    return p
class Provider(http.server.HTTPServer):
    def __init__(self):
        self.requests=[]
        super().__init__(('127.0.0.1',0),Handler)
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def answer(self):
        self.server.requests.append({'method':self.command,'path':self.path})
        size=int(self.headers.get('Content-Length','0'))
        if size: self.rfile.read(size)
        data=b'{"data":[]}'
        self.send_response(200 if self.command=='GET' else 500)
        self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    do_GET=answer
    do_POST=answer
ACTIVE_MCP=[]
class MCP:
    def __init__(self,launcher,args,label):
        self.label=label; self.id=0
        self.log=(OUT/(label+'.wire.jsonl')).open('w')
        self.err=(OUT/(label+'.stderr')).open('w')
        self.p=subprocess.Popen([str(launcher)]+args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err,env=ENV)
        self.closed=False
        ACTIVE_MCP.append(self)
        self.buf=b''
        self.send('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'recipient-qualification','version':'1'}})
        self.notify('notifications/initialized',{})
    def notify(self,method,params):
        self.p.stdin.write((json.dumps({'jsonrpc':'2.0','method':method,'params':params})+'\n').encode());self.p.stdin.flush()
    def send(self,method,params):
        self.id+=1; message={'jsonrpc':'2.0','id':self.id,'method':method,'params':params}
        self.log.write(json.dumps({'direction':'request','message':message})+'\n');self.log.flush()
        self.p.stdin.write((json.dumps(message)+'\n').encode());self.p.stdin.flush()
        deadline=time.monotonic()+50
        while b'\n' not in self.buf:
            if time.monotonic()>deadline: raise TimeoutError(method)
            if select.select([self.p.stdout],[],[],0.2)[0]:
                chunk=os.read(self.p.stdout.fileno(),65536)
                if not chunk: raise RuntimeError('MCP closed: '+method)
                self.buf+=chunk
                if len(self.buf)>512*1024: raise ValueError('MCP response exceeds 512 KiB')
        line,self.buf=self.buf.split(b'\n',1)
        answer=json.loads(line)
        self.log.write(json.dumps({'direction':'response','message':answer})+'\n');self.log.flush()
        record(self.label+' RPC response id '+str(self.id),answer.get('id')==self.id and 'error' not in answer)
        return answer['result']
    def call(self,name,args):
        answer=self.send('tools/call',{'name':name,'arguments':args})
        record(self.label+' '+name+' successful',not answer.get('isError'))
        return answer['structuredContent']
    def close(self):
        if self.closed:return
        self.closed=True
        self.p.stdin.close()
        try: self.p.wait(timeout=15)
        except subprocess.TimeoutExpired: self.p.terminate();self.p.wait(timeout=5)
        self.log.close();self.err.close()
        record(self.label+' adapter exit 0',self.p.returncode==0)
def snapshot(label):
    files={str(p.relative_to(DATA)):hashlib.sha256(p.read_bytes()).hexdigest() for p in DATA.rglob('*') if p.is_file() and p.suffix=='.json' and 'sessions' not in p.parts and 'progress-checker-plugins' not in p.parts}
    (OUT/(label+'.json')).write_text(json.dumps(files,indent=2)+'\n')
    return files
def assert_no_runtime_orphans(label):
    deadline=time.monotonic()+5
    while True:
        active=[]
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit(): continue
            try: argv=(entry/'cmdline').read_bytes().split(b'\0')
            except (FileNotFoundError,PermissionError,ProcessLookupError): continue
            if any(os.fsencode(BASE) in arg for arg in argv) and any(Path(os.fsdecode(arg)).name in ('checker-plugin','progress-checker','progress-checker-mcp') for arg in argv if arg):
                active.append({'pid':int(entry.name),'argv':[os.fsdecode(arg) for arg in argv if arg]})
        if not active: break
        if time.monotonic()>deadline:
            (OUT/(label+'-orphans.json')).write_text(json.dumps(active,indent=2)+'\n')
            raise AssertionError(label+' orphaned checker or watchdog')
        time.sleep(.1)
    record(label+' leaves no scoped checker adapter/service/watchdog process')

def native(label,tool_count):
    screen=Screen(160,50); raw=(OUT/(label+'.ansi')).open('wb')
    pid,fd=pty.fork()
    if pid==0:
        os.chdir(PROJECT)
        os.execve('/usr/local/bin/codex',['codex','--no-daemon','--no-alt-screen','--ask-for-approval','on-request','--sandbox','read-only'],ENV)
    fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',50,160,0,0))
    exited=False; status=None
    def pump(duration=.1):
        nonlocal exited,status
        if select.select([fd],[],[],duration)[0]:
            try: data=os.read(fd,65536)
            except OSError as e:
                if e.errno!=errno.EIO: raise
                data=b''
            if data:
                raw.write(data);raw.flush(); reply=screen.feed(data)
                if reply: os.write(fd,reply)
        if not exited:
            waited,s=os.waitpid(pid,os.WNOHANG)
            if waited: exited=True;status=os.waitstatus_to_exitcode(s)
    def until(predicate,description,timeout=50):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            pump()
            if predicate(screen.text()): return
            if exited: raise AssertionError('native exited '+str(status)+' before '+description)
        (OUT/(label+'-timeout.txt')).write_text(screen.text())
        raise AssertionError('native timeout '+description)
    def command(value):
        os.write(fd,value.encode());deadline=time.monotonic()+.25
        while time.monotonic()<deadline:pump(.05)
        os.write(fd,b'\r')
    try:
        until(lambda text:'Ask Codex to do anything' in text and 'GPT-6.1-Sol' in text and 'loading' not in text,'composer')
        deadline=time.monotonic()+50
        while time.monotonic()<deadline:
            command('/mcp');until(lambda text:'progress_checker:' in text,'MCP inventory')
            settle=time.monotonic()+2
            while time.monotonic()<settle:pump(.1)
            if f'progress_checker: connected ({tool_count} tools)' in screen.text(): break
        else: raise AssertionError('Native MCP did not become connected')
        record(label+' native connected with '+str(tool_count)+' tools')
        command('/mcp verbose')
        until(lambda text:'checker_get_progress' in text,'verbose tool discovery')
        deadline=time.monotonic()+1
        while time.monotonic()<deadline:pump(.05)
        (OUT/(label+'.txt')).write_text(screen.text())
        raw.flush(); record(label+' native discovers progress tool',b'checker_get_progress' in (OUT/(label+'.ansi')).read_bytes())
        if tool_count==10: record(label+' native discovers new plan submission',b'checker_submit_plan' in (OUT/(label+'.ansi')).read_bytes())
    finally:
        if not exited:
            command('/quit'); deadline=time.monotonic()+4
            while time.monotonic()<deadline and not exited:pump(.1)
        if not exited:
            os.kill(pid,signal.SIGTERM);os.waitpid(pid,0)
        raw.close();os.close(fd)
    record(label+' native clean exit',exited and status==0)
    assert_no_runtime_orphans(label)
def interrupt_qualification(*_):
    raise TimeoutError('Recipient qualification interrupted by shared deadline')
signal.signal(signal.SIGTERM,interrupt_qualification)

try:
    if options.namespace_mapped_root:
        attestation=json.loads(options.invoker_attestation.read_text())
        uid_map=[tuple(map(int,line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
        gid_map=[tuple(map(int,line.split())) for line in Path('/proc/self/gid_map').read_text().splitlines()]
        mounts=Path('/proc/self/mountinfo').read_text().splitlines()
        record('rootless mapped-root fixture has exactly one invoking non-root uid',os.getuid()==0 and attestation['invoker_euid']==1000 and uid_map==[(0,1000,1)])
        record('rootless mapped-root fixture has exactly one invoking non-root gid',os.getgid()==0 and attestation['invoker_egid']==1000 and gid_map==[(0,1000,1)])
        record('mapped-root executable metadata preserves checker policy',all(Path(p).stat().st_uid==0 and not Path(p).stat().st_mode&0o022 for p in ['/usr/bin/python3.14','/usr/bin/bwrap','/usr/bin/false']))
        record('mapped-root copied executables are readonly mounts',all(any(line.split()[4]==p and 'ro' in line.split()[5].split(',') for line in mounts) for p in ['/usr/bin/python3.14','/usr/bin/bwrap','/usr/bin/false']))
        record('mapped-root fixture excludes product source and host home',not Path('/home/luis').exists() and not Path('/r/checker-core').exists() and attestation['product_source_visible']==False and attestation['host_home_visible']==False)
        record('all copied executable bytes match invoking system runtime',all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==sha for p,sha in attestation['runtime_executable_sha256'].items()))
        record('all copied executables are readonly and owned by namespace root',all(Path(p).stat().st_uid==0 and not Path(p).stat().st_mode&0o022 and any(line.split()[4]==p and 'ro' in line.split()[5].split(',') for line in mounts) for p in attestation['runtime_executable_sha256']))
        capabilities={line.split(':')[0]:line.split(':')[1].strip() for line in Path('/proc/self/status').read_text().splitlines() if line.startswith(('CapEff:','CapPrm:','CapBnd:'))}
        record('mapped-root recipient has no effective permitted or bounding capabilities',int(capabilities['CapEff'],16)==0 and int(capabilities['CapPrm'],16)==0 and int(capabilities['CapBnd'],16)==0)
        REPORT['recipient_capabilities']=capabilities
        REPORT['recipient_namespace']={'euid':os.getuid(),'uid_map':uid_map,'gid_map':gid_map,'invoker_attestation':attestation,'qualification_mode':'fresh rootless mapped-root runtime; separate real UID1000 recipient receipts remain required'}
    else:
        record('recipient is non-root',os.getuid()==1000)
    release=Path('/etc/os-release').read_text()
    record('actual Fedora 44 x86_64 recipient', 'ID=fedora' in release and 'VERSION_ID=44' in release and os.uname().machine=='x86_64')
    record('no Rust Cargo Node',all(subprocess.run(['sh','-c','command -v '+name],capture_output=True).returncode!=0 for name in ['rustc','cargo','node']))
    archive=options.old_archive
    REPORT['archive_sha256']=hashlib.sha256(archive.read_bytes()).hexdigest()
    record('exact supplied archive hash',REPORT['archive_sha256']=='fbf12375255af78ff30b042a9f9938ecccec5e03d7e8504042dac1872b0f646a')
    PACKAGE=BASE/'package'
    PACKAGE.mkdir()
    extract_package(archive,PACKAGE)
    PACKAGE=next(PACKAGE.iterdir())
    checksums=json.loads((PACKAGE/'checksums.json').read_text())
    record('all internal package checksums match',all(hashlib.sha256((PACKAGE/p).read_bytes()).hexdigest()==h for p,h in checksums.items()))
    PROJECT.mkdir(parents=True);PROFILE.mkdir();DATA.mkdir(exist_ok=True)
    run('git-init',['/usr/bin/git','init',PROJECT])
    (PROJECT/'README.md').write_text('Disposable recipient project. No product source checkout.\n')
    original_agents=b'# Recipient instructions\n\nKeep the original recipient policy.\n'
    (PROJECT/'AGENTS.md').write_bytes(original_agents)
    (PROJECT/'.codex').mkdir();original_toml='[tui]\nnotifications = false\n'
    (PROJECT/'.codex/config.toml').write_text(original_toml)
    config={'schema_version':1,'project_id':'clean-recipient','enabled':True,'panel':{'show_on_start':True},'execution':{'max_parallel':1,'default_timeout_seconds':5},'fingerprint':{'extra_inputs':[],'exclude_outputs':[]},'checks':[{'id':'check','argv':['/usr/bin/false'],'cwd':'.','kind':'test','timeout_seconds':5}], 'milestones':[{'id':'recipient','title':'Recipient qualification fixture','in_scope':True,'depends_on':[],'criteria':[{'id':'install','description':'Actual recipient check remains unapproved','check_id':'check','required':True}]}]}
    (PROJECT/'.progress-checker').mkdir();(PROJECT/'.progress-checker/config.json').write_text(json.dumps(config,indent=2)+'\n')
    original_config=(PROJECT/'.progress-checker/config.json').read_bytes()
    run('git-add',['git','-C',PROJECT,'add','.'])
    run('git-commit',['git','-C',PROJECT,'-c','user.name=Recipient','-c','user.email=recipient@example.invalid','commit','-m','Recipient fixture'])
    provider=Provider();threading.Thread(target=provider.serve_forever,daemon=True).start()
    (PROFILE/'config.toml').write_text('model = "gpt-6.1-sol"\nmodel_provider = "recipient-local"\ncheck_for_update_on_startup = false\ncli_auth_credentials_store = "file"\n[model_providers.recipient-local]\nname = "Recipient local mock"\nbase_url = "http://127.0.0.1:'+str(provider.server_port)+'/v1"\nwire_api = "responses"\nrequires_openai_auth = false\nsupports_websockets = false\nrequest_max_retries = 0\n[analytics]\nenabled = false\n[tui]\nnotifications = false\nshow_tooltips = false\nscreen_reader_detection_done = true\n[projects.'+json.dumps(str(PROJECT))+']\ntrust_level = "trusted"\n')
    common=['--project',str(PROJECT),'--codex','/usr/local/bin/codex','--codex-home',str(PROFILE),'--data-home',str(DATA)]
    version=run('codex-version',['codex','--version'])
    record('actual supported standard Codex version',version.stdout.strip()=='codex-cli 0.160.0')
    run('old-install',['python3',PACKAGE/'install.py']+common)
    REPORT['old_runtime_sha256']={name:hashlib.sha256((PACKAGE/'plugin/bin'/name).read_bytes()).hexdigest() for name in ['progress-checker','progress-checker-mcp']}
    record('install preserves existing project config bytes',(PROJECT/'.progress-checker/config.json').read_bytes()==original_config)
    managed_agents=(PROJECT/'AGENTS.md').read_bytes()
    record('old install preserves original instructions bytes',managed_agents==original_agents)
    selector='progress-checker@progress-local-'+hashlib.sha256(os.fsencode(PROJECT)).hexdigest()[:12]
    REPORT['selector']=selector
    record('global plugin disabled',tomllib.loads((PROFILE/'config.toml').read_text())['plugins'][selector]['enabled']==False)
    record('project selected plugin enabled',tomllib.loads((PROJECT/'.codex/config.toml').read_text())['plugins'][selector]['enabled']==True)
    run('old-list',['codex','plugin','list','--marketplace',selector.split('@')[1],'--json'])
    manifests=list((PROFILE/'plugins/cache').rglob('plugin.json'))
    record('actual initial cached version 0.2.0-dev',len(manifests)==1 and json.loads(manifests[0].read_text())['version']=='0.2.0-dev')
    cached=manifests[0].parent; REPORT['native_cache']=str(cached)
    record('cache launch path independent of host source',not any('/home/luis' in p.read_text(errors='replace') for p in [cached/'mcp.json', cached/'plugin.json']))
    run('backend-version',[cached/'bin/progress-checker','--version'])
    if options.namespace_mapped_root:
        preargs=json.loads((cached/'mcp.json').read_text())['mcpServers']['progress_checker']['args']
        prem=MCP(cached/'bin/checker-plugin',preargs,'pre-native')
        prem.call('checker_get_project',{})
        prem.close()
    native('native-old-install',8)
    args=json.loads((cached/'mcp.json').read_text())['mcpServers']['progress_checker']['args']
    m=MCP(cached/'bin/checker-plugin',args,'before-update')
    listed=m.send('tools/list',{})
    record('actual old packaged MCP eight tools',len(listed['tools'])==8)
    REPORT['old_tools']=[t['name'] for t in listed['tools']]
    project=m.call('checker_get_project',{})
    (OUT/'project-before-claim.json').write_text(json.dumps(project,indent=2)+'\n')
    claim=m.call('checker_set_claim',{'milestone_id':'recipient','claim':'implemented','note':'Public claim preserved through update and removal; no check was approved or executed.','expected_revision':project['revision']})
    progress=m.call('checker_get_progress',{})
    (OUT/'progress-before-update.json').write_text(json.dumps(progress,indent=2)+'\n')
    record('old service startup and claim execute no configured checks',progress['result']['status']['latest']=={})
    record('implementation claim distinct from verification',progress['result']['claims']['recipient']=='implemented' and progress['result']['status']['progress']['verified']==0)
    m.close();time.sleep(2)
    assert_no_runtime_orphans(m.label)
    before=snapshot('private-state-before-update')
    (OUT/'old-stage-ready.json').write_text(json.dumps(REPORT,indent=2)+'\n')
    final_archive=options.archive
    expected_hash=options.sha256
    record('qualification archive hash pinned',len(expected_hash)==64 and all(c in '0123456789abcdef' for c in expected_hash))
    REPORT['upgrade_archive_sha256']=hashlib.sha256(final_archive.read_bytes()).hexdigest()
    record('exact final upgrade archive hash',REPORT['upgrade_archive_sha256']==expected_hash)
    FINAL_PACKAGE=BASE/'final-package';FINAL_PACKAGE.mkdir()
    extract_package(final_archive,FINAL_PACKAGE)
    FINAL_PACKAGE=next(FINAL_PACKAGE.iterdir())
    final_checksums=json.loads((FINAL_PACKAGE/'checksums.json').read_text())
    record('all final package checksums match',all(hashlib.sha256((FINAL_PACKAGE/p).read_bytes()).hexdigest()==h for p,h in final_checksums.items()))
    record('self-contained recipient instructions',all(term.lower() in (FINAL_PACKAGE/'README.md').read_text().lower() for term in ['0.160.0','3.11','2.39','install.py install','install.py update','install.py list','install.py remove','maintained Codex fork','public']))
    record('root licensing included',all((FINAL_PACKAGE/name).is_file() and (FINAL_PACKAGE/name).stat().st_size>0 for name in ['LICENSE','NOTICE','THIRD_PARTY_NOTICES.md']))
    inventory=json.loads((FINAL_PACKAGE/'plugin/third-party/inventory.json').read_text())
    record('dependency inventory explicitly scoped',inventory['scope']=='complete_backend_cargo_lock_not_linked_binary_sbom' and inventory['external_package_count']==len(inventory['packages']) and len(inventory['packages'])>0)
    materials=[item for package in inventory['packages'] for item in package['files_sha256'].items()]
    materials+=list(inventory['rust_standard_library']['files_sha256'].items())
    record('Rust standard library legal material included',bool(inventory['rust_standard_library']['files_sha256']))
    record('every dependency has licensing material',all(package['files_sha256'] for package in inventory['packages']))
    record('all inventoried dependency license files match',all(hashlib.sha256((FINAL_PACKAGE/'plugin/third-party'/name).read_bytes()).hexdigest()==digest for name,digest in materials))
    REPORT['recipient_requirements']={'platform':'Fedora 44 Linux x86_64','codex_version':'0.160.0','python_version':sys.version.split()[0],'toolchain_installed':False,'host_mounts':bool(options.namespace_mapped_root),'host_mount_scope':('curated readonly OS runtime plus selected archive/harness inputs and fresh output; no source or host home' if options.namespace_mapped_root else 'no host filesystem mounts'),'host_source_checkout_visible':False,'host_home_visible':False,'guest_euid':os.geteuid(),'dependency_license_packages':len(inventory['packages'])}
    REPORT['new_runtime_sha256']={name:hashlib.sha256((FINAL_PACKAGE/'plugin/bin'/name).read_bytes()).hexdigest() for name in ['progress-checker','progress-checker-mcp']}
    run('upgrade',['python3',FINAL_PACKAGE/'install.py','update']+common)
    record('upgrade preserves original instructions and adds one managed block',(PROJECT/'AGENTS.md').read_bytes().startswith(original_agents) and (PROJECT/'AGENTS.md').read_bytes().count(b'<!-- progress-checker:begin -->')==1)
    record('update preserves exact project check configuration',(PROJECT/'.progress-checker/config.json').read_bytes()==original_config)
    record('update preserves private JSON state bytes',snapshot('private-state-after-update')==before)
    run('new-list',['python3',FINAL_PACKAGE/'install.py','list']+common)
    native('native-upgrade',10)
    manifests=list((PROFILE/'plugins/cache').rglob('plugin.json'));cached=manifests[0].parent
    record('updated native cached version 0.2.1-dev',len(manifests)==1 and json.loads(manifests[0].read_text())['version']=='0.2.1-dev')
    m=MCP(cached/'bin/checker-plugin',args,'after-update')
    listed=m.send('tools/list',{'_meta':{'traceparent':'00-0123456789abcdef0123456789abcdef-0123456789abcdef-01'}})
    REPORT['tools']=[t['name'] for t in listed['tools']]
    record('upgraded packaged MCP has ten tools including plan history and submission',len(listed['tools'])==10 and {'checker_submit_plan','checker_get_plan_history'}.issubset(REPORT['tools']))
    progress=m.call('checker_get_progress',{})
    record('upgraded service startup executes no configured checks',progress['result']['status']['latest']=={})
    record('update keeps actual implemented claim unverified',progress['result']['claims']['recipient']=='implemented' and progress['result']['status']['progress']['verified']==0)
    (OUT/'progress-after-update.json').write_text(json.dumps(progress,indent=2)+'\n')
    m.close();time.sleep(2)
    assert_no_runtime_orphans(m.label)
    before_remove=snapshot('private-state-before-remove')
    run('remove',['python3',FINAL_PACKAGE/'install.py','remove']+common)
    record('remove restores original instructions bytes',(PROJECT/'AGENTS.md').read_bytes()==original_agents)
    record('remove preserves project config bytes',(PROJECT/'.progress-checker/config.json').read_bytes()==original_config)
    record('remove preserves unrelated project TOML',original_toml in (PROJECT/'.codex/config.toml').read_text())
    record('remove deletes only managed plugin settings',selector not in tomllib.loads((PROFILE/'config.toml').read_text()).get('plugins',{}) and selector not in tomllib.loads((PROJECT/'.codex/config.toml').read_text()).get('plugins',{}))
    record('remove preserves private JSON state bytes',snapshot('private-state-after-remove')==before_remove)
    record('native cache removed',not list((PROFILE/'plugins/cache').rglob('plugin.json')))
    run('marketplaces-after-remove',['codex','plugin','marketplace','list','--json'])
    record('marketplace registration removed','progress-local-' not in (OUT/'marketplaces-after-remove.stdout').read_text())
    probe=run('nested-bubblewrap-probe',['bwrap','--unshare-user','--unshare-pid','--unshare-net','--ro-bind','/','/','--','/usr/bin/true'],check=False)
    REPORT['nested_sandbox']={'probe_exit_code':probe.returncode,'stderr':probe.stderr,'configured_check_executed':False}
    if probe.returncode:
        REPORT['limitations'].append(('Further nested checker execution is not qualified by this rootless mapped-root packaging fixture.' if options.namespace_mapped_root else 'Default unprivileged OCI container denies nested bubblewrap namespace creation; check execution capability is not qualified by this recipient test.'))
    REPORT['upgrade']={'from':'0.2.0-dev','to':'0.2.1-dev','initial_state_created_by':'older packaged service','prior_clients_closed':True}
    REPORT['limitations'].append('No human-approved check evidence exists in the fixture; preservation covers actual public implementation claims and private state, not passing evidence.')
    REPORT['provider_requests']=provider.requests
    record('no inference requests',not any(r['method']=='POST' for r in provider.requests))
    provider.shutdown();provider.server_close()
    REPORT['fixture_directory']=str(BASE)
    REPORT['status']='passed'
except Exception as error:
    REPORT['status']='failed';REPORT['error']=str(error);REPORT['traceback']=traceback.format_exc()
finally:
    # Graceful close releases only this fixture's clients; writers retain their
    # own safe shutdown policy. A timed out recipient must never report passed.
    for client in ACTIVE_MCP:
        try:client.close()
        except Exception as cleanup_error:
            REPORT['status']='failed'
            REPORT.setdefault('cleanup_errors',[]).append(str(cleanup_error))
    for log in DATA.rglob('*.log'):
        if log.stat().st_size <= 1024*1024:
            (OUT/('runtime-'+str(log.relative_to(DATA)).replace('/','_'))).write_bytes(log.read_bytes())
    (OUT/'report.json').write_text(json.dumps(REPORT,indent=2)+'\n')
    print(json.dumps({'report_path':str(OUT/'report.json'),'report':REPORT},indent=2),flush=True)
    sys.exit(0 if REPORT['status']=='passed' else 1)
