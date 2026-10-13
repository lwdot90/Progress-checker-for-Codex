<# Native prebuilt artifact diagnostics only. No installer, Rust, Python or approval. #>
[CmdletBinding()]
param([string]$Output = (Join-Path $PSScriptRoot 'windows-diagnostics.json'))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Native Windows is required.' }
$root = $PSScriptRoot
$manifest = Get-Content -LiteralPath (Join-Path $root 'artifact-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.source_commit -notmatch '^[a-fA-F0-9]{40}$' -or
    $manifest.cargo_lock_sha256 -notmatch '^[a-fA-F0-9]{64}$' -or
    $manifest.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+[-.A-Za-z0-9]*$') { throw 'Invalid source provenance manifest.' }
# This local helper launches only three checksum-pinned --version probes, suspended
# until assigned to a non-breakaway kill-on-close Job. It is not a check sandbox.
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
public static class ProgressCheckerArtifactProbe {
 [StructLayout(LayoutKind.Sequential)] struct SECURITY { public int size; public IntPtr descriptor; public int inherit; }
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct STARTUP {
  public int cb; public IntPtr reserved, desktop, title; public uint x,y,width,height,charsX,charsY,fill,flags;
  public ushort show,reservedSize; public IntPtr reservedBytes,stdin,stdout,stderr;
 }
 [StructLayout(LayoutKind.Sequential)] struct STARTUP_EX { public STARTUP startup; public IntPtr attributes; }
 [StructLayout(LayoutKind.Sequential)] struct PROCESS { public IntPtr process,thread; public uint pid,tid; }
 [StructLayout(LayoutKind.Sequential)] struct BASIC_LIMITS { public long processTime,jobTime; public uint flags; public UIntPtr minimum,maximum; public uint active; public UIntPtr affinity; public uint priority,scheduling; }
 [StructLayout(LayoutKind.Sequential)] struct IO { public ulong reads,writes,others,readBytes,writeBytes,otherBytes; }
 [StructLayout(LayoutKind.Sequential)] struct EXTENDED { public BASIC_LIMITS basic; public IO io; public UIntPtr processMemory,jobMemory,peakProcess,peakJob; }
 [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
 [DllImport("kernel32",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int type,ref EXTENDED limits,uint bytes);
 [DllImport("kernel32",SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref SECURITY attributes,uint size);
 [DllImport("kernel32",SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
 [DllImport("kernel32",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,uint count,uint flags,ref UIntPtr bytes);
 [DllImport("kernel32",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,UIntPtr attribute,IntPtr value,UIntPtr size,IntPtr previous,IntPtr returned);
 [DllImport("kernel32")] static extern void DeleteProcThreadAttributeList(IntPtr list);
 [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string application,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string directory,ref STARTUP_EX startup,out PROCESS process);
 [DllImport("kernel32",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
 [DllImport("kernel32",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr handle,out uint code);
 [DllImport("kernel32",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
 [DllImport("kernel32",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
 [DllImport("kernel32",SetLastError=true)] static extern bool ReadFile(IntPtr handle,byte[] bytes,uint count,out uint read,IntPtr overlapped);
 [StructLayout(LayoutKind.Sequential)] struct FILE_INFO { public uint attributes; public System.Runtime.InteropServices.ComTypes.FILETIME creation,access,write; public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow; }
 [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string path,uint access,uint sharing,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr file,out FILE_INFO information);
 [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetWindowsDirectory(StringBuilder path,uint length);
 [DllImport("kernel32",SetLastError=true)] static extern uint GetCurrentThreadId();
 [DllImport("kernel32",SetLastError=true)] static extern IntPtr OpenThread(uint access,bool inherit,uint id);
 [DllImport("kernel32",SetLastError=true)] static extern bool CancelSynchronousIo(IntPtr thread);
 [StructLayout(LayoutKind.Sequential)] struct JOB_ACCOUNTING { public long userTime,kernelTime,periodUserTime,periodKernelTime; public uint pageFaults,totalProcesses,activeProcesses,totalTerminatedProcesses; }
 [DllImport("kernel32",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int type,out JOB_ACCOUNTING accounting,uint size,IntPtr returned);
 [DllImport("kernel32",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
 sealed class Capture { public List<byte> bytes=new List<byte>(); public volatile bool overflow; public volatile bool failed; public volatile bool stop; public volatile uint threadId; }
 static void Check(bool ok) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
 static void PinImage(string application,string expected,List<IntPtr> guards) {
  string canonical=Path.GetFullPath(application);
  if(canonical.StartsWith(@"\\")) throw new Exception("Remote/device image paths unsupported");
  List<string> parents=new List<string>(); string parent=Path.GetDirectoryName(canonical);
  while(!String.IsNullOrEmpty(parent)) { parents.Add(parent); string next=Path.GetDirectoryName(parent); if(next==parent) break; parent=next; }
  parents.Reverse();
  foreach(string directory in parents) {
   IntPtr handle=CreateFile(directory,0x80,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
   if(handle==new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error()); guards.Add(handle);
   FILE_INFO info; Check(GetFileInformationByHandle(handle,out info)); if((info.attributes&0x400)!=0) throw new Exception("Reparse ancestor unsupported");
  }
  IntPtr image=CreateFile(canonical,0x80000000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
  if(image==new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error()); guards.Add(image);
  FILE_INFO imageInfo; Check(GetFileInformationByHandle(image,out imageInfo)); if((imageInfo.attributes&0x410)!=0) throw new Exception("Reparse/nonfile image unsupported");
  using(SafeFileHandle wrapper=new SafeFileHandle(image,false))
  using(FileStream stream=new FileStream(wrapper,FileAccess.Read))
  using(SHA256 hash=SHA256.Create()) {
   if(stream.Length>256L*1024*1024) throw new Exception("Image size exceeded");
   string actual=BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();
   if(!String.Equals(actual,expected,StringComparison.OrdinalIgnoreCase)) throw new Exception("Pinned image checksum mismatch");
  }
 }
 static bool DrainJob(IntPtr job) {
  if(!TerminateJobObject(job,1)) return false;
  System.Diagnostics.Stopwatch retirement=System.Diagnostics.Stopwatch.StartNew();
  while(retirement.ElapsedMilliseconds<5000) {
   JOB_ACCOUNTING accounting;
   if(!QueryInformationJobObject(job,1,out accounting,(uint)Marshal.SizeOf(typeof(JOB_ACCOUNTING)),IntPtr.Zero)) return false;
   if(accounting.activeProcesses==0) return true;
   Thread.Sleep(25);
  }
  return false;
 }
 public static string Version(string application,string expectedHash) {
  if(application.IndexOf('"')>=0) throw new ArgumentException("Invalid executable path");
  IntPtr job=IntPtr.Zero,read=IntPtr.Zero,write=IntPtr.Zero,attributes=IntPtr.Zero,allowed=IntPtr.Zero,nul=IntPtr.Zero,environment=IntPtr.Zero;
  List<IntPtr> imageGuards=new List<IntPtr>();
  PROCESS process=new PROCESS(); bool assigned=false,initialized=false; Thread reader=null;
  Capture capture=new Capture();
  try {
   PinImage(application,expectedHash,imageGuards);
   job=CreateJobObject(IntPtr.Zero,"Local\\ProgressCheckerArtifact-"+Guid.NewGuid().ToString("N")); Check(job!=IntPtr.Zero);
   EXTENDED limits=new EXTENDED(); limits.basic.flags=0x2000; Check(SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(EXTENDED))));
   SECURITY security=new SECURITY(); security.size=Marshal.SizeOf(typeof(SECURITY)); security.inherit=1;
   Check(CreatePipe(out read,out write,ref security,4096)); Check(SetHandleInformation(read,1,0));
   UIntPtr size=UIntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);
   if(size.ToUInt64()==0 || size.ToUInt64()>65536) throw new Exception("Attribute bound exceeded");
   attributes=Marshal.AllocHGlobal((int)size.ToUInt64()); Check(InitializeProcThreadAttributeList(attributes,1,0,ref size)); initialized=true;
   nul=CreateFile("NUL",0x80000000,1|2,IntPtr.Zero,3,0,IntPtr.Zero);
   if(nul==new IntPtr(-1)) { nul=IntPtr.Zero; throw new Win32Exception(Marshal.GetLastWin32Error()); }
   Check(SetHandleInformation(nul,1,1));
   allowed=Marshal.AllocHGlobal(IntPtr.Size*2); Marshal.WriteIntPtr(allowed,write); Marshal.WriteIntPtr(allowed,IntPtr.Size,nul);
   Check(UpdateProcThreadAttribute(attributes,0,new UIntPtr(0x20002),allowed,new UIntPtr((uint)(IntPtr.Size*2)),IntPtr.Zero,IntPtr.Zero));
   STARTUP_EX startup=new STARTUP_EX(); startup.startup.cb=Marshal.SizeOf(typeof(STARTUP_EX)); startup.startup.flags=0x100;
   startup.startup.stdin=nul; startup.startup.stdout=write; startup.startup.stderr=write; startup.attributes=attributes;
   StringBuilder windows=new StringBuilder(32768); uint windowsLength=GetWindowsDirectory(windows,(uint)windows.Capacity);
   if(windowsLength==0 || windowsLength>=windows.Capacity) throw new Exception("Windows directory unavailable");
   string system=windows.ToString(); environment=Marshal.StringToHGlobalUni("PATH="+system+"\\System32\0SystemRoot="+system+"\0WINDIR="+system+"\0\0");
   Check(CreateProcess(application,new StringBuilder("\""+application+"\" --version"),IntPtr.Zero,IntPtr.Zero,true,0x4|0x80000|0x8000000|0x400,environment,System.IO.Path.GetDirectoryName(application),ref startup,out process));
   Check(AssignProcessToJobObject(job,process.process)); assigned=true;
   if(ResumeThread(process.thread)!=1) throw new Exception("Suspension invariant failed");
   Check(CloseHandle(write)); write=IntPtr.Zero;
   IntPtr pipe=read;
   reader=new Thread(delegate() {
    capture.threadId=GetCurrentThreadId();
    byte[] buffer=new byte[4096]; uint count;
    while(!capture.stop) {
     if(!ReadFile(pipe,buffer,(uint)buffer.Length,out count,IntPtr.Zero)) { if(Marshal.GetLastWin32Error()!=109) capture.failed=true; return; }
     if(count==0) return;
     if(capture.bytes.Count+count>1024) { capture.overflow=true; return; }
     for(int index=0;index<(int)count;index++) capture.bytes.Add(buffer[index]);
    }
   }); reader.IsBackground=true; reader.Start();
   System.Diagnostics.Stopwatch clock=System.Diagnostics.Stopwatch.StartNew();
   while(true) {
    uint waited=WaitForSingleObject(process.process,25);
    if(waited==0) break;
    if(waited!=258 || capture.overflow || clock.ElapsedMilliseconds>=10000) throw new Exception("Probe deadline/output exceeded");
   }
   uint exit; Check(GetExitCodeProcess(process.process,out exit));
   if(!DrainJob(job)) throw new Exception("Artifact process tree retirement unconfirmed");
   if(!reader.Join(1000) || capture.overflow || capture.failed || exit!=0) throw new Exception("Probe completion failed");
   return new UTF8Encoding(false,true).GetString(capture.bytes.ToArray()).Trim();
  } finally {
   if(assigned) { if(!DrainJob(job)) Environment.FailFast("Artifact process tree retirement could not be confirmed"); }
   else if(process.process!=IntPtr.Zero) TerminateProcess(process.process,1);
   if(process.process!=IntPtr.Zero && WaitForSingleObject(process.process,5000)!=0) Environment.FailFast("Artifact process termination could not be confirmed");
   // Stop further reads, then cancel the specific native reader thread repeatedly.
   // Do not close/reuse its pipe handle unless retirement is confirmed.
   capture.stop=true;
   if(write!=IntPtr.Zero) { CloseHandle(write); write=IntPtr.Zero; }
   if(reader!=null && !reader.Join(100)) {
    IntPtr nativeThread=capture.threadId==0 ? IntPtr.Zero : OpenThread(1,false,capture.threadId);
    try {
     System.Diagnostics.Stopwatch retirement=System.Diagnostics.Stopwatch.StartNew();
     while(reader.IsAlive && retirement.ElapsedMilliseconds<5000) {
      if(nativeThread==IntPtr.Zero && capture.threadId!=0) nativeThread=OpenThread(1,false,capture.threadId);
      if(nativeThread!=IntPtr.Zero) CancelSynchronousIo(nativeThread);
      reader.Join(50);
     }
     if(reader.IsAlive) Environment.FailFast("Artifact probe reader could not retire; aborting before handle reuse");
    } finally { if(nativeThread!=IntPtr.Zero) CloseHandle(nativeThread); }
   }
   if(initialized) DeleteProcThreadAttributeList(attributes);
   if(attributes!=IntPtr.Zero) Marshal.FreeHGlobal(attributes);
   if(allowed!=IntPtr.Zero) Marshal.FreeHGlobal(allowed);
   if(environment!=IntPtr.Zero) Marshal.FreeHGlobal(environment);
   if(nul!=IntPtr.Zero) CloseHandle(nul);
   if(process.thread!=IntPtr.Zero) CloseHandle(process.thread);
   if(process.process!=IntPtr.Zero) CloseHandle(process.process);
   if(write!=IntPtr.Zero) CloseHandle(write);
   if(read!=IntPtr.Zero) CloseHandle(read);
   if(job!=IntPtr.Zero) CloseHandle(job);
   for(int index=imageGuards.Count-1;index>=0;index--) CloseHandle(imageGuards[index]);
  }
 }
}
'@
$binaries = @()
foreach ($name in @('progress-checker', 'progress-checker-mcp', 'checker-global')) {
    $relative = 'bin/' + $name + '.exe'
    $path = Join-Path $root $relative
    $expected = $manifest.files.PSObject.Properties[$relative]
    if (-not $expected -or $expected.Value -notmatch '^[a-fA-F0-9]{64}$') { throw 'Missing artifact checksum.' }
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint -or $item.Length -gt 256MB) { throw 'Unsafe artifact file.' }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected.Value) { throw 'Artifact checksum mismatch; no probe launched.' }
    $status = 'failed; details withheld'; $version = $null
    try {
        $candidate = [ProgressCheckerArtifactProbe]::Version([IO.Path]::GetFullPath($path), $expected.Value)
        if ($candidate -ceq ($name + ' ' + $manifest.version)) { $version = $candidate; $status = 'passed' }
        else { $status = 'unexpected output withheld' }
    } catch { $status = 'failed; details withheld' }
    $binaries += [pscustomobject]@{ name=$name; sha256=$actual; version=$version; version_probe=$status }
}
$receipt = [ordered]@{ schema_version=1; source_commit=$manifest.source_commit; cargo_lock_sha256=$manifest.cargo_lock_sha256;
    windows_version=[Environment]::OSVersion.Version.ToString(); process_64_bit=[Environment]::Is64BitProcess;
    os_64_bit=[Environment]::Is64BitOperatingSystem; binaries=$binaries; qualified=$false;
    installation_executed=$false; approvals_executed=$false; checks_executed=$false;
    blocked_expected=@('native activation backend','qualified approval authority','native sandbox execution','qualified installation/update');
    collection='OS metadata and pinned artifact version/hash only; no home/config/private logs/environment dump' }
$destination = [IO.Path]::GetFullPath($Output)
$bytes = [Text.Encoding]::UTF8.GetBytes(($receipt | ConvertTo-Json -Depth 6))
$stream = [IO.File]::Open($destination,[IO.FileMode]::CreateNew)
try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
Write-Output 'Saved diagnostics. Review the JSON before sharing it; do not share terminal transcripts or environment dumps.'
