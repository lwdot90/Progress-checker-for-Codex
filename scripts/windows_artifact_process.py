"""Bounded native artifact inspection, not approval or a command sandbox.

Only trusted locally built executable --version probes use this adapter. A named
kill-on-close Job owns the entire process tree before its first instruction.
"""
import ctypes
from ctypes import wintypes as W
import os
import subprocess
import threading
import time
import uuid


def inspect_version(executable, timeout=10, limit=1024):
    if os.name != 'nt':
        raise OSError('Native artifact inspection requires Windows')
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    HANDLE = W.HANDLE
    SIZE = ctypes.c_size_t
    class Security(ctypes.Structure):
        _fields_ = [('size', W.DWORD), ('descriptor', ctypes.c_void_p), ('inherit', W.BOOL)]
    class Startup(ctypes.Structure):
        _fields_ = [('cb', W.DWORD), ('reserved', W.LPWSTR), ('desktop', W.LPWSTR), ('title', W.LPWSTR),
                    ('x', W.DWORD), ('y', W.DWORD), ('width', W.DWORD), ('height', W.DWORD),
                    ('chars_x', W.DWORD), ('chars_y', W.DWORD), ('fill', W.DWORD), ('flags', W.DWORD),
                    ('show', W.WORD), ('reserved_size', W.WORD), ('reserved_bytes', ctypes.c_void_p),
                    ('stdin', HANDLE), ('stdout', HANDLE), ('stderr', HANDLE)]
    class StartupEx(ctypes.Structure):
        _fields_ = [('startup', Startup), ('attributes', ctypes.c_void_p)]
    class ProcessInfo(ctypes.Structure):
        _fields_ = [('process', HANDLE), ('thread', HANDLE), ('pid', W.DWORD), ('tid', W.DWORD)]
    class BasicLimits(ctypes.Structure):
        _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64), ('flags', W.DWORD),
                    ('minimum', SIZE), ('maximum', SIZE), ('active', W.DWORD), ('affinity', SIZE),
                    ('priority', W.DWORD), ('scheduling', W.DWORD)]
    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in ('reads', 'writes', 'others', 'read_bytes', 'write_bytes', 'other_bytes')]
    class ExtendedLimits(ctypes.Structure):
        _fields_ = [('basic', BasicLimits), ('io', IoCounters), ('process_memory', SIZE), ('job_memory', SIZE), ('peak_process', SIZE), ('peak_job', SIZE)]
    signatures = {
        'CreateJobObjectW': ([ctypes.c_void_p, W.LPCWSTR], HANDLE),
        'SetInformationJobObject': ([HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD], W.BOOL),
        'CreatePipe': ([ctypes.POINTER(HANDLE), ctypes.POINTER(HANDLE), ctypes.POINTER(Security), W.DWORD], W.BOOL),
        'SetHandleInformation': ([HANDLE, W.DWORD, W.DWORD], W.BOOL),
        'InitializeProcThreadAttributeList': ([ctypes.c_void_p, W.DWORD, W.DWORD, ctypes.POINTER(SIZE)], W.BOOL),
        'UpdateProcThreadAttribute': ([ctypes.c_void_p, W.DWORD, SIZE, ctypes.c_void_p, SIZE, ctypes.c_void_p, ctypes.c_void_p], W.BOOL),
        'DeleteProcThreadAttributeList': ([ctypes.c_void_p], None),
        'CreateProcessW': ([W.LPCWSTR, W.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, W.BOOL, W.DWORD, ctypes.c_void_p, W.LPCWSTR, ctypes.POINTER(StartupEx), ctypes.POINTER(ProcessInfo)], W.BOOL),
        'AssignProcessToJobObject': ([HANDLE, HANDLE], W.BOOL),
        'ResumeThread': ([HANDLE], W.DWORD),
        'WaitForSingleObject': ([HANDLE, W.DWORD], W.DWORD),
        'GetExitCodeProcess': ([HANDLE, ctypes.POINTER(W.DWORD)], W.BOOL),
        'TerminateJobObject': ([HANDLE, W.UINT], W.BOOL),
        'TerminateProcess': ([HANDLE, W.UINT], W.BOOL),
        'ReadFile': ([HANDLE, ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.DWORD), ctypes.c_void_p], W.BOOL),
        'CloseHandle': ([HANDLE], W.BOOL),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(k, name); function.argtypes = arguments; function.restype = result
    def require(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
    handles = []
    job = k.CreateJobObjectW(None, 'Local\\ProgressCheckerArtifact-' + uuid.uuid4().hex)
    require(job); handles.append(job)
    process = ProcessInfo(); attributes = None; attributes_ready = False; reader = None; assigned = False
    try:
        limits = ExtendedLimits(); limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE; no breakaway.
        require(k.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
        read, write = HANDLE(), HANDLE()
        security = Security(ctypes.sizeof(Security), None, True)
        require(k.CreatePipe(ctypes.byref(read), ctypes.byref(write), ctypes.byref(security), 4096))
        handles.extend([read.value, write.value]); require(k.SetHandleInformation(read, 1, 0))
        size = SIZE()
        k.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        if not size.value or size.value > 65536:
            raise OSError('Invalid Windows handle-list size')
        attributes = ctypes.create_string_buffer(size.value)
        require(k.InitializeProcThreadAttributeList(attributes, 1, 0, ctypes.byref(size)))
        attributes_ready = True
        allowed = (HANDLE * 1)(write.value)
        require(k.UpdateProcThreadAttribute(attributes, 0, 0x20002, allowed, ctypes.sizeof(allowed), None, None))
        startup = StartupEx(); startup.startup.cb = ctypes.sizeof(startup)
        startup.startup.flags = 0x100; startup.startup.stdout = write; startup.startup.stderr = write
        startup.startup.stdin = None; startup.attributes = ctypes.cast(attributes, ctypes.c_void_p)
        application = os.path.abspath(executable)
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline([application, '--version']))
        require(k.CreateProcessW(application, command, None, None, True, 0x4 | 0x80000 | 0x8000000,
                                 None, os.path.dirname(application), ctypes.byref(startup), ctypes.byref(process)))
        handles.extend([process.process, process.thread])
        require(k.AssignProcessToJobObject(job, process.process)); assigned = True
        if k.ResumeThread(process.thread) != 1:
            raise OSError('Artifact inspection suspension invariant violated')
        require(k.CloseHandle(write)); handles.remove(write.value)
        data = bytearray(); errors = []; overflow = threading.Event()
        def drain():
            while True:
                buffer = ctypes.create_string_buffer(4096); count = W.DWORD()
                if not k.ReadFile(read, buffer, len(buffer), ctypes.byref(count), None):
                    error = ctypes.get_last_error()
                    if error != 109:
                        errors.append(error)
                    return
                if not count.value:
                    return
                if len(data) + count.value > limit:
                    overflow.set(); return
                data.extend(buffer.raw[:count.value])
        reader = threading.Thread(target=drain, daemon=True); reader.start()
        deadline = time.monotonic() + timeout
        while True:
            waited = k.WaitForSingleObject(process.process, 25)
            if waited == 0:
                break
            if waited != 258:
                raise OSError('Artifact process wait failed')
            if overflow.is_set() or time.monotonic() >= deadline:
                raise OSError('Artifact version exceeded output or time bound')
        code = W.DWORD(); require(k.GetExitCodeProcess(process.process, ctypes.byref(code)))
        # A successful parent cannot leave descendants holding inherited output.
        require(k.TerminateJobObject(job, 1))
        reader.join(max(0, deadline - time.monotonic()))
        if reader.is_alive() or overflow.is_set() or errors or code.value:
            raise OSError('Artifact version failed bounded completion')
        return bytes(data).decode('utf-8')
    finally:
        if assigned:
            k.TerminateJobObject(job, 1)
        elif process.process:
            k.TerminateProcess(process.process, 1)  # Never-resumed setup failure.
        if process.process:
            k.WaitForSingleObject(process.process, 5000)
        if reader:
            reader.join(1)
        if attributes_ready:
            k.DeleteProcThreadAttributeList(attributes)
        for handle in reversed(handles):
            k.CloseHandle(handle)
