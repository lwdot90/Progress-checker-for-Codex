//! Experimental native process lifetime primitives. Not an execution sandbox.
//!
//! These primitives must remain disconnected from production execution until the
//! AppContainer/ACL policy is implemented and qualified. A Job Object does not
//! prevent filesystem/network access or broker-created descendants. This module
//! deliberately has no general-purpose spawn function or fallback.
//! APIs: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
//! https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject
//! https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread

#[cfg(not(target_os = "windows"))]
pub fn unavailable() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Win32 process primitives require native Windows",
    )
}

#[cfg(target_os = "windows")]
pub use native::{AssignedProcess, GuardedProcess, PreparedWindowsLaunch, SuspendedProcess};

#[cfg(target_os = "windows")]
mod native {
    use super::super::windows_arguments::WindowsArguments;
    use super::super::windows_inventory::RuntimeManifest;
    use super::super::windows_token::LpacAttributes;
    use super::super::windows_trust::InstallationTrustGuard;
    use std::ffi::c_void;
    use std::io;
    use std::mem::{ManuallyDrop, size_of, zeroed};
    use std::os::windows::io::{AsRawHandle, OwnedHandle as StdOwnedHandle};
    use std::ptr::null;
    use std::time::{Duration, Instant};

    type Handle = *mut c_void;
    const KILL_ON_CLOSE: u32 = 0x00002000;
    const EXTENDED_LIMIT_INFORMATION: i32 = 9;
    const BASIC_ACCOUNTING_INFORMATION: i32 = 1;
    const INHERIT: u32 = 1;

    #[repr(C)]
    struct StartupInfo {
        cb: u32,
        reserved: *mut u16,
        desktop: *mut u16,
        title: *mut u16,
        x: u32,
        y: u32,
        x_size: u32,
        y_size: u32,
        x_chars: u32,
        y_chars: u32,
        fill_attribute: u32,
        flags: u32,
        show_window: u16,
        reserved_size: u16,
        reserved_bytes: *mut u8,
        stdin: Handle,
        stdout: Handle,
        stderr: Handle,
    }
    #[repr(C)]
    struct StartupInfoEx {
        startup: StartupInfo,
        attributes: *mut c_void,
    }
    #[repr(C)]
    struct ProcessInformation {
        process: Handle,
        thread: Handle,
        process_id: u32,
        thread_id: u32,
    }

    #[repr(C)]
    struct BasicLimits {
        process_user_time: i64,
        job_user_time: i64,
        flags: u32,
        minimum_working_set: usize,
        maximum_working_set: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }
    #[repr(C)]
    struct IoCounters {
        read_ops: u64,
        write_ops: u64,
        other_ops: u64,
        read_bytes: u64,
        write_bytes: u64,
        other_bytes: u64,
    }
    #[repr(C)]
    struct ExtendedLimits {
        basic: BasicLimits,
        io: IoCounters,
        process_memory: usize,
        job_memory: usize,
        peak_process_memory: usize,
        peak_job_memory: usize,
    }
    #[repr(C)]
    struct Accounting {
        user_time: i64,
        kernel_time: i64,
        period_user_time: i64,
        period_kernel_time: i64,
        page_faults: u32,
        total_processes: u32,
        active_processes: u32,
        terminated_processes: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(job: Handle, class: i32, info: *const c_void, len: u32) -> i32;
        fn QueryInformationJobObject(
            job: Handle,
            class: i32,
            info: *mut c_void,
            len: u32,
            returned: *mut u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn TerminateJobObject(job: Handle, code: u32) -> i32;
        fn TerminateProcess(process: Handle, code: u32) -> i32;
        fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> i32;
        fn ResumeThread(thread: Handle) -> u32;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        fn CreateProcessW(
            application: *const u16,
            command: *mut u16,
            process_security: *const c_void,
            thread_security: *const c_void,
            inherit: i32,
            flags: u32,
            environment: *const c_void,
            cwd: *const u16,
            startup: *mut StartupInfo,
            process: *mut ProcessInformation,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    struct OwnedHandle(Handle);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    struct Job(OwnedHandle);

    /// Unforgeable preparation boundary. Fields are private; the current factory
    /// always fails because project ACL, broker, and approval validation is not
    /// implemented/qualified. No caller can launch by supplying capability flags.
    pub struct PreparedWindowsLaunch {
        arguments: WindowsArguments,
        environment: Vec<u16>,
        cwd: Vec<u16>,
        stdio: Option<[StdOwnedHandle; 3]>,
        token: LpacAttributes,
        trust: Vec<InstallationTrustGuard>,
        runtime: RuntimeManifest,
    }
    impl PreparedWindowsLaunch {
        pub fn prepare() -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native project ACL/broker/approval preparation is not implemented or qualified",
            ))
        }

        /// Code path is intentionally unreachable through the unavailable
        /// preparation factory. Security preparation must be implemented first.
        pub fn launch(mut self) -> io::Result<GuardedProcess> {
            for guard in &self.trust {
                guard.revalidate().map_err(io::Error::other)?;
            }
            self.runtime.revalidate().map_err(io::Error::other)?;
            if self.trust.is_empty()
                || self.token.network_capability_count() != 0
                || !self.environment.ends_with(&[0, 0])
                || self.cwd.last() != Some(&0)
                || self.arguments.application.last() != Some(&0)
                || self.arguments.command_line.last() != Some(&0)
            {
                return Err(io::Error::other(
                    "prepared Windows security contract is invalid",
                ));
            }
            let stdio = self
                .stdio
                .as_ref()
                .ok_or_else(|| io::Error::other("prepared stdio handles are missing"))?;
            let handles = stdio.each_ref().map(|h| h.as_raw_handle());
            unsafe {
                self.token.set_stdio_handles(handles)?;
            }
            let mut info: StartupInfoEx = unsafe { zeroed() };
            info.startup.cb = size_of::<StartupInfoEx>() as u32;
            info.startup.flags = 0x100; // STARTF_USESTDHANDLES
            info.startup.stdin = handles[0];
            info.startup.stdout = handles[1];
            info.startup.stderr = handles[2];
            info.attributes = self.token.as_ptr();
            let mut child: ProcessInformation = unsafe { zeroed() };
            // CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT |
            // EXTENDED_STARTUPINFO_PRESENT. No shell and no PATH resolution;
            // inherit TRUE is restricted by the SAME list's HANDLE_LIST.
            if unsafe {
                CreateProcessW(
                    self.arguments.application.as_ptr(),
                    self.arguments.command_line.as_mut_ptr(),
                    null(),
                    null(),
                    1,
                    0x4 | 0x400 | 0x80000,
                    self.environment.as_ptr().cast(),
                    self.cwd.as_ptr(),
                    &mut info.startup,
                    &mut child,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            // Parent copies of child pipe ends must close after creation or EOF
            // can never reach the separately retained log readers.
            drop(self.stdio.take());
            let suspended = unsafe { SuspendedProcess::adopt(child.process, child.thread)? };
            let process = suspended.assign_and_resume()?;
            Ok(GuardedProcess {
                process,
                security: ManuallyDrop::new(self),
            })
        }
    }

    /// Keeps immutable-runtime/trust handles and LPAC/stdio backing alive until
    /// after process termination. Must not be interpreted as verified support.
    pub struct GuardedProcess {
        process: AssignedProcess,
        security: ManuallyDrop<PreparedWindowsLaunch>,
    }
    impl GuardedProcess {
        pub fn terminate_and_drain(&self, timeout: Duration) -> io::Result<()> {
            let _ = &self.security;
            self.process.terminate_and_drain(timeout)
        }
    }
    impl Drop for GuardedProcess {
        fn drop(&mut self) {
            // Never unlock immutable-runtime/security guards merely because the
            // root process exited: all job members must have terminated first.
            if self
                .process
                .terminate_and_drain(Duration::from_secs(5))
                .is_ok()
            {
                unsafe {
                    ManuallyDrop::drop(&mut self.security);
                }
            }
            // On failed confirmation deliberately retain the security leases
            // until this host process exits. AssignedProcess still drops below
            // and issues final termination/kill-on-close. A future production
            // caller must return Unknown and stop accepting new work on cleanup
            // failure; this retention is not passing evidence or qualification.
        }
    }
    impl Job {
        fn create() -> io::Result<Self> {
            // Anonymous and non-inheritable: sandbox code cannot open this job by
            // name or retain a handle that suppresses kill-on-close.
            let raw = unsafe { CreateJobObjectW(null(), null()) };
            if raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = Self(OwnedHandle(raw));
            if unsafe { SetHandleInformation(raw, INHERIT, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut limits: ExtendedLimits = unsafe { zeroed() };
            // Setting exactly KILL_ON_CLOSE leaves both BREAKAWAY flags absent.
            limits.basic.flags = KILL_ON_CLOSE;
            if unsafe {
                SetInformationJobObject(
                    raw,
                    EXTENDED_LIMIT_INFORMATION,
                    (&limits as *const ExtendedLimits).cast(),
                    size_of::<ExtendedLimits>() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        fn terminate_and_drain(&self, timeout: Duration) -> io::Result<()> {
            if unsafe { TerminateJobObject(self.0.0, 1) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "termination timeout exceeds platform limit",
                )
            })?;
            loop {
                let mut info: Accounting = unsafe { zeroed() };
                let mut returned = 0;
                if unsafe {
                    QueryInformationJobObject(
                        self.0.0,
                        BASIC_ACCOUNTING_INFORMATION,
                        (&mut info as *mut Accounting).cast(),
                        size_of::<Accounting>() as u32,
                        &mut returned,
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                if returned != size_of::<Accounting>() as u32 {
                    return Err(io::Error::other("unexpected Windows job accounting size"));
                }
                if info.active_processes == 0 {
                    return Ok(());
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "job descendants did not terminate within deadline",
                    ));
                }
                std::thread::sleep(remaining.min(Duration::from_millis(10)));
            }
        }
    }

    /// Owns a newly created child whose primary thread has never run.
    pub struct SuspendedProcess {
        process: OwnedHandle,
        thread: OwnedHandle,
    }
    impl SuspendedProcess {
        /// Adopt handles from a successful restricted `CreateProcessW` call.
        ///
        /// # Safety
        /// Both handles must be distinct, valid, exclusively owned handles from
        /// the same newly created process, created with CREATE_SUSPENDED. The
        /// caller must enforce AppContainer, ACL, approved argv/environment/cwd,
        /// restricted inherited handles, and executable identity BEFORE creation.
        /// Neither handle may subsequently be used or closed by the caller.
        /// Exception: syntactically invalid handles are rejected before adoption,
        /// and the caller retains ownership of BOTH handles on that error. Once
        /// validation succeeds, ownership transfers even if later setup fails.
        pub unsafe fn adopt(process: Handle, thread: Handle) -> io::Result<Self> {
            if process.is_null()
                || thread.is_null()
                || process == (-1isize) as Handle
                || thread == (-1isize) as Handle
                || process == thread
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid suspended process handles",
                ));
            }
            let owned = Self {
                process: OwnedHandle(process),
                thread: OwnedHandle(thread),
            };
            // Explicitly erase inheritance even if the creation adapter erred.
            if unsafe { SetHandleInformation(process, INHERIT, 0) } == 0
                || unsafe { SetHandleInformation(thread, INHERIT, 0) } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(owned)
        }

        /// No instruction runs before job assignment succeeds. On any failure,
        /// owned handles terminate the child and close; no uncontained fallback.
        pub fn assign_and_resume(self) -> io::Result<AssignedProcess> {
            let job = Job::create()?;
            if unsafe { AssignProcessToJobObject(job.0.0, self.process.0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let previous = unsafe { ResumeThread(self.thread.0) };
            if previous != 1 {
                // Zero means a violated suspension invariant; >1 means still
                // suspended. Neither permits continuing as a valid launch.
                return Err(if previous == u32::MAX {
                    io::Error::last_os_error()
                } else {
                    io::Error::other("unexpected initial thread suspension count")
                });
            }
            Ok(AssignedProcess { child: self, job })
        }

        /// Confirm this child has exited after termination. Before assignment
        /// the never-run invariant ensures it cannot yet have descendants.
        pub fn terminate_and_wait(&self, timeout: Duration) -> io::Result<()> {
            let millis = u32::try_from(timeout.as_millis())
                .ok()
                .filter(|value| *value != u32::MAX)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "finite termination timeout required",
                    )
                })?;
            // TerminateProcess can fail if already exited; still inspect its
            // signaled process handle before treating that as cleanup failure.
            let terminated = unsafe { TerminateProcess(self.process.0, 1) };
            let termination_error = (terminated == 0).then(io::Error::last_os_error);
            match unsafe { WaitForSingleObject(self.process.0, millis) } {
                0 => Ok(()),
                258 => Err(termination_error.unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "child termination was not confirmed within deadline",
                    )
                })),
                u32::MAX => Err(io::Error::last_os_error()),
                _ => Err(io::Error::other("unexpected process wait result")),
            }
        }
    }
    impl Drop for SuspendedProcess {
        fn drop(&mut self) {
            // Best-effort bounded wait even on pre-assignment setup failure.
            // Destructors cannot report failure: callers must use explicit drain
            // before claiming confirmed cleanup. No infinite wait on a bad OS.
            let _ = self.terminate_and_wait(Duration::from_secs(5));
        }
    }

    /// Lifetime owner of the process and its non-breakaway job. Never evidence of
    /// filesystem/network isolation. Not Send/Sync; raw handles remain private.
    pub struct AssignedProcess {
        child: SuspendedProcess,
        job: Job,
    }
    impl AssignedProcess {
        /// Explicit termination confirms all job members exited. Caller must
        /// separately drain bounded logs and distinguish normal exit/cancellation.
        pub fn terminate_and_drain(&self, timeout: Duration) -> io::Result<()> {
            self.job.terminate_and_drain(timeout)
        }
    }
    impl Drop for AssignedProcess {
        fn drop(&mut self) {
            // Final kill-on-close remains effective even if explicit termination
            // fails. Drop does not claim that asynchronous termination completed.
            unsafe {
                TerminateJobObject(self.job.0.0, 1);
            }
            let _ = &self.child;
        }
    }
}
