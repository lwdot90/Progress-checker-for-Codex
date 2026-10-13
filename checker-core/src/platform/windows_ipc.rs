//! Native Windows pipe peer lifetime observation.
//!
//! This primitive is deliberately insufficient to authorize approval. A peer
//! process handle proves a process lifetime, not a human terminal or trusted
//! executable. The native approval route must remain disabled until the token,
//! executable, console and private-state checks are implemented and qualified.

/// The Windows approval transport is not qualified yet.
pub fn require_qualified_approval_transport() -> Result<(), String> {
    Err(
        "APPROVAL_PEER_REQUIRED: native Windows human-terminal authentication is not qualified"
            .into(),
    )
}

#[cfg(windows)]
mod native {
    use super::super::windows_ffi::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, CreateFileW,
        GetCurrentProcess, GetCurrentThread, GetFileInformationByHandle, GetTokenInformation,
        Handle, IsValidSid, LocalFree, OpenProcessToken, ReadFile, SecurityAttributes, WriteFile,
    };
    use super::super::windows_trust::InstallationTrustGuard;
    use sha2::{Digest, Sha256};
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::io::{AsRawHandle, OwnedHandle, RawHandle};
    use std::path::{Path, PathBuf};

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const WAIT_TIMEOUT: u32 = 258;
    const TOKEN_QUERY: u32 = 8;
    const ERROR_IO_PENDING: i32 = 997;
    const ERROR_PIPE_CONNECTED: i32 = 535;
    const MAX_FRAME_BYTES: usize = 1024 * 1024;

    #[repr(C)]
    #[derive(Default)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: Handle,
    }

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }
    #[repr(C)]
    struct TokenGroupsOne {
        count: u32,
        first: SidAndAttributes,
    }

    const _: () = {
        assert!(std::mem::offset_of!(TokenGroupsOne, first) == std::mem::size_of::<usize>());
        assert!(
            std::mem::size_of::<Overlapped>()
                == 4 * std::mem::size_of::<usize>()
                    + if std::mem::size_of::<usize>() == 4 {
                        4
                    } else {
                        0
                    }
        );
        assert!(std::mem::size_of::<SecurityAttributes>() == 3 * std::mem::size_of::<usize>());
    };

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    #[derive(Default, Clone, PartialEq, Eq)]
    struct FileInformation {
        attributes: u32,
        creation: [u32; 2],
        access: [u32; 2],
        write: [u32; 2],
        volume: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetNamedPipeClientProcessId(pipe: Handle, pid: *mut u32) -> i32;
        fn GetNamedPipeServerProcessId(pipe: Handle, pid: *mut u32) -> i32;
        fn QueryFullProcessImageNameW(
            process: Handle,
            flags: u32,
            name: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn WaitNamedPipeW(name: *const u16, milliseconds: u32) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn GetProcessTimes(
            process: Handle,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        fn CreateNamedPipeW(
            name: *const u16,
            mode: u32,
            pipe_mode: u32,
            instances: u32,
            output: u32,
            input: u32,
            timeout: u32,
            security: *const SecurityAttributes,
        ) -> Handle;
        fn CreateEventW(
            attributes: *const SecurityAttributes,
            manual: i32,
            initial: i32,
            name: *const u16,
        ) -> Handle;
        fn ConnectNamedPipe(pipe: Handle, overlapped: *mut Overlapped) -> i32;
        fn GetOverlappedResult(
            handle: Handle,
            overlapped: *mut Overlapped,
            count: *mut u32,
            wait: i32,
        ) -> i32;
        fn CancelIoEx(handle: Handle, overlapped: *mut Overlapped) -> i32;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenThreadToken(thread: Handle, access: u32, as_self: i32, token: *mut Handle) -> i32;
        fn ImpersonateNamedPipeClient(pipe: Handle) -> i32;
        fn RevertToSelf() -> i32;
    }

    struct LocalAllocation(*mut c_void);
    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    struct ImpersonationGuard;
    impl Drop for ImpersonationGuard {
        fn drop(&mut self) {
            // Continuing with an unexpected thread token can expose state.
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }

    /// OS-derived user and logon session identity; never a wire-provided SID.
    #[derive(Clone, PartialEq, Eq)]
    pub struct PipeTokenIdentity {
        user: String,
        logon: String,
    }

    impl PipeTokenIdentity {
        pub fn current_service() -> Result<Self, String> {
            let mut raw = std::ptr::null_mut();
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
                return Err(last_error("open service token"));
            }
            let token = unsafe { OwnedHandle::from_raw_handle(raw) };
            token_identity(&token)
        }

        /// Call synchronously on the thread that read a request from this pipe.
        /// No async yield is permitted while Windows thread impersonation is active.
        pub fn observe_matching_client(&self, pipe: &impl AsRawHandle) -> Result<Self, String> {
            if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
                return Err(last_error("impersonate pipe client for identification"));
            }
            let guard = ImpersonationGuard;
            let result = (|| {
                let mut raw = std::ptr::null_mut();
                if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) } == 0 {
                    return Err(last_error("open client token"));
                }
                let token = unsafe { OwnedHandle::from_raw_handle(raw) };
                let identity = token_identity(&token)?;
                if &identity != self {
                    return Err(
                        "APPROVAL_PEER_REQUIRED: wrong Windows user or logon session".into(),
                    );
                }
                Ok(identity)
            })();
            drop(guard);
            result
        }

        /// Create a single local pipe with a protected logon-SID-only DACL.
        /// The current user is owner; a user-SID allow ACE is intentionally absent
        /// because it would admit the user's other logon sessions.
        pub fn create_server_pipe(&self, suffix: &str) -> Result<OwnedHandle, String> {
            if suffix.is_empty()
                || suffix.len() > 128
                || !suffix
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            {
                return Err("invalid Windows service pipe suffix".into());
            }
            // Specific client read/write rights exclude FILE_CREATE_PIPE_INSTANCE (4).
            let sddl = wide(&format!(
                "O:{}D:P(A;;0x0012019b;;;{})",
                self.user, self.logon
            ));
            let mut descriptor = std::ptr::null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(last_error("build protected pipe DACL"));
            }
            let allocation = LocalAllocation(descriptor);
            let security = SecurityAttributes {
                length: std::mem::size_of::<SecurityAttributes>() as u32,
                descriptor: allocation.0,
                inherit: 0,
            };
            let name = wide(&format!("\\\\.\\pipe\\progress-checker-{suffix}"));
            // DUPLEX | OVERLAPPED | FIRST_PIPE_INSTANCE; byte mode | reject remote.
            let raw = unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    3 | 0x4000_0000 | 0x0008_0000,
                    8,
                    1,
                    65536,
                    65536,
                    0,
                    &security,
                )
            };
            if raw == -1isize as Handle {
                return Err(last_error("create protected service pipe"));
            }
            Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
        }
    }

    /// One bounded request per connection. This is transport authentication,
    /// not terminal identity, image identity or command approval authority.
    pub struct BoundedPipeServer {
        pipe: OwnedHandle,
        expected: PipeTokenIdentity,
    }

    pub struct AuthenticatedPipeConnection {
        pipe: OwnedHandle,
        expected: PipeTokenIdentity,
        peer: PipePeerLifetime,
    }

    impl BoundedPipeServer {
        pub fn create(suffix: &str) -> Result<Self, String> {
            let expected = PipeTokenIdentity::current_service()?;
            let pipe = expected.create_server_pipe(suffix)?;
            Ok(Self { pipe, expected })
        }

        /// Uses four-byte big-endian length followed by at most 1 MiB payload.
        /// The aggregate connect/header/body deadline must be 1..=60,000 ms.
        /// Caller must separately validate JSON schema and reject approval RPCs.
        pub fn accept_request(
            self,
            timeout_ms: u32,
        ) -> Result<(AuthenticatedPipeConnection, Vec<u8>), String> {
            let deadline = deadline(timeout_ms)?;
            overlapped_io(
                &self.pipe,
                deadline,
                |overlapped| unsafe { ConnectNamedPipe(self.pipe.as_raw_handle(), overlapped) },
                true,
            )?;
            let peer = PipePeerLifetime::observe(&self.pipe)?;
            let mut header = [0u8; 4];
            read_exact(&self.pipe, &mut header, deadline)?;
            let length = u32::from_be_bytes(header) as usize;
            if length == 0 || length > MAX_FRAME_BYTES {
                return Err("IPC_FRAME_INVALID: Windows request exceeds frame bound".into());
            }
            let mut body = vec![0u8; length];
            read_exact(&self.pipe, &mut body, deadline)?;
            self.expected.observe_matching_client(&self.pipe)?;
            peer.recheck(&self.pipe)?;
            let connection = AuthenticatedPipeConnection {
                pipe: self.pipe,
                expected: self.expected,
                peer,
            };
            Ok((connection, body))
        }
    }

    impl AuthenticatedPipeConnection {
        pub fn recheck(&self) -> Result<(), String> {
            self.peer.recheck(&self.pipe)?;
            self.expected.observe_matching_client(&self.pipe)?;
            self.peer.recheck(&self.pipe)
        }

        /// One response, with the same framing and size/deadline limits.
        pub fn reply(self, bytes: &[u8], timeout_ms: u32) -> Result<(), String> {
            if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
                return Err("IPC_FRAME_INVALID: Windows reply exceeds frame bound".into());
            }
            let deadline = deadline(timeout_ms)?;
            self.recheck()?;
            write_all(&self.pipe, &(bytes.len() as u32).to_be_bytes(), deadline)?;
            write_all(&self.pipe, bytes, deadline)?;
            self.recheck()
        }
    }

    fn deadline(timeout_ms: u32) -> Result<std::time::Instant, String> {
        if !(1..=60_000).contains(&timeout_ms) {
            return Err("IPC_TIMEOUT_INVALID: expected 1..=60000 milliseconds".into());
        }
        Ok(std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms.into()))
    }

    fn read_exact(
        pipe: &OwnedHandle,
        mut bytes: &mut [u8],
        deadline: std::time::Instant,
    ) -> Result<(), String> {
        while !bytes.is_empty() {
            let count = overlapped_io(
                pipe,
                deadline,
                |overlapped| unsafe {
                    ReadFile(
                        pipe.as_raw_handle(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len() as u32,
                        std::ptr::null_mut(),
                        overlapped.cast(),
                    )
                },
                false,
            )? as usize;
            if count == 0 || count > bytes.len() {
                return Err("IPC_FRAME_INVALID: truncated request".into());
            }
            bytes = &mut bytes[count..];
        }
        Ok(())
    }

    fn write_all(
        pipe: &OwnedHandle,
        mut bytes: &[u8],
        deadline: std::time::Instant,
    ) -> Result<(), String> {
        while !bytes.is_empty() {
            let count = overlapped_io(
                pipe,
                deadline,
                |overlapped| unsafe {
                    WriteFile(
                        pipe.as_raw_handle(),
                        bytes.as_ptr().cast(),
                        bytes.len() as u32,
                        std::ptr::null_mut(),
                        overlapped.cast(),
                    )
                },
                false,
            )? as usize;
            if count == 0 || count > bytes.len() {
                return Err("IPC_FRAME_INVALID: truncated reply".into());
            }
            bytes = &bytes[count..];
        }
        Ok(())
    }

    /// Keeps the OVERLAPPED and data buffer live until completion or cancellation.
    /// Failure to retire a cancelled kernel operation aborts instead of returning
    /// with a pending operation referencing freed Rust memory.
    fn overlapped_io(
        pipe: &OwnedHandle,
        deadline: std::time::Instant,
        mut start: impl FnMut(*mut Overlapped) -> i32,
        connecting: bool,
    ) -> Result<u32, String> {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or("IPC_TIMEOUT: Windows pipe deadline expired")?;
        let raw_event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if raw_event.is_null() {
            return Err(last_error("create pipe I/O event"));
        }
        let event = unsafe { OwnedHandle::from_raw_handle(raw_event) };
        let mut overlapped = Overlapped {
            event: event.as_raw_handle(),
            ..Default::default()
        };
        let started = start(&mut overlapped);
        if started == 0 {
            let error = std::io::Error::last_os_error();
            if connecting && error.raw_os_error() == Some(ERROR_PIPE_CONNECTED) {
                return Ok(0);
            }
            if error.raw_os_error() != Some(ERROR_IO_PENDING) {
                return Err(format!("IPC_IO_FAILED: {error}"));
            }
            let milliseconds = remaining.as_millis().clamp(1, 60_000) as u32;
            if unsafe { WaitForSingleObject(event.as_raw_handle(), milliseconds) } != 0 {
                // CancelIoEx can race completion; both outcomes must be drained.
                unsafe {
                    CancelIoEx(pipe.as_raw_handle(), &mut overlapped);
                }
                if unsafe { WaitForSingleObject(event.as_raw_handle(), 5_000) } != 0 {
                    std::process::abort();
                }
                let mut count = 0;
                unsafe {
                    GetOverlappedResult(pipe.as_raw_handle(), &mut overlapped, &mut count, 0);
                }
                return Err("IPC_TIMEOUT: Windows pipe operation cancelled".into());
            }
        }
        let mut count = 0;
        if unsafe { GetOverlappedResult(pipe.as_raw_handle(), &mut overlapped, &mut count, 0) } == 0
        {
            return Err(last_error("complete pipe operation"));
        }
        Ok(count)
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct TokenInformation {
        words: Vec<usize>,
        bytes: usize,
    }

    fn token_information(token: &OwnedHandle, class: u32) -> Result<TokenInformation, String> {
        let mut size = 0;
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                class,
                std::ptr::null_mut(),
                0,
                &mut size,
            );
        }
        if size == 0 || size > 1024 * 1024 {
            return Err(last_error("size token identity"));
        }
        let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        let allocated = buffer.len() * std::mem::size_of::<usize>();
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                class,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            )
        } == 0
        {
            return Err(last_error("read token identity"));
        }
        if size == 0 || size as usize > allocated {
            return Err("invalid token return length".into());
        }
        Ok(TokenInformation {
            words: buffer,
            bytes: size as usize,
        })
    }

    fn token_identity(token: &OwnedHandle) -> Result<PipeTokenIdentity, String> {
        let user = token_information(token, 1)?; // TokenUser
        let groups = token_information(token, 28)?; // TokenLogonSid
        if user.bytes < std::mem::size_of::<SidAndAttributes>()
            || groups.bytes < std::mem::size_of::<TokenGroupsOne>()
        {
            return Err("APPROVAL_PEER_REQUIRED: incomplete Windows token identity".into());
        }
        let user_info = unsafe { &*user.words.as_ptr().cast::<SidAndAttributes>() };
        let logon_info = unsafe { &*groups.words.as_ptr().cast::<TokenGroupsOne>() };
        if logon_info.count != 1 || logon_info.first.attributes & 0xc000_0000 != 0xc000_0000 {
            return Err("APPROVAL_PEER_REQUIRED: Windows logon SID absent".into());
        }
        Ok(PipeTokenIdentity {
            user: sid_from_information(&user, user_info.sid)?,
            logon: sid_from_information(&groups, logon_info.first.sid)?,
        })
    }

    fn sid_from_information(
        information: &TokenInformation,
        sid: *mut c_void,
    ) -> Result<String, String> {
        let base = information.words.as_ptr() as usize;
        let end = base
            .checked_add(information.bytes)
            .ok_or("invalid token address range")?;
        let address = sid as usize;
        let header_end = address.checked_add(8).ok_or("invalid SID address")?;
        if address < base || header_end > end {
            return Err("token SID outside returned buffer".into());
        }
        let count = unsafe { *(sid.cast::<u8>().add(1)) } as usize;
        let sid_end = header_end
            .checked_add(count * 4)
            .ok_or("invalid SID length")?;
        if count > 15 || sid_end > end || unsafe { IsValidSid(sid) } == 0 {
            return Err("invalid token SID representation".into());
        }
        sid_string(sid)
    }

    fn sid_string(sid: *mut c_void) -> Result<String, String> {
        let mut text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err(last_error("format token SID"));
        }
        let allocation = LocalAllocation(text.cast());
        let mut length = 0;
        while length < 256 && unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        if length == 256 {
            return Err("APPROVAL_PEER_REQUIRED: invalid token SID text".into());
        }
        let result = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
            .map_err(|_| "APPROVAL_PEER_REQUIRED: invalid SID encoding".to_string());
        drop(allocation);
        result
    }

    /// Retains a kernel process object rather than trusting a reusable PID.
    /// Fields cannot be supplied by an IPC request or deserialized from JSON.
    pub struct PipePeerLifetime {
        process: OwnedHandle,
        pid: u32,
        created: u64,
        server: bool,
    }

    impl PipePeerLifetime {
        /// Observe a connected server-side pipe handle acquired by the service.
        /// This does not prove identity or approval authority.
        pub fn observe(pipe: &impl AsRawHandle) -> Result<Self, String> {
            Self::observe_direction(pipe, false)
        }

        fn observe_direction(pipe: &impl AsRawHandle, server: bool) -> Result<Self, String> {
            use std::os::windows::io::FromRawHandle;
            let mut pid = 0;
            // SAFETY: the borrowed pipe handle remains live for each API call.
            if query_pipe_pid(pipe.as_raw_handle(), server, &mut pid) == 0 || pid == 0 {
                return Err(last_error("query pipe peer"));
            }
            let raw =
                unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
            if raw.is_null() {
                return Err(last_error("retain pipe peer process"));
            }
            // SAFETY: OpenProcess returned a new owned handle; OwnedHandle closes it.
            let process = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
            let created = creation_time(process.as_raw_handle())?;
            let peer = Self {
                process,
                pid,
                created,
                server,
            };
            peer.recheck(pipe)?;
            Ok(peer)
        }

        /// Reject disconnect, termination, changed pipe peer and PID reuse.
        pub fn recheck(&self, pipe: &impl AsRawHandle) -> Result<(), String> {
            let mut pid = 0;
            if query_pipe_pid(pipe.as_raw_handle(), self.server, &mut pid) == 0
                || pid != self.pid
                || unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } != WAIT_TIMEOUT
                || creation_time(self.process.as_raw_handle())? != self.created
            {
                return Err("APPROVAL_PEER_REQUIRED: Windows pipe peer lifetime changed".into());
            }
            Ok(())
        }
    }

    fn query_pipe_pid(pipe: RawHandle, server: bool, pid: &mut u32) -> i32 {
        unsafe {
            if server {
                GetNamedPipeServerProcessId(pipe, pid)
            } else {
                GetNamedPipeClientProcessId(pipe, pid)
            }
        }
    }

    impl PipePeerLifetime {
        fn check_process_identity(&self, expected: &PipeTokenIdentity) -> Result<(), String> {
            let mut raw = std::ptr::null_mut();
            if unsafe { OpenProcessToken(self.process.as_raw_handle(), TOKEN_QUERY, &mut raw) } == 0
            {
                return Err(last_error("open retained peer token"));
            }
            let token = unsafe { OwnedHandle::from_raw_handle(raw) };
            if &token_identity(&token)? != expected {
                return Err("IPC_PEER_INVALID: retained process user/logon mismatch".into());
            }
            Ok(())
        }

        fn observe_image(&self, expected_path: &Path) -> Result<RetainedPeerImage, String> {
            let mut name = vec![0u16; 32768];
            let mut length = name.len() as u32;
            if unsafe {
                QueryFullProcessImageNameW(
                    self.process.as_raw_handle(),
                    0,
                    name.as_mut_ptr(),
                    &mut length,
                )
            } == 0
                || length == 0
                || length as usize >= name.len()
            {
                return Err(last_error("query retained peer executable"));
            }
            use std::os::windows::ffi::OsStringExt;
            let path = PathBuf::from(std::ffi::OsString::from_wide(&name[..length as usize]));
            RetainedPeerImage::observe(&path, expected_path)
        }
    }

    /// Verify this process against the fixed installed CLI without wire claims.
    /// Its process lifetime remains live for the duration of this function's caller.
    pub fn verify_current_cli_image(expected_path: &Path) -> Result<RetainedPeerImage, String> {
        let mut name = vec![0u16; 32768];
        let mut length = name.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(GetCurrentProcess(), 0, name.as_mut_ptr(), &mut length)
        } == 0
            || length == 0
            || length as usize >= name.len()
        {
            return Err(last_error("query current CLI image"));
        }
        use std::os::windows::ffi::OsStringExt;
        let path = PathBuf::from(std::ffi::OsString::from_wide(&name[..length as usize]));
        RetainedPeerImage::observe(&path, expected_path)
    }

    /// OS-derived image identity with retained audited installation/file handles.
    /// This is not proof of a human terminal or of the process's mapped PE pages.
    pub struct RetainedPeerImage {
        actual_guard: InstallationTrustGuard,
        expected_guard: InstallationTrustGuard,
        file: std::fs::File,
        information: FileInformation,
        digest: [u8; 32],
    }

    impl RetainedPeerImage {
        fn observe(actual_path: &Path, expected_path: &Path) -> Result<Self, String> {
            let actual_guard = InstallationTrustGuard::audit(actual_path)?;
            let expected_guard = InstallationTrustGuard::audit(expected_path)?;
            let mut actual = open_image(actual_path)?;
            let mut expected = open_image(expected_path)?;
            let information = file_information(&actual)?;
            let expected_info = file_information(&expected)?;
            let digest = image_digest(&mut actual)?;
            if information.volume != expected_info.volume
                || information.index_high != expected_info.index_high
                || information.index_low != expected_info.index_low
                || digest != image_digest(&mut expected)?
            {
                return Err(
                    "IPC_PEER_INVALID: OS peer image differs from trusted installed image".into(),
                );
            }
            let mut result = Self {
                actual_guard,
                expected_guard,
                file: actual,
                information,
                digest,
            };
            result.recheck()?;
            Ok(result)
        }

        pub fn recheck(&mut self) -> Result<(), String> {
            self.actual_guard.revalidate()?;
            self.expected_guard.revalidate()?;
            let now = file_information(&self.file)?;
            if now.volume != self.information.volume
                || now.index_high != self.information.index_high
                || now.index_low != self.information.index_low
                || now.attributes != self.information.attributes
                || now.write != self.information.write
                || now.size_high != self.information.size_high
                || now.size_low != self.information.size_low
                || image_digest(&mut self.file)? != self.digest
            {
                return Err("IPC_PEER_INVALID: retained image changed".into());
            }
            Ok(())
        }
    }

    impl AuthenticatedPipeConnection {
        /// expected_path must come from trusted installation configuration, not JSON.
        pub fn verify_client_image(
            &self,
            expected_path: &Path,
        ) -> Result<RetainedPeerImage, String> {
            self.recheck()?;
            let image = self.peer.observe_image(expected_path)?;
            self.recheck()?;
            Ok(image)
        }
    }

    fn open_image(path: &Path) -> Result<std::fs::File, String> {
        let name: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        if name[..name.len() - 1].contains(&0) {
            return Err("invalid executable path".into());
        }
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                0x8000_0000,
                1,
                std::ptr::null(),
                3,
                0x0020_0000,
                std::ptr::null_mut(),
            )
        };
        if raw == -1isize as Handle {
            return Err(last_error("retain executable file"));
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let file = std::fs::File::from(handle);
        if file_information(&file)?.attributes & (0x10 | 0x400) != 0 {
            return Err("IPC_PEER_INVALID: executable is directory or reparse point".into());
        }
        Ok(file)
    }

    fn file_information(file: &std::fs::File) -> Result<FileInformation, String> {
        let mut information = FileInformation::default();
        if unsafe {
            GetFileInformationByHandle(
                file.as_raw_handle(),
                (&mut information as *mut FileInformation).cast(),
            )
        } == 0
        {
            return Err(last_error("query retained executable identity"));
        }
        Ok(information)
    }

    fn image_digest(file: &mut std::fs::File) -> Result<[u8; 32], String> {
        use std::io::{Read, Seek, SeekFrom};
        let length = file.metadata().map_err(|e| e.to_string())?.len();
        if length == 0 || length > 128 * 1024 * 1024 {
            return Err("executable hash size limit exceeded".into());
        }
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut total = 0u64;
        loop {
            let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > length {
                return Err("executable changed while hashing".into());
            }
            digest.update(&buffer[..count]);
        }
        if total != length {
            return Err("executable truncated while hashing".into());
        }
        Ok(digest.finalize().into())
    }

    /// A local client retaining OS server lifetime, identity and trusted image.
    /// Caller must derive expected_server_image from a trusted installed package.
    pub struct VerifiedPipeClient {
        pipe: OwnedHandle,
        peer: PipePeerLifetime,
        expected: PipeTokenIdentity,
        image: RetainedPeerImage,
    }

    impl VerifiedPipeClient {
        pub fn connect(
            suffix: &str,
            expected_server_image: &Path,
            timeout_ms: u32,
        ) -> Result<Self, String> {
            if suffix.is_empty()
                || suffix.len() > 128
                || !suffix
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            {
                return Err("invalid Windows service pipe suffix".into());
            }
            let deadline = deadline(timeout_ms)?;
            let name = wide(&format!("\\\\.\\pipe\\progress-checker-{suffix}"));
            let pipe = loop {
                if std::time::Instant::now() >= deadline {
                    return Err("IPC_TIMEOUT: connecting native pipe".into());
                }
                // Specific DACL rights, overlapped, SECURITY_SQOS_PRESENT and IDENTIFICATION.
                let raw = unsafe {
                    CreateFileW(
                        name.as_ptr(),
                        0x0012_019b,
                        0,
                        std::ptr::null(),
                        3,
                        0x4000_0000 | 0x0010_0000 | 0x0001_0000,
                        std::ptr::null_mut(),
                    )
                };
                if raw != -1isize as Handle {
                    break unsafe { OwnedHandle::from_raw_handle(raw) };
                }
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(231) {
                    return Err(format!("IPC_CONNECT_FAILED: {error}"));
                }
                let remaining = deadline
                    .checked_duration_since(std::time::Instant::now())
                    .ok_or("IPC_TIMEOUT: connecting native pipe")?;
                if unsafe {
                    WaitNamedPipeW(name.as_ptr(), remaining.as_millis().clamp(1, 60_000) as u32)
                } == 0
                {
                    return Err(last_error("wait for native service pipe"));
                }
            };
            let expected = PipeTokenIdentity::current_service()?;
            let peer = PipePeerLifetime::observe_direction(&pipe, true)?;
            peer.check_process_identity(&expected)?;
            let image = peer.observe_image(expected_server_image)?;
            let mut client = Self {
                pipe,
                peer,
                expected,
                image,
            };
            client.recheck()?;
            Ok(client)
        }

        pub fn recheck(&mut self) -> Result<(), String> {
            self.peer.recheck(&self.pipe)?;
            self.peer.check_process_identity(&self.expected)?;
            self.image.recheck()?;
            self.peer.recheck(&self.pipe)
        }

        pub fn exchange(mut self, request: &[u8], timeout_ms: u32) -> Result<Vec<u8>, String> {
            if request.is_empty() || request.len() > MAX_FRAME_BYTES {
                return Err("IPC_FRAME_INVALID: native client request exceeds bound".into());
            }
            self.recheck()?;
            let deadline = deadline(timeout_ms)?;
            write_all(&self.pipe, &(request.len() as u32).to_be_bytes(), deadline)?;
            write_all(&self.pipe, request, deadline)?;
            let mut header = [0u8; 4];
            read_exact(&self.pipe, &mut header, deadline)?;
            let length = u32::from_be_bytes(header) as usize;
            if length == 0 || length > MAX_FRAME_BYTES {
                return Err("IPC_FRAME_INVALID: native server response exceeds bound".into());
            }
            let mut response = vec![0u8; length];
            read_exact(&self.pipe, &mut response, deadline)?;
            self.recheck()?;
            Ok(response)
        }
    }

    fn creation_time(process: RawHandle) -> Result<u64, String> {
        let mut creation = FileTime::default();
        let mut exit = FileTime::default();
        let mut kernel = FileTime::default();
        let mut user = FileTime::default();
        if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) }
            == 0
        {
            return Err(last_error("query peer creation time"));
        }
        Ok((u64::from(creation.high) << 32) | u64::from(creation.low))
    }

    fn last_error(operation: &str) -> String {
        format!(
            "APPROVAL_PEER_REQUIRED: {operation}: {}",
            std::io::Error::last_os_error()
        )
    }
}

#[cfg(windows)]
pub use native::{
    AuthenticatedPipeConnection, BoundedPipeServer, PipePeerLifetime, PipeTokenIdentity,
    RetainedPeerImage, VerifiedPipeClient, verify_current_cli_image,
};
