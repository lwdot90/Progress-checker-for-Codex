//! Unqualified native Windows approval-console prototype.
//!
//! Client-side ConsoleAPI checks do not prove a human terminal to the server.
//! Confirmation is always blocked until that independent proof is qualified.
//! This module never writes approvals, grants, evidence or service state.

pub fn require_qualified_console_broker() -> Result<(), String> {
    Err("APPROVAL_PEER_REQUIRED: independent Windows server-side console authority is not qualified".into())
}

#[cfg(windows)]
mod native {
    use super::super::windows_ffi::Handle;
    use super::super::windows_ipc::{
        PipeTokenIdentity, RetainedPeerImage, verify_current_cli_image,
    };
    use serde::Serialize;
    use std::{
        ffi::c_void,
        os::windows::io::{AsRawHandle, BorrowedHandle, OwnedHandle},
        path::Path,
    };

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(which: u32) -> Handle;
        fn GetFileType(handle: Handle) -> u32;
        fn GetConsoleMode(handle: Handle, mode: *mut u32) -> i32;
        fn ReadConsoleW(
            handle: Handle,
            buffer: *mut c_void,
            count: u32,
            read: *mut u32,
            control: Handle,
        ) -> i32;
        fn WriteConsoleW(
            handle: Handle,
            buffer: *const c_void,
            count: u32,
            written: *mut u32,
            reserved: Handle,
        ) -> i32;
        fn CancelSynchronousIo(thread: Handle) -> i32;
    }

    /// Not serializable and not a service-verifiable terminal authority.
    pub struct ConsolePrompt {
        input: OwnedHandle,
        output: OwnedHandle,
        image: RetainedPeerImage,
        _identity: PipeTokenIdentity,
        preview: Vec<u16>,
        phrase: String,
    }

    /// expected_cli must be a fixed trusted installed path from the CLI adapter.
    /// definition must be its complete canonical exact approval binding.
    pub fn prepare_console_prompt(
        expected_cli: &Path,
        check_id: &str,
        definition: &impl Serialize,
        binding_digest: &str,
    ) -> Result<ConsolePrompt, String> {
        if check_id.is_empty()
            || check_id.len() > 160
            || !check_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("invalid console check identifier".into());
        }
        let hash = binding_digest
            .strip_prefix("sha256:")
            .ok_or("invalid exact binding digest")?;
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("invalid exact binding digest".into());
        }
        let definition = serde_json::to_string_pretty(definition).map_err(|e| e.to_string())?;
        if definition.len() > 32 * 1024
            || definition.chars().any(|c| {
                (c.is_control() && c != '\n' && c != '\t')
                    || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            })
        {
            return Err("console definition exceeds safe display bounds".into());
        }
        let image = verify_current_cli_image(expected_cli)?;
        let identity = PipeTokenIdentity::current_service()?;
        let input = console_handle(-10i32 as u32, true)?;
        let output = console_handle(-11i32 as u32, false)?;
        let preview = format!("UNQUALIFIED WINDOWS APPROVAL PREVIEW\r\nCheck: {check_id}\r\nBinding: {binding_digest}\r\n{definition}\r\nNo approval is created. Independent server console authority remains blocked.\r\n").encode_utf16().collect();
        Ok(ConsolePrompt {
            input,
            output,
            image,
            _identity: identity,
            preview,
            phrase: format!("APPROVE {binding_digest}"),
        })
    }

    impl ConsolePrompt {
        /// Shows exact definition only; creates no authorization or challenge.
        pub fn render_preview(&mut self) -> Result<(), String> {
            self.image.recheck()?;
            validate_console(&self.input, true)?;
            validate_console(&self.output, false)?;
            let mut remaining = self.preview.as_slice();
            while !remaining.is_empty() {
                let chunk = remaining.len().min(4096);
                let mut written = 0;
                if unsafe {
                    WriteConsoleW(
                        self.output.as_raw_handle(),
                        remaining.as_ptr().cast(),
                        chunk as u32,
                        &mut written,
                        std::ptr::null_mut(),
                    )
                } == 0
                    || written == 0
                    || written as usize > chunk
                {
                    return Err(last_error("write exact approval preview"));
                }
                remaining = &remaining[written as usize..];
            }
            self.image.recheck()
        }

        /// Permanently refused by the current qualification gate before reading.
        /// The reader prototype does not feed confirmation and returns no grant.
        pub fn confirm(mut self, timeout_ms: u32) -> Result<(), String> {
            super::require_qualified_console_broker()?;
            if !(1..=60_000).contains(&timeout_ms) {
                return Err("invalid confirmation timeout".into());
            }
            self.image.recheck()?;
            validate_console(&self.input, true)?;
            let answer = bounded_console_read(self.input, timeout_ms)?;
            if answer != self.phrase {
                return Err("human confirmation did not match exact binding".into());
            }
            self.image.recheck()?;
            // Even if the independent gate is changed later, this prototype
            // cannot represent a completed service approval.
            Err("APPROVAL_PEER_REQUIRED: native approval commit is not implemented".into())
        }
    }

    fn console_handle(which: u32, input: bool) -> Result<OwnedHandle, String> {
        let raw = unsafe { GetStdHandle(which) };
        if raw.is_null() || raw == -1isize as Handle {
            return Err("standard console handle absent".into());
        }
        // Same-process duplication retains the actual standard handle. This is
        // not the forbidden cross-process duplication of a console handle.
        let handle = unsafe { BorrowedHandle::borrow_raw(raw) }
            .try_clone_to_owned()
            .map_err(|e| e.to_string())?;
        validate_console(&handle, input)?;
        Ok(handle)
    }

    fn validate_console(handle: &OwnedHandle, input: bool) -> Result<(), String> {
        let mut mode = 0;
        if unsafe { GetFileType(handle.as_raw_handle()) } != 2
            || unsafe { GetConsoleMode(handle.as_raw_handle(), &mut mode) } == 0
        {
            return Err("actual standard input/output is not a native console handle".into());
        }
        if input && mode & 6 != 6 {
            return Err("console requires echoed line input".into());
        }
        Ok(())
    }

    fn bounded_console_read(input: OwnedHandle, timeout_ms: u32) -> Result<String, String> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let mut buffer = [0u16; 256];
            let mut read = 0;
            let result = if unsafe {
                ReadConsoleW(
                    input.as_raw_handle(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                Err(last_error("read console confirmation"))
            } else if read as usize > buffer.len() {
                Err("invalid console read length".into())
            } else {
                String::from_utf16(&buffer[..read as usize])
                    .map_err(|_| "invalid console input encoding".into())
            };
            let _ = sender.send(result);
        });
        let result =
            match receiver.recv_timeout(std::time::Duration::from_millis(timeout_ms.into())) {
                Ok(result) => result,
                Err(_) => {
                    unsafe {
                        CancelSynchronousIo(worker.as_raw_handle());
                    }
                    // Retire the pending synchronous read before releasing handles.
                    if receiver
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .is_err()
                    {
                        std::process::abort();
                    }
                    let _ = worker.join();
                    return Err("console confirmation timed out".into());
                }
            };
        worker
            .join()
            .map_err(|_| "console reader failed".to_string())?;
        result.map(|text| text.trim_end_matches(['\r', '\n']).to_owned())
    }

    fn last_error(operation: &str) -> String {
        format!(
            "APPROVAL_PEER_REQUIRED: {operation}: {}",
            std::io::Error::last_os_error()
        )
    }
}

#[cfg(windows)]
pub use native::{ConsolePrompt, prepare_console_prompt};
