//! Candidate native Windows private-state primitives. Not wired into StateStore.
//! Qualification must cover ACL/reparse races, crash durability and writer lock
//! exclusion before the store's Unsupported gate can be removed.
pub fn require_qualified_state_backend() -> Result<(), String> {
    Err("UNSUPPORTED_PLATFORM: native Windows protected-state backend is not qualified".into())
}

#[cfg(any(windows, test))]
fn validate_child_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name
            .chars()
            .any(|character| character < ' ' || "<>:\"/\\|?*".contains(character))
        || matches!(name, "." | "..")
        || name.ends_with(['.', ' '])
    {
        return Err("invalid state child name".into());
    }
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || (stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && matches!(stem.as_bytes()[3], b'1'..=b'9'))
    {
        return Err("reserved Windows state child name".into());
    }
    Ok(())
}

#[cfg(windows)]
mod native {
    use crate::platform::windows_ffi::{
        AceHeader, ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        CreateDirectoryW, CreateFileW, FlushFileBuffers, GetAce, GetCurrentProcess,
        GetFileInformationByHandle, GetLengthSid, GetSecurityDescriptorControl, GetSecurityInfo,
        GetTokenInformation, Handle, IsValidAcl, IsValidSid, LocalFree, OpenProcessToken, ReadFile,
        SecurityAttributes, SetFileInformationByHandle, WriteFile,
    };
    use std::{
        ffi::c_void,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        path::{Component, Path, PathBuf},
    };
    struct Allocation(Handle);
    impl Drop for Allocation {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    fn error(context: &str) -> String {
        format!("{context}: {}", std::io::Error::last_os_error())
    }
    fn wide(path: &Path) -> Result<Vec<u16>, String> {
        let mut text: Vec<_> = path.as_os_str().encode_wide().collect();
        if text.contains(&0) {
            return Err("state path contains NUL".into());
        }
        text.push(0);
        Ok(text)
    }
    fn sid_string(sid: Handle) -> Result<String, String> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err("invalid state SID".into());
        }
        let mut text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err(error("convert state SID"));
        }
        let _owned = Allocation(text.cast());
        let mut length = 0;
        while length < 256 && unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        if length == 256 {
            return Err("state SID exceeds limit".into());
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
            .map_err(|_| "invalid state SID encoding".into())
    }
    pub(crate) fn current_user_sid() -> Result<String, String> {
        let mut raw = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut raw) } == 0 {
            return Err(error("open state token"));
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut required = 0;
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                1,
                std::ptr::null_mut(),
                0,
                &mut required,
            );
        }
        if required < std::mem::size_of::<Handle>() as u32 || required > 65536 {
            return Err("invalid state token size".into());
        }
        // Pointer-aligned storage for TOKEN_USER's SID_AND_ATTRIBUTES prefix.
        let mut buffer = vec![
            0usize;
            (required as usize + std::mem::size_of::<usize>() - 1)
                / std::mem::size_of::<usize>()
        ];
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                1,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(error("read state token"));
        }
        sid_string(unsafe { *buffer.as_ptr().cast::<Handle>() })
    }
    fn descriptor(user: &str) -> Result<Allocation, String> {
        // Protected DACL: only the OS-derived user and SYSTEM; child inheritance
        // is limited to these two principals. No Everyone/Administrators allow.
        let sddl = format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)");
        let text: Vec<_> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut raw = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut raw,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(error("create state ACL"));
        }
        Ok(Allocation(raw))
    }
    fn no_reparse(file: &OwnedHandle, directory: bool) -> Result<(), String> {
        let mut info = [0u32; 13];
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr().cast()) }
            == 0
        {
            return Err(error("read state file identity"));
        }
        if info[0] & 0x400 != 0 || (info[0] & 0x10 != 0) != directory {
            return Err("state object type or reparse point rejected".into());
        }
        Ok(())
    }
    fn file_identity(file: &OwnedHandle) -> Result<(u32, u32, u32), String> {
        let mut info = [0u32; 13];
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr().cast()) }
            == 0
        {
            return Err(error("read state object identity"));
        }
        Ok((info[7], info[11], info[12]))
    }
    fn audit_private(file: &OwnedHandle, user: &str) -> Result<(), String> {
        let mut owner = std::ptr::null_mut();
        let mut acl = std::ptr::null_mut();
        let mut raw = std::ptr::null_mut();
        if unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                1,
                1 | 4,
                &mut owner,
                std::ptr::null_mut(),
                &mut acl,
                std::ptr::null_mut(),
                &mut raw,
            )
        } != 0
        {
            return Err("state security descriptor unavailable".into());
        }
        let _owned = Allocation(raw);
        if sid_string(owner)? != user {
            return Err("state owner is not current user".into());
        }
        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorControl(raw, &mut control, &mut revision) } == 0
            || control & 0x1000 == 0
        {
            return Err("state DACL is not protected".into());
        }
        if acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
            return Err("state DACL absent or invalid".into());
        }
        let count = unsafe { (*acl).count };
        if count != 2 {
            return Err("state DACL must contain exactly user and SYSTEM allows".into());
        }
        let mut user_seen = false;
        let mut system_seen = false;
        for index in 0..u32::from(count) {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
                return Err("state ACE unavailable".into());
            }
            let header = unsafe { &*ace.cast::<AceHeader>() };
            if header.kind != 0
                || header.flags & 0x10 != 0
                || header.flags & !3 != 0
                || header.size < 16
            {
                return Err("state ACE format rejected".into());
            }
            let mask = unsafe { std::ptr::read_unaligned(ace.cast::<u8>().add(4).cast::<u32>()) };
            if mask != 0x001f01ff {
                return Err("state ACE access mask rejected".into());
            }
            let sid = unsafe { ace.cast::<u8>().add(8).cast::<c_void>() };
            let size = 8 + 4 * usize::from(unsafe { *ace.cast::<u8>().add(9) });
            if size > usize::from(header.size) - 8
                || unsafe { IsValidSid(sid) } == 0
                || unsafe { GetLengthSid(sid) } as usize != size
            {
                return Err("state ACE SID malformed".into());
            }
            match sid_string(sid)?.as_str() {
                value if value == user && !user_seen => user_seen = true,
                "S-1-5-18" if !system_seen => system_seen = true,
                _ => return Err("state ACE principal rejected".into()),
            }
        }
        if !user_seen || !system_seen {
            return Err("state ACL principals missing".into());
        }
        Ok(())
    }
    fn open(
        path: &Path,
        access: u32,
        share: u32,
        security: *const SecurityAttributes,
        disposition: u32,
    ) -> Result<OwnedHandle, String> {
        let text = wide(path)?;
        let raw = unsafe {
            CreateFileW(
                text.as_ptr(),
                access,
                share,
                security,
                disposition,
                0x02200000,
                std::ptr::null_mut(),
            )
        };
        if raw == -1isize as Handle {
            return Err(error("open protected state"));
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }
    /// Retain ancestor handles against rename/delete while operating in a private
    /// directory. Existing ACLs are audited, never silently repaired.
    pub struct PrivateDirectory {
        path: PathBuf,
        user: String,
        _ancestors: Vec<OwnedHandle>,
    }
    impl PrivateDirectory {
        pub fn open_existing(path: &Path) -> Result<Self, String> {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, Component::ParentDir))
            {
                return Err("state path must be absolute without parent traversal".into());
            }
            let user = current_user_sid()?;
            let mut handles = Vec::new();
            for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
                if ancestor.as_os_str().is_empty() {
                    continue;
                }
                if handles.len() >= 256 {
                    return Err("state ancestor limit exceeded".into());
                }
                let file = open(ancestor, 0x00020080, 3, std::ptr::null(), 3)?;
                no_reparse(&file, true)?;
                handles.push(file);
            }
            audit_private(handles.last().ok_or("missing state directory")?, &user)?;
            Ok(Self {
                path: path.into(),
                user,
                _ancestors: handles,
            })
        }
        fn child(&self, name: &str) -> Result<PathBuf, String> {
            let directory = self
                ._ancestors
                .last()
                .ok_or("missing private directory handle")?;
            no_reparse(directory, true)?;
            audit_private(directory, &self.user)?;
            super::validate_child_name(name)?;
            Ok(self.path.join(name))
        }
        pub fn create_child(&self, name: &str) -> Result<Self, String> {
            let path = self.child(name)?;
            let text = wide(&path)?;
            let sd = descriptor(&self.user)?;
            let sa = SecurityAttributes {
                length: std::mem::size_of::<SecurityAttributes>() as u32,
                descriptor: sd.0,
                inherit: 0,
            };
            if unsafe { CreateDirectoryW(text.as_ptr(), &sa) } == 0 {
                return Err(error("create private state directory"));
            }
            Self::open_existing(&path)
        }
        /// Exclusive no-sharing file handle is held for the writer lifetime.
        /// Existing lock ownership and ACL are checked after opening by handle.
        pub fn acquire_writer(&self, name: &str) -> Result<WriterLock, String> {
            let path = self.child(name)?;
            let sd = descriptor(&self.user)?;
            let sa = SecurityAttributes {
                length: std::mem::size_of::<SecurityAttributes>() as u32,
                descriptor: sd.0,
                inherit: 0,
            };
            let handle = open(&path, 0xc0020080, 0, &sa, 4)?;
            no_reparse(&handle, false)?;
            audit_private(&handle, &self.user)?;
            Ok(WriterLock { _handle: handle })
        }
        /// Create only; never overwrite or synthesize an approval/evidence record.
        /// Caller must obtain these bytes from a qualified OS cryptographic RNG.
        pub fn create_key(&self, name: &str, bytes: &[u8; 32]) -> Result<OwnedHandle, String> {
            let sd = descriptor(&self.user)?;
            let sa = SecurityAttributes {
                length: std::mem::size_of::<SecurityAttributes>() as u32,
                descriptor: sd.0,
                inherit: 0,
            };
            let file = open(&self.child(name)?, 0xc0020080, 0, &sa, 1)?;
            no_reparse(&file, false)?;
            audit_private(&file, &self.user)?;
            let mut written = 0;
            if unsafe {
                WriteFile(
                    file.as_raw_handle(),
                    bytes.as_ptr().cast(),
                    32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            } == 0
                || written != 32
            {
                return Err(error("write private state key"));
            }
            if unsafe { FlushFileBuffers(file.as_raw_handle()) } == 0 {
                return Err(error("flush private state key"));
            }
            Ok(file)
        }
        /// Read a bounded snapshot through one retained handle. Sharing permits
        /// readers only, so concurrent mutation/rename/deletion cannot change the
        /// opened object while bytes and ACL are being validated.
        pub fn read_private(&self, name: &str, limit: usize) -> Result<Vec<u8>, String> {
            if limit == 0 || limit > 4 * 1024 * 1024 {
                return Err("private read limit must be 1..=4 MiB".into());
            }
            let file = self.audit_key(name)?;
            let mut bytes = Vec::new();
            let mut buffer = [0u8; 8192];
            loop {
                let remaining = limit.saturating_sub(bytes.len()) + 1;
                let requested = remaining.min(buffer.len()) as u32;
                let mut read = 0;
                if unsafe {
                    ReadFile(
                        file.as_raw_handle(),
                        buffer.as_mut_ptr().cast(),
                        requested,
                        &mut read,
                        std::ptr::null_mut(),
                    )
                } == 0
                {
                    return Err(error("read private state file"));
                }
                if read > requested {
                    return Err("invalid private read length".into());
                }
                if read == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..read as usize]);
                if bytes.len() > limit {
                    return Err("private state file exceeds read limit".into());
                }
            }
            no_reparse(&file, false)?;
            audit_private(&file, &self.user)?;
            Ok(bytes)
        }
        /// Candidate handle-relative rename within this held private directory.
        /// Flags are zero: an existing destination is NEVER replaced. This is
        /// publication of a new immutable name, not a store replacement API.
        /// Windows qualification and crash durability remain separate gates.
        /// References: https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info
        /// https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ne-minwinbase-file_info_by_handle_class
        pub fn rename_new(&self, source_name: &str, target_name: &str) -> Result<(), String> {
            let source_path = self.child(source_name)?;
            super::validate_child_name(target_name)?;
            if source_name.eq_ignore_ascii_case(target_name) {
                return Err("source and destination names must differ".into());
            }
            let directory = self
                ._ancestors
                .last()
                .ok_or("missing private directory handle")?;
            let source = open(&source_path, 0xc0030080, 0, std::ptr::null(), 3)?;
            no_reparse(&source, false)?;
            audit_private(&source, &self.user)?;
            let before = file_identity(&source)?;
            if unsafe { FlushFileBuffers(source.as_raw_handle()) } == 0 {
                return Err(error("flush rename source"));
            }
            let name: Vec<u16> = target_name.encode_utf16().collect();
            #[repr(C)]
            struct RenameInfo {
                flags: u32,
                root: Handle,
                length: u32,
                name: [u16; 1],
            }
            let offset = std::mem::offset_of!(RenameInfo, name);
            let size = offset
                .checked_add(
                    name.len()
                        .checked_add(1)
                        .and_then(|length| length.checked_mul(2))
                        .ok_or("rename name overflow")?,
                )
                .ok_or("rename size overflow")?;
            if size > 65536 {
                return Err("rename information exceeds limit".into());
            }
            // Machine-word alignment accommodates the HANDLE in RenameInfo.
            let mut information = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
            let raw = information.as_mut_ptr().cast::<u8>();
            unsafe {
                raw.cast::<u32>().write(0); // No replacement or POSIX flags.
                raw.add(std::mem::offset_of!(RenameInfo, root))
                    .cast::<Handle>()
                    .write(directory.as_raw_handle());
                raw.add(std::mem::offset_of!(RenameInfo, length))
                    .cast::<u32>()
                    .write((name.len() * 2) as u32);
                std::ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    raw.add(offset).cast::<u16>(),
                    name.len(),
                );
            }
            no_reparse(directory, true)?;
            audit_private(directory, &self.user)?;
            if unsafe {
                SetFileInformationByHandle(source.as_raw_handle(), 22, raw.cast(), size as u32)
            } == 0
            {
                return Err(error("rename new immutable state name"));
            }
            if file_identity(&source)? != before {
                return Err("renamed source identity changed".into());
            }
            no_reparse(&source, false)?;
            audit_private(&source, &self.user)?;
            // The file handle remains bound to the original object. A flush
            // failure after rename means publication may already have occurred;
            // callers must reconcile by identity, never retry with replacement.
            if unsafe { FlushFileBuffers(source.as_raw_handle()) } == 0 {
                return Err(error("flush renamed state object"));
            }
            Ok(())
        }
        /// MoveFileExW operates on paths and cannot assert the expected target
        /// identity while replacing it. Do not expose that weaker operation as
        /// an authenticated state transaction. A qualified handle-relative
        /// rename/flush protocol is required before replacing existing records.
        pub fn replace_private(&self, _name: &str, _bytes: &[u8]) -> Result<(), String> {
            Err("UNSUPPORTED_PLATFORM: native handle-relative atomic protected-state replacement and durability are not qualified".into())
        }
        pub fn audit_key(&self, name: &str) -> Result<OwnedHandle, String> {
            let file = open(&self.child(name)?, 0x80020080, 1, std::ptr::null(), 3)?;
            no_reparse(&file, false)?;
            audit_private(&file, &self.user)?;
            Ok(file)
        }
    }
    pub struct WriterLock {
        _handle: OwnedHandle,
    }
}
#[cfg(windows)]
pub(crate) use native::current_user_sid;
#[cfg(windows)]
pub use native::{PrivateDirectory, WriterLock};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_state_remains_explicitly_unqualified() {
        assert!(
            require_qualified_state_backend()
                .unwrap_err()
                .contains("not qualified")
        );
    }

    #[test]
    fn rejects_traversal_streams_devices_and_ambiguous_windows_names() {
        for name in [
            "",
            ".",
            "..",
            "../key",
            "dir\\key",
            "key:stream",
            "key.",
            "key ",
            "CON",
            "nul.txt",
            "COM1.key",
            "lpt9",
            "bad*key",
            "bad?key",
            "bad\0key",
        ] {
            assert!(validate_child_name(name).is_err(), "accepted {name:?}");
        }
        for name in [
            "authentication.key",
            "writer.lock",
            "snapshot.json",
            "COM10",
            "records-123",
        ] {
            assert!(validate_child_name(name).is_ok(), "rejected {name:?}");
        }
    }
}
