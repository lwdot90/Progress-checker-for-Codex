//! Handle-relative native source reads. Not yet wired to production evidence.
//! Root confinement rejects reparse points and holds each directory without
//! write/delete sharing. Inventory selection still requires a trusted Git helper.
//! The elapsed deadline is checked between operations; a blocked OS syscall
//! cannot be interrupted by this primitive. It is not a hard wall-clock bound.

/// Explicit limits of the candidate snapshot primitive, not qualification proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotLimits {
    pub maximum_objects: usize,
    pub maximum_file_bytes: u64,
    pub maximum_total_bytes: u64,
    pub cooperative_deadline_seconds: u64,
}
pub const SNAPSHOT_LIMITS: SnapshotLimits = SnapshotLimits {
    maximum_objects: 50_000,
    maximum_file_bytes: 64 * 1024 * 1024,
    maximum_total_bytes: 512 * 1024 * 1024,
    cooperative_deadline_seconds: 30,
};
#[cfg(windows)]
mod native {
    use super::SNAPSHOT_LIMITS;
    use crate::platform::windows_ffi::{CreateFileW, GetFileInformationByHandle, Handle};
    use sha2::{Digest, Sha256};
    use std::{
        ffi::c_void,
        fs::File,
        io::{self, Read},
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        path::{Component, Path, Prefix},
    };
    use std::{
        sync::Mutex,
        time::{Duration, Instant},
    };
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDriveTypeW(root: *const u16) -> u32;
    }
    fn check_deadline(started: Instant) -> io::Result<()> {
        if started.elapsed() > Duration::from_secs(SNAPSHOT_LIMITS.cooperative_deadline_seconds) {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native snapshot deadline exceeded",
            ))
        } else {
            Ok(())
        }
    }
    const REPARSE: u32 = 0x400;
    const DIRECTORY: u32 = 0x10;
    const MAX_FILES: usize = SNAPSHOT_LIMITS.maximum_objects;
    const MAX_FILE: u64 = SNAPSHOT_LIMITS.maximum_file_bytes;
    const MAX_TOTAL: u64 = SNAPSHOT_LIMITS.maximum_total_bytes;
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root: Handle,
        name: *mut UnicodeString,
        attributes: u32,
        descriptor: *mut c_void,
        qos: *mut c_void,
    }
    #[repr(C)]
    #[derive(Default)]
    struct IoStatus {
        status: usize,
        information: usize,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct Information {
        attributes: u32,
        creation: FileTime,
        access: FileTime,
        write: FileTime,
        volume: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            handle: *mut Handle,
            access: u32,
            attributes: *mut ObjectAttributes,
            status: *mut IoStatus,
            allocation: *const i64,
            file_attributes: u32,
            sharing: u32,
            disposition: u32,
            options: u32,
            ea: *const c_void,
            ea_length: u32,
        ) -> i32;
        fn NtQueryDirectoryFile(
            handle: Handle,
            event: Handle,
            apc: *const c_void,
            context: *const c_void,
            status: *mut IoStatus,
            buffer: *mut c_void,
            length: u32,
            class: u32,
            single: u8,
            name: *const UnicodeString,
            restart: u8,
        ) -> i32;
    }
    const _: () = assert!(std::mem::size_of::<Information>() == 52);
    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }
    fn nt_error(status: i32) -> io::Error {
        io::Error::other(format!(
            "native confined operation failed: NTSTATUS {status:#x}"
        ))
    }
    fn information(handle: Handle) -> io::Result<Information> {
        let mut info = Information::default();
        if unsafe { GetFileInformationByHandle(handle, (&mut info as *mut Information).cast()) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        if info.attributes & REPARSE != 0 {
            return Err(invalid("reparse points are not source inputs"));
        }
        Ok(info)
    }
    fn component(
        parent: Handle,
        name: &std::ffi::OsStr,
        directory: bool,
    ) -> io::Result<OwnedHandle> {
        component_kind(parent, name, Some(directory))
    }
    fn component_kind(
        parent: Handle,
        name: &std::ffi::OsStr,
        directory: Option<bool>,
    ) -> io::Result<OwnedHandle> {
        let mut utf16: Vec<u16> = name.encode_wide().collect();
        if utf16.is_empty()
            || utf16.len() > 255
            || utf16.iter().any(|v| matches!(*v, 0 | 47 | 92 | 58))
        {
            return Err(invalid("invalid source component"));
        }
        let mut unicode = UnicodeString {
            length: (utf16.len() * 2) as u16,
            maximum_length: (utf16.len() * 2) as u16,
            buffer: utf16.as_mut_ptr(),
        };
        let mut attributes = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root: parent,
            name: &mut unicode,
            attributes: 0x40,
            descriptor: std::ptr::null_mut(),
            qos: std::ptr::null_mut(),
        };
        let mut handle = std::ptr::null_mut();
        let mut status = IoStatus::default();
        // FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT; explicitly
        // require directory/non-directory. FILE_SHARE_READ denies writes/deletes.
        let options = 0x0020_0000
            | 0x20
            | match directory {
                Some(true) => 1,
                Some(false) => 0x40,
                None => 0,
            };
        let result = unsafe {
            NtCreateFile(
                &mut handle,
                0x8000_0000 | 0x0010_0000,
                &mut attributes,
                &mut status,
                std::ptr::null(),
                0,
                1,
                1,
                options,
                std::ptr::null(),
                0,
            )
        };
        if result < 0 {
            return Err(nt_error(result));
        }
        let owned = unsafe { OwnedHandle::from_raw_handle(handle) };
        let info = information(owned.as_raw_handle())?;
        if directory.is_some_and(|expected| (info.attributes & DIRECTORY != 0) != expected) {
            return Err(invalid("source object type mismatch"));
        }
        Ok(owned)
    }
    /// The root and its ancestor descriptors remain held until the snapshot ends.
    pub struct ConfinedRoot {
        directories: Vec<OwnedHandle>,
        identity: Information,
        cursor: Mutex<()>,
    }
    impl ConfinedRoot {
        pub fn open(path: &Path) -> io::Result<Self> {
            let mut parts = path.components();
            let drive = match parts.next() {
                Some(Component::Prefix(p)) => match p.kind() {
                    Prefix::Disk(d) | Prefix::VerbatimDisk(d) => d,
                    _ => return Err(invalid("only local drive roots supported")),
                },
                _ => return Err(invalid("absolute local drive root required")),
            };
            if parts.next() != Some(Component::RootDir) {
                return Err(invalid("absolute root required"));
            }
            let local_anchor: Vec<u16> = format!("{}:\\", drive as char)
                .encode_utf16()
                .chain(Some(0))
                .collect();
            // Only fixed local drive classification is accepted. Remote, removable,
            // unknown and substituted remote volumes fail before opening source.
            if unsafe { GetDriveTypeW(local_anchor.as_ptr()) } != 3 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "native source volume must be a fixed local drive",
                ));
            }
            let anchor = format!("\\\\?\\{}:\\", drive as char);
            let wide: Vec<u16> = anchor.encode_utf16().chain(Some(0)).collect();
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    0x8000_0000 | 0x0010_0000,
                    1,
                    std::ptr::null(),
                    3,
                    0x0200_0000 | 0x0020_0000,
                    std::ptr::null_mut(),
                )
            };
            if handle as isize == -1 {
                return Err(io::Error::last_os_error());
            }
            let mut directories = vec![unsafe { OwnedHandle::from_raw_handle(handle) }];
            information(directories[0].as_raw_handle())?;
            for part in parts {
                let Component::Normal(name) = part else {
                    return Err(invalid("noncanonical source root"));
                };
                let next = component(directories.last().unwrap().as_raw_handle(), name, true)?;
                directories.push(next);
            }
            let identity = information(directories.last().unwrap().as_raw_handle())?;
            Ok(Self {
                directories,
                identity,
                cursor: Mutex::new(()),
            })
        }
        fn handle(&self) -> Handle {
            self.directories.last().unwrap().as_raw_handle()
        }
        /// Enumerate a single directory, bounded and without following children.
        pub fn names(&self) -> io::Result<Vec<String>> {
            let _cursor = self
                .cursor
                .lock()
                .map_err(|_| invalid("native enumeration lock poisoned"))?;
            self.directory_names(self.handle(), Instant::now())
        }
        fn directory_names(&self, handle: Handle, started: Instant) -> io::Result<Vec<String>> {
            let mut result = Vec::new();
            let mut buffer = vec![0u8; 65536];
            let mut restart = 1;
            loop {
                check_deadline(started)?;
                let mut status = IoStatus::default();
                let code = unsafe {
                    NtQueryDirectoryFile(
                        handle,
                        std::ptr::null_mut(),
                        std::ptr::null(),
                        std::ptr::null(),
                        &mut status,
                        buffer.as_mut_ptr().cast(),
                        buffer.len() as u32,
                        12,
                        0,
                        std::ptr::null(),
                        restart,
                    )
                };
                check_deadline(started)?;
                restart = 0;
                if code as u32 == 0x8000_0006 {
                    break;
                } // STATUS_NO_MORE_FILES
                if code < 0 {
                    return Err(nt_error(code));
                }
                let length = status.information;
                if length > buffer.len() || length < 12 {
                    return Err(invalid("invalid directory inventory"));
                }
                let mut offset = 0;
                loop {
                    check_deadline(started)?;
                    if offset + 12 > length {
                        return Err(invalid("truncated inventory entry"));
                    }
                    let next =
                        u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
                    let bytes =
                        u32::from_le_bytes(buffer[offset + 8..offset + 12].try_into().unwrap())
                            as usize;
                    if bytes % 2 != 0 || offset + 12 + bytes > length {
                        return Err(invalid("invalid inventory name"));
                    }
                    let units: Vec<u16> = buffer[offset + 12..offset + 12 + bytes]
                        .chunks_exact(2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]))
                        .collect();
                    let name = String::from_utf16(&units)
                        .map_err(|_| invalid("non-Unicode inventory name"))?;
                    if name != "." && name != ".." {
                        result.push(name);
                        if result.len() > MAX_FILES {
                            return Err(invalid("inventory limit exceeded"));
                        }
                    }
                    if next == 0 {
                        break;
                    }
                    if next < 12 + bytes || offset + next >= length {
                        return Err(invalid("invalid inventory offset"));
                    }
                    offset += next;
                }
            }
            result.sort();
            let mut normalized = std::collections::BTreeSet::new();
            if result
                .iter()
                .any(|name| !normalized.insert(name.to_lowercase()))
            {
                return Err(invalid("case ambiguous native inventory"));
            }
            Ok(result)
        }
        /// Recursively snapshot all regular files, excluding Git metadata and
        /// explicitly approved output directories. This is filesystem inventory,
        /// not Git-aware source selection and is not production evidence yet.
        /// `tracked` must eventually come from the trusted Git integration.
        pub fn filesystem_snapshot(
            &self,
            head: &str,
            excludes: &[String],
            tracked: &[String],
        ) -> io::Result<crate::fingerprint::WorktreeFingerprint> {
            use std::collections::BTreeMap;
            let _cursor = self
                .cursor
                .lock()
                .map_err(|_| invalid("native enumeration lock poisoned"))?;
            let started = Instant::now();
            let deadline = || check_deadline(started);
            if head.is_empty()
                || head.len() > 1024
                || head.contains('\0')
                || excludes.len() > MAX_FILES
                || tracked.len() > MAX_FILES
                || excludes
                    .iter()
                    .chain(tracked)
                    .any(|path| path.is_empty() || path.len() > 4096 || path.contains('\0'))
                || excludes
                    .iter()
                    .chain(tracked)
                    .try_fold(0usize, |total, path| total.checked_add(path.len()))
                    .is_none_or(|bytes| bytes > 8 * 1024 * 1024)
            {
                return Err(invalid("native snapshot argument limit exceeded"));
            }
            let mut exclusions = Vec::new();
            for value in excludes {
                let prefix = value
                    .strip_suffix("/**")
                    .ok_or_else(|| invalid("output exclusion requires directory/**"))?;
                if prefix.is_empty()
                    || prefix.contains('\\')
                    || prefix.split('/').any(|p| {
                        p.is_empty()
                            || p == "."
                            || p == ".."
                            || p.contains(':')
                            || p.contains('*')
                            || p.contains('?')
                            || p.contains('\0')
                    })
                {
                    return Err(invalid("invalid output exclusion"));
                }
                let lowered = prefix.to_lowercase();
                let covered = |path: &str| {
                    let path = path.to_lowercase();
                    path == lowered || path.starts_with(&(lowered.clone() + "/"))
                };
                if covered(".progress-checker/config.json") || tracked.iter().any(|p| covered(p)) {
                    return Err(invalid(
                        "output exclusion overlaps mandatory or tracked input",
                    ));
                }
                exclusions.push(lowered);
            }
            let excluded = |path: &str| {
                let path = path.to_lowercase();
                exclusions
                    .iter()
                    .any(|prefix| path == *prefix || path.starts_with(&(prefix.clone() + "/")))
            };
            // Hold every opened directory and file through final revalidation.
            // Resource exhaustion fails closed rather than releasing identities.
            let mut directories = Vec::<(OwnedHandle, Information, Vec<String>)>::new();
            let mut pending = vec![(self.handle(), String::new())];
            let root_names = self.directory_names(self.handle(), started)?;
            let mut files = BTreeMap::<String, (File, Information)>::new();
            let mut objects = 0usize;
            let mut inventory_names = root_names.len();
            while let Some((parent, prefix)) = pending.pop() {
                deadline()?;
                let names = self.directory_names(parent, started)?;
                for name in &names {
                    deadline()?;
                    if name.eq_ignore_ascii_case(".git") {
                        continue;
                    }
                    let path = if prefix.is_empty() {
                        name.clone()
                    } else {
                        format!("{prefix}/{name}")
                    };
                    if excluded(&path) {
                        continue;
                    }
                    objects += 1;
                    if objects > MAX_FILES {
                        return Err(invalid("native inventory object limit exceeded"));
                    }
                    let handle = component_kind(parent, std::ffi::OsStr::new(name), None)?;
                    let info = information(handle.as_raw_handle())?;
                    if info.volume != self.identity.volume {
                        return Err(invalid("native inventory crossed volume"));
                    }
                    if info.attributes & DIRECTORY != 0 {
                        let child_names = self.directory_names(handle.as_raw_handle(), started)?;
                        inventory_names = inventory_names
                            .checked_add(child_names.len())
                            .ok_or_else(|| invalid("native inventory count overflow"))?;
                        if inventory_names > MAX_FILES {
                            return Err(invalid("native aggregate inventory limit exceeded"));
                        }
                        let raw = handle.as_raw_handle();
                        directories.push((handle, info, child_names));
                        pending.push((raw, path));
                    } else {
                        files.insert(path, (File::from(handle), info));
                    }
                }
            }
            let mut hash = Sha256::new();
            let frame = |hash: &mut Sha256, value: &[u8]| {
                hash.update((value.len() as u64).to_be_bytes());
                hash.update(value);
            };
            frame(&mut hash, b"progress-checker/source/v1");
            frame(&mut hash, head.as_bytes());
            let mut total = 0u64;
            let mut bytes = Vec::new();
            for (path, (file, before)) in &mut files {
                deadline()?;
                let size = ((before.size_high as u64) << 32) | before.size_low as u64;
                total = total
                    .checked_add(size)
                    .ok_or_else(|| invalid("native input byte overflow"))?;
                if size > MAX_FILE || total > MAX_TOTAL {
                    return Err(invalid("native input byte limit exceeded"));
                }
                bytes.clear();
                let mut block = [0u8; 65536];
                loop {
                    deadline()?;
                    let count = file.read(&mut block)?;
                    if count == 0 {
                        break;
                    }
                    if bytes.len() as u64 + count as u64 > MAX_FILE {
                        return Err(invalid("native input grew beyond bound"));
                    }
                    bytes.extend_from_slice(&block[..count]);
                }
                let mut after = information(file.as_raw_handle())?;
                after.access = before.access;
                if after != *before || bytes.len() as u64 != size {
                    return Err(invalid("native input changed during read"));
                }
                frame(&mut hash, path.as_bytes());
                frame(&mut hash, b"regular");
                frame(&mut hash, &bytes);
            }
            // Re-enumerate complete directory names, including excluded output
            // names. Concurrent creation anywhere fails closed for this snapshot.
            for (directory, before, names) in &directories {
                deadline()?;
                let mut after = information(directory.as_raw_handle())?;
                after.access = before.access;
                if after != *before
                    || self.directory_names(directory.as_raw_handle(), started)? != *names
                {
                    return Err(invalid("native directory changed during snapshot"));
                }
            }
            for (file, before) in files.values() {
                deadline()?;
                let mut after = information(file.as_raw_handle())?;
                after.access = before.access;
                if after != *before {
                    return Err(invalid("native source identity changed"));
                }
            }
            let mut root_after = information(self.handle())?;
            root_after.access = self.identity.access;
            if root_after != self.identity
                || self.directory_names(self.handle(), started)? != root_names
            {
                return Err(invalid("native root changed during snapshot"));
            }
            deadline()?;
            Ok(crate::fingerprint::WorktreeFingerprint {
                head: if head == "unborn" {
                    None
                } else {
                    Some(head.to_owned())
                },
                digest: format!("sha256:{:x}", hash.finalize()),
                input_count: files.len(),
            })
        }
        /// Hash supplied literal source paths. Selection must come from a trusted
        /// inventory. This primitive does not grant evidence or execute commands.
        pub fn hash_paths(&self, paths: &[String]) -> io::Result<Vec<(String, String, u64)>> {
            let _cursor = self
                .cursor
                .lock()
                .map_err(|_| invalid("native enumeration lock poisoned"))?;
            let started = Instant::now();
            if paths.len() > MAX_FILES
                || paths
                    .iter()
                    .any(|path| path.is_empty() || path.len() > 4096 || path.contains('\0'))
                || paths
                    .iter()
                    .try_fold(0usize, |total, path| total.checked_add(path.len()))
                    .is_none_or(|bytes| bytes > 8 * 1024 * 1024)
            {
                return Err(invalid("input count limit exceeded"));
            }
            let mut total = 0u64;
            let mut output = Vec::new();
            for path in paths {
                check_deadline(started)?;
                let mut names = Path::new(path).components().peekable();
                let mut parent = self.handle();
                let mut held = Vec::new();
                let mut file = None;
                while let Some(part) = names.next() {
                    let Component::Normal(name) = part else {
                        return Err(invalid("literal relative source paths required"));
                    };
                    if name.to_string_lossy().eq_ignore_ascii_case(".git") {
                        return Err(invalid("Git metadata is not a source input"));
                    }
                    let directory = names.peek().is_some();
                    let opened = component(parent, name, directory)?;
                    if directory {
                        held.push(opened);
                        parent = held.last().unwrap().as_raw_handle();
                    } else {
                        file = Some(opened);
                    }
                }
                let opened = file.ok_or_else(|| invalid("empty source input"))?;
                let before = information(opened.as_raw_handle())?;
                if before.volume != self.identity.volume {
                    return Err(invalid("source crossed volume boundary"));
                }
                let size = ((before.size_high as u64) << 32) | before.size_low as u64;
                total = total
                    .checked_add(size)
                    .ok_or_else(|| invalid("input size overflow"))?;
                if size > MAX_FILE || total > MAX_TOTAL {
                    return Err(invalid("input byte limit exceeded"));
                }
                let mut reader = File::from(opened);
                let mut hash = Sha256::new();
                let mut bytes = [0u8; 65536];
                let mut count = 0u64;
                loop {
                    check_deadline(started)?;
                    let read = reader.read(&mut bytes)?;
                    if read == 0 {
                        break;
                    }
                    count += read as u64;
                    if count > MAX_FILE {
                        return Err(invalid("file grew beyond bound"));
                    }
                    hash.update(&bytes[..read]);
                }
                let after = information(reader.as_raw_handle())?;
                // Last access time may change on read; all other binding fields must match.
                let mut stable_after = after;
                stable_after.access = before.access;
                if stable_after != before || count != size {
                    return Err(invalid("source changed during read"));
                }
                output.push((path.clone(), format!("sha256:{:x}", hash.finalize()), size));
            }
            let mut after = information(self.handle())?;
            after.access = self.identity.access;
            if after != self.identity {
                return Err(invalid("source root changed during snapshot"));
            }
            Ok(output)
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn confined_source_hashes_full_content_and_rejects_escape() {
            let directory = tempfile::tempdir().unwrap();
            std::fs::write(directory.path().join("source.txt"), b"source bytes").unwrap();
            let root = ConfinedRoot::open(directory.path()).unwrap();
            assert!(root.names().unwrap().contains(&"source.txt".to_owned()));
            let result = root.hash_paths(&["source.txt".to_owned()]).unwrap();
            assert_eq!(result[0].2, 12);
            assert_eq!(
                result[0].1,
                format!("sha256:{:x}", Sha256::digest(b"source bytes"))
            );
            for escaped in [
                "../source.txt",
                "C:\\source.txt",
                ".git/config",
                "source.txt:stream",
            ] {
                assert!(root.hash_paths(&[escaped.to_owned()]).is_err());
            }
        }

        #[test]
        fn recursive_snapshot_frames_full_content_and_validates_exclusions() {
            let directory = tempfile::tempdir().unwrap();
            std::fs::create_dir(directory.path().join("nested")).unwrap();
            std::fs::create_dir(directory.path().join("output")).unwrap();
            std::fs::write(directory.path().join("nested/source"), b"content").unwrap();
            std::fs::write(directory.path().join("output/artifact"), b"build").unwrap();
            let root = ConfinedRoot::open(directory.path()).unwrap();
            let snapshot = root
                .filesystem_snapshot(
                    "unborn",
                    &["output/**".to_owned()],
                    &["nested/source".to_owned()],
                )
                .unwrap();
            let mut expected = Sha256::new();
            for bytes in [
                b"progress-checker/source/v1".as_slice(),
                b"unborn",
                b"nested/source",
                b"regular",
                b"content",
            ] {
                expected.update((bytes.len() as u64).to_be_bytes());
                expected.update(bytes);
            }
            assert_eq!(snapshot.input_count, 1);
            assert_eq!(snapshot.digest, format!("sha256:{:x}", expected.finalize()));
            assert!(
                root.filesystem_snapshot(
                    "unborn",
                    &["nested/**".to_owned()],
                    &["nested/source".to_owned()]
                )
                .is_err()
            );
            assert!(
                root.filesystem_snapshot("unborn", &[".progress-checker/**".to_owned()], &[])
                    .is_err()
            );
        }

        #[test]
        fn held_root_denies_rename_and_delete_sharing() {
            let directory = tempfile::tempdir().unwrap();
            let root = ConfinedRoot::open(directory.path()).unwrap();
            let renamed = directory.path().with_extension("replaced");
            assert!(std::fs::rename(directory.path(), &renamed).is_err());
            drop(root);
        }
    }
}
#[cfg(windows)]
pub use native::ConfinedRoot;

#[cfg(test)]
mod limit_tests {
    use super::*;

    #[test]
    fn native_snapshot_limits_are_explicit_and_bounded() {
        assert_eq!(SNAPSHOT_LIMITS.maximum_objects, 50_000);
        assert_eq!(SNAPSHOT_LIMITS.maximum_file_bytes, 64 * 1024 * 1024);
        assert_eq!(SNAPSHOT_LIMITS.maximum_total_bytes, 512 * 1024 * 1024);
        assert!(SNAPSHOT_LIMITS.maximum_file_bytes <= SNAPSHOT_LIMITS.maximum_total_bytes);
        assert_eq!(SNAPSHOT_LIMITS.cooperative_deadline_seconds, 30);
    }
}
