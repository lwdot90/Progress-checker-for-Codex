//! Experimental isolated snapshot ACL broker. No live project/home/state mounts.
//! Explicit bytes must come from a future source-bound approved snapshot broker;
//! this primitive does not authenticate their provenance or authorize execution.
//! Production preparation remains unavailable until Windows qualification.
//!
//! Unresolved integration requirements: bind copied bytes and runtime closure to
//! the exact human approval/source digest; retain this snapshot and canonical cwd
//! guards in the launch contract; prevent identity reuse and audit profile/network
//! exemptions; prove parent traversal exposes only the snapshot; revoke partial
//! grants on sealing failure and securely retire snapshots. Existing input locks
//! deny delete/atomic replacement, and non-inheriting ACLs require an explicit
//! policy for child-created objects. ACL revalidation is not a content hash.
//! https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
//! https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format

fn validate_relative(path: &str) -> Result<Vec<&str>, String> {
    if path.is_empty() || path.len() > 4096 || path.starts_with(['/', '\\']) {
        return Err("snapshot path must be a bounded relative path".into());
    }
    let components: Vec<_> = path.split(['/', '\\']).collect();
    for name in &components {
        if name.is_empty()
            || matches!(*name, "." | "..")
            || name.ends_with(['.', ' '])
            || name.chars().any(|ch| ch < ' ' || "<>:\"|?*".contains(ch))
        {
            return Err("snapshot path contains ambiguous Windows components".into());
        }
        let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
        if matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || matches!(
            stem.strip_prefix("COM")
                .or_else(|| stem.strip_prefix("LPT")),
            Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³")
        ) {
            return Err("snapshot path contains reserved Windows devices".into());
        }
    }
    Ok(components)
}

fn validate_app_sid(sid: &str) -> Result<(), String> {
    let suffix = sid
        .strip_prefix("S-1-15-2-")
        .ok_or("only a specific AppContainer package SID is permitted")?;
    // Derived per-profile package SIDs have seven hash subauthorities; broad
    // ALL_APPLICATION_PACKAGES and ALL_RESTRICTED_APPLICATION_PACKAGES do not.
    if suffix.split('-').count() != 7
        || suffix
            .split('-')
            .any(|part| part.is_empty() || part.parse::<u32>().is_err())
        || sid.len() > 184
    {
        return Err("invalid or broad application-package SID".into());
    }
    Ok(())
}

pub fn require_qualified_project_broker() -> Result<(), String> {
    Err("native Windows source-bound snapshot/ACL broker is not qualified".into())
}

#[cfg(windows)]
pub use native::{ProjectSnapshot, SnapshotBuilder};

#[cfg(windows)]
mod native {
    use super::super::windows_ffi::*;
    use super::super::windows_state::{PrivateDirectory, current_user_sid};
    use std::{
        collections::BTreeMap,
        fs::File,
        io::Write,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle},
        },
        path::{Path, PathBuf},
    };
    const READ_EXECUTE: u32 = 0x001200a9;
    const PROJECT_MODIFY: u32 = 0x001301ff; // Read/write/execute/delete, NOT WRITE_DAC/WRITE_OWNER.
    const FULL: u32 = 0x001f01ff;
    struct Allocation(Handle);
    impl Drop for Allocation {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    struct Object {
        file: File,
        directory: bool,
    }
    fn wide(path: &Path) -> Result<Vec<u16>, String> {
        let mut value: Vec<_> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err("snapshot path contains NUL".into());
        }
        value.push(0);
        Ok(value)
    }
    fn descriptor(user: &str, app: Option<(&str, u32)>) -> Result<Allocation, String> {
        let child = app
            .map(|(sid, mask)| format!("(A;;0x{mask:08x};;;{sid})"))
            .unwrap_or_default();
        // Every object gets a protected explicit ACL; no inherited/broad rights.
        let text = format!("O:{user}D:P(A;;FA;;;{user})(A;;FA;;;SY){child}");
        let encoded: Vec<_> = text.encode_utf16().chain(Some(0)).collect();
        let mut raw = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                encoded.as_ptr(),
                1,
                &mut raw,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(format!(
                "snapshot descriptor creation failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Allocation(raw))
    }
    fn sid_string(sid: Handle) -> Result<String, String> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err("invalid snapshot ACL SID".into());
        }
        let mut raw = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
            return Err("snapshot SID conversion failed".into());
        }
        let _allocation = Allocation(raw.cast());
        let mut count = 0;
        while count < 256 && unsafe { *raw.add(count) } != 0 {
            count += 1;
        }
        if count == 256 {
            return Err("snapshot SID length limit".into());
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(raw, count) })
            .map_err(|_| "snapshot SID encoding failed".into())
    }
    fn audit(object: &Object, user: &str, app: Option<(&str, u32)>) -> Result<(), String> {
        let mut info = [0u32; 13];
        if unsafe {
            GetFileInformationByHandle(object.file.as_raw_handle(), info.as_mut_ptr().cast())
        } == 0
            || info[0] & 0x400 != 0
            || (info[0] & 0x10 != 0) != object.directory
        {
            return Err("snapshot object is unavailable, reparsed, or changed kind".into());
        }
        if !object.directory && info[10] != 1 {
            return Err("snapshot hard links are unsupported".into());
        }
        let mut owner = std::ptr::null_mut();
        let mut acl = std::ptr::null_mut();
        let mut sd = std::ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                object.file.as_raw_handle(),
                1,
                1 | 4,
                &mut owner,
                std::ptr::null_mut(),
                &mut acl,
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        if status != 0 {
            return Err(format!("snapshot ACL read failed: {status}"));
        }
        let _allocation = Allocation(sd);
        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) } == 0
            || control & 0x1000 == 0
            || sid_string(owner)? != user
            || acl.is_null()
            || unsafe { IsValidAcl(acl) } == 0
        {
            return Err("snapshot owner/protected ACL does not match broker".into());
        }
        let mut expected = BTreeMap::from([(user.to_owned(), FULL), ("S-1-5-18".to_owned(), FULL)]);
        if let Some((sid, mask)) = app {
            expected.insert(sid.to_owned(), mask);
        }
        if unsafe { (*acl).count as usize } != expected.len() {
            return Err("unexpected snapshot ACL principal count".into());
        }
        for index in 0..unsafe { (*acl).count } {
            let mut raw = std::ptr::null_mut();
            if unsafe { GetAce(acl, u32::from(index), &mut raw) } == 0 || raw.is_null() {
                return Err("snapshot ACE unavailable".into());
            }
            let header = unsafe { &*raw.cast::<AceHeader>() };
            if header.kind != 0 || header.flags != 0 || header.size < 16 {
                return Err("unsupported snapshot ACE".into());
            }
            let mask = unsafe { *raw.cast::<u8>().add(4).cast::<u32>() };
            let sid = unsafe { raw.cast::<u8>().add(8).cast() };
            if unsafe { IsValidSid(sid) } == 0
                || unsafe { GetLengthSid(sid) } > u32::from(header.size) - 8
            {
                return Err("invalid snapshot ACE SID".into());
            }
            if expected.remove(&sid_string(sid)?) != Some(mask) {
                return Err("snapshot ACL grants unexpected permissions".into());
            }
        }
        if !expected.is_empty() {
            return Err("snapshot ACL is missing expected permissions".into());
        }
        Ok(())
    }
    fn set_acl(object: &Object, user: &str, app: &str, mask: u32) -> Result<(), String> {
        let sd = descriptor(user, Some((app, mask)))?;
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = std::ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) } == 0
            || present == 0
            || dacl.is_null()
        {
            return Err("snapshot ACL descriptor is missing DACL".into());
        }
        let status = unsafe {
            SetSecurityInfo(
                object.file.as_raw_handle(),
                1,
                4 | 0x80000000,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(format!("snapshot ACL install failed: {status}"));
        }
        audit(object, user, Some((app, mask)))
    }
    fn create_object(path: &Path, directory: bool, user: &str) -> Result<Object, String> {
        let sd = descriptor(user, None)?;
        let sa = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            descriptor: sd.0,
            inherit: 0,
        };
        let encoded = wide(path)?;
        if directory && unsafe { CreateDirectoryW(encoded.as_ptr(), &sa) } == 0 {
            return Err("exclusive snapshot directory creation failed".into());
        }
        let raw = unsafe {
            CreateFileW(
                encoded.as_ptr(),
                if directory { 0x00060080 } else { 0xc0060080 },
                3,
                &sa,
                if directory { 3 } else { 1 },
                0x00200000 | if directory { 0x02000000 } else { 0 },
                std::ptr::null_mut(),
            )
        };
        if raw == (-1isize) as Handle {
            return Err("exclusive snapshot handle creation failed".into());
        }
        let object = Object {
            file: unsafe { File::from_raw_handle(raw) },
            directory,
        };
        audit(&object, user, None)?;
        Ok(object)
    }

    /// Stages explicitly supplied project bytes under an OS-audited broker-only
    /// parent. Partial snapshots remain private; AppContainer ACLs installed last.
    pub struct SnapshotBuilder {
        root: PathBuf,
        user: String,
        app: String,
        bytes: usize,
        objects: BTreeMap<PathBuf, Object>,
        _parent: PrivateDirectory,
    }
    impl SnapshotBuilder {
        pub fn create(parent: &Path, name: &str, app_sid: &str) -> Result<Self, String> {
            let names = super::validate_relative(name)?;
            if names.len() != 1 {
                return Err("snapshot root must be one unique child name".into());
            }
            super::validate_app_sid(app_sid)?;
            let parent_guard = PrivateDirectory::open_existing(parent)?;
            let user = current_user_sid()?;
            let root = parent.join(name);
            let object = create_object(&root, true, &user)?;
            Ok(Self {
                root,
                user,
                app: app_sid.into(),
                bytes: 0,
                objects: BTreeMap::from([(PathBuf::new(), object)]),
                _parent: parent_guard,
            })
        }
        pub fn add_file(&mut self, relative: &str, bytes: &[u8]) -> Result<(), String> {
            let components = super::validate_relative(relative)?;
            if bytes.len() > 128 * 1024 * 1024
                || self
                    .bytes
                    .checked_add(bytes.len())
                    .is_none_or(|total| total > 512 * 1024 * 1024)
                || self.objects.len() >= 100_000
            {
                return Err("snapshot resource limit exceeded".into());
            }
            let mut path = PathBuf::new();
            for name in &components[..components.len() - 1] {
                path.push(name);
                if !self.objects.contains_key(&path) {
                    let object = create_object(&self.root.join(&path), true, &self.user)?;
                    self.objects.insert(path.clone(), object);
                }
                let object = self.objects.get(&path).ok_or("snapshot parent missing")?;
                if !object.directory {
                    return Err("snapshot ancestor is not a directory".into());
                }
                audit(object, &self.user, None)?;
            }
            path.push(components.last().ok_or("missing snapshot file name")?);
            let mut object = create_object(&self.root.join(&path), false, &self.user)?;
            object
                .file
                .write_all(bytes)
                .map_err(|_| "snapshot write failed")?;
            object
                .file
                .sync_all()
                .map_err(|_| "snapshot flush failed")?;
            self.bytes += bytes.len();
            self.objects.insert(path, object);
            Ok(())
        }
        /// Child access is explicit per object. No original project or runtime
        /// directories are exposed; runtime must be separately copied/read-only.
        pub fn seal(self, read_only: bool) -> Result<ProjectSnapshot, String> {
            let mask = if read_only {
                READ_EXECUTE
            } else {
                PROJECT_MODIFY
            };
            // Grant descendants first, root last. No child may be launched until
            // this finishes. Identity reuse and traverse privileges must be
            // addressed by the broker; root ordering alone is not isolation.
            for (path, object) in self
                .objects
                .iter()
                .filter(|(path, _)| !path.as_os_str().is_empty())
            {
                let _ = path;
                set_acl(object, &self.user, &self.app, mask)?;
            }
            set_acl(
                self.objects
                    .get(Path::new(""))
                    .ok_or("snapshot root missing")?,
                &self.user,
                &self.app,
                mask,
            )?;
            Ok(ProjectSnapshot {
                builder: self,
                mask,
            })
        }
    }
    pub struct ProjectSnapshot {
        builder: SnapshotBuilder,
        mask: u32,
    }
    impl ProjectSnapshot {
        pub fn path(&self) -> &Path {
            &self.builder.root
        }
        pub fn revalidate(&self) -> Result<(), String> {
            for object in self.builder.objects.values() {
                audit(
                    object,
                    &self.builder.user,
                    Some((&self.builder.app, self.mask)),
                )?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn snapshot_names_reject_traversal_devices_streams_and_ambiguity() {
        for bad in [
            "",
            "../secret",
            "C:\\home",
            "\\\\server\\share",
            "a:stream",
            "NUL.txt",
            "COM¹.txt",
            "com²",
            "LPT³.log",
            "a/../b",
            "a//b",
            "a. ",
            "file\0",
        ] {
            assert!(super::validate_relative(bad).is_err(), "{bad:?}");
        }
        assert!(super::validate_relative("src/main.rs").is_ok());
    }
    #[test]
    fn broad_application_principals_are_never_granted() {
        for bad in [
            "S-1-15-2-1",
            "S-1-15-2-2",
            "S-1-15-3-42",
            "S-1-1-0",
            "S-1-15-2-",
            "S-1-15-2-1;FA;;;WD",
        ] {
            assert!(super::validate_app_sid(bad).is_err());
        }
        assert!(super::validate_app_sid("S-1-15-2-123-456-789-234-567-890-111").is_ok());
        assert!(super::require_qualified_project_broker().is_err());
    }
}
