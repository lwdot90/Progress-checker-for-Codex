//! Native Windows runtime manifest collector. No shell, PATH search, registry,
//! environment enumeration, or package-manager execution is performed.
//!
//! Integration must supply an explicit approved runtime closure: interpreter,
//! runtime DLLs, helper, and libraries it can load. A signature alone does not
//! establish immutable installation ACLs or a complete dependency closure.
//! References: https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust
//! https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew

use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};

const MAX_FILES: usize = 256;
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);

/// This is evidence identity, not proof of executable trust or authorization.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RuntimeFileIdentity {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
}

/// Open with only read sharing on Windows, denying replacement/write handles
/// for the lifetime of the collector. Existing incompatible handles fail closed.
fn open_read_locked(path: &std::path::Path) -> Result<File, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1); // FILE_SHARE_READ; no WRITE or DELETE sharing.
    }
    options
        .open(path)
        .map_err(|_| "runtime file unavailable for stable read".into())
}

fn digest(file: &mut File, started: Instant) -> Result<String, String> {
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "runtime read failed")?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65536];
    let mut bytes = 0_u64;
    loop {
        if started.elapsed() > DEADLINE {
            return Err("runtime inventory time limit exceeded".into());
        }
        let count = file.read(&mut buffer).map_err(|_| "runtime read failed")?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        if bytes > MAX_FILE_BYTES {
            return Err("runtime file size limit exceeded".into());
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}

/// Collect observations of explicit files. All read locks are released before
/// this function returns; these observations cannot authorize or protect launch.
/// Launch preparation must use RuntimeManifest::collect and retain that guard,
/// audit installation trust separately, and bind identities into the grant.
/// This API has no default runtime paths or package inventory claim: Windows
/// applications have no universal package database. A complete closure must
/// include transitive DLLs, API-set mappings, dynamically loaded libraries, and
/// interpreter modules; the static PE parser does not establish that closure.
pub fn collect_runtime_files(paths: &[PathBuf]) -> Result<Vec<RuntimeFileIdentity>, String> {
    Ok(RuntimeManifest::collect(paths)?.identities().to_vec())
}

/// Retains all runtime file locks until dropped. Keep this object alive through
/// process creation and execution; serializing identities never transfers locks.
pub struct RuntimeManifest {
    bindings: Vec<(PathBuf, PathBuf)>,
    opened: Vec<(PathBuf, File, u64)>,
    identities: Vec<RuntimeFileIdentity>,
}

impl RuntimeManifest {
    pub fn identities(&self) -> &[RuntimeFileIdentity] {
        &self.identities
    }

    /// Fresh full hash plus requested path and file-object identity comparison.
    pub fn revalidate(&mut self) -> Result<(), String> {
        let started = Instant::now();
        for (requested, canonical) in &self.bindings {
            if requested
                .canonicalize()
                .map_err(|_| "runtime path changed")?
                != *canonical
            {
                return Err("runtime path changed".into());
            }
        }
        for ((path, file, bytes), identity) in self.opened.iter_mut().zip(&self.identities) {
            let fresh = open_read_locked(path)?;
            if file_identity(file)? != file_identity(&fresh)?
                || file
                    .metadata()
                    .map_err(|_| "runtime metadata unavailable")?
                    .len()
                    != *bytes
                || digest(file, started)? != identity.sha256
            {
                return Err("runtime closure changed during collection".into());
            }
        }
        Ok(())
    }

    pub fn collect(paths: &[PathBuf]) -> Result<Self, String> {
        if paths.is_empty() || paths.len() > MAX_FILES {
            return Err("runtime closure must contain 1 through 256 explicit files".into());
        }
        let started = Instant::now();
        let mut canonical = Vec::new();
        let mut bindings = Vec::new();
        for path in paths {
            if !path.is_absolute() {
                return Err("runtime path must be absolute".into());
            }
            let resolved = path
                .canonicalize()
                .map_err(|_| "runtime path unavailable")?;
            bindings.push((path.clone(), resolved.clone()));
            canonical.push(resolved);
        }
        canonical.sort();
        canonical.dedup();
        let mut opened = Vec::new();
        let mut total = 0_u64;
        for path in canonical {
            let file = open_read_locked(&path)?;
            let metadata = file
                .metadata()
                .map_err(|_| "runtime metadata unavailable")?;
            if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
                return Err("runtime closure contains unsupported file".into());
            }
            total = total
                .checked_add(metadata.len())
                .ok_or("runtime size overflow")?;
            if total > MAX_TOTAL_BYTES {
                return Err("runtime inventory size limit exceeded".into());
            }
            opened.push((path, file, metadata.len()));
        }
        let mut result = Vec::new();
        for (path, file, bytes) in &mut opened {
            result.push(RuntimeFileIdentity {
                path: path.clone(),
                bytes: *bytes,
                sha256: digest(file, started)?,
            });
        }
        let mut manifest = Self {
            bindings,
            opened,
            identities: result,
        };
        manifest.revalidate()?;
        Ok(manifest)
    }
}

#[cfg(unix)]
fn file_identity(file: &File) -> Result<(u64, u64), String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file
        .metadata()
        .map_err(|_| "runtime identity unavailable")?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn file_identity(file: &File) -> Result<(u64, u64), String> {
    use crate::platform::windows_ffi::{FileInformation, GetFileInformationByHandle};
    use std::os::windows::io::AsRawHandle;
    let mut info = FileInformation { values: [0; 13] };
    if unsafe {
        GetFileInformationByHandle(
            file.as_raw_handle(),
            (&mut info as *mut FileInformation).cast(),
        )
    } == 0
    {
        return Err("runtime file identity unavailable".into());
    }
    Ok((
        u64::from(info.values[7]),
        (u64::from(info.values[11]) << 32) | u64::from(info.values[12]),
    ))
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_file: &File) -> Result<(u64, u64), String> {
    Err("runtime file identity unsupported on this platform".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_collects_explicit_bytes_and_revalidates() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("runtime.bin");
        std::fs::write(&path, b"runtime").unwrap();
        let mut manifest = RuntimeManifest::collect(&[path]).unwrap();
        assert_eq!(manifest.identities()[0].bytes, 7);
        manifest.revalidate().unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn replacement_and_symlink_retarget_are_rejected() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        let link = root.path().join("link");
        std::fs::write(&first, b"same").unwrap();
        std::fs::write(&second, b"same").unwrap();
        symlink(&first, &link).unwrap();
        let mut manifest = RuntimeManifest::collect(&[link.clone()]).unwrap();
        std::fs::remove_file(&link).unwrap();
        symlink(&second, &link).unwrap();
        assert!(manifest.revalidate().is_err());
        let mut manifest = RuntimeManifest::collect(&[first.clone()]).unwrap();
        std::fs::rename(&second, &first).unwrap();
        assert!(manifest.revalidate().is_err());
    }
    #[cfg(windows)]
    #[test]
    fn held_runtime_manifest_denies_write_then_releases_on_drop() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("runtime.bin");
        std::fs::write(&path, b"same").unwrap();
        let manifest = RuntimeManifest::collect(&[path.clone()]).unwrap();
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        drop(manifest);
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_ok());
    }
}
