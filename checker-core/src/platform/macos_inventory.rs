//! Conservative macOS identity inputs. This is not a package dependency closure
//! or a declaration that macOS check execution has been qualified.
use std::path::PathBuf;

/// Collect bounded, content-based identities for the OS version, system dynamic
/// loader, and explicitly approved executables. Callers must separately bind any
/// additional runtime/dependency mounts exposed to their execution sandbox.
pub fn collect(executables: &[PathBuf]) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "macos")]
    {
        native::collect(executables)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = executables;
        Err("macOS environment identity requires a native macOS host".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn another_host_cannot_supply_macos_identity() {
        assert!(collect(&[]).unwrap_err().contains("native macOS host"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn excessive_input_count_is_rejected_before_collection() {
        assert!(
            collect(&vec![PathBuf::from("/usr/bin/true"); 127])
                .unwrap_err()
                .contains("file limit")
        );
    }
}

#[cfg(target_os = "macos")]
mod native {
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File},
        io::Read,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    const MAX_FILES: usize = 128;
    const MAX_BYTES: u64 = 512 * 1024 * 1024;
    const MAX_TIME: Duration = Duration::from_secs(30);

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Stamp {
        dev: u64,
        ino: u64,
        len: u64,
        mtime: (i64, i64),
        ctime: (i64, i64),
        mode: u32,
        uid: u32,
    }

    fn trusted(metadata: &fs::Metadata) -> Result<Stamp, String> {
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(
                "macOS identity input must be a root-owned, non-writable regular file".into(),
            );
        }
        Ok(identity_stamp(metadata))
    }

    fn identity_stamp(metadata: &fs::Metadata) -> Stamp {
        Stamp {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
            mode: metadata.mode(),
            uid: metadata.uid(),
        }
    }

    fn stamp(path: &Path) -> Result<Stamp, String> {
        trusted(&fs::metadata(path).map_err(|e| format!("macOS identity input unavailable: {e}"))?)
    }

    fn trusted_path(path: &Path) -> Result<PathBuf, String> {
        let canonical = path
            .canonicalize()
            .map_err(|e| format!("macOS identity path unavailable: {e}"))?;
        if !canonical.starts_with("/System")
            && !canonical.starts_with("/usr")
            && !canonical.starts_with("/bin")
            && !canonical.starts_with("/sbin")
        {
            return Err("macOS identity inputs must resolve inside trusted system paths".into());
        }
        // A trusted file under a writable ancestor is replaceable even when its
        // own permissions look safe. Check all canonical ancestors as well.
        for ancestor in canonical.ancestors().skip(1) {
            let metadata = fs::metadata(ancestor).map_err(|e| e.to_string())?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err("macOS identity input has an untrusted parent directory".into());
            }
        }
        Ok(canonical)
    }

    fn digest_file(file: &mut File, started: Instant, total: &mut u64) -> Result<String, String> {
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            if started.elapsed() > MAX_TIME {
                return Err("macOS environment identity exceeds time limit".into());
            }
            let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            *total = total
                .checked_add(count as u64)
                .ok_or("macOS identity size overflow")?;
            if *total > MAX_BYTES {
                return Err("macOS environment identity exceeds size limit".into());
            }
            digest.update(&buffer[..count]);
        }
        Ok(format!("{:x}", digest.finalize()))
    }

    pub(super) fn collect(executables: &[PathBuf]) -> Result<Vec<u8>, String> {
        if executables.len() > MAX_FILES - 2 {
            return Err("macOS environment identity exceeds file limit".into());
        }
        let requested = [
            PathBuf::from("/System/Library/CoreServices/SystemVersion.plist"),
            PathBuf::from("/usr/lib/dyld"),
        ]
        .into_iter()
        .chain(executables.iter().cloned())
        .collect::<Vec<_>>();
        let paths = requested
            .iter()
            .map(|p| trusted_path(p))
            .collect::<Result<Vec<_>, _>>()?;
        let before = paths
            .iter()
            .map(|p| stamp(p))
            .collect::<Result<Vec<_>, _>>()?;
        let started = Instant::now();
        let mut total = 0u64;
        let mut identities = Vec::new();
        let mut digests = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            if trusted_path(&requested[index])? != *path || stamp(path)? != before[index] {
                return Err("macOS environment changed before reading identity inputs".into());
            }
            let mut file = File::open(path).map_err(|e| e.to_string())?;
            if trusted(&file.metadata().map_err(|e| e.to_string())?)? != before[index] {
                return Err("macOS environment changed while opening identity inputs".into());
            }
            let digest = digest_file(&mut file, started, &mut total)?;
            if trusted(&file.metadata().map_err(|e| e.to_string())?)? != before[index]
                || trusted_path(&requested[index])? != *path
                || stamp(path)? != before[index]
            {
                return Err("macOS environment changed while reading identity inputs".into());
            }
            identities.push(serde_json::json!({
                "requested": requested[index], "canonical": path,
                "size": before[index].len, "sha256": digest.clone()
            }));
            digests.push(digest);
        }
        // Reopen the complete original path closure, not just retained file
        // handles: same-size rewrites and alias retargeting must invalidate it.
        for (index, requested_path) in requested.iter().enumerate() {
            if trusted_path(requested_path)? != paths[index]
                || stamp(&paths[index])? != before[index]
            {
                return Err("macOS environment changed while collecting identities".into());
            }
            let mut file = File::open(&paths[index]).map_err(|e| e.to_string())?;
            if trusted(&file.metadata().map_err(|e| e.to_string())?)? != before[index]
                || digest_file(&mut file, started, &mut total)? != digests[index]
                || trusted(&file.metadata().map_err(|e| e.to_string())?)? != before[index]
            {
                return Err("macOS runtime closure content changed during revalidation".into());
            }
        }
        for (index, requested_path) in requested.iter().enumerate() {
            if trusted_path(requested_path)? != paths[index]
                || stamp(&paths[index])? != before[index]
            {
                return Err("macOS runtime closure paths changed during revalidation".into());
            }
        }
        serde_json::to_vec(&serde_json::json!({
            "schema": "progress-checker.macos-system-identity.v1",
            "architecture": std::env::consts::ARCH,
            "scope": "os-version-loader-and-explicit-executables",
            "files": identities
        }))
        .map_err(|e| e.to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{PermissionsExt, symlink};

        #[test]
        fn writable_fixture_is_never_trusted() {
            let root = tempfile::tempdir().unwrap();
            let file = root.path().join("runtime");
            fs::write(&file, b"runtime").unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
            assert!(trusted(&fs::metadata(file).unwrap()).is_err());
        }

        #[test]
        fn symlink_to_non_system_fixture_is_rejected() {
            let root = tempfile::tempdir().unwrap();
            let file = root.path().join("runtime");
            let link = root.path().join("runtime-link");
            fs::write(&file, b"runtime").unwrap();
            symlink(&file, &link).unwrap();
            assert!(
                trusted_path(&link)
                    .unwrap_err()
                    .contains("trusted system paths")
            );
        }

        #[test]
        fn identity_stamp_detects_same_size_rewrite_and_atomic_replacement() {
            let root = tempfile::tempdir().unwrap();
            let file = root.path().join("runtime");
            fs::write(&file, b"before").unwrap();
            let before = identity_stamp(&fs::metadata(&file).unwrap());
            std::thread::sleep(Duration::from_millis(2));
            fs::write(&file, b"after!").unwrap();
            let rewritten = identity_stamp(&fs::metadata(&file).unwrap());
            assert_ne!(before, rewritten);
            let replacement = root.path().join("replacement");
            fs::write(&replacement, b"after!").unwrap();
            fs::rename(&replacement, &file).unwrap();
            assert_ne!(rewritten, identity_stamp(&fs::metadata(&file).unwrap()));
        }
    }
}
