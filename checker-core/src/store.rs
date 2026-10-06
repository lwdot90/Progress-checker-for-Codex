//! Project-external, single-writer persistence. A held store owns the writer lock.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_HISTORY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HISTORY_FILES: usize = 2048;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u32,
    context: String,
    authentication: String,
    payload: serde_json::Value,
}

/// A corrupt primary snapshot is retained for inspection; a validated backup may
/// be loaded instead. Neither path ever deletes immutable history.
#[derive(Debug)]
pub struct LoadedSnapshot<T> {
    pub value: Option<T>,
    pub warning: Option<String>,
}

pub struct StateStore {
    directory: PathBuf,
    _lock: File,
    key: [u8; 32],
}

impl Drop for StateStore {
    fn drop(&mut self) {
        // A concurrent fork temporarily inherits this open file description
        // until exec closes its CLOEXEC descriptor. Explicitly release our
        // ownership so that such a child cannot delay the next writer after
        // this store has finished all writes.
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn authenticate(bytes: &[u8], key: &[u8; 32]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("fixed HMAC key");
    mac.update(bytes);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn verify_authentication(bytes: &[u8], key: &[u8; 32], encoded: &str) -> bool {
    if encoded.len() != 64 || !encoded.is_ascii() {
        return false;
    }
    let signature: Result<Vec<_>, _> = (0..64)
        .step_by(2)
        .map(|offset| u8::from_str_radix(&encoded[offset..offset + 2], 16))
        .collect();
    let Ok(signature) = signature else {
        return false;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("fixed HMAC key");
    mac.update(bytes);
    mac.verify_slice(&signature).is_ok()
}

fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

fn reject_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(invalid(format!(
            "state path is a symlink: {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn prospective_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    if absolute
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid("state base may not contain parent traversal"));
    }
    let mut ancestor = absolute.as_path();
    let mut missing = Vec::new();
    while !ancestor.exists() {
        missing.push(
            ancestor
                .file_name()
                .ok_or_else(|| invalid("invalid state base"))?
                .to_os_string(),
        );
        ancestor = ancestor
            .parent()
            .ok_or_else(|| invalid("invalid state base"))?;
    }
    let mut resolved = fs::canonicalize(ancestor)?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn private_directory(path: &Path) -> io::Result<()> {
    reject_symlink(path)?;
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if fs::metadata(path)?.uid() != unsafe { libc::geteuid() } {
            return Err(invalid("state directory is owned by another user"));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn stable_lock_directory() -> io::Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = unsafe { libc::geteuid() };
        let runtime = PathBuf::from(format!("/run/user/{uid}"));
        if fs::symlink_metadata(&runtime).is_ok_and(|metadata| {
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == uid
                && metadata.mode() & 0o077 == 0
        }) {
            let path = runtime.join("progress-checker-locks");
            private_directory(&path)?;
            return Ok(path);
        }
    }
    #[cfg(unix)]
    let home = {
        use std::ffi::CStr;
        use std::os::unix::ffi::OsStrExt;
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0u8; 64 * 1024];
        let status = unsafe {
            libc::getpwuid_r(
                libc::geteuid(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status != 0 || result.is_null() {
            return Err(invalid("unable to resolve current user's stable home"));
        }
        let entry = unsafe { entry.assume_init() };
        if entry.pw_dir.is_null() {
            return Err(invalid("user home is unavailable"));
        }
        let bytes = unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes();
        PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
    };
    #[cfg(not(unix))]
    let home =
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| invalid("user home is required"))?);
    let path = prospective_path(&home.join(".local/state/progress-checker-locks"))?;
    private_directory(&path)?;
    Ok(path)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn record_context(path: &Path) -> io::Result<String> {
    let parts: Option<Vec<_>> = path
        .components()
        .rev()
        .take(3)
        .map(|part| part.as_os_str().to_str().map(str::to_owned))
        .collect();
    let mut parts = parts.ok_or_else(|| invalid("invalid state path encoding"))?;
    parts.reverse();
    Ok(parts.join("/"))
}

fn encode<T: Serialize>(value: &T, key: &[u8; 32], context: &str) -> io::Result<Vec<u8>> {
    let payload = serde_json::to_value(value).map_err(invalid)?;
    let canonical = serde_json::to_vec(&(context, &payload)).map_err(invalid)?;
    let bytes = serde_json::to_vec_pretty(&Envelope {
        schema_version: 1,
        context: context.to_owned(),
        authentication: authenticate(&canonical, key),
        payload,
    })
    .map_err(invalid)?;
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(invalid("state exceeds maximum JSON size"));
    }
    Ok(bytes)
}

fn decode<T: DeserializeOwned>(path: &Path, key: &[u8; 32]) -> io::Result<T> {
    reject_symlink(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("state must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_JSON_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(invalid("state exceeds maximum JSON size"));
    }
    let envelope: Envelope = serde_json::from_slice(&bytes).map_err(invalid)?;
    let context = record_context(path)?;
    let canonical = serde_json::to_vec(&(&envelope.context, &envelope.payload)).map_err(invalid)?;
    if envelope.schema_version != 1
        || envelope.context != context
        || !verify_authentication(&canonical, key, &envelope.authentication)
    {
        return Err(invalid("state schema or integrity hash is invalid"));
    }
    serde_json::from_value(envelope.payload).map_err(invalid)
}

fn atomic_write(path: &Path, bytes: &[u8], immutable: bool) -> io::Result<()> {
    reject_symlink(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("state path has no parent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    if immutable {
        temporary
            .persist_noclobber(path)
            .map_err(|error| error.error)?;
    } else {
        temporary.persist(path).map_err(|error| error.error)?;
    }
    sync_directory(parent)
}

impl StateStore {
    /// Distinct canonical linked worktrees and project IDs receive distinct
    /// stores. The base itself must be outside the worktree.
    pub fn open(base: &Path, worktree: &Path, project_id: &str) -> io::Result<Self> {
        let worktree = fs::canonicalize(worktree)?;
        if project_id.is_empty() {
            return Err(invalid("empty project identity"));
        }
        let base = prospective_path(base)?;
        if base.starts_with(&worktree) {
            return Err(invalid(
                "runtime state must be outside the project worktree",
            ));
        }
        private_directory(&base)?;
        let key = digest(&serde_json::to_vec(&worktree).map_err(invalid)?);
        let worktree_directory = base.join(&key);
        private_directory(&worktree_directory)?;
        let lock_directory = stable_lock_directory()?;
        if lock_directory.starts_with(&worktree) || worktree.starts_with(&lock_directory) {
            return Err(invalid("stable writer lock overlaps the project worktree"));
        }
        let lock_path = lock_directory.join(format!("{key}.lock"));
        reject_symlink(&lock_path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let lock = options.open(lock_path)?;
        if !lock.metadata()?.is_file() {
            return Err(invalid("writer lock must be a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let error = io::Error::last_os_error();
                return Err(io::Error::new(
                    error.kind(),
                    format!("another checker owns this worktree: {error}"),
                ));
            }
        }
        #[cfg(not(unix))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Phase 1 writer locking requires Linux",
        ));
        let directory = worktree_directory.join(digest(project_id.as_bytes()));
        private_directory(&directory)?;
        private_directory(&directory.join("attempts"))?;
        let key_path = worktree_directory.join("authentication.key");
        reject_symlink(&key_path)?;
        let key = if key_path.exists() {
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
                options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
                let metadata = fs::symlink_metadata(&key_path)?;
                if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                    return Err(invalid(
                        "authentication key must be private and owned by current user",
                    ));
                }
            }
            let file = options.open(&key_path)?;
            if !file.metadata()?.is_file() {
                return Err(invalid("authentication key must be a regular file"));
            }
            let mut bytes = Vec::new();
            file.take(33).read_to_end(&mut bytes)?;
            bytes
                .try_into()
                .map_err(|_| invalid("invalid authentication key length"))?
        } else {
            let mut key = [0u8; 32];
            File::open("/dev/urandom")?.read_exact(&mut key)?;
            atomic_write(&key_path, &key, true)?;
            key
        };
        Ok(Self {
            directory,
            _lock: lock,
            key,
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn load_snapshot<T: DeserializeOwned>(&self) -> io::Result<LoadedSnapshot<T>> {
        let primary = self.directory.join("snapshot.json");
        match decode(&primary, &self.key) {
            Ok(value) => Ok(LoadedSnapshot {
                value: Some(value),
                warning: None,
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(LoadedSnapshot {
                value: None,
                warning: None,
            }),
            Err(error) => {
                let backup = decode(&self.directory.join("snapshot.backup.json"), &self.key).ok();
                Ok(LoadedSnapshot {
                    value: backup,
                    warning: Some(format!(
                        "current snapshot is invalid; history retained: {error}"
                    )),
                })
            }
        }
    }

    pub fn save_snapshot<T: Serialize>(&self, value: &T) -> io::Result<()> {
        let primary = self.directory.join("snapshot.json");
        let encoded = encode(value, &self.key, &record_context(&primary)?)?;
        self.check_history_quota(encoded.len().saturating_mul(2))?;
        // Only validated state becomes the last-valid backup. A corrupt current
        // file must never overwrite the backup during recovery.
        if let Ok(previous) = decode::<serde_json::Value>(&primary, &self.key) {
            atomic_write(
                &self.directory.join("snapshot.backup.json"),
                &encode(
                    &previous,
                    &self.key,
                    &record_context(&self.directory.join("snapshot.backup.json"))?,
                )?,
                false,
            )?;
        }
        atomic_write(&primary, &encoded, false)
    }

    fn check_history_quota(&self, additional: usize) -> io::Result<()> {
        let mut total = additional as u64;
        for snapshot in ["snapshot.json", "snapshot.backup.json"] {
            let path = self.directory.join(snapshot);
            reject_symlink(&path)?;
            match fs::metadata(path) {
                Ok(metadata) => {
                    total = total.saturating_add(metadata.len());
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let mut count = 1usize;
        for directory in ["attempts", "logs"] {
            let path = self.directory.join(directory);
            reject_symlink(&path)?;
            let entries = match fs::read_dir(path) {
                Ok(entries) => entries,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            for entry in entries {
                let entry = entry?;
                let metadata = fs::symlink_metadata(entry.path())?;
                if !metadata.is_file() {
                    return Err(invalid("history contains unsupported entries"));
                }
                total = total.saturating_add(metadata.len());
                count = count.saturating_add(1);
                if total > MAX_HISTORY_BYTES || count > MAX_HISTORY_FILES {
                    return Err(invalid(
                        "history quota reached; preserve referenced evidence before manual archival",
                    ));
                }
            }
        }
        if total > MAX_HISTORY_BYTES {
            return Err(invalid("history quota reached"));
        }
        Ok(())
    }

    /// Publish an immutable attempt before publishing any snapshot referencing
    /// it. Reusing an identifier is an error, including byte-identical retries.
    pub fn append_attempt<T: Serialize>(&self, id: &str, value: &T) -> io::Result<()> {
        if id.is_empty() {
            return Err(invalid("empty attempt identifier"));
        }
        let path = self.attempt_path(id);
        let context = record_context(&path)?;
        let bytes = encode(value, &self.key, &context)?;
        self.check_history_quota(bytes.len())?;
        atomic_write(&path, &bytes, true)
    }

    pub fn read_attempt<T: DeserializeOwned>(&self, id: &str) -> io::Result<T> {
        decode(&self.attempt_path(id), &self.key)
    }

    /// Logs are immutable authenticated payloads. The reference is opaque and
    /// cannot escape the protected store; the public hash binds evidence to bytes.
    pub fn append_log(&self, id: &str, bytes: &[u8]) -> io::Result<(String, String)> {
        if id.is_empty() {
            return Err(invalid("empty log identifier"));
        }
        let reference = format!("{}.json", digest(id.as_bytes()));
        let logs = self.directory.join("logs");
        private_directory(&logs)?;
        let encoded = encode(&bytes, &self.key, &record_context(&logs.join(&reference))?)?;
        self.check_history_quota(encoded.len())?;
        atomic_write(&logs.join(&reference), &encoded, true)?;
        Ok((reference, format!("sha256:{}", digest(bytes))))
    }

    pub fn read_log(&self, reference: &str, expected_sha256: &str) -> io::Result<Vec<u8>> {
        if !reference.is_ascii()
            || reference.len() != 69
            || !reference.ends_with(".json")
            || !reference[..64].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("invalid log reference"));
        }
        let bytes: Vec<u8> = decode(&self.directory.join("logs").join(reference), &self.key)?;
        if expected_sha256 != format!("sha256:{}", digest(&bytes)) {
            return Err(invalid("log content hash mismatch"));
        }
        Ok(bytes)
    }

    fn attempt_path(&self, id: &str) -> PathBuf {
        self.directory
            .join("attempts")
            .join(format!("{}.json", digest(id.as_bytes())))
    }
}

/// Recovery never turns an interrupted replacement or older backup into green.
/// Callers publish the changed snapshot and preserve immutable original records.
pub fn recover_evidence(
    evidence: &mut crate::model::CheckEvidence,
    snapshot_was_corrupt: bool,
) -> bool {
    use crate::model::{ExecutionState, Freshness, Outcome};
    if snapshot_was_corrupt || evidence.execution_state != ExecutionState::Finished {
        evidence.execution_state = ExecutionState::Finished;
        evidence.outcome = Some(Outcome::Unknown);
        evidence.freshness = Freshness::Pending;
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let worktree = root.path().join("worktree");
        fs::create_dir(&worktree).unwrap();
        let base = root.path().join("state");
        (root, base, worktree)
    }

    #[test]
    fn dropping_writer_unlocks_even_while_an_inherited_description_remains_open() {
        let (_root, base, worktree) = fixture();
        let first = StateStore::open(&base, &worktree, "project").unwrap();
        // dup shares the same open file description, exactly like the
        // descriptor inherited between fork and exec in another test thread.
        let inherited = first._lock.try_clone().unwrap();
        assert!(StateStore::open(&base, &worktree, "project").is_err());
        drop(first);
        let next = StateStore::open(&base, &worktree, "project").unwrap();
        drop(inherited);
        // Closing the old description must not release the new owner's lock.
        assert!(StateStore::open(&base, &worktree, "project").is_err());
        drop(next);
        assert!(StateStore::open(&base, &worktree, "project").is_ok());
    }

    #[test]
    fn exclusive_writer_and_worktree_isolation() {
        let (_root, base, worktree) = fixture();
        let first = StateStore::open(&base, &worktree, "project").unwrap();
        assert!(StateStore::open(&base, &worktree, "project").is_err());
        assert!(StateStore::open(&base, &worktree, "other-project").is_err());
        assert!(StateStore::open(&base.with_extension("other"), &worktree, "project").is_err());
        let first_directory = first.directory().to_path_buf();
        drop(first);
        let other = StateStore::open(&base, &worktree, "other-project").unwrap();
        assert_ne!(first_directory, other.directory());
        drop(other);
        assert!(StateStore::open(&base, &worktree, "project").is_ok());
    }

    #[test]
    fn corrupt_snapshot_keeps_last_valid_snapshot_and_immutable_history() {
        let (_root, base, worktree) = fixture();
        let store = StateStore::open(&base, &worktree, "project").unwrap();
        store
            .append_attempt("../attempt", &json!({"outcome": "passed"}))
            .unwrap();
        assert!(store.append_attempt("../attempt", &json!({})).is_err());
        store.save_snapshot(&json!({"revision": 1})).unwrap();
        store.save_snapshot(&json!({"revision": 2})).unwrap();
        fs::write(store.directory().join("snapshot.json"), b"broken").unwrap();
        let restored = store.load_snapshot::<serde_json::Value>().unwrap();
        assert_eq!(restored.value.unwrap(), json!({"revision": 1}));
        assert!(restored.warning.is_some());
        assert_eq!(
            store
                .read_attempt::<serde_json::Value>("../attempt")
                .unwrap(),
            json!({"outcome": "passed"})
        );
    }

    #[test]
    fn tampered_attempt_fails_integrity() {
        let (_root, base, worktree) = fixture();
        let store = StateStore::open(&base, &worktree, "project").unwrap();
        store
            .append_attempt("attempt", &json!({"outcome": "passed"}))
            .unwrap();
        let path = store.attempt_path("attempt");
        let text = fs::read_to_string(&path)
            .unwrap()
            .replace("passed", "failed");
        fs::write(path, text).unwrap();
        assert!(store.read_attempt::<serde_json::Value>("attempt").is_err());
    }

    #[test]
    fn state_inside_project_is_rejected() {
        let (_root, _base, worktree) = fixture();
        assert!(StateStore::open(&worktree.join("state"), &worktree, "project").is_err());
    }
    #[test]
    fn authenticated_logs_reject_wrong_hash_and_unsafe_references() {
        let (_root, base, worktree) = fixture();
        let store = StateStore::open(&base, &worktree, "project").unwrap();
        let (reference, hash) = store.append_log("attempt", b"bounded output").unwrap();
        assert_eq!(
            store.read_log(&reference, &hash).unwrap(),
            b"bounded output"
        );
        assert!(store.read_log(&reference, "sha256:wrong").is_err());
        assert!(store.read_log("../snapshot.json", &hash).is_err());
        assert!(
            store
                .read_log(&format!("{}é.json", "a".repeat(62)), &hash)
                .is_err()
        );
    }

    #[test]
    fn interrupted_and_corrupt_backup_evidence_recovers_unknown() {
        use crate::model::{CheckEvidence, ExecutionState, Freshness, Outcome, SourceIdentity};
        let mut evidence = CheckEvidence {
            run_id: "run".into(),
            check_id: "check".into(),
            execution_state: ExecutionState::Running,
            outcome: None,
            freshness: Freshness::Pending,
            source: SourceIdentity {
                git_commit: "head".into(),
                fingerprint: "fingerprint".into(),
                config_hash: "config".into(),
                checker_version: "version".into(),
                environment_signature: "environment".into(),
            },
            command_hash: "command".into(),
            log_ref: None,
            log_sha256: None,
        };
        assert!(recover_evidence(&mut evidence, false));
        assert_eq!(evidence.outcome, Some(Outcome::Unknown));
        evidence.outcome = Some(Outcome::Passed);
        evidence.freshness = Freshness::Current;
        assert!(recover_evidence(&mut evidence, true));
        assert_eq!(evidence.outcome, Some(Outcome::Unknown));
    }

    #[test]
    fn quota_fails_closed_without_deleting_history() {
        let (_root, base, worktree) = fixture();
        let store = StateStore::open(&base, &worktree, "project").unwrap();
        let oversized = store.directory().join("attempts/retained.json");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_HISTORY_BYTES)
            .unwrap();
        assert!(
            store
                .append_attempt("new", &json!({"outcome": "passed"}))
                .is_err()
        );
        assert!(store.append_log("new", b"output").is_err());
        assert!(store.save_snapshot(&json!({})).is_err());
        assert_eq!(fs::metadata(oversized).unwrap().len(), MAX_HISTORY_BYTES);
    }

    #[test]
    fn authenticated_record_cannot_be_replayed_under_a_different_identity() {
        let (_root, base, worktree) = fixture();
        let store = StateStore::open(&base, &worktree, "project").unwrap();
        store
            .append_attempt("first", &json!({"outcome": "passed"}))
            .unwrap();
        fs::copy(store.attempt_path("first"), store.attempt_path("second")).unwrap();
        assert!(store.read_attempt::<serde_json::Value>("second").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn state_symlinks_are_rejected_and_inside_project_is_not_created() {
        use std::os::unix::fs::symlink;
        let (_root, base, worktree) = fixture();
        let inside = worktree.join("state");
        assert!(StateStore::open(&inside, &worktree, "project").is_err());
        assert!(!inside.exists());
        let store = StateStore::open(&base, &worktree, "project").unwrap();
        let outside = base.join("outside");
        fs::write(&outside, b"preserved").unwrap();
        symlink(&outside, store.directory().join("snapshot.json")).unwrap();
        assert!(store.save_snapshot(&json!({})).is_err());
        assert_eq!(fs::read(outside).unwrap(), b"preserved");
    }
}
