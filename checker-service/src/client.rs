//! The same bounded Unix-socket client is used by human CLI and MCP callers.
use crate::protocol::{MAX_FRAME_BYTES, Operation, Request, Response, SCHEMA_VERSION};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub canonical_root: PathBuf,
    pub socket_path: PathBuf,
}
impl Endpoint {
    pub fn for_root(root: &Path, state_dir: &Path) -> Result<Self, String> {
        let canonical_root = root.canonicalize().map_err(|e| e.to_string())?;
        let state_dir = state_dir.canonicalize().map_err(|e| e.to_string())?;
        checker_core::security::validate_state_separation(&canonical_root, &state_dir)?;
        validate_private_directory(&state_dir)?;
        use std::os::unix::ffi::OsStrExt;
        let digest = format!(
            "{:x}",
            Sha256::digest(canonical_root.as_os_str().as_bytes())
        );
        let mut socket_path = state_dir.join(format!("ipc-{}.sock", &digest[..24]));
        if socket_path.as_os_str().as_bytes().len() > 100 {
            let directory = short_socket_directory(&canonical_root)?;
            let mut context = Sha256::new();
            context.update(canonical_root.as_os_str().as_bytes());
            context.update([0]);
            context.update(state_dir.as_os_str().as_bytes());
            let digest = format!("{:x}", context.finalize());
            socket_path = directory.join(format!("ipc-{}.sock", &digest[..24]));
        }
        Ok(Self {
            canonical_root,
            socket_path,
        })
    }
    pub fn validate(&self) -> Result<(), String> {
        let parent = self
            .socket_path
            .parent()
            .ok_or("missing socket directory")?;
        validate_private_directory(parent)?;
        let metadata = std::fs::symlink_metadata(&self.socket_path).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err("IPC socket must be a private socket owned by the current user".into());
        }
        Ok(())
    }
}
fn short_socket_directory(root: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    let parent = Path::new("/tmp");
    let metadata = std::fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o1000 == 0 {
        return Err("Short IPC runtime requires a root-owned sticky /tmp directory".into());
    }
    let directory = parent.join(format!("progress-checker-ipc-{}", unsafe {
        libc::geteuid()
    }));
    if directory.starts_with(root) || root.starts_with(&directory) {
        return Err("project and protected IPC runtime must not overlap".into());
    }
    match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.to_string()),
    }
    validate_private_directory(&directory)?;
    if std::fs::symlink_metadata(&directory)
        .map_err(|e| e.to_string())?
        .mode()
        & 0o7777
        != 0o700
    {
        return Err("Short IPC runtime directory must have mode 0700".into());
    }
    checker_core::security::validate_state_separation(root, &directory)?;
    Ok(directory)
}
pub fn validate_private_directory(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err("IPC directory must be owned by the current user with mode 0700".into());
    }
    Ok(())
}
#[derive(Clone, Debug)]
pub struct Client {
    pub endpoint: Endpoint,
    pub timeout: Duration,
}
impl Client {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            timeout: Duration::from_secs(30),
        }
    }
    pub fn call(&self, operation: Operation) -> Result<Response, String> {
        self.endpoint.validate()?;
        let request_id = format!(
            "client-{}-{}",
            std::process::id(),
            REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let request = Request {
            schema_version: SCHEMA_VERSION,
            request_id: request_id.clone(),
            operation,
        };
        request.validate()?;
        let mut stream =
            UnixStream::connect(&self.endpoint.socket_path).map_err(|e| e.to_string())?;
        validate_peer(&stream)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| e.to_string())?;
        write_frame(
            &mut stream,
            &serde_json::to_vec(&request).map_err(|e| e.to_string())?,
        )?;
        let response: Response =
            serde_json::from_slice(&read_frame(&mut stream)?).map_err(|e| e.to_string())?;
        response.validate(&request_id)?;
        Ok(response)
    }
    pub async fn async_call(&self, operation: Operation) -> Result<Response, String> {
        let client = self.clone();
        tokio::task::spawn_blocking(move || client.call(operation))
            .await
            .map_err(|e| e.to_string())?
    }
}
/// Same-user credentials are checked after connect, closing metadata/connect races.
pub fn validate_peer(stream: &UnixStream) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
        || credentials.uid != unsafe { libc::geteuid() }
    {
        return Err("IPC peer is not the current user".into());
    }
    Ok(())
}
pub fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix).map_err(|e| e.to_string())?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err("invalid IPC frame length".into());
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}
pub fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err("invalid IPC frame length".into());
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(|e| e.to_string())?;
    writer.write_all(bytes).map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoints_are_root_specific_and_reject_shared_or_overlapping_state() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let state = temp.path().join("state");
        for directory in [&first, &second, &state] {
            std::fs::create_dir(directory).unwrap();
        }
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let a = Endpoint::for_root(&first, &state).unwrap();
        let b = Endpoint::for_root(&second, &state).unwrap();
        assert_ne!(a.socket_path, b.socket_path);
        assert_eq!(
            a.socket_path,
            Endpoint::for_root(&first.join("."), &state)
                .unwrap()
                .socket_path
        );
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Endpoint::for_root(&first, &state).is_err());
        assert!(Endpoint::for_root(&first, &first).is_err());
    }
    #[test]
    fn long_state_paths_use_private_short_ipc_without_relocating_state() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("project");
        std::fs::create_dir(&root).unwrap();
        let state = temporary.path().join("long-state-".repeat(12));
        let second_state = temporary.path().join("other-state-".repeat(12));
        for path in [&state, &second_state] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(state.join("retained-record"), b"unchanged").unwrap();
        let endpoint = Endpoint::for_root(&root, &state).unwrap();
        assert!(endpoint.socket_path.as_os_str().as_bytes().len() <= 100);
        assert!(!endpoint.socket_path.starts_with(&state));
        validate_private_directory(endpoint.socket_path.parent().unwrap()).unwrap();
        assert_eq!(
            endpoint.socket_path,
            Endpoint::for_root(&root.join("."), &state.join("."))
                .unwrap()
                .socket_path
        );
        assert_ne!(
            endpoint.socket_path,
            Endpoint::for_root(&root, &second_state)
                .unwrap()
                .socket_path
        );
        assert_eq!(
            std::fs::read(state.join("retained-record")).unwrap(),
            b"unchanged"
        );
    }
    #[test]
    fn sockets_cannot_be_replaced_with_files_or_links() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let endpoint = Endpoint {
            canonical_root: PathBuf::from("/"),
            socket_path: temp.path().join("socket"),
        };
        std::fs::write(&endpoint.socket_path, b"not a socket").unwrap();
        assert!(endpoint.validate().is_err());
        std::fs::remove_file(&endpoint.socket_path).unwrap();
        std::os::unix::fs::symlink("elsewhere", &endpoint.socket_path).unwrap();
        assert!(endpoint.validate().is_err());
        let (stream, _peer) = UnixStream::pair().unwrap();
        assert!(validate_peer(&stream).is_ok());
    }
    #[test]
    fn frames_reject_empty_oversized_and_truncated_input() {
        for input in [
            0u32.to_be_bytes().to_vec(),
            ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec(),
            vec![0, 0, 0, 2, 1],
        ] {
            assert!(read_frame(&mut input.as_slice()).is_err());
        }
        let mut output = Vec::new();
        write_frame(&mut output, b"hello").unwrap();
        assert_eq!(read_frame(&mut output.as_slice()).unwrap(), b"hello");
    }
}
