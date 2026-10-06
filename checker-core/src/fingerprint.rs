//! Bounded source identity. Exclusions may remove untracked build output only.
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_LIST: usize = 8 * 1024 * 1024;
const MAX_INPUTS: usize = 50_000;
const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Default)]
pub struct FingerprintOptions {
    pub extra_inputs: Vec<String>,
    pub exclude_outputs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorktreeFingerprint {
    pub head: Option<String>,
    pub digest: String,
    pub input_count: usize,
}

pub type FingerprintError = io::Error;
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Domain separated identity for configuration, command definitions and environment.
pub fn hash_parts(domain: &str, parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    frame(&mut hash, domain.as_bytes());
    for part in parts {
        frame(&mut hash, part);
    }
    format!("sha256:{:x}", hash.finalize())
}
fn frame(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn relative(value: &str) -> io::Result<PathBuf> {
    if value.is_empty() || value.contains(['\\', '\0', '*', '?', '[', ']']) {
        return Err(invalid("input paths must be literal relative paths"));
    }
    let path = Path::new(value);
    if path
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(invalid("escaped or noncanonical input path"));
    }
    if path.components().any(|c| c.as_os_str() == ".git") {
        return Err(invalid("Git metadata is not a source input"));
    }
    Ok(path.to_owned())
}

fn git(root: &Path, arguments: &[&str]) -> io::Result<Vec<u8>> {
    let mut child = Command::new("/usr/bin/git")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("HOME", root)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(|| invalid("missing Git output"))?
        .take((MAX_LIST + 1) as u64)
        .read_to_end(&mut output)?;
    if output.len() > MAX_LIST {
        let _ = child.kill();
        let _ = child.wait();
        return Err(invalid("Git input inventory exceeds limit"));
    }
    if !child.wait()?.success() {
        return Err(invalid("Git inventory unavailable"));
    }
    Ok(output)
}

fn paths(bytes: &[u8]) -> io::Result<BTreeSet<PathBuf>> {
    bytes
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| {
            let value =
                std::str::from_utf8(p).map_err(|_| invalid("non-UTF-8 input path unsupported"))?;
            relative(value)
        })
        .collect()
}

/// Fingerprint tracked paths (including deleted files) and nonignored untracked files.
/// Symlinks are identified by their target bytes, never followed for content.
pub fn fingerprint(root: &Path, options: &FingerprintOptions) -> io::Result<WorktreeFingerprint> {
    let root = root.canonicalize()?;
    let git_root = git(&root, &["rev-parse", "--show-toplevel"])?;
    let actual = Path::new(
        std::str::from_utf8(&git_root)
            .map_err(|_| invalid("non-UTF-8 worktree"))?
            .trim_end(),
    )
    .canonicalize()?;
    if actual != root {
        return Err(invalid("fingerprint requires the exact Git worktree root"));
    }
    let tracked = paths(&git(&root, &["ls-files", "-z", "--cached"])?)?;
    let mut inputs = tracked.clone();
    let exclusions: Vec<PathBuf> = options
        .exclude_outputs
        .iter()
        .map(|value| {
            let prefix = value
                .strip_suffix("/**")
                .ok_or_else(|| invalid("output exclusions require a directory/** pattern"))?;
            relative(prefix)
        })
        .collect::<io::Result<_>>()?;
    for exclusion in &exclusions {
        if Path::new(".progress-checker/config.json").starts_with(exclusion) {
            return Err(invalid("output exclusion overlaps mandatory configuration"));
        }
        if tracked.iter().any(|p| p.starts_with(exclusion)) {
            return Err(invalid("output exclusion overlaps tracked source"));
        }
    }
    let untracked = paths(&git(
        &root,
        &["ls-files", "-z", "--others", "--exclude-standard"],
    )?)?;
    for path in untracked.iter().cloned() {
        if !exclusions.iter().any(|e| path.starts_with(e)) {
            inputs.insert(path);
        }
    }
    for value in &options.extra_inputs {
        let path = relative(value)?;
        if exclusions.iter().any(|e| path.starts_with(e)) {
            return Err(invalid("extra input overlaps an output exclusion"));
        }
        inputs.insert(path);
    }
    if inputs.len() > MAX_INPUTS {
        return Err(invalid("too many source inputs"));
    }
    let head = match git(&root, &["rev-parse", "--verify", "HEAD"]) {
        Ok(bytes) => Some(
            String::from_utf8(bytes)
                .map_err(|_| invalid("invalid HEAD"))?
                .trim()
                .to_owned(),
        ),
        Err(_) => {
            // Only a genuinely unborn branch may omit HEAD.
            let reference = git(&root, &["symbolic-ref", "-q", "HEAD"])?;
            let reference = std::str::from_utf8(&reference)
                .map_err(|_| invalid("invalid HEAD ref"))?
                .trim();
            let status = Command::new("/usr/bin/git")
                .args([
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.hooksPath=/dev/null",
                ])
                .arg("-C")
                .arg(&root)
                .args(["show-ref", "--verify", "--quiet", reference])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &root)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            if status.code() != Some(1) {
                return Err(invalid("HEAD cannot be resolved"));
            }
            None
        }
    };
    let mut hash = Sha256::new();
    frame(&mut hash, b"progress-checker/source/v1");
    frame(&mut hash, head.as_deref().unwrap_or("unborn").as_bytes());
    let mut total = 0u64;
    for path in &inputs {
        frame(
            &mut hash,
            path.to_str()
                .ok_or_else(|| invalid("non-UTF-8 path"))?
                .as_bytes(),
        );
        let full = root.join(path);
        // Resolve the parent, not the final symlink. This rejects symlink escapes.
        let parent = full
            .parent()
            .ok_or_else(|| invalid("missing input parent"))?;
        match parent.canonicalize() {
            Ok(parent) if parent.starts_with(&root) => {}
            Ok(_) => return Err(invalid("input parent escapes worktree")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Check every existing ancestor before allowing a tracked deletion.
                let mut ancestor = parent;
                while !ancestor.exists() {
                    ancestor = ancestor
                        .parent()
                        .ok_or_else(|| invalid("input ancestor missing"))?;
                }
                if !ancestor.canonicalize()?.starts_with(&root) {
                    return Err(invalid("deleted input escapes worktree"));
                }
            }
            Err(e) => return Err(e),
        }
        let metadata = match fs::symlink_metadata(&full) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound && tracked.contains(path) => {
                frame(&mut hash, b"deleted");
                continue;
            }
            Err(e) => return Err(e),
        };
        if metadata.file_type().is_symlink() {
            frame(&mut hash, b"symlink");
            let target = confined_link(&root, path)?;
            frame(
                &mut hash,
                target
                    .to_str()
                    .ok_or_else(|| invalid("non-UTF-8 symlink target unsupported"))?
                    .as_bytes(),
            );
        } else if metadata.is_file() {
            if metadata.len() > MAX_FILE {
                return Err(invalid("source file exceeds limit"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                frame(
                    &mut hash,
                    if metadata.permissions().mode() & 0o111 != 0 {
                        b"executable"
                    } else {
                        b"regular"
                    },
                );
            }
            #[cfg(not(unix))]
            frame(&mut hash, b"regular");
            let mut bytes = Vec::new();
            let file = confined_file(&root, path)?;
            let opened = file.metadata()?;
            if !opened.is_file() {
                return Err(invalid("input changed type"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if opened.dev() != metadata.dev()
                    || opened.ino() != metadata.ino()
                    || opened.mode() != metadata.mode()
                {
                    return Err(invalid("input replaced during fingerprint"));
                }
            }

            (&file).take(MAX_FILE + 1).read_to_end(&mut bytes)?;
            let read_end = file.metadata()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if read_end.mode() != opened.mode()
                    || read_end.ctime() != opened.ctime()
                    || read_end.ctime_nsec() != opened.ctime_nsec()
                {
                    return Err(invalid("opened input metadata changed during fingerprint"));
                }
            }
            if read_end.len() != opened.len() || read_end.modified()? != opened.modified()? {
                return Err(invalid("opened input changed during fingerprint"));
            }
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| invalid("input size overflow"))?;
            if bytes.len() as u64 > MAX_FILE || total > MAX_TOTAL {
                return Err(invalid("source byte limit exceeded"));
            }
            frame(&mut hash, &bytes);
            let after = fs::symlink_metadata(&full)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if after.dev() != metadata.dev()
                    || after.ino() != metadata.ino()
                    || after.mode() != metadata.mode()
                    || after.ctime() != metadata.ctime()
                    || after.ctime_nsec() != metadata.ctime_nsec()
                {
                    return Err(invalid("source metadata changed during fingerprint"));
                }
            }
            if !after.is_file()
                || after.len() != metadata.len()
                || after.modified()? != metadata.modified()?
            {
                return Err(invalid("source changed during fingerprint"));
            }
        } else {
            return Err(invalid(
                "directories, submodules and special inputs are unsupported",
            ));
        }
    }
    if tracked != paths(&git(&root, &["ls-files", "-z", "--cached"])?)? {
        return Err(invalid("tracked inventory changed during fingerprint"));
    }
    if untracked
        != paths(&git(
            &root,
            &["ls-files", "-z", "--others", "--exclude-standard"],
        )?)?
    {
        return Err(invalid("untracked inventory changed during fingerprint"));
    }
    let current_head = match git(&root, &["rev-parse", "--verify", "HEAD"]) {
        Ok(bytes) => Some(
            String::from_utf8(bytes)
                .map_err(|_| invalid("invalid HEAD"))?
                .trim()
                .to_owned(),
        ),
        Err(error) if head.is_some() => return Err(error),
        Err(_) => {
            let reference = git(&root, &["symbolic-ref", "-q", "HEAD"])?;
            let reference = std::str::from_utf8(&reference)
                .map_err(|_| invalid("invalid HEAD ref"))?
                .trim();
            let status = Command::new("/usr/bin/git")
                .args([
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.hooksPath=/dev/null",
                ])
                .arg("-C")
                .arg(&root)
                .args(["show-ref", "--verify", "--quiet", reference])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &root)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            if status.code() != Some(1) {
                return Err(invalid("HEAD cannot be resolved"));
            }
            None
        }
    };
    if current_head != head {
        return Err(invalid("HEAD changed during fingerprint"));
    }
    Ok(WorktreeFingerprint {
        head,
        digest: format!("sha256:{:x}", hash.finalize()),
        input_count: inputs.len(),
    })
}

#[cfg(unix)]
fn confined_file(root: &Path, relative: &Path) -> io::Result<fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let mut directory = fs::File::open(root)?;
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let name =
            CString::new(component.as_os_str().as_bytes()).map_err(|_| invalid("NUL in input"))?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if components.peek().is_some() {
                libc::O_DIRECTORY
            } else {
                libc::O_NONBLOCK
            };
        // Each descriptor is owned immediately; no symlink component is followed.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        directory = unsafe { fs::File::from_raw_fd(fd) };
    }
    Ok(directory)
}
#[cfg(not(unix))]
fn confined_file(_root: &Path, _relative: &Path) -> io::Result<fs::File> {
    Err(invalid(
        "fingerprinting requires Unix descriptor confinement",
    ))
}

#[cfg(unix)]
fn confined_link(root: &Path, relative: &Path) -> io::Result<PathBuf> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let parent = relative
        .parent()
        .ok_or_else(|| invalid("missing symlink parent"))?;
    let directory = if parent.as_os_str().is_empty() {
        fs::File::open(root)?
    } else {
        confined_file(root, parent)?
    };
    if !directory.metadata()?.is_dir() {
        return Err(invalid("symlink parent is not a directory"));
    }
    let name = CString::new(
        relative
            .file_name()
            .ok_or_else(|| invalid("missing symlink name"))?
            .as_bytes(),
    )
    .map_err(|_| invalid("NUL in symlink"))?;
    let mut target = vec![0u8; 4097];
    let length = unsafe {
        libc::readlinkat(
            directory.as_raw_fd(),
            name.as_ptr(),
            target.as_mut_ptr().cast(),
            target.len(),
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize >= target.len() {
        return Err(invalid("symlink target exceeds limit"));
    }
    target.truncate(length as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_vec(target)))
}
#[cfg(not(unix))]
fn confined_link(_root: &Path, _relative: &Path) -> io::Result<PathBuf> {
    Err(invalid(
        "fingerprinting requires Unix descriptor confinement",
    ))
}

/// Persistent invalidation hints, including edit-and-revert events.
#[cfg(target_os = "linux")]
pub struct SourceWatch {
    fd: std::os::fd::OwnedFd,
    parent_watch: i32,
    root_name: Vec<u8>,
    directories: std::collections::BTreeMap<i32, PathBuf>,
    exclusions: Vec<PathBuf>,
    dirty: bool,
}

#[cfg(target_os = "linux")]
impl SourceWatch {
    pub fn start(root: &Path) -> io::Result<Self> {
        Self::start_with_options(root, &FingerprintOptions::default())
    }

    pub fn start_with_options(root: &Path, options: &FingerprintOptions) -> io::Result<Self> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        let root = root.canonicalize()?;
        let tracked = paths(&git(&root, &["ls-files", "-z", "--cached"])?)?;
        let exclusions: Vec<PathBuf> = options
            .exclude_outputs
            .iter()
            .map(|value| {
                relative(
                    value
                        .strip_suffix("/**")
                        .ok_or_else(|| invalid("output exclusions require directory/**"))?,
                )
            })
            .collect::<io::Result<_>>()?;
        for exclusion in &exclusions {
            if Path::new(".progress-checker/config.json").starts_with(exclusion) {
                return Err(invalid("output exclusion overlaps mandatory configuration"));
            }
            if tracked.iter().any(|p| p.starts_with(exclusion)) {
                return Err(invalid("output exclusion overlaps tracked source"));
            }
        }
        for extra in &options.extra_inputs {
            let extra = relative(extra)?;
            if exclusions.iter().any(|e| extra.starts_with(e)) {
                return Err(invalid("extra input overlaps output exclusion"));
            }
        }
        let parent = root
            .parent()
            .ok_or_else(|| invalid("cannot watch filesystem root"))?;
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        let add = |path: &Path, mask: u32| -> io::Result<i32> {
            let name = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| invalid("NUL in watch path"))?;
            let watch = unsafe {
                libc::inotify_add_watch(
                    fd.as_raw_fd(),
                    name.as_ptr(),
                    mask | libc::IN_ONLYDIR | libc::IN_DONT_FOLLOW,
                )
            };
            if watch < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(watch)
        };
        let parent_watch = add(
            parent,
            libc::IN_CREATE
                | libc::IN_DELETE
                | libc::IN_MOVED_FROM
                | libc::IN_MOVED_TO
                | libc::IN_ATTRIB
                | libc::IN_DELETE_SELF
                | libc::IN_MOVE_SELF,
        )?;
        let mask = libc::IN_MODIFY
            | libc::IN_ATTRIB
            | libc::IN_CLOSE_WRITE
            | libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF;
        let mut pending = vec![root.clone()];
        let mut directories = std::collections::BTreeMap::new();
        let mut count = 0;
        while let Some(directory) = pending.pop() {
            count += 1;
            if count > MAX_INPUTS {
                return Err(invalid("too many directories to monitor"));
            }
            let relative_directory = directory
                .strip_prefix(&root)
                .map_err(|_| invalid("watch escaped root"))?;
            if exclusions.iter().any(|e| relative_directory.starts_with(e)) {
                continue;
            }
            directories.insert(add(&directory, mask)?, relative_directory.to_owned());
            for entry in fs::read_dir(&directory)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    pending.push(entry.path());
                }
            }
        }
        Ok(Self {
            fd,
            parent_watch,
            root_name: root
                .file_name()
                .ok_or_else(|| invalid("missing root name"))?
                .as_bytes()
                .to_vec(),
            directories,
            exclusions,
            dirty: false,
        })
    }

    pub fn changed(&mut self) -> io::Result<bool> {
        use std::os::fd::AsRawFd;
        let mut buffer = [0u8; 65536];
        loop {
            let length = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if length < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    return Ok(self.dirty);
                }
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if length == 0 {
                return Err(invalid("source monitor disconnected"));
            }
            let mut offset = 0;
            let length = length as usize;
            while offset < length {
                let header = std::mem::size_of::<libc::inotify_event>();
                if length - offset < header {
                    return Err(invalid("truncated source event"));
                }
                let event = unsafe {
                    std::ptr::read_unaligned(
                        buffer.as_ptr().add(offset).cast::<libc::inotify_event>(),
                    )
                };
                let end = offset
                    .checked_add(header)
                    .and_then(|n| n.checked_add(event.len as usize))
                    .ok_or_else(|| invalid("source event overflow"))?;
                if end > length {
                    return Err(invalid("truncated source event name"));
                }
                if event.mask & libc::IN_Q_OVERFLOW != 0 {
                    return Err(invalid("source event queue overflow"));
                }
                let name = &buffer[offset + header..end];
                let name = name.split(|b| *b == 0).next().unwrap_or_default();
                let watch_lost = event.mask
                    & (libc::IN_IGNORED
                        | libc::IN_DELETE_SELF
                        | libc::IN_MOVE_SELF
                        | libc::IN_UNMOUNT)
                    != 0;
                if event.wd == self.parent_watch {
                    if name == self.root_name || watch_lost {
                        self.dirty = true;
                    }
                } else {
                    use std::os::unix::ffi::OsStrExt;
                    let directory = self
                        .directories
                        .get(&event.wd)
                        .ok_or_else(|| invalid("unknown source watch"))?;
                    let path = directory.join(std::ffi::OsStr::from_bytes(name));
                    if watch_lost || !self.exclusions.iter().any(|e| path.starts_with(e)) {
                        self.dirty = true;
                    }
                }
                offset = end;
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub struct SourceWatch;
#[cfg(not(target_os = "linux"))]
impl SourceWatch {
    pub fn start(_root: &Path) -> io::Result<Self> {
        Err(invalid("source monitoring requires Linux"))
    }
    pub fn start_with_options(_root: &Path, _options: &FingerprintOptions) -> io::Result<Self> {
        Err(invalid("source monitoring requires Linux"))
    }
    pub fn changed(&mut self) -> io::Result<bool> {
        Err(invalid("source monitoring requires Linux"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn repo() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        assert!(
            Command::new("/usr/bin/git")
                .args(["init", "-q"])
                .arg(temp.path())
                .status()
                .unwrap()
                .success()
        );
        fs::write(temp.path().join("tracked"), "initial").unwrap();
        assert!(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(temp.path())
                .args(["add", "tracked"])
                .status()
                .unwrap()
                .success()
        );
        temp
    }
    #[test]
    fn content_deletion_and_nonignored_untracked_change_identity() {
        let root = repo();
        let options = FingerprintOptions::default();
        let original = fingerprint(root.path(), &options).unwrap();
        assert_eq!(original, fingerprint(root.path(), &options).unwrap());
        fs::write(root.path().join("tracked"), "changed").unwrap();
        assert_ne!(
            original.digest,
            fingerprint(root.path(), &options).unwrap().digest
        );
        fs::remove_file(root.path().join("tracked")).unwrap();
        let deleted = fingerprint(root.path(), &options).unwrap();
        assert_eq!(deleted.input_count, 1);
        fs::write(root.path().join("untracked"), "new").unwrap();
        assert_ne!(
            deleted.digest,
            fingerprint(root.path(), &options).unwrap().digest
        );
    }
    #[test]
    fn ignores_outputs_but_requires_explicit_ignored_inputs() {
        let root = repo();
        fs::write(root.path().join(".gitignore"), "secret\ntarget/\n").unwrap();
        fs::write(root.path().join("secret"), "one").unwrap();
        let base = fingerprint(root.path(), &FingerprintOptions::default()).unwrap();
        fs::write(root.path().join("secret"), "two").unwrap();
        assert_eq!(
            base,
            fingerprint(root.path(), &FingerprintOptions::default()).unwrap()
        );
        let options = FingerprintOptions {
            extra_inputs: vec!["secret".into()],
            exclude_outputs: vec!["target/**".into()],
        };
        let before = fingerprint(root.path(), &options).unwrap();
        fs::write(root.path().join("secret"), "three").unwrap();
        assert_ne!(
            before.digest,
            fingerprint(root.path(), &options).unwrap().digest
        );
        fs::create_dir(root.path().join("target")).unwrap();
        fs::write(root.path().join("target/out"), "output").unwrap();
        assert_eq!(
            fingerprint(root.path(), &options).unwrap().input_count,
            before.input_count
        );
    }
    #[test]
    fn rejects_escaped_paths_excluded_source_and_directories() {
        let root = repo();
        for path in [
            "../escape",
            "/absolute",
            "a/../tracked",
            "a\\escape",
            ".git/config",
        ] {
            let options = FingerprintOptions {
                extra_inputs: vec![path.into()],
                ..Default::default()
            };
            assert!(fingerprint(root.path(), &options).is_err(), "{path}");
        }
        let options = FingerprintOptions {
            exclude_outputs: vec!["tracked/**".into()],
            ..Default::default()
        };
        assert!(fingerprint(root.path(), &options).is_err());
        fs::create_dir(root.path().join("directory")).unwrap();
        let options = FingerprintOptions {
            extra_inputs: vec!["directory".into()],
            ..Default::default()
        };
        assert!(fingerprint(root.path(), &options).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn mode_symlink_targets_and_parent_escape() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = repo();
        let options = FingerprintOptions::default();
        let before = fingerprint(root.path(), &options).unwrap();
        fs::set_permissions(
            root.path().join("tracked"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert_ne!(
            before.digest,
            fingerprint(root.path(), &options).unwrap().digest
        );
        symlink("missing-a", root.path().join("link")).unwrap();
        let before = fingerprint(root.path(), &options).unwrap();
        fs::remove_file(root.path().join("link")).unwrap();
        symlink("missing-b", root.path().join("link")).unwrap();
        assert_ne!(
            before.digest,
            fingerprint(root.path(), &options).unwrap().digest
        );
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("file"), "outside").unwrap();
        symlink(outside.path(), root.path().join("escape")).unwrap();
        let options = FingerprintOptions {
            extra_inputs: vec!["escape/file".into()],
            ..Default::default()
        };
        assert!(fingerprint(root.path(), &options).is_err());
    }
    #[test]
    fn domains_and_part_boundaries_are_distinct() {
        assert_ne!(
            hash_parts("command", &[b"ab", b"c"]),
            hash_parts("command", &[b"a", b"bc"])
        );
        assert_ne!(
            hash_parts("config", &[b"same"]),
            hash_parts("environment", &[b"same"])
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn monitor_detects_edit_revert_nested_creation_and_root_swap() {
        let root = repo();
        fs::create_dir(root.path().join("nested")).unwrap();
        let mut watch = SourceWatch::start(root.path()).unwrap();
        assert!(!watch.changed().unwrap());
        fs::write(root.path().join("tracked"), "edited").unwrap();
        fs::write(root.path().join("tracked"), "initial").unwrap();
        assert!(watch.changed().unwrap());
        assert!(watch.changed().unwrap());
        let mut watch = SourceWatch::start(root.path()).unwrap();
        fs::write(root.path().join("nested/new"), "new").unwrap();
        assert!(watch.changed().unwrap());
        let mut watch = SourceWatch::start(root.path()).unwrap();
        let moved = root.path().with_extension("moved");
        fs::rename(root.path(), &moved).unwrap();
        fs::create_dir(root.path()).unwrap();
        assert!(watch.changed().unwrap());
        fs::remove_dir_all(moved).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn approved_output_changes_do_not_hide_source_or_extra_input_edits() {
        let root = repo();
        let options = FingerprintOptions {
            exclude_outputs: vec!["target/**".into()],
            extra_inputs: vec!["ignored-input".into()],
        };
        fs::write(root.path().join("ignored-input"), "one").unwrap();
        let mut watch = SourceWatch::start_with_options(root.path(), &options).unwrap();
        fs::create_dir(root.path().join("target")).unwrap();
        fs::write(root.path().join("target/output"), "built").unwrap();
        assert!(!watch.changed().unwrap());
        fs::write(root.path().join("tracked"), "changed").unwrap();
        fs::write(root.path().join("tracked"), "initial").unwrap();
        assert!(watch.changed().unwrap());
        let mut watch = SourceWatch::start_with_options(root.path(), &options).unwrap();
        fs::write(root.path().join("target/output"), "rebuilt").unwrap();
        assert!(!watch.changed().unwrap());
        fs::write(root.path().join("ignored-input"), "two").unwrap();
        assert!(watch.changed().unwrap());
        let mut watch = SourceWatch::start_with_options(root.path(), &options).unwrap();
        fs::write(root.path().join("targetish"), "source").unwrap();
        assert!(watch.changed().unwrap());
        let bad = FingerprintOptions {
            exclude_outputs: vec!["tracked/**".into()],
            ..Default::default()
        };
        assert!(SourceWatch::start_with_options(root.path(), &bad).is_err());
        let config_excluded = FingerprintOptions {
            exclude_outputs: vec![".progress-checker/**".into()],
            ..Default::default()
        };
        assert!(fingerprint(root.path(), &config_excluded).is_err());
        assert!(SourceWatch::start_with_options(root.path(), &config_excluded).is_err());
        let bad = FingerprintOptions {
            extra_inputs: vec!["target/input".into()],
            ..options
        };
        assert!(SourceWatch::start_with_options(root.path(), &bad).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn repository_fsmonitor_hook_is_never_executed() {
        let root = repo();
        let marker = root.path().join("hook-ran");
        let hook = format!("!touch {}", marker.display());
        assert!(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(root.path())
                .args(["config", "core.fsmonitor", &hook])
                .status()
                .unwrap()
                .success()
        );
        fingerprint(root.path(), &FingerprintOptions::default()).unwrap();
        assert!(!marker.exists());
    }
}
