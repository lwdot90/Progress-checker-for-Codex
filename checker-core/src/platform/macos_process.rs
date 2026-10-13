//! Native macOS spawn preparation. No execution API is enabled yet.
//!
//! A process group is a cleanup aid, not descendant containment: malicious
//! children may create new sessions. macOS has no Linux PID namespace here.
//! Therefore successful leader exit must not establish complete cleanup.
#![cfg(target_os = "macos")]

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// Native posix_spawn attribute/file-action preparation, with no spawn syscall.
/// CLOEXEC_DEFAULT closes every unspecified descriptor irrespective of current
/// RLIMIT_NOFILE, including private state/status FDs. Only the three explicitly
/// dup2'd standard streams survive. Caller retains the borrowed stream handles
/// until actual launch; preparation borrows them to enforce that lifetime.
pub struct NativeSpawnPreparation<'a> {
    attributes: libc::posix_spawnattr_t,
    actions: libc::posix_spawn_file_actions_t,
    streams: [std::os::fd::BorrowedFd<'a>; 3],
}

impl<'a> NativeSpawnPreparation<'a> {
    pub fn new(streams: [std::os::fd::BorrowedFd<'a>; 3]) -> Result<Self, String> {
        use std::os::fd::AsRawFd;
        if streams.iter().any(|stream| stream.as_raw_fd() < 3) {
            return Err(
                "native macOS standard-stream sources must be owned descriptors above 2".into(),
            );
        }
        let mut attributes = std::mem::MaybeUninit::<libc::posix_spawnattr_t>::uninit();
        let mut actions = std::mem::MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
        let status = unsafe { libc::posix_spawnattr_init(attributes.as_mut_ptr()) };
        if status != 0 {
            return Err(format!(
                "macOS spawn attribute initialization failed: {status}"
            ));
        }
        let mut attributes = unsafe { attributes.assume_init() };
        let status = unsafe { libc::posix_spawn_file_actions_init(actions.as_mut_ptr()) };
        if status != 0 {
            unsafe {
                libc::posix_spawnattr_destroy(&mut attributes);
            }
            return Err(format!(
                "macOS spawn file action initialization failed: {status}"
            ));
        }
        let mut prepared = Self {
            attributes,
            actions: unsafe { actions.assume_init() },
            streams,
        };
        let flags =
            (libc::POSIX_SPAWN_CLOEXEC_DEFAULT | libc::POSIX_SPAWN_SETPGROUP) as libc::c_short;
        let status = unsafe { libc::posix_spawnattr_setflags(&mut prepared.attributes, flags) };
        if status != 0 {
            return Err(format!(
                "macOS default descriptor isolation unavailable: {status}"
            ));
        }
        let status = unsafe { libc::posix_spawnattr_setpgroup(&mut prepared.attributes, 0) };
        if status != 0 {
            return Err(format!("macOS new process group unavailable: {status}"));
        }
        for target in 0..3 {
            let status = unsafe {
                libc::posix_spawn_file_actions_adddup2(
                    &mut prepared.actions,
                    prepared.streams[target].as_raw_fd(),
                    target as libc::c_int,
                )
            };
            if status != 0 {
                return Err(format!(
                    "macOS standard-stream isolation unavailable: {status}"
                ));
            }
        }
        Ok(prepared)
    }

    pub fn require_qualified_launch(&self) -> Result<(), String> {
        Err("macOS native spawn refused: sandbox inheritance and detached-descendant containment are unqualified".into())
    }
}

impl Drop for NativeSpawnPreparation<'_> {
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.actions);
            libc::posix_spawnattr_destroy(&mut self.attributes);
        }
    }
}

/// Owned preparation prevents external code from bypassing the qualification
/// gate by extracting the underlying Command and calling spawn itself.
pub struct PreparedMacosProcess {
    command: Command,
}

impl PreparedMacosProcess {
    /// Prepare an already reviewed, absolute sandbox launcher and exact argv.
    /// This does not establish executable trust or authorization; the caller
    /// must perform the ordinary approval binding and hash validation first.
    pub fn new(launcher: &Path, argv: &[String], cwd: &Path) -> Result<Self, String> {
        if !launcher.is_absolute()
            || launcher.canonicalize().ok().as_deref() != Some(launcher)
            || cwd.canonicalize().ok().as_deref() != Some(cwd)
            || !cwd.is_dir()
            || argv.iter().any(|argument| argument.contains('\0'))
        {
            return Err("macOS launcher requires canonical paths and NUL-free exact argv".into());
        }
        let mut command = Command::new(launcher);
        command
            .args(argv)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        // Descriptor inheritance must use NativeSpawnPreparation below when
        // qualification enables execution. No RLIMIT-based descriptor scan:
        // an existing descriptor may lie above a subsequently lowered limit.
        Ok(Self { command })
    }

    /// Deliberately fails before OS spawn, even if preparation succeeded.
    /// A future native supervisor must prove detached descendants cannot survive
    /// before this gate can be replaced. Profile enforcement alone is inadequate.
    pub fn spawn(&mut self) -> Result<Child, String> {
        let _ = &self.command;
        Err("macOS execution unavailable: detached-descendant cleanup is unqualified".into())
    }
}

/// Signals only a group whose still-live leader is owned by this caller.
/// The caller must invalidate the guard before reaping the leader; otherwise
/// its numeric PID might be reused and signal an unrelated process group.
/// No Drop implementation performs signals implicitly.
pub struct OwnedProcessGroup {
    leader: Option<libc::pid_t>,
}

impl OwnedProcessGroup {
    pub fn from_unreaped_child(child: &Child) -> Result<Self, String> {
        let leader = libc::pid_t::try_from(child.id()).map_err(|_| "invalid macOS child PID")?;
        if leader <= 1 || unsafe { libc::getpgid(leader) } != leader {
            return Err("macOS child is not the expected live process-group leader".into());
        }
        Ok(Self {
            leader: Some(leader),
        })
    }

    pub fn signal(&self, signal: libc::c_int) -> Result<(), String> {
        if ![libc::SIGTERM, libc::SIGKILL].contains(&signal) {
            return Err("unsupported cleanup signal".into());
        }
        let leader = self
            .leader
            .ok_or("macOS process-group ownership invalidated")?;
        if unsafe { libc::kill(-leader, signal) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }

    pub fn invalidate_before_reap(&mut self) {
        self.leader = None;
    }
}
