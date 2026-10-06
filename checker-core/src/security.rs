//! Exact local approval binding and a fail-closed Linux sandbox.
//! Repository configuration never creates an approval. The human-facing caller
//! supplies a separately stored approval after presenting the complete binding.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBinding {
    pub canonical_root: PathBuf,
    pub config_hash: String,
    pub command_hash: String,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub environment: BTreeMap<String, String>,
    pub sandbox_profile: String,
    pub executable_hash: String,
    pub sandbox_binary_hash: String,
}

pub const SANDBOX_PROFILE: &str = "linux-bwrap-no-network-no-home-v1";

fn binary_hash(path: &Path) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("UNKNOWN_EXECUTABLE: {}: {e}", path.display()))?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err(format!(
            "UNKNOWN_EXECUTABLE: {} is not an executable file",
            path.display()
        ));
    }
    if !metadata.is_file()
        || metadata.len() > 64 * 1024 * 1024
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err("sandbox and executable must be bounded root-owned non-writable files".into());
    }
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

/// The writable worktree must never expose the trust store or evidence writer.
pub fn validate_state_separation(root: &Path, state_directory: &Path) -> Result<(), String> {
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let state = state_directory.canonicalize().map_err(|e| e.to_string())?;
    if state.starts_with(&root) || root.starts_with(&state) {
        return Err("project and protected user state must not overlap".into());
    }
    Ok(())
}

impl ApprovalBinding {
    pub fn new(
        root: &Path,
        config_hash: String,
        command_hash: String,
        mut argv: Vec<String>,
        cwd: &Path,
    ) -> Result<Self, String> {
        let canonical_root = root
            .canonicalize()
            .map_err(|e| format!("project root: {e}"))?;
        let cwd = cwd
            .canonicalize()
            .map_err(|e| format!("working directory: {e}"))?;
        let executable = argv.first().ok_or("empty command")?;
        if !Path::new(executable).is_absolute() {
            return Err("executable must be absolute".into());
        }
        let resolved = Path::new(executable)
            .canonicalize()
            .map_err(|e| format!("UNKNOWN_EXECUTABLE: {executable}: {e}"))?;
        argv[0] = resolved.to_str().ok_or("non-UTF-8 executable")?.to_owned();
        let executable = &argv[0];
        let executable_hash = binary_hash(Path::new(executable))?;
        let sandbox_binary_hash = binary_hash(Path::new("/usr/bin/bwrap"))?;
        let binding = Self {
            canonical_root,
            config_hash,
            command_hash,
            argv,
            cwd,
            environment: BTreeMap::from([
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), "/tmp".into()),
                ("LANG".into(), "C.UTF-8".into()),
            ]),
            sandbox_profile: SANDBOX_PROFILE.into(),
            executable_hash,
            sandbox_binary_hash,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn approval_digest(&self) -> Result<String, String> {
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    fn validate(&self) -> Result<(), String> {
        if self.sandbox_profile != SANDBOX_PROFILE {
            return Err("unsupported sandbox profile".into());
        }
        if !self.canonical_root.is_dir()
            || !self.cwd.is_dir()
            || self.canonical_root.canonicalize().ok().as_ref() != Some(&self.canonical_root)
            || self.cwd.canonicalize().ok().as_ref() != Some(&self.cwd)
            || !self.cwd.starts_with(&self.canonical_root)
        {
            return Err("noncanonical or escaped working directory".into());
        }
        for hash in [
            &self.config_hash,
            &self.command_hash,
            &self.executable_hash,
            &self.sandbox_binary_hash,
        ] {
            if !hash
                .strip_prefix("sha256:")
                .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err("invalid definition hash".into());
            }
        }
        if self.argv.is_empty() || self.argv.iter().any(|s| s.contains('\0')) {
            return Err("empty command or NUL argument".into());
        }
        let executable = Path::new(&self.argv[0]);
        let resolved = executable
            .canonicalize()
            .map_err(|e| format!("UNKNOWN_EXECUTABLE: {}: {e}", executable.display()))?;
        if !executable.is_absolute() || resolved != executable || !resolved.starts_with("/usr") {
            return Err("Phase 1 executable must resolve under /usr".into());
        }
        if binary_hash(executable)? != self.executable_hash
            || binary_hash(Path::new("/usr/bin/bwrap"))? != self.sandbox_binary_hash
        {
            return Err("PERMISSION_REQUIRED: executable or sandbox binary changed".into());
        }
        let fixed = BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), "/tmp".into()),
            ("LANG".into(), "C.UTF-8".into()),
        ]);
        if self.environment != fixed {
            return Err("Phase 1 permits only the fixed secret-free environment".into());
        }
        // A root containing system mounts cannot safely become a writable bind.
        if self.canonical_root == Path::new("/")
            || ["/usr", "/etc", "/dev", "/proc"].iter().any(|p| {
                Path::new(p).starts_with(&self.canonical_root) || self.canonical_root.starts_with(p)
            })
        {
            return Err("project root overlaps a sandbox system mount".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalApproval {
    pub schema_version: u32,
    pub binding: ApprovalBinding,
    pub binding_digest: String,
}

/// Constructible only after checking an independently supplied human approval.
#[derive(Debug)]
pub struct AuthorizedExecution {
    binding: ApprovalBinding,
}

pub fn authorize(
    binding: ApprovalBinding,
    approval: &LocalApproval,
) -> Result<AuthorizedExecution, String> {
    binding.validate()?;
    if approval.schema_version != 1
        || approval.binding != binding
        || approval.binding_digest != binding.approval_digest()?
    {
        return Err("PERMISSION_REQUIRED: exact local approval does not match".into());
    }
    Ok(AuthorizedExecution { binding })
}

impl AuthorizedExecution {
    pub fn argv(&self) -> &[String] {
        &self.binding.argv
    }
    pub fn cwd(&self) -> &Path {
        &self.binding.cwd
    }
    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.binding.environment
    }
    pub fn redactions(&self) -> Vec<String> {
        Vec::new()
    }

    /// No unsandboxed fallback. Spawn errors and namespace denial remain errors.
    pub fn sandbox_command(&self) -> Result<Command, String> {
        self.build_sandbox_command(None)
    }

    /// A private pipe receives Bubblewrap's exit-code only after successful
    /// setup and exec. The sandboxed command never inherits this descriptor.
    pub fn sandbox_command_with_status_fd(&self, fd: i32) -> Result<Command, String> {
        if fd < 3 {
            return Err("invalid sandbox status descriptor".into());
        }
        self.build_sandbox_command(Some(fd))
    }

    fn build_sandbox_command(&self, status_fd: Option<i32>) -> Result<Command, String> {
        self.binding.validate()?;
        let bwrap = Path::new("/usr/bin/bwrap");
        if !bwrap.is_file() {
            return Err("restricted sandbox unavailable".into());
        }
        let mut command = Command::new(bwrap);
        command.env_clear().envs(&self.binding.environment);
        if let Some(fd) = status_fd {
            command.args(["--json-status-fd", &fd.to_string()]);
        }
        command.args([
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
        ]);
        command
            .arg("--bind")
            .arg(&self.binding.canonical_root)
            .arg(&self.binding.canonical_root);
        command
            .arg("--chdir")
            .arg(&self.binding.cwd)
            .arg("--")
            .args(&self.binding.argv);
        Ok(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(root: &Path) -> ApprovalBinding {
        ApprovalBinding::new(
            root,
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
            vec!["/usr/bin/true".into()],
            root,
        )
        .unwrap()
    }

    #[test]
    fn exact_approval_rejects_every_changed_binding_dimension() {
        let root = tempfile::tempdir().unwrap();
        let binding = fixture(root.path());
        let approval = LocalApproval {
            schema_version: 1,
            binding_digest: binding.approval_digest().unwrap(),
            binding: binding.clone(),
        };
        assert!(authorize(binding.clone(), &approval).is_ok());
        let other = tempfile::tempdir().unwrap();
        let mut variants = Vec::new();
        let mut value = binding.clone();
        value.canonical_root = other.path().canonicalize().unwrap();
        variants.push(value);
        let mut value = binding.clone();
        value.config_hash = format!("sha256:{}", "c".repeat(64));
        variants.push(value);
        let mut value = binding.clone();
        value.command_hash = format!("sha256:{}", "d".repeat(64));
        variants.push(value);
        let mut value = binding.clone();
        value.argv.push("extra".into());
        variants.push(value);
        let mut value = binding.clone();
        value.cwd = other.path().canonicalize().unwrap();
        variants.push(value);
        let mut value = binding.clone();
        value.environment.insert("TOKEN".into(), "secret".into());
        variants.push(value);
        let mut value = binding.clone();
        value.sandbox_profile = "unsandboxed".into();
        variants.push(value);
        let mut value = binding.clone();
        value.executable_hash = format!("sha256:{}", "e".repeat(64));
        variants.push(value);
        let mut value = binding.clone();
        value.sandbox_binary_hash = format!("sha256:{}", "f".repeat(64));
        variants.push(value);
        for variant in variants {
            assert!(authorize(variant, &approval).is_err());
        }
        let mut tampered = approval.clone();
        tampered.binding_digest = "sha256:fake".into();
        assert!(authorize(binding, &tampered).is_err());
    }

    #[test]
    fn paths_shell_and_secret_environment_are_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let mut binding = fixture(root.path());
        binding.argv = vec!["true".into()];
        assert!(binding.validate().is_err());
        binding.argv = vec!["/usr/bin/true".into(), "nul\0argument".into()];
        assert!(binding.validate().is_err());
        assert!(
            ApprovalBinding::new(
                root.path(),
                "bad".into(),
                "bad".into(),
                vec!["/usr/bin/true".into()],
                Path::new("/")
            )
            .is_err()
        );
    }

    #[test]
    fn writable_project_cannot_contain_approval_store() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        std::fs::create_dir(&state).unwrap();
        assert!(validate_state_separation(root.path(), &state).is_err());
        assert!(validate_state_separation(&state, root.path()).is_err());
        let separate = tempfile::tempdir().unwrap();
        assert!(validate_state_separation(root.path(), separate.path()).is_ok());
    }

    #[test]
    fn missing_and_non_executable_commands_are_unknown() {
        assert!(
            binary_hash(Path::new("/usr"))
                .unwrap_err()
                .starts_with("UNKNOWN_EXECUTABLE:")
        );
        assert!(
            binary_hash(Path::new("/usr/bin/progress-checker-missing-test-fixture"))
                .unwrap_err()
                .starts_with("UNKNOWN_EXECUTABLE:")
        );
    }
}
