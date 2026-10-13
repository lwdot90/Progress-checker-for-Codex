//! Native code-signing identity building block, never execution authorization.
//! Apple requirement verification needs an explicit trusted anchor policy:
//! https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements
//! Entitlements are bound as exact extracted bytes; caller must review their
//! semantics. A valid signature alone does not prove sandbox containment,
//! notarization, immutable installation, or complete runtime dependency closure.
//! The fixed system helper gets bounded pipes and owned process-group cleanup;
//! escaped-descendant containment remains native-unqualified. Never reuse this
//! collector supervisor to launch arbitrary project commands.
use std::path::Path;

#[derive(Clone, Debug)]
pub struct SigningPolicy {
    pub team_identifier: String,
    pub signing_identifier: String,
    /// Exact expected line, including `designated => ` prefix.
    pub designated_requirement: String,
    /// sha256: followed by lowercase hexadecimal, for extracted XML bytes.
    pub entitlements_sha256: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SignedIdentity {
    pub canonical_path: std::path::PathBuf,
    pub executable_sha256: String,
    pub codesign_sha256: String,
    pub designated_requirement: String,
    pub entitlements_sha256: String,
    pub team_identifier: String,
    pub signing_identifier: String,
}

fn validate_policy(policy: &SigningPolicy) -> Result<(), String> {
    if policy.team_identifier.len() != 10
        || !policy
            .team_identifier
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        || policy.signing_identifier.is_empty()
        || policy.signing_identifier.len() > 255
        || !policy
            .signing_identifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        || !policy.designated_requirement.starts_with("designated => ")
        || policy.designated_requirement.len() > 8192
        || policy.designated_requirement.chars().any(char::is_control)
        || policy.entitlements_sha256.len() != 71
        || !policy.entitlements_sha256.starts_with("sha256:")
        || !policy.entitlements_sha256[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("macOS signing policy requires exact reviewed team, identifier, requirement and entitlement hash".into());
    }
    Ok(())
}

/// Only a trusted caller may supply policy. This collector is not connected to
/// approval, check launch, or platform activation. Unsigned and ad-hoc code must
/// fail Apple-anchored external requirement verification.
pub fn collect_signed_identity(
    path: &Path,
    policy: &SigningPolicy,
) -> Result<SignedIdentity, String> {
    validate_policy(policy)?;
    #[cfg(target_os = "macos")]
    {
        native::collect(path, policy)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Err("macOS signing identity requires a native macOS host".into())
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::Read,
        os::{
            fd::AsRawFd,
            unix::{fs::MetadataExt, process::CommandExt},
        },
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    const TOOL: &str = "/usr/bin/codesign";
    const LIMIT: u64 = 1024 * 1024;

    struct OwnedCollector {
        child: std::process::Child,
        unreaped_group: Option<libc::pid_t>,
    }
    impl OwnedCollector {
        fn terminate_group_before_reap(&mut self) -> Result<(), String> {
            if let Some(group) = self.unreaped_group {
                // Leader PID remains allocated until wait(), preventing numeric
                // group reuse between ownership validation and cleanup signal.
                if unsafe { libc::kill(-group, libc::SIGKILL) } != 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                {
                    return Err("codesign owned-group cleanup failed".into());
                }
                self.unreaped_group = None;
            }
            Ok(())
        }

        fn reap_if_exited(&mut self) -> Result<Option<std::process::ExitStatus>, String> {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return Err("codesign process lifetime observation failed".into());
            }
            if info.si_pid != self.child.id() as libc::pid_t {
                return Ok(None);
            }
            self.terminate_group_before_reap()?;
            // WNOWAIT just observed this owned child as exited; wait cannot
            // block awaiting its exit. No unconditional blocking wait occurs.
            self.child.wait().map(Some).map_err(|e| e.to_string())
        }
    }
    impl Drop for OwnedCollector {
        fn drop(&mut self) {
            // Child::drop does not terminate a running process. Ensure even
            // metadata/read failures cannot abandon the fixed helper.
            let _ = self.terminate_group_before_reap();
            let _ = self.child.kill();
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(1) {
                match self.reap_if_exited() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
            // Cleanup failures never yield a SignedIdentity. If the OS refuses
            // termination, avoid an unbounded wait; native operational recovery
            // and escaped descendants remain outside qualification here.
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Stamp(u64, u64, u64, i64, i64, i64, i64, u32, u32);
    fn stamp(metadata: &fs::Metadata) -> Stamp {
        Stamp(
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
            metadata.mode(),
            metadata.uid(),
        )
    }
    fn file_hash(path: &Path) -> Result<(Stamp, String), String> {
        let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
        let before = file.metadata().map_err(|e| e.to_string())?;
        if !before.is_file() || before.len() > 256 * 1024 * 1024 {
            return Err("macOS signing identity requires a bounded regular executable".into());
        }
        let started = Instant::now();
        let mut hash = Sha256::new();
        let mut count = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            if started.elapsed() > Duration::from_secs(10) {
                return Err("signing identity read timed out".into());
            }
            let read = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if read == 0 {
                break;
            }
            count += read as u64;
            if count > 256 * 1024 * 1024 {
                return Err("signing identity exceeds size limit".into());
            }
            hash.update(&buffer[..read]);
        }
        let expected = stamp(&before);
        if count != before.len()
            || stamp(&file.metadata().map_err(|e| e.to_string())?) != expected
            || stamp(&fs::metadata(path).map_err(|e| e.to_string())?) != expected
        {
            return Err("macOS signing identity changed during read".into());
        }
        Ok((expected, format!("sha256:{:x}", hash.finalize())))
    }

    fn run(arguments: &[&str], path: &Path) -> Result<(Vec<u8>, Vec<u8>), String> {
        let child = Command::new(TOOL)
            .env_clear()
            .env("LANG", "C")
            .args(arguments)
            .arg("--")
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|e| e.to_string())?;
        let group = child.id() as libc::pid_t;
        let mut child = OwnedCollector {
            child,
            unreaped_group: (group > 1).then_some(group),
        };
        if group <= 1 {
            return Err("invalid codesign process identity".into());
        }
        let mut stdout = child
            .child
            .stdout
            .take()
            .ok_or("codesign stdout unavailable")?;
        let mut stderr = child
            .child
            .stderr
            .take()
            .ok_or("codesign stderr unavailable")?;
        for descriptor in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
            if flags < 0
                || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err("codesign pipe setup failed".into());
            }
        }
        let started = Instant::now();
        let mut output = Vec::new();
        let mut error = Vec::new();
        let mut stdout_eof = false;
        let mut stderr_eof = false;
        let mut status = None;
        loop {
            if started.elapsed() > Duration::from_secs(10) {
                return Err("codesign exceeded bounded collection limits".into());
            }
            drain_pipe(&mut stdout, &mut output, &mut stdout_eof)?;
            drain_pipe(&mut stderr, &mut error, &mut stderr_eof)?;
            if status.is_none() {
                status = child.reap_if_exited()?;
            }
            if status.is_some() && stdout_eof && stderr_eof {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !status.is_some_and(|status| status.success()) {
            return Err("macOS signing verification or identity extraction failed".into());
        }
        Ok((output, error))
    }

    fn drain_pipe(pipe: &mut impl Read, bytes: &mut Vec<u8>, eof: &mut bool) -> Result<(), String> {
        if *eof {
            return Ok(());
        }
        let mut buffer = [0u8; 8192];
        // Bound each drain cycle so an always-writing stream cannot starve the
        // other pipe or process deadline. No disk output can grow unchecked.
        for _ in 0..16 {
            match pipe.read(&mut buffer) {
                Ok(0) => {
                    *eof = true;
                    break;
                }
                Ok(count) => {
                    if bytes.len() + count > LIMIT as usize {
                        return Err("codesign output exceeds size limit".into());
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("codesign pipe read failed".into()),
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod pipe_tests {
        use super::*;
        #[test]
        fn output_limit_rejects_growth_without_disk_spooling() {
            let mut source = std::io::Cursor::new(vec![b'x'; LIMIT as usize + 1]);
            let mut bytes = Vec::new();
            let mut eof = false;
            while bytes.len() < LIMIT as usize {
                drain_pipe(&mut source, &mut bytes, &mut eof).unwrap();
            }
            assert!(drain_pipe(&mut source, &mut bytes, &mut eof).is_err());
            assert_eq!(bytes.len(), LIMIT as usize);
        }
    }

    pub(super) fn collect(path: &Path, policy: &SigningPolicy) -> Result<SignedIdentity, String> {
        if !path.is_absolute() {
            return Err("signing identity path must be absolute".into());
        }
        let canonical = path.canonicalize().map_err(|e| e.to_string())?;
        let tool_path = Path::new(TOOL);
        if tool_path.canonicalize().map_err(|e| e.to_string())? != tool_path {
            return Err("codesign must be the canonical system executable".into());
        }
        for ancestor in tool_path.ancestors() {
            let metadata = fs::metadata(ancestor).map_err(|e| e.to_string())?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err("codesign installation is not root-owned and non-writable".into());
            }
        }
        let before = file_hash(&canonical)?;
        let tool_before = file_hash(tool_path)?;
        let requirement = format!(
            "=anchor apple generic and identifier \"{}\" and certificate leaf[subject.OU] = \"{}\"",
            policy.signing_identifier, policy.team_identifier
        );
        run(
            &["--verify", "--strict", "--test-requirement", &requirement],
            &canonical,
        )?;
        let full_requirement = format!(
            "={}",
            policy
                .designated_requirement
                .strip_prefix("designated => ")
                .ok_or("reviewed designated requirement prefix missing")?
        );
        run(
            &[
                "--verify",
                "--strict",
                "--test-requirement",
                &full_requirement,
            ],
            &canonical,
        )?;
        let (out, err) = run(&["--display", "--requirements", "-"], &canonical)?;
        let text = String::from_utf8([out, err].concat())
            .map_err(|_| "codesign requirement is not UTF-8")?;
        let requirements = text
            .lines()
            .filter(|line| line.starts_with("designated => "))
            .collect::<Vec<_>>();
        if requirements != [policy.designated_requirement.as_str()] {
            return Err("macOS designated requirement differs from reviewed policy".into());
        }
        // Apple's TN3125 explicitly pipes this command's XML stdout to plutil;
        // diagnostic stderr is separate and is not part of the entitlement hash.
        // https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles
        let (entitlements, _) = run(&["--display", "--entitlements", "-", "--xml"], &canonical)?;
        if entitlements.is_empty() {
            return Err("macOS helper must carry explicit reviewed entitlements".into());
        }
        let entitlements_sha256 = format!("sha256:{:x}", Sha256::digest(&entitlements));
        if entitlements_sha256 != policy.entitlements_sha256 {
            return Err("macOS entitlements differ from reviewed policy".into());
        }
        run(
            &["--verify", "--strict", "--test-requirement", &requirement],
            &canonical,
        )?;
        run(
            &[
                "--verify",
                "--strict",
                "--test-requirement",
                &full_requirement,
            ],
            &canonical,
        )?;
        if path.canonicalize().map_err(|e| e.to_string())? != canonical
            || file_hash(&canonical)? != before
            || file_hash(tool_path)? != tool_before
        {
            return Err("macOS signing identity changed during collection".into());
        }
        Ok(SignedIdentity {
            canonical_path: canonical,
            executable_sha256: before.1,
            codesign_sha256: tool_before.1,
            designated_requirement: policy.designated_requirement.clone(),
            entitlements_sha256,
            team_identifier: policy.team_identifier.clone(),
            signing_identifier: policy.signing_identifier.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> SigningPolicy {
        SigningPolicy {
            team_identifier: "ABCDEFGHI1".into(),
            signing_identifier: "org.example.helper".into(),
            designated_requirement: "designated => anchor apple generic".into(),
            entitlements_sha256: format!("sha256:{}", "a".repeat(64)),
        }
    }
    #[test]
    fn policy_rejects_requirement_injection_and_missing_entitlement_binding() {
        let mut value = policy();
        value.team_identifier = "\" or always".into();
        assert!(validate_policy(&value).is_err());
        let mut value = policy();
        value.signing_identifier = "bad\"identifier".into();
        assert!(validate_policy(&value).is_err());
        let mut value = policy();
        value.entitlements_sha256.clear();
        assert!(validate_policy(&value).is_err());
    }
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn foreign_host_never_claims_signing_identity() {
        assert!(
            collect_signed_identity(Path::new("/fixture"), &policy())
                .unwrap_err()
                .contains("native macOS")
        );
    }
    #[test]
    #[cfg(target_os = "macos")]
    fn unsigned_fixture_never_yields_trusted_identity() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("unsigned-helper");
        std::fs::write(&file, b"unsigned fixture, not native signed code").unwrap();
        assert!(collect_signed_identity(&file, &policy()).is_err());
    }
}
