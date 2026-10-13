//! macOS confinement research artifact, deliberately unavailable for execution.
//!
//! Apple documents App Sandbox and inheritance for embedded command-line tools:
//! https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox
//! The legacy sandbox-exec interface is deprecated; do not silently substitute an
//! unrestricted process or treat a generated Seatbelt profile as qualification.
//! https://developer.apple.com/forums/thread/661939
use std::path::{Path, PathBuf};
use std::process::Command;

pub const PROFILE_ID: &str = "macos-seatbelt-no-network-no-home-candidate-v1";
pub const UNAVAILABLE_REASON: &str = "macOS restricted execution is unavailable: native sandbox containment, inherited descriptors, and descendant cleanup have not been qualified";

/// Explicit constraints for a future native-host profile qualification harness.
/// These canonical directories must be supplied by a trusted caller, never by
/// project configuration alone. No system-wide writable temporary directory is
/// granted: each run needs its own empty scratch directory.
#[derive(Debug, Clone)]
pub struct CandidateDirectories {
    pub project: PathBuf,
    pub scratch: PathBuf,
    pub private_state: PathBuf,
    pub home: PathBuf,
}

fn canonical_directory(path: &Path) -> Result<PathBuf, String> {
    let canonical = path.canonicalize().map_err(|e| e.to_string())?;
    if canonical != path || !canonical.is_dir() {
        return Err("macOS candidate requires existing canonical directories".into());
    }
    Ok(canonical)
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn quoted_path(path: &Path) -> Result<String, String> {
    let value = path.to_str().ok_or("non-UTF-8 sandbox path")?;
    if value.chars().any(char::is_control) {
        return Err("control characters are forbidden in sandbox paths".into());
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// Produce a conservative profile for review; never spawn a process with it.
/// No network, Mach-service, IPC or broad home-directory allowance is emitted.
/// Runtime access is limited to OS runtime trees, the project, and owned scratch.
/// This is intentionally incomplete for many developer tools; broadening it
/// requires native-host negative probes and approval-binding changes.
pub fn research_profile(directories: &CandidateDirectories) -> Result<String, String> {
    let project = canonical_directory(&directories.project)?;
    let scratch = canonical_directory(&directories.scratch)?;
    let state = canonical_directory(&directories.private_state)?;
    let home = canonical_directory(&directories.home)?;
    if overlaps(&project, &scratch)
        || overlaps(&project, &state)
        || overlaps(&scratch, &state)
        || overlaps(&scratch, &home)
        || project == home
        || home.starts_with(&project)
    {
        return Err("macOS candidate project, scratch, home, and private state overlap".into());
    }
    for runtime in ["/System", "/usr", "/bin", "/sbin", "/dev"] {
        if overlaps(&project, Path::new(runtime)) || overlaps(&scratch, Path::new(runtime)) {
            return Err("macOS candidate writable directory overlaps an OS runtime".into());
        }
    }
    let project = quoted_path(&project)?;
    let scratch = quoted_path(&scratch)?;
    let state_denials = forbidden_alias_probe_targets(&state)?
        .iter()
        .map(|path| quoted_path(path).map(|quoted| format!("(subpath {quoted})")))
        .collect::<Result<Vec<_>, _>>()?
        .join(" ");
    Ok(format!(
        "(version 1)\n(deny default)\n\
         (allow process-exec process-fork)\n\
         (allow file-read* (subpath \"/System/Library/Frameworks\") (subpath \"/System/Library/PrivateFrameworks\") (subpath \"/System/Library/dyld\") (subpath \"/usr/lib\") (subpath \"/usr/bin\") (subpath \"/bin\") (subpath \"/sbin\"))\n\
         (allow file-read* file-write* (subpath {project}) (subpath {scratch}))\n\
         (deny file-read* file-write* {state_denials})\n\
         (deny network*)\n"
    ))
}

/// The Data-volume spelling can expose the same inode through a different
/// pathname. A native qualification harness must try both spellings; no path
/// string comparison can prove kernel policy enforcement across these aliases.
/// Return targets only; this module never opens them or runs a probe itself.
pub fn forbidden_alias_probe_targets(path: &Path) -> Result<Vec<PathBuf>, String> {
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("alias probe path must be absolute without traversal".into());
    }
    let mut targets = vec![path.to_path_buf()];
    let data_volume = Path::new("/System/Volumes/Data");
    if let Ok(relative) = path.strip_prefix(data_volume) {
        targets.push(Path::new("/").join(relative));
    } else {
        targets.push(data_volume.join(path.strip_prefix("/").map_err(|e| e.to_string())?));
    }
    if let Ok(relative) = path.strip_prefix("/private") {
        targets.push(Path::new("/").join(relative));
    } else if path.starts_with("/var") || path.starts_with("/tmp") || path.starts_with("/etc") {
        targets
            .push(Path::new("/private").join(path.strip_prefix("/").map_err(|e| e.to_string())?));
    }
    targets.sort();
    targets.dedup();
    Ok(targets)
}

/// Embedded child tool entitlements scaffold. Apple requires these two App
/// Sandbox keys for inheritance, not an independent sandbox on the child.
/// This XML neither signs a binary nor grants project access. A trusted signed
/// containing launcher must establish the parent sandbox; no network or broad
/// home entitlements are included. Signing and runtime proof remain mandatory.
/// https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html
pub const INHERITED_HELPER_ENTITLEMENTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.security.inherit</key><true/>
</dict></plist>
"#;

/// There is no feature flag, environment variable or caller-supplied bool that
/// enables production execution. Root integration must map this error to
/// Outcome::Unknown, never to a passing check or direct unsandboxed invocation.
pub fn prepare_command() -> Result<Command, String> {
    Err(UNAVAILABLE_REASON.into())
}
