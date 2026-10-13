//! Signed macOS helper package contract. Preparation is not qualification.
//! No project configuration, environment flag or agent-supplied boolean can
//! convert this manifest into permission to execute.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHelperContract {
    pub schema_version: u32,
    pub canonical_bundle: PathBuf,
    pub canonical_helper: PathBuf,
    pub helper_sha256: String,
    /// Required designated signing requirement, supplied by reviewed release
    /// policy, not accepted from a project-local plan or untrusted config.
    pub designated_requirement: String,
    pub team_identifier: String,
    pub signing_identifier: String,
    /// Every packaged interpreter/library/resource in the approved closure.
    /// This is a manifest assertion; completeness needs native loader inspection.
    pub runtime_closure: BTreeMap<PathBuf, String>,
    pub child_entitlements_sha256: String,
}

fn validate_hash(hash: &str) -> Result<(), String> {
    if !hash.strip_prefix("sha256:").is_some_and(|value| {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err("invalid helper contract SHA-256".into());
    }
    Ok(())
}

/// Strict semantic scaffold: accept only the reviewed two-key child plist.
/// This intentionally rejects alternate XML serializations; native extraction
/// needs a real plist parser before broader serialization support is enabled.
/// A hash match against arbitrary caller-selected XML is not sufficient.
pub fn validate_inherited_entitlement_scaffold(bytes: &[u8]) -> Result<(), String> {
    if bytes != super::macos_sandbox::INHERITED_HELPER_ENTITLEMENTS.as_bytes() {
        return Err("child entitlement scaffold must contain exactly reviewed app-sandbox and inherit true keys".into());
    }
    Ok(())
}

fn validate_canonical(path: &Path) -> Result<(), String> {
    if !path.is_absolute() || path.canonicalize().ok().as_deref() != Some(path) {
        return Err("helper contract requires existing canonical absolute paths".into());
    }
    Ok(())
}

fn validate_file(path: &Path, expected: &str) -> Result<(), String> {
    use std::io::Read;
    validate_canonical(path)?;
    validate_hash(expected)?;
    let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 * 1024 {
        return Err("helper closure entry must be a bounded regular file".into());
    }
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut length = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        length += count as u64;
        if length > 64 * 1024 * 1024 {
            return Err("helper closure entry grew beyond size limit".into());
        }
        hash.update(&buffer[..count]);
    }
    let after = file.metadata().map_err(|e| e.to_string())?;
    let path_after = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if length != opened.len()
        || opened.len() != after.len()
        || opened.modified().ok() != after.modified().ok()
        || after.len() != path_after.len()
        || after.modified().ok() != path_after.modified().ok()
    {
        return Err("helper closure entry changed during bounded read".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let stamp = |value: &std::fs::Metadata| {
            (
                value.dev(),
                value.ino(),
                value.ctime(),
                value.ctime_nsec(),
                value.mode(),
                value.uid(),
            )
        };
        if stamp(&opened) != stamp(&after) || stamp(&after) != stamp(&path_after) {
            return Err("helper closure entry identity changed during bounded read".into());
        }
    }
    let actual = format!("sha256:{:x}", hash.finalize());
    if actual != expected {
        return Err("signed helper closure content changed".into());
    }
    Ok(())
}

impl SignedHelperContract {
    /// Compare a collector observation against package assertions. This method
    /// is pure matching, not authentication: SignedIdentity is publicly
    /// constructible, so a caller can fabricate it. Only the trusted native
    /// collector may supply observations to a future activation path.
    pub fn match_identity_assertions(
        &self,
        identity: &super::macos_trust::SignedIdentity,
    ) -> Result<(), String> {
        validate_hash(&identity.codesign_sha256)?;
        if identity.canonical_path != self.canonical_helper
            || identity.executable_sha256 != self.helper_sha256
            || identity.team_identifier != self.team_identifier
            || identity.signing_identifier != self.signing_identifier
            || identity.designated_requirement != self.designated_requirement
            || identity.entitlements_sha256 != self.child_entitlements_sha256
        {
            return Err(
                "native identity observation differs from helper contract assertions".into(),
            );
        }
        Ok(())
    }

    /// Validate package assertions only. This does not validate a code signature,
    /// entitlements, filesystem ownership, runtime closure completeness or trust.
    pub fn validate_package_assertions(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.designated_requirement.trim().is_empty()
            || self.designated_requirement.contains('\0')
            || self.team_identifier.len() != 10
            || self.signing_identifier.is_empty()
            || self.signing_identifier.len() > 255
            || !self
                .signing_identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
            || !self
                .team_identifier
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return Err("invalid signed helper contract identity assertions".into());
        }
        validate_canonical(&self.canonical_bundle)?;
        if !self.canonical_bundle.is_dir()
            || !self.canonical_helper.starts_with(&self.canonical_bundle)
            || self.runtime_closure.is_empty()
        {
            return Err(
                "helper and nonempty runtime closure must belong to canonical bundle".into(),
            );
        }
        validate_file(&self.canonical_helper, &self.helper_sha256)?;
        validate_hash(&self.child_entitlements_sha256)?;
        for (path, expected) in &self.runtime_closure {
            if !path.starts_with(&self.canonical_bundle) {
                return Err("runtime closure escapes signed helper bundle".into());
            }
            validate_file(path, expected)?;
        }
        Ok(())
    }

    /// Code-signing verification needs the platform Security.framework verifier,
    /// a trusted release designated requirement, extracted actual entitlements,
    /// and a separately established parent sandbox. A matching self-asserted
    /// team string or manifest digest is never a verified identity.
    pub fn require_verified_native_runtime(&self) -> Result<(), String> {
        self.validate_package_assertions()?;
        Err("macOS signed helper runtime refused: native code-signing identity, actual inherited entitlements, CLOEXEC-default descriptor isolation, closure completeness, and descendant lifecycle are unqualified".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fabricated_matching_identity_is_never_runtime_authorization() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory.path().canonicalize().unwrap();
        let helper = bundle.join("helper");
        std::fs::write(&helper, b"unsigned helper fixture").unwrap();
        let hash = format!("sha256:{:x}", Sha256::digest(b"unsigned helper fixture"));
        let entitlement_hash = format!("sha256:{}", "a".repeat(64));
        let contract = SignedHelperContract {
            schema_version: 1,
            canonical_bundle: bundle,
            canonical_helper: helper.clone(),
            helper_sha256: hash.clone(),
            designated_requirement: "designated => anchor apple generic".into(),
            team_identifier: "ABCDEFGHI1".into(),
            signing_identifier: "org.example.helper".into(),
            runtime_closure: BTreeMap::from([(helper.clone(), hash.clone())]),
            child_entitlements_sha256: entitlement_hash.clone(),
        };
        let mut fabricated = super::super::macos_trust::SignedIdentity {
            canonical_path: helper,
            executable_sha256: hash,
            codesign_sha256: format!("sha256:{}", "b".repeat(64)),
            designated_requirement: contract.designated_requirement.clone(),
            entitlements_sha256: entitlement_hash,
            team_identifier: contract.team_identifier.clone(),
            signing_identifier: "org.example.helper".into(),
        };
        assert!(contract.match_identity_assertions(&fabricated).is_ok());
        assert!(contract.require_verified_native_runtime().is_err());
        fabricated.team_identifier = "ZZZZZZZZZ9".into();
        assert!(contract.match_identity_assertions(&fabricated).is_err());
        fabricated.team_identifier = contract.team_identifier.clone();
        fabricated.signing_identifier = "org.example.other".into();
        assert!(contract.match_identity_assertions(&fabricated).is_err());
    }

    #[test]
    fn extra_network_entitlement_is_rejected_even_with_valid_xml() {
        let exact = super::super::macos_sandbox::INHERITED_HELPER_ENTITLEMENTS;
        assert!(validate_inherited_entitlement_scaffold(exact.as_bytes()).is_ok());
        let changed = exact.replace(
            "</dict>",
            "<key>com.apple.security.network.client</key><true/></dict>",
        );
        assert!(validate_inherited_entitlement_scaffold(changed.as_bytes()).is_err());
        let disabled = exact.replace("<true/>", "<false/>");
        assert!(validate_inherited_entitlement_scaffold(disabled.as_bytes()).is_err());
    }
}
