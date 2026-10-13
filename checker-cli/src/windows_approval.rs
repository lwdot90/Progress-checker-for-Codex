//! Unwired native Windows CLI approval preparation prototype.
//!
//! This client observation is never server authority. Callers must supply image
//! policy from trusted installation configuration, never an MCP request or a
//! worktree file. Nothing here creates grants, invokes approval RPCs, or runs a
//! command. The production CLI remains platform-gated until independent server
//! checks and native execution are qualified.
#![cfg(windows)]

use std::path::{Path, PathBuf};

use checker_core::platform::{
    windows_inventory::RuntimeManifest, windows_trust::InstallationTrustGuard,
};

/// Retains audited executable ancestors and file locks throughout a preview.
/// No public deserialization or approval-capability boolean is provided.
pub struct PreparedApprovalPreview {
    image_path: PathBuf,
    image_trust: InstallationTrustGuard,
    image_manifest: RuntimeManifest,
    definition_json: String,
    check_id: String,
}

impl PreparedApprovalPreview {
    /// Verify this CLI's exact installed image and compile-time package version.
    /// `expected_image` and `expected_hash` must come from trusted installation
    /// policy. Hash equality alone is not executable or human identity proof.
    pub fn prepare(
        expected_image: &Path,
        expected_hash: &str,
        expected_version: &str,
        check_id: &str,
        exact_definition: &impl serde::Serialize,
    ) -> Result<Self, String> {
        if expected_version != env!("CARGO_PKG_VERSION") {
            return Err(
                "APPROVAL_CLIENT_INVALID: CLI version differs from installation policy".into(),
            );
        }
        if check_id.is_empty()
            || check_id.len() > 128
            || !check_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        {
            return Err("APPROVAL_CLIENT_INVALID: invalid exact check identity".into());
        }
        if expected_hash.len() != 71
            || !expected_hash.starts_with("sha256:")
            || !expected_hash[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("APPROVAL_CLIENT_INVALID: invalid fixed image hash".into());
        }
        if !expected_image.is_absolute() {
            return Err("APPROVAL_CLIENT_INVALID: fixed image path must be absolute".into());
        }
        let image_path = std::env::current_exe()
            .map_err(|_| "APPROVAL_CLIENT_INVALID: current image unavailable")?;
        let expected = expected_image
            .canonicalize()
            .map_err(|_| "APPROVAL_CLIENT_INVALID: installed image unavailable")?;
        let actual = image_path
            .canonicalize()
            .map_err(|_| "APPROVAL_CLIENT_INVALID: current image unavailable")?;
        if actual != expected {
            return Err(
                "APPROVAL_CLIENT_INVALID: current image differs from fixed installed CLI".into(),
            );
        }
        let image_trust = InstallationTrustGuard::audit(&image_path)?;
        let image_manifest = RuntimeManifest::collect(&[image_path.clone()])?;
        if image_manifest.identities().len() != 1
            || image_manifest.identities()[0].sha256 != expected_hash
        {
            return Err(
                "APPROVAL_CLIENT_INVALID: installed CLI content differs from fixed policy".into(),
            );
        }
        let definition_json = serde_json::to_string_pretty(exact_definition)
            .map_err(|_| "APPROVAL_CLIENT_INVALID: exact definition cannot be displayed")?;
        if definition_json.len() > 1024 * 1024 {
            return Err("APPROVAL_CLIENT_INVALID: exact definition exceeds preview bound".into());
        }
        Ok(Self {
            image_path,
            image_trust,
            image_manifest,
            definition_json,
            check_id: check_id.into(),
        })
    }

    /// Revalidate held image identity before any client console observation.
    pub fn revalidate(&mut self) -> Result<(), String> {
        self.image_trust.revalidate()?;
        self.image_manifest.revalidate()?;
        if std::env::current_exe()
            .map_err(|_| "APPROVAL_CLIENT_INVALID: current image unavailable")?
            .canonicalize()
            .map_err(|_| "APPROVAL_CLIENT_INVALID: current image unavailable")?
            != self
                .image_path
                .canonicalize()
                .map_err(|_| "APPROVAL_CLIENT_INVALID: installed image changed")?
        {
            return Err("APPROVAL_CLIENT_INVALID: current image changed".into());
        }
        Ok(())
    }

    pub fn exact_definition_json(&self) -> &str {
        &self.definition_json
    }
    pub fn check_id(&self) -> &str {
        &self.check_id
    }

    /// Display the exact definition through native console preflight only.
    /// No confirmation is read and no grant is created. The digest must bind the
    /// same reviewed server challenge; this adapter does not invent a challenge.
    pub fn render_console_preview(&mut self, binding_digest: &str) -> Result<(), String> {
        self.revalidate()?;
        let definition: serde_json::Value = serde_json::from_str(&self.definition_json)
            .map_err(|_| "APPROVAL_CLIENT_INVALID: preview definition changed")?;
        let mut prompt = checker_core::platform::windows_console::prepare_console_prompt(
            &self.image_path,
            &self.check_id,
            &definition,
            binding_digest,
        )?;
        prompt.render_preview()?;
        self.revalidate()
    }

    /// Approval cannot be minted from a preview, even after typed confirmation.
    pub fn require_server_authority(&self) -> Result<(), String> {
        checker_core::platform::windows_ipc::require_qualified_approval_transport()
    }
}
