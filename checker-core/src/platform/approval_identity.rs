//! Proposed portable approval identity. Pure values only: no grant creation,
//! trust discovery, command launch, or authorization decision is provided here.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    LinuxBubblewrap,
    MacosNative,
    WindowsNative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeRole {
    Executable,
    Launcher,
    Dependency,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIdentity {
    pub role: RuntimeRole,
    /// Exact canonical spelling established by the backend's trusted collector.
    pub canonical_path: String,
    pub bytes: u64,
    pub content_hash: String,
    /// Identity of the reviewed ownership/ACL/signing/dependency-load policy.
    /// A hash is an identity reference, not proof that this policy was checked.
    pub trust_policy_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalIdentityV2 {
    pub schema_version: u32,
    pub backend: Backend,
    pub canonical_root: String,
    pub canonical_cwd: String,
    pub config_hash: String,
    pub command_hash: String,
    pub argv: Vec<String>,
    #[serde(deserialize_with = "unique_environment")]
    pub environment: BTreeMap<String, String>,
    pub sandbox_profile_id: String,
    pub sandbox_profile_hash: String,
    pub runtime_closure: Vec<RuntimeIdentity>,
}

fn unique_environment<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct EnvironmentVisitor;
    impl<'de> serde::de::Visitor<'de> for EnvironmentVisitor {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("at most 256 unique environment entries")
        }
        fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = entries.next_entry::<String, String>()? {
                if values.len() >= 256 || values.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive environment entries",
                    ));
                }
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(EnvironmentVisitor)
}

// Deliberately uninhabited: no public or internal constructor exists until
// backend authorization AND native containment qualification are implemented.
enum QualifiedBackend {}

/// Proposed ownership contract: native launch must keep protected state,
/// installation trust, isolated project and runtime locks alive together with
/// the exact reviewed identity. This type currently cannot be constructed.
pub struct NativeLaunchContract<'a, ProtectedState, InstallationTrust, ProjectSnapshot> {
    identity: &'a ApprovalIdentityV2,
    state: &'a ProtectedState,
    trust: &'a InstallationTrust,
    project: &'a ProjectSnapshot,
    runtime: &'a super::windows_inventory::RuntimeManifest,
    qualification: QualifiedBackend,
}

fn hash_valid(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn text_valid(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32_768 && !value.chars().any(char::is_control)
}

fn canonical_spelling(backend: Backend, path: &str) -> bool {
    if !text_valid(path) {
        return false;
    }
    match backend {
        Backend::LinuxBubblewrap | Backend::MacosNative => {
            path.starts_with('/')
                && !path.contains("//")
                && !path.split('/').any(|part| part == "." || part == "..")
        }
        // Only canonical local-drive paths. UNC/network and device paths are
        // deliberately excluded pending explicit backend policy qualification.
        Backend::WindowsNative => {
            let Some(rest) = path.strip_prefix("\\\\?\\") else {
                return false;
            };
            let bytes = rest.as_bytes();
            bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\'
                && !rest.contains('/')
                && !rest[3..].split('\\').any(|part| {
                    part.is_empty()
                        || part.ends_with(['.', ' '])
                        || part.contains(':')
                        || part == "."
                        || part == ".."
                })
        }
    }
}

impl ApprovalIdentityV2 {
    /// Structural validation only. The execution backend must additionally
    /// establish canonical objects, state separation, trust, containment, and
    /// exact equality with a separately human-approved stored grant.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 2 {
            return Err("unsupported approval identity version".into());
        }
        if !canonical_spelling(self.backend, &self.canonical_root)
            || !canonical_spelling(self.backend, &self.canonical_cwd)
        {
            return Err("approval identity requires canonical backend paths".into());
        }
        let separator = if self.backend == Backend::WindowsNative {
            '\\'
        } else {
            '/'
        };
        let root_prefix = format!(
            "{}{separator}",
            self.canonical_root.trim_end_matches(separator)
        );
        if self.canonical_cwd != self.canonical_root
            && !self.canonical_cwd.starts_with(&root_prefix)
        {
            return Err("working directory escapes approved project root".into());
        }
        if ![
            &self.config_hash,
            &self.command_hash,
            &self.sandbox_profile_hash,
        ]
        .iter()
        .all(|hash| hash_valid(hash))
        {
            return Err("approval identity contains invalid definition hashes".into());
        }
        let prefix = match self.backend {
            Backend::LinuxBubblewrap => "linux-",
            Backend::MacosNative => "macos-",
            Backend::WindowsNative => "windows-",
        };
        if !text_valid(&self.sandbox_profile_id) || !self.sandbox_profile_id.starts_with(prefix) {
            return Err("sandbox profile belongs to a different backend".into());
        }
        if self.argv.is_empty()
            || self.argv.len() > 4096
            || self
                .argv
                .iter()
                .any(|argument| argument.len() > 32_768 || argument.contains('\0'))
            || !canonical_spelling(self.backend, &self.argv[0])
        {
            return Err("invalid exact command arguments".into());
        }
        if self.environment.len() > 256
            || self.environment.iter().any(|(key, value)| {
                !text_valid(key)
                    || key.contains('=')
                    || value.len() > 32_768
                    || value.contains('\0')
            })
        {
            return Err("invalid exact environment".into());
        }
        let total_text = self.argv.iter().map(String::len).sum::<usize>()
            + self
                .environment
                .iter()
                .map(|(key, value)| key.len() + value.len())
                .sum::<usize>();
        if total_text > 1024 * 1024 {
            return Err("command and environment exceed identity size bound".into());
        }
        if self.backend == Backend::WindowsNative {
            let mut environment_keys = BTreeSet::new();
            if self
                .environment
                .keys()
                .any(|key| !environment_keys.insert(key.to_lowercase()))
            {
                return Err("Windows environment contains case-alias duplicates".into());
            }
        }
        if self.runtime_closure.is_empty() || self.runtime_closure.len() > 256 {
            return Err("runtime closure must contain 1 through 256 identities".into());
        }
        let mut seen = BTreeSet::new();
        let mut executable_count = 0;
        let mut launcher_count = 0;
        let mut total_bytes = 0_u64;
        for runtime in &self.runtime_closure {
            if !canonical_spelling(self.backend, &runtime.canonical_path)
                || !hash_valid(&runtime.content_hash)
                || !hash_valid(&runtime.trust_policy_hash)
                || runtime.bytes > 128 * 1024 * 1024
                || !seen.insert(if self.backend == Backend::WindowsNative {
                    runtime.canonical_path.to_lowercase()
                } else {
                    runtime.canonical_path.clone()
                })
            {
                return Err("invalid or duplicate runtime identity".into());
            }
            total_bytes += runtime.bytes;
            if total_bytes > 512 * 1024 * 1024 {
                return Err("runtime closure exceeds 512 MiB".into());
            }
            if runtime.role == RuntimeRole::Executable {
                executable_count += 1;
                if runtime.canonical_path != self.argv[0] {
                    return Err("runtime executable differs from exact command".into());
                }
            }
            if runtime.role == RuntimeRole::Launcher {
                launcher_count += 1;
            }
        }
        if executable_count != 1 || launcher_count != 1 {
            return Err("runtime closure requires one executable and one confined launcher".into());
        }
        Ok(())
    }

    /// Bind the exact serialized closure ordering as well as all command and
    /// backend values. A digest never authorizes execution by itself.
    pub fn digest(&self) -> Result<String, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("serialized approval identity exceeds 4 MiB".into());
        }
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ApprovalIdentityV2 {
        let hash = format!("sha256:{}", "a".repeat(64));
        ApprovalIdentityV2 {
            schema_version: 2,
            backend: Backend::LinuxBubblewrap,
            canonical_root: "/project".into(),
            canonical_cwd: "/project/checks".into(),
            config_hash: hash.clone(),
            command_hash: hash.clone(),
            argv: vec!["/usr/bin/python3".into(), "test.py".into()],
            environment: BTreeMap::from([("HOME".into(), "/tmp".into())]),
            sandbox_profile_id: "linux-reviewed-test-v2".into(),
            sandbox_profile_hash: hash.clone(),
            runtime_closure: vec![
                RuntimeIdentity {
                    role: RuntimeRole::Executable,
                    canonical_path: "/usr/bin/python3".into(),
                    bytes: 1,
                    content_hash: hash.clone(),
                    trust_policy_hash: hash.clone(),
                },
                RuntimeIdentity {
                    role: RuntimeRole::Launcher,
                    canonical_path: "/usr/bin/bwrap".into(),
                    bytes: 1,
                    content_hash: hash.clone(),
                    trust_policy_hash: hash,
                },
            ],
        }
    }

    #[test]
    fn digest_changes_with_profile_runtime_and_exact_arguments() {
        let original = fixture();
        let digest = original.digest().unwrap();
        for changed in [0, 1, 2] {
            let mut binding = original.clone();
            match changed {
                0 => binding.sandbox_profile_hash = format!("sha256:{}", "b".repeat(64)),
                1 => binding.runtime_closure[1].content_hash = format!("sha256:{}", "b".repeat(64)),
                _ => binding.argv.push("--verbose".into()),
            }
            assert_ne!(binding.digest().unwrap(), digest);
        }
    }

    #[test]
    fn mismatched_backend_escaped_cwd_and_missing_launcher_are_rejected() {
        let mut binding = fixture();
        binding.backend = Backend::WindowsNative;
        assert!(binding.validate().is_err());
        let mut binding = fixture();
        binding.canonical_cwd = "/project-other".into();
        assert!(binding.validate().is_err());
        let mut binding = fixture();
        binding.runtime_closure.pop();
        assert!(binding.validate().is_err());
    }

    #[test]
    fn legacy_identity_is_not_implicitly_upgraded() {
        let mut binding = fixture();
        binding.schema_version = 1;
        assert!(binding.digest().is_err());
    }

    #[test]
    fn duplicate_environment_json_is_rejected_before_map_collapse() {
        let json = serde_json::to_string(&fixture()).unwrap().replace(
            "\"environment\":{\"HOME\":\"/tmp\"}",
            "\"environment\":{\"HOME\":\"/tmp\",\"HOME\":\"/other\"}",
        );
        assert!(serde_json::from_str::<ApprovalIdentityV2>(&json).is_err());
    }

    #[test]
    fn windows_case_aliases_and_alternate_streams_are_rejected() {
        let mut binding = fixture();
        binding.backend = Backend::WindowsNative;
        binding.canonical_root = r"\\?\C:\project".into();
        binding.canonical_cwd = r"\\?\C:\project\checks".into();
        binding.argv[0] = r"\\?\C:\Runtime\python.exe".into();
        binding.sandbox_profile_id = "windows-lpac-candidate-v2".into();
        binding.runtime_closure[0].canonical_path = binding.argv[0].clone();
        binding.runtime_closure[1].canonical_path = r"\\?\C:\Runtime\launcher.exe".into();
        assert!(binding.validate().is_ok());
        binding
            .environment
            .insert("home".into(), "elsewhere".into());
        assert!(binding.validate().is_err());
        binding.environment.remove("home");
        let mut alias = binding.runtime_closure[0].clone();
        alias.role = RuntimeRole::Dependency;
        alias.canonical_path = r"\\?\C:\runtime\PYTHON.exe".into();
        binding.runtime_closure.push(alias);
        assert!(binding.validate().is_err());
        assert!(!canonical_spelling(
            Backend::WindowsNative,
            r"\\?\C:\Runtime\python.exe:stream"
        ));
    }
}
