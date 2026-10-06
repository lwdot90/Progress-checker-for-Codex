use std::collections::HashSet;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub project_id: String,
    pub enabled: bool,
    pub panel: Panel,
    pub execution: Execution,
    pub fingerprint: Fingerprint,
    pub checks: Vec<Check>,
    pub milestones: Vec<Milestone>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Panel {
    pub show_on_start: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub max_parallel: u32,
    pub default_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Fingerprint {
    pub extra_inputs: Vec<String>,
    pub exclude_outputs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub id: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub kind: String,
    pub timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Milestone {
    pub id: String,
    pub title: String,
    pub in_scope: bool,
    pub depends_on: Vec<String>,
    pub criteria: Vec<Criterion>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Criterion {
    pub id: String,
    pub description: String,
    pub check_id: String,
    pub required: bool,
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 || self.project_id.trim().is_empty() {
            return Err("Expected schema_version 1 and a nonempty project_id".into());
        }
        if self.execution.max_parallel == 0 || self.execution.default_timeout_seconds == 0 {
            return Err("Execution parallelism and default timeout must be positive".into());
        }
        for path in self
            .fingerprint
            .extra_inputs
            .iter()
            .chain(&self.fingerprint.exclude_outputs)
        {
            if !project_relative_path(path) {
                return Err(format!("Unsafe fingerprint path: {path}"));
            }
        }
        let mut checks = HashSet::new();
        for check in &self.checks {
            if check.id.trim().is_empty() || !checks.insert(check.id.as_str()) {
                return Err(format!("Empty or duplicate check ID: {}", check.id));
            }
            if check.timeout_seconds == 0
                || check
                    .argv
                    .first()
                    .is_none_or(|executable| executable.trim().is_empty())
                || check.argv.iter().any(|argument| argument.contains('\0'))
            {
                return Err(format!(
                    "Invalid command or timeout for check: {}",
                    check.id
                ));
            }
            if !project_relative_path(&check.cwd) {
                return Err(format!("Unsafe working directory for check: {}", check.id));
            }
        }
        let mut milestones = HashSet::new();
        for milestone in &self.milestones {
            if milestone.id.trim().is_empty()
                || milestone.title.trim().is_empty()
                || !milestones.insert(milestone.id.as_str())
            {
                return Err(format!(
                    "Empty or duplicate milestone ID/title: {}",
                    milestone.id
                ));
            }
        }
        for milestone in &self.milestones {
            if milestone
                .depends_on
                .iter()
                .any(|id| !milestones.contains(id.as_str()))
            {
                return Err(format!(
                    "Unknown dependency for milestone: {}",
                    milestone.id
                ));
            }
            let mut criteria = HashSet::new();
            for criterion in &milestone.criteria {
                if criterion.id.trim().is_empty() || !criteria.insert(criterion.id.as_str()) {
                    return Err(format!(
                        "Empty or duplicate criterion ID in: {}",
                        milestone.id
                    ));
                }
                if !checks.contains(criterion.check_id.as_str()) {
                    return Err(format!(
                        "Unknown criterion check in milestone: {}",
                        milestone.id
                    ));
                }
            }
            if !milestone
                .criteria
                .iter()
                .any(|criterion| criterion.required)
            {
                return Err(format!(
                    "Milestone has no required criteria: {}",
                    milestone.id
                ));
            }
        }
        let mut resolved = HashSet::new();
        while resolved.len() < milestones.len() {
            let previous = resolved.len();
            for milestone in &self.milestones {
                if milestone
                    .depends_on
                    .iter()
                    .all(|id| resolved.contains(id.as_str()))
                {
                    resolved.insert(milestone.id.as_str());
                }
            }
            if resolved.len() == previous {
                return Err("Milestone dependency cycle".into());
            }
        }
        Ok(())
    }
}

// This is lexical validation only. A future command runner must also resolve symlinks
// against its approved root before reading inputs or launching any command.
pub fn project_relative_path(path: &str) -> bool {
    !(path.trim().is_empty()
        || path.starts_with(['/', '\\'])
        || path.contains('\0')
        || (path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && path.as_bytes().get(1) == Some(&b':'))
        || path.split(['/', '\\']).any(|component| component == ".."))
}

impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let config: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        config.validate()?;
        Ok(config)
    }
    pub fn hash(&self) -> String {
        hash_json(self)
    }
    pub fn check(&self, id: &str) -> Option<&Check> {
        self.checks.iter().find(|check| check.id == id)
    }
}
impl Check {
    pub fn hash(&self) -> String {
        hash_json(self)
    }
}
fn hash_json(value: &impl Serialize) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("configuration serialization"))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../examples/config.json")).unwrap()
    }
    #[test]
    fn strict_validation_rejects_bad_configuration() {
        let original = fixture();
        assert!(Config::parse(&serde_json::to_vec(&original).unwrap()).is_ok());
        for change in [
            "unknown",
            "version",
            "duplicate",
            "cycle",
            "required",
            "path",
            "timeout",
            "reference",
        ] {
            let mut value = original.clone();
            match change {
                "unknown" => value["forged"] = true.into(),
                "version" => value["schema_version"] = 2.into(),
                "duplicate" => {
                    let check = value["checks"][0].clone();
                    value["checks"].as_array_mut().unwrap().push(check);
                }
                "cycle" => {
                    let id = value["milestones"][0]["id"].clone();
                    value["milestones"][0]["depends_on"] = serde_json::json!([id]);
                }
                "required" => value["milestones"][0]["criteria"][0]["required"] = false.into(),
                "path" => value["checks"][0]["cwd"] = "../outside".into(),
                "timeout" => value["checks"][0]["timeout_seconds"] = 0.into(),
                "reference" => value["milestones"][0]["criteria"][0]["check_id"] = "missing".into(),
                _ => unreachable!(),
            }
            assert!(
                Config::parse(&serde_json::to_vec(&value).unwrap()).is_err(),
                "{change}"
            );
        }
    }
    #[test]
    fn portable_paths_and_command_hashes() {
        for path in [
            "/tmp",
            "\\root",
            "C:relative",
            "a/../b",
            "a\\..\\b",
            "",
            "\0",
        ] {
            assert!(!project_relative_path(path), "{path:?}");
        }
        assert!(project_relative_path("target/**"));
        let config = Config::parse(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
        let mut check = config.checks[0].clone();
        let old = check.hash();
        check.argv.push("--changed".into());
        assert_ne!(old, check.hash());
    }
}
