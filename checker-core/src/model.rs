//! Claims are input; verification is always recomputed against fresh evidence.
use crate::config::Config;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Claim {
    #[default]
    Planned,
    Implemented,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Queued,
    Running,
    Finished,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Passed,
    Failed,
    Skipped,
    Unknown,
    Cancelled,
    TimedOut,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    Current,
    Stale,
    Pending,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub git_commit: String,
    pub fingerprint: String,
    pub config_hash: String,
    pub checker_version: String,
    pub environment_signature: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckEvidence {
    pub run_id: String,
    pub check_id: String,
    pub execution_state: ExecutionState,
    pub outcome: Option<Outcome>,
    pub freshness: Freshness,
    pub source: SourceIdentity,
    pub command_hash: String,
    pub log_ref: Option<String>,
    pub log_sha256: Option<String>,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MilestoneEvaluation {
    pub milestone_id: String,
    pub implementation_claim: Claim,
    pub verified: bool,
    pub blockers: Vec<String>,
    pub evidence_refs: Vec<String>,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Progress {
    pub verified: usize,
    pub scoped: usize,
    pub percent: Option<usize>,
    pub milestones: Vec<MilestoneEvaluation>,
}

/// `latest` must contain only the newest attempt per check. Queued/running
/// replacements block verification immediately; an older green is never consulted.
/// The caller must validate referenced log hashes before providing evidence.
pub fn evaluate(
    config: &Config,
    claims: &BTreeMap<String, Claim>,
    latest: &BTreeMap<String, CheckEvidence>,
    current: &SourceIdentity,
) -> Result<Progress, String> {
    config.validate()?;
    let config_hash = config.hash();
    let mut verified_ids = BTreeSet::new();
    let mut pending: BTreeSet<&str> = config.milestones.iter().map(|m| m.id.as_str()).collect();
    let mut results = BTreeMap::new();
    while !pending.is_empty() {
        for milestone in &config.milestones {
            if !pending.contains(milestone.id.as_str())
                || milestone
                    .depends_on
                    .iter()
                    .any(|id| pending.contains(id.as_str()))
            {
                continue;
            }
            let claim = claims.get(&milestone.id).copied().unwrap_or_default();
            let mut blockers = Vec::new();
            let mut evidence_refs = Vec::new();
            if !config.enabled {
                blockers.push("project disabled".into());
            }
            if !milestone.in_scope {
                blockers.push("out of scope".into());
            }
            if claim != Claim::Implemented {
                blockers.push("implementation not claimed".into());
            }
            for dependency in &milestone.depends_on {
                if !verified_ids.contains(dependency) {
                    blockers.push(format!("dependency {dependency} is unverified"));
                }
            }
            for criterion in milestone
                .criteria
                .iter()
                .filter(|criterion| criterion.required)
            {
                let check = config
                    .check(&criterion.check_id)
                    .expect("validated check reference");
                let passing = latest.get(&criterion.check_id).filter(|evidence| {
                    !evidence.run_id.is_empty()
                        && evidence.check_id == check.id
                        && evidence.execution_state == ExecutionState::Finished
                        && evidence.outcome == Some(Outcome::Passed)
                        && evidence.freshness == Freshness::Current
                        && evidence.source == *current
                        && current.config_hash == config_hash
                        && evidence.command_hash == check.hash()
                        && evidence
                            .log_ref
                            .as_ref()
                            .is_some_and(|value| !value.is_empty())
                        && evidence
                            .log_sha256
                            .as_ref()
                            .is_some_and(|value| !value.is_empty())
                });
                if let Some(evidence) = passing {
                    evidence_refs.push(format!("{}/{}", evidence.run_id, evidence.check_id));
                } else {
                    blockers.push(format!(
                        "criterion {} lacks current passing evidence",
                        criterion.id
                    ));
                }
            }
            let verified = blockers.is_empty();
            if verified {
                verified_ids.insert(milestone.id.clone());
            }
            results.insert(
                milestone.id.clone(),
                MilestoneEvaluation {
                    milestone_id: milestone.id.clone(),
                    implementation_claim: claim,
                    verified,
                    blockers,
                    evidence_refs,
                },
            );
            pending.remove(milestone.id.as_str());
        }
    }
    let scoped = config.milestones.iter().filter(|m| m.in_scope).count();
    let verified = verified_ids.len();
    Ok(Progress {
        verified,
        scoped,
        percent: (scoped > 0).then(|| verified * 100 / scoped),
        milestones: config
            .milestones
            .iter()
            .map(|m| results.remove(&m.id).expect("evaluated milestone"))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> (
        Config,
        BTreeMap<String, Claim>,
        BTreeMap<String, CheckEvidence>,
        SourceIdentity,
    ) {
        let config = Config::parse(include_bytes!("../examples/config.json")).unwrap();
        let source = SourceIdentity {
            git_commit: "head".into(),
            fingerprint: "source".into(),
            config_hash: config.hash(),
            checker_version: "v1".into(),
            environment_signature: "env".into(),
        };
        let claims = config
            .milestones
            .iter()
            .map(|m| (m.id.clone(), Claim::Implemented))
            .collect();
        let latest = config
            .checks
            .iter()
            .map(|check| {
                (
                    check.id.clone(),
                    CheckEvidence {
                        run_id: "run-1".into(),
                        check_id: check.id.clone(),
                        execution_state: ExecutionState::Finished,
                        outcome: Some(Outcome::Passed),
                        freshness: Freshness::Current,
                        source: source.clone(),
                        command_hash: check.hash(),
                        log_ref: Some("log".into()),
                        log_sha256: Some("sha256:log".into()),
                    },
                )
            })
            .collect();
        (config, claims, latest, source)
    }
    #[test]
    fn every_nonpass_replacement_blocks_old_success_and_dependencies() {
        let (config, claims, latest, source) = setup();
        assert_eq!(
            evaluate(&config, &claims, &latest, &source)
                .unwrap()
                .verified,
            3
        );
        for outcome in [
            Outcome::Failed,
            Outcome::Skipped,
            Outcome::Unknown,
            Outcome::Cancelled,
            Outcome::TimedOut,
        ] {
            let mut changed = latest.clone();
            changed.get_mut("opt-in-test").unwrap().outcome = Some(outcome);
            assert_eq!(
                evaluate(&config, &claims, &changed, &source)
                    .unwrap()
                    .verified,
                0
            );
        }
        for state in [ExecutionState::Queued, ExecutionState::Running] {
            let mut changed = latest.clone();
            changed.get_mut("opt-in-test").unwrap().execution_state = state;
            assert_eq!(
                evaluate(&config, &claims, &changed, &source)
                    .unwrap()
                    .verified,
                0
            );
        }
    }
    #[test]
    fn freshness_identity_missing_logs_and_claims_are_not_green() {
        let (config, mut claims, latest, source) = setup();
        for kind in [
            "stale",
            "pending",
            "source",
            "git_commit",
            "checker_version",
            "environment_signature",
            "config_hash",
            "command",
            "log",
            "missing",
        ] {
            let mut changed = latest.clone();
            if kind == "missing" {
                changed.remove("opt-in-test");
            } else {
                let evidence = changed.get_mut("opt-in-test").unwrap();
                match kind {
                    "stale" => evidence.freshness = Freshness::Stale,
                    "pending" => evidence.freshness = Freshness::Pending,
                    "source" => evidence.source.fingerprint = "changed".into(),
                    "git_commit" => evidence.source.git_commit = "changed".into(),
                    "checker_version" => evidence.source.checker_version = "changed".into(),
                    "environment_signature" => {
                        evidence.source.environment_signature = "changed".into()
                    }
                    "config_hash" => evidence.source.config_hash = "changed".into(),
                    "command" => evidence.command_hash = "changed".into(),
                    "log" => evidence.log_sha256 = None,
                    _ => unreachable!(),
                }
            }
            assert_eq!(
                evaluate(&config, &claims, &changed, &source)
                    .unwrap()
                    .verified,
                0,
                "{kind}"
            );
        }
        claims.insert("project-opt-in".into(), Claim::Planned);
        assert_eq!(
            evaluate(&config, &claims, &latest, &source)
                .unwrap()
                .verified,
            0
        );
        assert!(serde_json::from_str::<Claim>("\"verified\"").is_err());
    }
    #[test]
    fn empty_scope_is_not_complete_and_config_changes_invalidate() {
        let (mut config, claims, latest, source) = setup();
        config
            .milestones
            .iter_mut()
            .for_each(|m| m.in_scope = false);
        let progress = evaluate(&config, &claims, &latest, &source).unwrap();
        assert_eq!(progress.percent, None);
        assert_eq!(progress.verified, 0);
        config.milestones[0].in_scope = true;
        assert_eq!(
            evaluate(&config, &claims, &latest, &source)
                .unwrap()
                .verified,
            0
        );
    }
}
