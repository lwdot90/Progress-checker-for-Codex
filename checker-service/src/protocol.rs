//! Bounded, versioned requests. Plan definitions never grant execution approval.
use checker_core::model::Claim;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub request_id: String,
    pub operation: Operation,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Operation {
    Project,
    ApprovalChallenge {
        check_id: String,
    },
    ApprovalCommit {
        challenge_id: String,
        binding: checker_core::security::ApprovalBinding,
    },
    Milestones {
        scope: Option<bool>,
    },
    SetClaim {
        milestone_id: String,
        claim: Claim,
        note: String,
        expected_revision: u64,
    },
    SubmitPlan {
        config: checker_core::config::Config,
        reason: String,
        expected_revision: u64,
        expected_config_hash: String,
    },
    PlanHistory {
        offset: usize,
        limit: usize,
    },
    RunChecks {
        check_ids: Vec<String>,
        idempotency_key: String,
        expected_config_hash: String,
        expected_revision: u64,
    },
    GetRun {
        run_id: String,
    },
    Progress,
    GetLog {
        run_id: String,
        check_id: String,
        offset: u64,
        limit: usize,
    },
    CancelRun {
        run_id: String,
        expected_revision: u64,
    },
    Subscribe {
        after_revision: Option<u64>,
    },
}
// Serde internally tagged unit variants discard unknown fields. Decode through
// struct variants instead so Project/Progress are as strict as mutations.
impl<'de> Deserialize<'de> for Operation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
        enum StrictOperation {
            Project {},
            ApprovalChallenge {
                check_id: String,
            },
            ApprovalCommit {
                challenge_id: String,
                binding: checker_core::security::ApprovalBinding,
            },
            Milestones {
                scope: Option<bool>,
            },
            SetClaim {
                milestone_id: String,
                claim: Claim,
                note: String,
                expected_revision: u64,
            },
            SubmitPlan {
                config: checker_core::config::Config,
                reason: String,
                expected_revision: u64,
                expected_config_hash: String,
            },
            PlanHistory {
                offset: usize,
                limit: usize,
            },
            RunChecks {
                check_ids: Vec<String>,
                idempotency_key: String,
                expected_config_hash: String,
                expected_revision: u64,
            },
            GetRun {
                run_id: String,
            },
            Progress {},
            GetLog {
                run_id: String,
                check_id: String,
                offset: u64,
                limit: usize,
            },
            CancelRun {
                run_id: String,
                expected_revision: u64,
            },
            Subscribe {
                after_revision: Option<u64>,
            },
        }
        Ok(match StrictOperation::deserialize(deserializer)? {
            StrictOperation::Project {} => Self::Project,
            StrictOperation::ApprovalChallenge { check_id } => Self::ApprovalChallenge { check_id },
            StrictOperation::ApprovalCommit {
                challenge_id,
                binding,
            } => Self::ApprovalCommit {
                challenge_id,
                binding,
            },
            StrictOperation::SubmitPlan {
                config,
                reason,
                expected_revision,
                expected_config_hash,
            } => Self::SubmitPlan {
                config,
                reason,
                expected_revision,
                expected_config_hash,
            },
            StrictOperation::PlanHistory { offset, limit } => Self::PlanHistory { offset, limit },
            StrictOperation::Milestones { scope } => Self::Milestones { scope },
            StrictOperation::SetClaim {
                milestone_id,
                claim,
                note,
                expected_revision,
            } => Self::SetClaim {
                milestone_id,
                claim,
                note,
                expected_revision,
            },
            StrictOperation::RunChecks {
                check_ids,
                idempotency_key,
                expected_config_hash,
                expected_revision,
            } => Self::RunChecks {
                check_ids,
                idempotency_key,
                expected_config_hash,
                expected_revision,
            },
            StrictOperation::GetRun { run_id } => Self::GetRun { run_id },
            StrictOperation::Progress {} => Self::Progress,
            StrictOperation::GetLog {
                run_id,
                check_id,
                offset,
                limit,
            } => Self::GetLog {
                run_id,
                check_id,
                offset,
                limit,
            },
            StrictOperation::CancelRun {
                run_id,
                expected_revision,
            } => Self::CancelRun {
                run_id,
                expected_revision,
            },
            StrictOperation::Subscribe { after_revision } => Self::Subscribe { after_revision },
        })
    }
}
impl Request {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported schema_version".into());
        }
        validate_id(&self.request_id)?;
        match &self.operation {
            Operation::ApprovalChallenge { check_id } => validate_id(check_id),
            Operation::ApprovalCommit {
                challenge_id,
                binding,
            } => {
                if challenge_id.len() != 64
                    || !challenge_id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("invalid approval challenge identifier".into());
                }
                if serde_json::to_vec(binding)
                    .map_err(|e| e.to_string())?
                    .len()
                    > 128 * 1024
                    || !binding.canonical_root.is_absolute()
                    || !binding.cwd.is_absolute()
                    || !binding.cwd.starts_with(&binding.canonical_root)
                    || binding.argv.is_empty()
                    || binding.argv.iter().any(|arg| arg.contains('\0'))
                    || binding.sandbox_profile != checker_core::security::SANDBOX_PROFILE
                {
                    return Err("invalid bounded approval binding".into());
                }
                for hash in [
                    &binding.config_hash,
                    &binding.command_hash,
                    &binding.executable_hash,
                    &binding.sandbox_binary_hash,
                ] {
                    if hash.len() != 71
                        || !hash.starts_with("sha256:")
                        || !hash[7..].bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return Err("invalid approval binding hash".into());
                    }
                }
                Ok(())
            }
            Operation::SubmitPlan {
                config,
                reason,
                expected_config_hash,
                ..
            } => {
                checker_core::engine::validate_plan(config, reason)?;
                if expected_config_hash.len() != 71
                    || !expected_config_hash.starts_with("sha256:")
                    || !expected_config_hash[7..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err("invalid config hash".into());
                }
                Ok(())
            }
            Operation::PlanHistory { limit, .. } => {
                if *limit == 0 || *limit > 5 {
                    return Err("history page limit must be 1 through 5".into());
                }
                Ok(())
            }
            Operation::SetClaim {
                milestone_id, note, ..
            } => {
                validate_id(milestone_id)?;
                if note.len() > 4096
                    || note
                        .chars()
                        .any(|c| c.is_control() && c != '\n' && c != '\t')
                {
                    return Err("invalid bounded claim note".into());
                }
                Ok(())
            }
            Operation::RunChecks {
                check_ids,
                idempotency_key,
                expected_config_hash,
                ..
            } => {
                if check_ids.is_empty() || check_ids.len() > 64 {
                    return Err("invalid check selection".into());
                }
                let mut unique = std::collections::BTreeSet::new();
                for id in check_ids {
                    validate_id(id)?;
                    if !unique.insert(id) {
                        return Err("duplicate check identifier".into());
                    }
                }
                validate_id(idempotency_key)?;
                if idempotency_key.len() > 128 {
                    return Err("idempotency key too long".into());
                }
                if !expected_config_hash.starts_with("sha256:")
                    || expected_config_hash.len() != 71
                    || !expected_config_hash[7..]
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit())
                {
                    return Err("invalid config hash".into());
                }
                Ok(())
            }
            Operation::GetLog {
                run_id,
                check_id,
                limit,
                ..
            } => {
                validate_id(run_id)?;
                validate_id(check_id)?;
                if *limit == 0 || *limit > 32 * 1024 {
                    return Err("invalid bounded log limit".into());
                }
                Ok(())
            }
            Operation::GetRun { run_id } | Operation::CancelRun { run_id, .. } => {
                validate_id(run_id)
            }
            _ => Ok(()),
        }
    }
}
pub fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.len() > 160
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || id == "."
        || id == ".."
    {
        return Err("invalid bounded identifier".into());
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceError {
    pub code: String,
    pub message: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub schema_version: u32,
    pub request_id: String,
    pub service_instance_id: String,
    pub revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ServiceError>,
}
impl Response {
    pub fn validate(&self, request_id: &str) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION || self.request_id != request_id {
            return Err("response version or request identity mismatch".into());
        }
        validate_id(&self.service_instance_id)?;
        if self.result.is_some() == self.error.is_some() {
            return Err("response must contain exactly one result or error".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approval_operations_reject_declared_peer_authority_and_invalid_nonce() {
        let binding = serde_json::json!({
            "canonical_root":"/fixture", "config_hash":format!("sha256:{}", "a".repeat(64)),
            "command_hash":format!("sha256:{}", "b".repeat(64)), "argv":["/usr/bin/true"],
            "cwd":"/fixture", "environment":{}, "sandbox_profile":checker_core::security::SANDBOX_PROFILE,
            "executable_hash":format!("sha256:{}", "c".repeat(64)),
            "sandbox_binary_hash":format!("sha256:{}", "d".repeat(64)),
        });
        for mut operation in [
            serde_json::json!({"operation":"approval_challenge","check_id":"check"}),
            serde_json::json!({"operation":"approval_commit","challenge_id":"a".repeat(64),"binding":binding}),
        ] {
            operation
                .as_object_mut()
                .unwrap()
                .insert("peer".into(), serde_json::json!({"tty":true,"pid":42}));
            assert!(serde_json::from_value::<Operation>(operation).is_err());
        }
        for id in ["", "../check", "a/b"] {
            let request = Request {
                schema_version: 1,
                request_id: "test".into(),
                operation: Operation::ApprovalChallenge {
                    check_id: id.into(),
                },
            };
            assert!(request.validate().is_err());
        }
        for id in ["a".repeat(63), "G".repeat(64), "../nonce".into()] {
            let operation = serde_json::json!({"operation":"approval_commit","challenge_id":id,"binding":binding});
            let request = Request {
                schema_version: 1,
                request_id: "test".into(),
                operation: serde_json::from_value(operation).unwrap(),
            };
            assert!(request.validate().is_err());
        }
    }
    #[test]
    fn rejects_remote_command_and_verified_claim_fields() {
        for operation in [
            r#"{"operation":"run_checks","check_ids":["safe"],"argv":["sh"]}"#,
            r#"{"operation":"set_claim","milestone_id":"safe","claim":"verified"}"#,
            r#"{"operation":"get_log","run_id":"../../secret"}"#,
        ] {
            let encoded =
                format!(r#"{{"schema_version":1,"request_id":"r1","operation":{operation}}}"#);
            assert!(match serde_json::from_str::<Request>(&encoded) {
                Err(_) => true,
                Ok(r) => r.validate().is_err(),
            });
        }
    }
    #[test]
    fn read_only_unit_operations_reject_unknown_authority_fields() {
        for operation in ["project", "progress"] {
            assert!(
                serde_json::from_value::<Operation>(serde_json::json!({"operation": operation}))
                    .is_ok()
            );
            for field in ["root", "argv", "environment", "approval", "unused"] {
                let mut object = serde_json::json!({"operation": operation});
                object
                    .as_object_mut()
                    .unwrap()
                    .insert(field.into(), Value::Null);
                assert!(
                    serde_json::from_value::<Operation>(object).is_err(),
                    "{operation}: {field}"
                );
            }
        }
    }
    #[test]
    fn response_identity_and_exclusive_payload_are_checked() {
        let mut response = Response {
            schema_version: 1,
            request_id: "r".into(),
            service_instance_id: "instance".into(),
            revision: 1,
            result: Some(Value::Null),
            error: None,
        };
        assert!(response.validate("r").is_ok());
        assert!(response.validate("other").is_err());
        response.error = Some(ServiceError {
            code: "invalid".into(),
            message: "invalid".into(),
        });
        assert!(response.validate("r").is_err());
    }
}
