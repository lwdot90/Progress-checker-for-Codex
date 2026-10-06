//! Revisioned plan transactions: prepare durably, replace config, then commit.
use super::*;
use std::collections::BTreeSet;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanSummary {
    pub id: String,
    pub reason: String,
    pub submitted_at: String,
    pub before_hash: String,
    pub after_hash: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanChange {
    pub summary: PlanSummary,
    pub before: Config,
    pub after: Config,
    pub prior_claims: BTreeMap<String, Claim>,
}

pub fn validate_plan(config: &Config, reason: &str) -> Result<(), String> {
    config.validate()?;
    if reason.trim().is_empty()
        || reason.len() > 4096
        || reason
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err("A bounded nonempty reason is required for scope changes".into());
    }
    if config.milestones.len() > 128
        || config.checks.len() > 128
        || serde_json::to_vec(config).map_err(error)?.len() > 64 * 1024
    {
        return Err("Plan exceeds 128 milestones/checks or 64 KiB".into());
    }
    let valid_id = |id: &str| {
        !id.is_empty()
            && id.len() <= 160
            && id != "."
            && id != ".."
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    for milestone in &config.milestones {
        if !valid_id(&milestone.id)
            || milestone.criteria.len() > 128
            || milestone
                .criteria
                .iter()
                .any(|criterion| !valid_id(&criterion.id))
        {
            return Err("Invalid bounded milestone/criterion identifier".into());
        }
    }
    for check in &config.checks {
        if !valid_id(&check.id) || check.argv.len() > 128 {
            return Err("Invalid bounded check definition".into());
        }
    }
    Ok(())
}

fn replace_config(root: &Path, change: &PlanChange) -> Result<(), String> {
    replace_config_inner(root, change, || {})
}

fn replace_config_inner(
    root: &Path,
    change: &PlanChange,
    before_rename: impl FnOnce(),
) -> Result<(), String> {
    let directory_path = root.join(".progress-checker");
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&directory_path)
        .map_err(error)?;
    let metadata = directory.metadata().map_err(error)?;
    let ensure_directory = || {
        let current = fs::symlink_metadata(&directory_path).map_err(error)?;
        if !current.is_dir()
            || current.file_type().is_symlink()
            || metadata.ino() != current.ino()
            || metadata.dev() != current.dev()
        {
            return Err("Plan directory changed during update".to_string());
        }
        Ok(())
    };
    ensure_directory()?;
    if read_config_directory(&directory)?.hash() != change.before.hash() {
        return Err("PLAN_CONFLICT: configuration changed before replacement".into());
    }
    let name = std::ffi::CString::new(format!(".{}.tmp", change.summary.id)).map_err(error)?;
    // A crash may leave this transaction's incomplete temporary file.
    unsafe {
        libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0);
    }
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o644,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut temporary = unsafe { fs::File::from_raw_fd(fd) };
    let result = (|| {
        let mut bytes = serde_json::to_vec_pretty(&change.after).map_err(error)?;
        bytes.push(b'\n');
        temporary.write_all(&bytes).map_err(error)?;
        temporary.sync_all().map_err(error)?;
        before_rename();
        ensure_directory()?;
        if read_config_directory(&directory)?.hash() != change.before.hash() {
            return Err("PLAN_CONFLICT: configuration changed during update".into());
        }
        let target = c"config.json";
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                name.as_ptr(),
                directory.as_raw_fd(),
                target.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        directory.sync_all().map_err(error)?;
        ensure_directory()?;
        if read_config_directory(&directory)?.hash() != change.after.hash() {
            return Err("PLAN_CONFLICT: configuration changed after replacement".into());
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0);
        }
    }
    result
}

impl Engine {
    pub fn plan_history(&self) -> &[PlanSummary] {
        &self.saved.plan_history
    }

    pub fn submit_plan(
        &mut self,
        config: Config,
        reason: &str,
        expected_revision: u64,
        expected_config_hash: &str,
    ) -> Result<Option<PlanSummary>, String> {
        self.ensure_available()?;
        self.refresh_config()?;
        if expected_revision != self.revision() {
            return Err("REVISION_CONFLICT: read the current project revision".into());
        }
        if self.config.hash() != expected_config_hash {
            return Err("PLAN_CONFLICT: read the current configuration hash".into());
        }
        validate_plan(&config, reason)?;
        if config.project_id != self.config.project_id {
            return Err("Plan cannot change the bound project identity".into());
        }
        if self
            .saved
            .latest
            .values()
            .any(|evidence| evidence.execution_state != ExecutionState::Finished)
        {
            return Err(
                "PLAN_BUSY: finish or cancel active checks before revising the plan".into(),
            );
        }
        if config == self.config {
            return Ok(None);
        }
        if self.saved.plan_history.len() >= 1024 {
            return Err("Plan history is full; archive private state before continuing".into());
        }
        // Reject exclusions that hide tracked/config inputs before committing.
        let _monitor = fingerprint::SourceWatch::start_with_options(
            &self.root,
            &FingerprintOptions {
                extra_inputs: config.fingerprint.extra_inputs.clone(),
                exclude_outputs: config.fingerprint.exclude_outputs.clone(),
            },
        )
        .map_err(error)?;
        let before_ids = self
            .config
            .milestones
            .iter()
            .map(|m| m.id.clone())
            .collect::<BTreeSet<_>>();
        let after_ids = config
            .milestones
            .iter()
            .map(|m| m.id.clone())
            .collect::<BTreeSet<_>>();
        let changed_checks = config
            .checks
            .iter()
            .filter(|check| {
                self.config
                    .checks
                    .iter()
                    .find(|prior| prior.id == check.id)
                    .is_some_and(|prior| prior != *check)
            })
            .map(|check| check.id.as_str())
            .collect::<BTreeSet<_>>();
        let summary = PlanSummary {
            id: format!(
                "plan-{}-{}-{}",
                Utc::now().timestamp_nanos_opt().ok_or("clock overflow")?,
                std::process::id(),
                self.revision()
            ),
            reason: reason.into(),
            submitted_at: Utc::now().to_rfc3339(),
            before_hash: self.config.hash(),
            after_hash: config.hash(),
            added: after_ids.difference(&before_ids).cloned().collect(),
            removed: before_ids.difference(&after_ids).cloned().collect(),
            changed: config
                .milestones
                .iter()
                .filter(|milestone| {
                    self.config
                        .milestones
                        .iter()
                        .find(|prior| prior.id == milestone.id)
                        .is_some_and(|prior| {
                            prior != *milestone
                                || milestone.criteria.iter().any(|criterion| {
                                    changed_checks.contains(criterion.check_id.as_str())
                                })
                        })
                })
                .map(|m| m.id.clone())
                .collect(),
        };
        let change = PlanChange {
            summary: summary.clone(),
            before: self.config.clone(),
            after: config,
            prior_claims: self.saved.claims.clone(),
        };
        self.store
            .append_attempt(&summary.id, &change)
            .map_err(error)?;
        self.saved.pending_plan = Some(change);
        self.persist()?;
        self.recover_plan()?;
        Ok(Some(summary))
    }

    pub(super) fn recover_plan(&mut self) -> Result<(), String> {
        let Some(change) = self.saved.pending_plan.clone() else {
            return Ok(());
        };
        validate_plan(&change.after, &change.summary.reason)?;
        let result = (|| {
            let current = read_config(&self.root)?;
            if current.hash() == change.before.hash() {
                replace_config(&self.root, &change)?;
            } else if current.hash() != change.after.hash() {
                return Err("PLAN_CONFLICT: pending plan conflicts with an external config edit; restore the journal's before/after definition before reopening".into());
            }
            self.config = change.after;
            self.saved.approvals.clear();
            for id in change.summary.removed.iter().chain(&change.summary.changed) {
                self.saved.claims.remove(id);
                self.saved.claim_notes.remove(id);
            }
            self.saved.plan_history.push(change.summary);
            self.saved.pending_plan = None;
            self.persist()
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, Engine) {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("project");
        fs::create_dir_all(root.join(".progress-checker")).unwrap();
        let mut config: Config =
            serde_json::from_str(include_str!("../examples/config.json")).unwrap();
        for check in &mut config.checks {
            check.argv = vec!["/usr/bin/true".into()];
        }
        fs::write(
            root.join(".progress-checker/config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        assert!(
            std::process::Command::new("/usr/bin/git")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .args(["init", "--quiet"])
                .arg(&root)
                .status()
                .unwrap()
                .success()
        );
        let engine = Engine::open(&root, &base.path().join("state")).unwrap();
        (base, engine)
    }
    #[test]
    fn plan_records_changes_resets_changed_claims_and_clears_approvals() {
        let (base, mut engine) = fixture();
        let id = engine.config.milestones[0].id.clone();
        engine.saved.claims.insert(id.clone(), Claim::Implemented);
        let check_id = engine.config.checks[0].id.clone();
        let binding = engine.approval_binding(&check_id).unwrap();
        engine.approve(&check_id, binding).unwrap();
        assert!(!engine.saved.approvals.is_empty());
        let mut next = engine.config.clone();
        next.milestones[0].title.push_str(" revised");
        let mut added = next.milestones[0].clone();
        added.id = "new-milestone".into();
        next.milestones.push(added);
        let before_hash = engine.config.hash();
        let change = engine
            .submit_plan(
                next.clone(),
                "Add scope and revise the original milestone",
                engine.revision(),
                &before_hash,
            )
            .unwrap()
            .unwrap();
        assert_eq!(change.added, vec!["new-milestone"]);
        assert_eq!(change.changed, vec![id.clone()]);
        assert!(!engine.saved.claims.contains_key(&id));
        assert!(engine.saved.approvals.is_empty());
        assert_eq!(read_config(engine.root()).unwrap(), next);
        let root = engine.root.clone();
        drop(engine);
        let restored = Engine::open(&root, &base.path().join("state")).unwrap();
        assert_eq!(restored.plan_history()[0].id, change.id);
        assert_eq!(restored.config, next);
    }
    #[test]
    fn plan_rejects_stale_revisions_hashes_and_invalid_dags_without_writes() {
        let (_base, mut engine) = fixture();
        let before = engine.config.clone();
        let mut next = before.clone();
        next.milestones[0].title.push_str(" new");
        assert!(
            engine
                .submit_plan(
                    next.clone(),
                    "reason",
                    engine.revision() + 1,
                    &before.hash()
                )
                .is_err()
        );
        assert!(
            engine
                .submit_plan(next.clone(), "reason", engine.revision(), "stale")
                .is_err()
        );
        next.milestones[0].depends_on = vec![next.milestones[0].id.clone()];
        assert!(
            engine
                .submit_plan(next, "reason", engine.revision(), &before.hash())
                .is_err()
        );
        assert_eq!(read_config(engine.root()).unwrap(), before);
        assert!(engine.plan_history().is_empty());
    }
    #[test]
    fn replacing_plan_directory_during_update_is_rejected() {
        let (_base, engine) = fixture();
        let before = engine.config.clone();
        let mut after = before.clone();
        after.milestones[0].title.push_str(" revised");
        let change = PlanChange {
            summary: PlanSummary {
                id: "plan-directory-swap".into(),
                reason: "test directory replacement".into(),
                submitted_at: Utc::now().to_rfc3339(),
                before_hash: before.hash(),
                after_hash: after.hash(),
                added: vec![],
                removed: vec![],
                changed: vec![before.milestones[0].id.clone()],
            },
            before: before.clone(),
            after,
            prior_claims: BTreeMap::new(),
        };
        let result = replace_config_inner(engine.root(), &change, || {
            fs::rename(
                engine.root().join(".progress-checker"),
                engine.root().join("detached"),
            )
            .unwrap();
            fs::create_dir(engine.root().join(".progress-checker")).unwrap();
            fs::write(
                engine.root().join(".progress-checker/config.json"),
                serde_json::to_vec(&before).unwrap(),
            )
            .unwrap();
        });
        assert!(result.unwrap_err().contains("Plan directory changed"));
        assert_eq!(read_config(engine.root()).unwrap(), before);
        assert_eq!(
            Config::parse(&fs::read(engine.root().join("detached/config.json")).unwrap()).unwrap(),
            before
        );
    }
    #[test]
    fn changing_check_definition_marks_affected_milestones_changed() {
        let (_base, mut engine) = fixture();
        let mut next = engine.config.clone();
        let check_id = next.checks[0].id.clone();
        let affected = next
            .milestones
            .iter()
            .filter(|m| m.criteria.iter().any(|c| c.check_id == check_id))
            .map(|m| m.id.clone())
            .collect::<Vec<_>>();
        assert!(!affected.is_empty());
        for id in &affected {
            engine.saved.claims.insert(id.clone(), Claim::Implemented);
        }
        next.checks[0].argv.push("changed-argument".into());
        let revision = engine.revision();
        let hash = engine.config.hash();
        let summary = engine
            .submit_plan(next, "Revise acceptance command", revision, &hash)
            .unwrap()
            .unwrap();
        assert_eq!(summary.changed, affected);
        for id in &affected {
            assert!(!engine.saved.claims.contains_key(id));
        }
    }
    #[test]
    fn pending_plan_recovers_before_and_after_atomic_config_replace() {
        for already_replaced in [false, true] {
            let (base, mut engine) = fixture();
            let before = engine.config.clone();
            let mut after = before.clone();
            after.milestones[0].title.push_str(" changed");
            let change = PlanChange {
                summary: PlanSummary {
                    id: "plan-recovery".into(),
                    reason: "test interrupted plan".into(),
                    submitted_at: Utc::now().to_rfc3339(),
                    before_hash: before.hash(),
                    after_hash: after.hash(),
                    added: vec![],
                    removed: vec![],
                    changed: vec![before.milestones[0].id.clone()],
                },
                before,
                after: after.clone(),
                prior_claims: BTreeMap::new(),
            };
            engine.saved.pending_plan = Some(change.clone());
            engine.persist().unwrap();
            if already_replaced {
                replace_config(engine.root(), &change).unwrap();
            } else {
                fs::write(
                    engine.root().join(".progress-checker/.plan-recovery.tmp"),
                    b"partial",
                )
                .unwrap();
            }
            let root = engine.root.clone();
            drop(engine);
            let restored = Engine::open(&root, &base.path().join("state")).unwrap();
            assert_eq!(restored.config, after);
            assert!(restored.saved.pending_plan.is_none());
            assert_eq!(restored.plan_history().len(), 1);
        }
    }
}
