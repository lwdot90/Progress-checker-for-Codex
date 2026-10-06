//! Phase 1 synchronous writer and asynchronous single-command coordinator.
use crate::{
    config::Config,
    fingerprint::{self, FingerprintOptions},
    model::{
        self, CheckEvidence, Claim, ExecutionState, Freshness, Outcome, Progress, SourceIdentity,
    },
    runner::{self, RunResult},
    security::{self, ApprovalBinding, LocalApproval},
    store::StateStore,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

#[path = "plan.rs"]
mod plan;
pub use plan::PlanChange;
pub use plan::PlanSummary;
pub use plan::validate_plan;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SavedState {
    schema_version: u32,
    revision: u64,
    claims: BTreeMap<String, Claim>,
    #[serde(default)]
    claim_notes: BTreeMap<String, String>,
    latest: BTreeMap<String, CheckEvidence>,
    approvals: BTreeMap<String, LocalApproval>,
    #[serde(default)]
    requests: BTreeMap<String, RunAcceptance>,
    #[serde(default)]
    batch_requests: BTreeMap<String, BatchAcceptance>,
    #[serde(default)]
    pending_plan: Option<PlanChange>,
    #[serde(default)]
    plan_history: Vec<PlanSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    pub schema_version: u32,
    pub run_id: String,
    pub check_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub before: SourceIdentity,
    pub after: Option<SourceIdentity>,
    pub changed_during_run: bool,
    pub evidence: CheckEvidence,
    pub result: RunResult,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub schema_version: u32,
    pub revision: u64,
    pub project_id: String,
    pub source: SourceIdentity,
    pub latest: BTreeMap<String, CheckEvidence>,
    pub progress: Progress,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunAcceptance {
    pub run_id: String,
    pub check_id: String,
    pub expected_config_hash: String,
    pub revision: u64,
}

pub enum PrepareOutcome {
    Accepted(Box<PreparedRun>),
    Existing(RunAcceptance),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchAcceptance {
    pub run_id: String,
    pub check_ids: Vec<String>,
    pub run_ids: Vec<String>,
    pub expected_config_hash: String,
    pub revision: u64,
    #[serde(default)]
    pub cancel_requested: bool,
}

pub enum PrepareBatchOutcome {
    Accepted(PreparedBatch),
    Existing(BatchAcceptance),
}

pub struct PreparedBatch {
    pub acceptance: BatchAcceptance,
    pub runs: Vec<PreparedRun>,
}

pub struct PreparedRun {
    pub acceptance: RunAcceptance,
    root: PathBuf,
    authorized: security::AuthorizedExecution,
    timeout: Duration,
    watch: fingerprint::SourceWatch,
    evidence: CheckEvidence,
    started_at: String,
}

pub struct CompletedRun {
    evidence: CheckEvidence,
    started_at: String,
    duration_ms: u64,
    watch: fingerprint::SourceWatch,
    changed: bool,
    result: RunResult,
}

impl PreparedRun {
    pub async fn execute(mut self, cancel: CancellationToken) -> CompletedRun {
        let timer = Instant::now();
        let config_valid = read_config(&self.root)
            .is_ok_and(|config| config.hash() == self.evidence.source.config_hash);
        let task = async {
            if !config_valid {
                RunResult {
                    outcome: Outcome::Unknown,
                    exit_code: None,
                    stdout: runner::BoundedLog {
                        text: String::new(),
                        truncated: false,
                    },
                    stderr: runner::BoundedLog {
                        text: String::new(),
                        truncated: false,
                    },
                    reason: Some(
                        "configuration changed after accepting run; approval must be reviewed"
                            .into(),
                    ),
                }
            } else {
                runner::run_command(&self.authorized, self.timeout, cancel.clone()).await
            }
        };
        tokio::pin!(task);
        let mut interval = tokio::time::interval(Duration::from_millis(40));
        let mut changed = false;
        let result = loop {
            tokio::select! {
                result = &mut task => break result,
                _ = interval.tick() => {
                    match self.watch.changed() {
                        Ok(value) => changed |= value,
                        Err(_) => { changed = true; cancel.cancel(); }
                    }
                }
            }
        };
        changed |= self.watch.changed().unwrap_or(true);
        CompletedRun {
            evidence: self.evidence,
            started_at: self.started_at,
            duration_ms: timer.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            watch: self.watch,
            changed,
            result,
        }
    }
}

pub struct Engine {
    root: PathBuf,
    config: Config,
    store: StateStore,
    saved: SavedState,
    warnings: Vec<String>,
    poisoned: bool,
}

fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn read_config(root: &Path) -> Result<Config, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)
        .map_err(error)?;
    let open = |parent: &fs::File, name: &str, flags: i32| -> Result<fs::File, String> {
        let name = std::ffi::CString::new(name).map_err(error)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    };
    let config_directory = open(
        &directory,
        ".progress-checker",
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
    read_config_directory(&config_directory)
}
fn read_config_directory(directory: &fs::File) -> Result<Config, String> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c"config.json".as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(error)?;
    if !metadata.is_file() || metadata.len() > 256 * 1024 {
        return Err("configuration is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(256 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    if bytes.len() > 256 * 1024 {
        return Err("configuration exceeds size limit".into());
    }
    Config::parse(&bytes)
}
fn log_bytes(result: &RunResult) -> Result<Vec<u8>, String> {
    serde_json::to_vec(result).map_err(error)
}

impl Engine {
    pub fn open(root: &Path, state_base: &Path) -> Result<Self, String> {
        let root = root.canonicalize().map_err(error)?;
        let config = read_config(&root)?;
        let store = StateStore::open(state_base, &root, &config.project_id).map_err(error)?;
        security::validate_state_separation(&root, store.directory())?;
        let loaded = store.load_snapshot::<SavedState>().map_err(error)?;
        let mut saved = loaded.value.unwrap_or(SavedState {
            schema_version: 1,
            ..SavedState::default()
        });
        if saved.schema_version != 1 {
            return Err("unsupported state schema".into());
        }
        let mut warnings = Vec::new();
        let invalid = loaded.warning.is_some();
        if let Some(warning) = loaded.warning {
            warnings.push(warning);
        }
        let mut recovered = false;
        for evidence in saved.latest.values_mut() {
            if invalid || evidence.execution_state != ExecutionState::Finished {
                evidence.execution_state = ExecutionState::Finished;
                evidence.outcome = Some(Outcome::Unknown);
                evidence.freshness = Freshness::Pending;
                evidence.log_ref = None;
                evidence.log_sha256 = None;
                recovered = true;
            }
        }
        if invalid {
            saved.approvals.clear();
        }
        if recovered {
            saved.revision = saved.revision.checked_add(1).ok_or("revision exhausted")?;
            store.save_snapshot(&saved).map_err(error)?;
            warnings.push(
                "Interrupted or recovered attempts are unknown; run again after approval".into(),
            );
        }
        let mut engine = Self {
            root,
            config,
            store,
            saved,
            warnings,
            poisoned: false,
        };
        engine.recover_plan()?;
        Ok(engine)
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    /// Refresh the validated definition before a service captures monitor options.
    pub fn refresh_configuration(&mut self) -> Result<(), String> {
        self.refresh_config()
    }
    fn refresh_config(&mut self) -> Result<(), String> {
        self.ensure_available()?;
        let config = read_config(&self.root)?;
        if config.project_id != self.config.project_id {
            return Err("project identity changed; reopen checker".into());
        }
        self.config = config;
        Ok(())
    }
    fn ensure_available(&self) -> Result<(), String> {
        if self.poisoned {
            Err("STORAGE_UNAVAILABLE: reopen checker after a failed durable write".into())
        } else {
            Ok(())
        }
    }
    fn persist(&mut self) -> Result<(), String> {
        self.ensure_available()?;
        self.saved.revision = match self.saved.revision.checked_add(1) {
            Some(revision) => revision,
            None => {
                self.poisoned = true;
                return Err("revision exhausted".into());
            }
        };
        match self.store.save_snapshot(&self.saved) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.poisoned = true;
                Err(error(err))
            }
        }
    }
    pub fn approval_binding(&self, check_id: &str) -> Result<ApprovalBinding, String> {
        let check = self.config.check(check_id).ok_or("unknown check")?;
        let mut argv = check.argv.clone();
        let executable = Path::new(&argv[0]);
        if executable.is_absolute() {
            argv[0] = executable
                .canonicalize()
                .map_err(error)?
                .to_string_lossy()
                .into();
        } else {
            if executable.components().count() != 1 {
                return Err("executable must be a system name or absolute path".into());
            }
            argv[0] = Path::new("/usr/bin")
                .join(executable)
                .canonicalize()
                .map_err(error)?
                .to_string_lossy()
                .into();
        }
        ApprovalBinding::new(
            &self.root,
            self.config.hash(),
            check.hash(),
            argv,
            &self.root.join(&check.cwd),
        )
    }
    fn source(&self) -> Result<SourceIdentity, String> {
        self.ensure_available()?;
        let mut consistency_watch = fingerprint::SourceWatch::start_with_options(
            &self.root,
            &FingerprintOptions {
                extra_inputs: self.config.fingerprint.extra_inputs.clone(),
                exclude_outputs: self.config.fingerprint.exclude_outputs.clone(),
            },
        )
        .map_err(error)?;
        let report = fingerprint::fingerprint(
            &self.root,
            &FingerprintOptions {
                extra_inputs: self.config.fingerprint.extra_inputs.clone(),
                exclude_outputs: self.config.fingerprint.exclude_outputs.clone(),
            },
        )
        .map_err(error)?;
        let bindings = self
            .config
            .checks
            .iter()
            .map(|check| self.approval_binding(&check.id))
            .collect::<Result<Vec<_>, _>>()?;
        // Fedora package inventory captures installed compiler/library versions.
        // Unavailable environment inspection never yields current verification.
        let package_bytes = crate::environment::package_inventory()?;
        let mut package_lines = package_bytes
            .split(|byte| *byte == b'\n')
            .collect::<Vec<_>>();
        package_lines.sort();
        let kernel = fs::read("/proc/sys/kernel/osrelease").map_err(error)?;
        let environment_signature = fingerprint::hash_parts(
            "phase1-environment",
            &[
                &serde_json::to_vec(&bindings).map_err(error)?,
                &package_lines.concat(),
                &kernel,
            ],
        );
        if consistency_watch.changed().map_err(error)?
            || read_config(&self.root)?.hash() != self.config.hash()
        {
            return Err("source or configuration changed while checking freshness".into());
        }
        Ok(SourceIdentity {
            git_commit: report.head.unwrap_or_else(|| "unborn".into()),
            fingerprint: report.digest,
            config_hash: self.config.hash(),
            checker_version: env!("CARGO_PKG_VERSION").into(),
            environment_signature,
        })
    }
    pub fn status(&mut self) -> Result<Status, String> {
        self.refresh_config()?;
        let source = self.source()?;
        let mut latest = self.saved.latest.clone();
        let mut warnings = self.warnings.clone();
        for evidence in latest.values_mut() {
            if evidence.source != source {
                evidence.freshness = Freshness::Stale;
            }
            if evidence.outcome == Some(Outcome::Passed) {
                let valid = (|| -> Result<(), String> {
                    let record = self
                        .store
                        .read_attempt::<RunRecord>(&format!("{}-finish", evidence.run_id))
                        .map_err(error)?;
                    if record.evidence
                        != *self
                            .saved
                            .latest
                            .get(&evidence.check_id)
                            .ok_or("missing evidence")?
                        || record.result.outcome != Outcome::Passed
                        || record.result.exit_code != Some(0)
                    {
                        return Err("attempt provenance mismatch".into());
                    }
                    let bytes = self
                        .store
                        .read_log(
                            evidence.log_ref.as_deref().ok_or("missing log")?,
                            evidence.log_sha256.as_deref().ok_or("missing log hash")?,
                        )
                        .map_err(error)?;
                    if bytes != log_bytes(&record.result)? {
                        return Err("log does not match attempt".into());
                    }
                    Ok(())
                })();
                if let Err(reason) = valid {
                    evidence.outcome = Some(Outcome::Unknown);
                    evidence.freshness = Freshness::Pending;
                    warnings.push(format!(
                        "{} evidence unavailable: {reason}",
                        evidence.check_id
                    ));
                }
            }
        }
        let progress = model::evaluate(&self.config, &self.saved.claims, &latest, &source)?;
        Ok(Status {
            schema_version: 1,
            revision: self.saved.revision,
            project_id: self.config.project_id.clone(),
            source,
            latest,
            progress,
            warnings,
        })
    }
    pub fn set_claim(
        &mut self,
        id: &str,
        claim: Claim,
        expected_revision: u64,
    ) -> Result<Status, String> {
        self.set_claim_with_note(id, claim, "", expected_revision)
    }
    pub fn set_claim_with_note(
        &mut self,
        id: &str,
        claim: Claim,
        note: &str,
        expected_revision: u64,
    ) -> Result<Status, String> {
        if note.len() > 4096
            || note
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            return Err("invalid claim note".into());
        }
        self.refresh_config()?;
        if self.saved.revision != expected_revision {
            return Err("REVISION_CONFLICT".into());
        }
        if !self
            .config
            .milestones
            .iter()
            .any(|milestone| milestone.id == id)
        {
            return Err("unknown milestone".into());
        }
        self.saved.claims.insert(id.into(), claim);
        self.saved.claim_notes.insert(id.into(), note.into());
        self.persist()?;
        self.status()
    }
    pub fn approve(&mut self, id: &str, binding: ApprovalBinding) -> Result<Status, String> {
        self.refresh_config()?;
        let current = self.approval_binding(id)?;
        if current != binding {
            return Err("definition changed during approval".into());
        }
        self.saved.approvals.insert(
            id.into(),
            LocalApproval {
                schema_version: 1,
                binding_digest: binding.approval_digest()?,
                binding,
            },
        );
        self.persist()?;
        self.status()
    }
    /// Commit a service refresh generation without changing claims or evidence.
    pub fn advance_revision(&mut self) -> Result<(), String> {
        self.persist()
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn revision(&self) -> u64 {
        self.saved.revision
    }
    pub fn claims(&self) -> &BTreeMap<String, Claim> {
        &self.saved.claims
    }
    pub fn claim_notes(&self) -> &BTreeMap<String, String> {
        &self.saved.claim_notes
    }
    pub fn run_record(&self, run_id: &str) -> Result<RunRecord, String> {
        self.store
            .read_attempt(&format!("{run_id}-finish"))
            .map_err(error)
    }
    pub fn read_log(&self, reference: &str, hash: &str) -> Result<Vec<u8>, String> {
        self.store.read_log(reference, hash).map_err(error)
    }
    pub fn prepare_run(
        &mut self,
        id: &str,
        key: &str,
        expected_config_hash: &str,
    ) -> Result<PrepareOutcome, String> {
        self.ensure_available()?;
        if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
            return Err("invalid idempotency key".into());
        }
        if let Some(existing) = self.saved.requests.get(key) {
            if existing.check_id != id || existing.expected_config_hash != expected_config_hash {
                return Err("IDEMPOTENCY_CONFLICT".into());
            }
            return Ok(PrepareOutcome::Existing(existing.clone()));
        }
        if self.saved.batch_requests.contains_key(key) {
            return Err("IDEMPOTENCY_CONFLICT".into());
        }
        if self.saved.requests.len() + self.saved.batch_requests.len() >= 4096 {
            return Err(
                "idempotency registry full; retained request identities cannot be evicted safely"
                    .into(),
            );
        }
        self.refresh_config()?;
        if self.config.hash() != expected_config_hash {
            return Err("CONFIG_CONFLICT".into());
        }
        if !self.config.enabled {
            return Err("project disabled".into());
        }
        if self
            .saved
            .latest
            .values()
            .any(|e| e.execution_state != ExecutionState::Finished)
        {
            return Err("RUN_BUSY".into());
        }
        let check = self.config.check(id).ok_or("unknown check")?.clone();
        let binding = self.approval_binding(id)?;
        let approval = self
            .saved
            .approvals
            .get(id)
            .ok_or("PERMISSION_REQUIRED: human approval of this exact command is required")?;
        security::validate_state_separation(&self.root, self.store.directory())?;
        let authorized = security::authorize(binding, approval)?;
        let watch = fingerprint::SourceWatch::start_with_options(
            &self.root,
            &FingerprintOptions {
                extra_inputs: self.config.fingerprint.extra_inputs.clone(),
                exclude_outputs: self.config.fingerprint.exclude_outputs.clone(),
            },
        )
        .map_err(error)?;
        let before = self.source()?;
        let started_at = Utc::now().to_rfc3339();
        let run_id = format!(
            "run-{}-{}-{}",
            Utc::now()
                .timestamp_nanos_opt()
                .ok_or("clock unavailable")?,
            std::process::id(),
            self.saved.revision
        );
        let evidence = CheckEvidence {
            run_id: run_id.clone(),
            check_id: id.into(),
            execution_state: ExecutionState::Queued,
            outcome: None,
            freshness: Freshness::Pending,
            source: before.clone(),
            command_hash: check.hash(),
            log_ref: None,
            log_sha256: None,
        };
        // Persist request identity and invalidation before any subprocess exists.
        let acceptance = RunAcceptance {
            run_id: run_id.clone(),
            check_id: id.into(),
            expected_config_hash: expected_config_hash.into(),
            revision: self
                .saved
                .revision
                .checked_add(1)
                .ok_or("revision exhausted")?,
        };
        self.saved.latest.insert(id.into(), evidence.clone());
        self.saved.requests.insert(key.into(), acceptance.clone());
        self.persist()?;
        self.store
            .append_attempt(&format!("{run_id}-start"), &evidence)
            .map_err(|err| {
                self.poisoned = true;
                error(err)
            })?;
        Ok(PrepareOutcome::Accepted(Box::new(PreparedRun {
            acceptance,
            root: self.root.clone(),
            authorized,
            timeout: Duration::from_secs(check.timeout_seconds),
            watch,
            evidence,
            started_at,
        })))
    }

    pub fn lookup_batch_request(&self, key: &str) -> Option<&BatchAcceptance> {
        self.saved.batch_requests.get(key)
    }
    pub fn batch(&self, run_id: &str) -> Option<&BatchAcceptance> {
        self.saved
            .batch_requests
            .values()
            .find(|batch| batch.run_id == run_id)
    }

    pub fn request_cancel(&mut self, run_id: &str) -> Result<bool, String> {
        self.ensure_available()?;
        let check_run_ids = self.batch(run_id).ok_or("unknown run")?.run_ids.clone();
        let active = self.saved.latest.values().any(|e| {
            check_run_ids.contains(&e.run_id) && e.execution_state != ExecutionState::Finished
        });
        if !active {
            return Ok(false);
        }
        let batch = self
            .saved
            .batch_requests
            .values_mut()
            .find(|b| b.run_id == run_id)
            .ok_or("unknown run")?;
        if !batch.cancel_requested {
            batch.cancel_requested = true;
            self.persist()?;
        }
        Ok(true)
    }

    pub fn prepare_batch(
        &mut self,
        check_ids: &[String],
        key: &str,
        expected_config_hash: &str,
        expected_revision: u64,
    ) -> Result<PrepareBatchOutcome, String> {
        self.ensure_available()?;
        if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
            return Err("invalid idempotency key".into());
        }
        if let Some(existing) = self.saved.batch_requests.get(key) {
            if existing.check_ids != check_ids
                || existing.expected_config_hash != expected_config_hash
            {
                return Err("IDEMPOTENCY_CONFLICT".into());
            }
            return Ok(PrepareBatchOutcome::Existing(existing.clone()));
        }
        if self.saved.requests.contains_key(key) {
            return Err("IDEMPOTENCY_CONFLICT".into());
        }
        if self.saved.requests.len() + self.saved.batch_requests.len() >= 4096 {
            return Err("idempotency registry full".into());
        }
        if check_ids.is_empty() || check_ids.len() > 64 {
            return Err("batch must contain between one and 64 checks".into());
        }
        let unique = check_ids.iter().collect::<std::collections::BTreeSet<_>>();
        if unique.len() != check_ids.len() {
            return Err("duplicate check in batch".into());
        }
        self.refresh_config()?;
        if self.saved.revision != expected_revision {
            return Err("REVISION_CONFLICT".into());
        }
        if self.config.hash() != expected_config_hash {
            return Err("CONFIG_CONFLICT".into());
        }
        if !self.config.enabled {
            return Err("project disabled".into());
        }
        if self
            .saved
            .latest
            .values()
            .any(|e| e.execution_state != ExecutionState::Finished)
        {
            return Err("RUN_BUSY".into());
        }
        security::validate_state_separation(&self.root, self.store.directory())?;
        // Validate EVERY definition/approval before publishing ANY accepted check.
        let definitions = check_ids
            .iter()
            .map(|id| {
                let check = self.config.check(id).ok_or("unknown check")?.clone();
                let binding = self.approval_binding(id)?;
                let approval = self.saved.approvals.get(id).ok_or(
                    "PERMISSION_REQUIRED: human approval of this exact command is required",
                )?;
                let authorized = security::authorize(binding, approval)?;
                let watch = fingerprint::SourceWatch::start_with_options(
                    &self.root,
                    &FingerprintOptions {
                        extra_inputs: self.config.fingerprint.extra_inputs.clone(),
                        exclude_outputs: self.config.fingerprint.exclude_outputs.clone(),
                    },
                )
                .map_err(error)?;
                Ok((check, authorized, watch))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let before = self.source()?;
        let started_at = Utc::now().to_rfc3339();
        let parent = format!(
            "batch-{}-{}-{}",
            Utc::now()
                .timestamp_nanos_opt()
                .ok_or("clock unavailable")?,
            std::process::id(),
            self.saved.revision
        );
        let revision = self
            .saved
            .revision
            .checked_add(1)
            .ok_or("revision exhausted")?;
        let run_ids = (0..check_ids.len())
            .map(|index| format!("{parent}-{index}"))
            .collect::<Vec<_>>();
        let acceptance = BatchAcceptance {
            run_id: parent,
            check_ids: check_ids.to_vec(),
            run_ids: run_ids.clone(),
            expected_config_hash: expected_config_hash.into(),
            revision,
            cancel_requested: false,
        };
        let runs = definitions
            .into_iter()
            .zip(run_ids)
            .map(|((check, authorized, watch), run_id)| {
                let evidence = CheckEvidence {
                    run_id: run_id.clone(),
                    check_id: check.id.clone(),
                    execution_state: ExecutionState::Queued,
                    outcome: None,
                    freshness: Freshness::Pending,
                    source: before.clone(),
                    command_hash: check.hash(),
                    log_ref: None,
                    log_sha256: None,
                };
                PreparedRun {
                    acceptance: RunAcceptance {
                        run_id,
                        check_id: check.id,
                        expected_config_hash: expected_config_hash.into(),
                        revision,
                    },
                    root: self.root.clone(),
                    authorized,
                    timeout: Duration::from_secs(check.timeout_seconds),
                    watch,
                    evidence,
                    started_at: started_at.clone(),
                }
            })
            .collect::<Vec<_>>();
        for run in &runs {
            self.saved
                .latest
                .insert(run.evidence.check_id.clone(), run.evidence.clone());
        }
        self.saved
            .batch_requests
            .insert(key.into(), acceptance.clone());
        self.persist()?;
        for run in &runs {
            self.store
                .append_attempt(&format!("{}-start", run.acceptance.run_id), &run.evidence)
                .map_err(|err| {
                    self.poisoned = true;
                    error(err)
                })?;
        }
        Ok(PrepareBatchOutcome::Accepted(PreparedBatch {
            acceptance,
            runs,
        }))
    }

    pub fn mark_running(&mut self, run_id: &str) -> Result<(), String> {
        self.ensure_available()?;
        let evidence = self
            .saved
            .latest
            .values_mut()
            .find(|e| e.run_id == run_id)
            .ok_or("unknown accepted run")?;
        if evidence.execution_state != ExecutionState::Queued {
            return Err("run is not queued".into());
        }
        evidence.execution_state = ExecutionState::Running;
        self.persist()
    }

    pub fn finish_run(&mut self, completed: CompletedRun) -> Result<Status, String> {
        self.ensure_available()?;
        let CompletedRun {
            mut evidence,
            started_at,
            duration_ms,
            mut watch,
            mut changed,
            result,
        } = completed;
        let run_id = evidence.run_id.clone();
        let id = evidence.check_id.clone();
        if self.saved.latest.get(&id).map(|e| &e.run_id) != Some(&run_id) {
            return Err("run no longer owns latest attempt".into());
        }
        let before = evidence.source.clone();
        let after = self.refresh_config().and_then(|_| self.source()).ok();
        changed |= watch.changed().unwrap_or(true);
        changed |= after.as_ref() != Some(&before);
        evidence.execution_state = ExecutionState::Finished;
        evidence.outcome = Some(result.outcome);
        evidence.freshness = if changed {
            Freshness::Stale
        } else {
            Freshness::Current
        };
        let (reference, hash) = self
            .store
            .append_log(&run_id, &log_bytes(&result)?)
            .map_err(|err| {
                self.poisoned = true;
                error(err)
            })?;
        evidence.log_ref = Some(reference);
        evidence.log_sha256 = Some(hash);
        let record = RunRecord {
            schema_version: 1,
            run_id: run_id.clone(),
            check_id: id.clone(),
            started_at,
            finished_at: Utc::now().to_rfc3339(),
            duration_ms,
            before,
            after,
            changed_during_run: changed,
            evidence: evidence.clone(),
            result,
        };
        self.store
            .append_attempt(&format!("{run_id}-finish"), &record)
            .map_err(|err| {
                self.poisoned = true;
                error(err)
            })?;
        self.saved.latest.insert(id, evidence);
        self.persist()?;
        self.status()
    }
    pub async fn run(&mut self, id: &str, cancel: CancellationToken) -> Result<Status, String> {
        self.refresh_config()?;
        let hash = self.config.hash();
        let key = format!(
            "cli-{}-{}",
            Utc::now()
                .timestamp_nanos_opt()
                .ok_or("clock unavailable")?,
            self.saved.revision
        );
        match self.prepare_run(id, &key, &hash)? {
            PrepareOutcome::Accepted(prepared) => {
                self.mark_running(&prepared.acceptance.run_id)?;
                self.finish_run((*prepared).execute(cancel).await)
            }
            PrepareOutcome::Existing(_) => Err("unexpected CLI request collision".into()),
        }
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "service_engine_tests.rs"]
mod service_tests;
