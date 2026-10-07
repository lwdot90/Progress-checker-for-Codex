//! One blocking actor owns the engine; socket readers consume immutable snapshots.
use crate::{
    client::Endpoint,
    protocol::{MAX_FRAME_BYTES, Operation, Request, Response, SCHEMA_VERSION, ServiceError},
};
use checker_core::security::ApprovalBinding;
use checker_core::{
    engine::{CompletedRun, Engine, PrepareBatchOutcome},
    fingerprint::{FingerprintOptions, SourceWatch},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex, RwLock, mpsc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{oneshot, watch},
};
use tokio_util::sync::CancellationToken;

struct Command {
    operation: Operation,
    approval_peer: Option<ApprovalPeer>,
    response: oneshot::Sender<Result<Value, String>>,
}
// Peer authority is constructed from SO_PEERCRED and /proc only, never JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ApprovalPeer {
    pid: u32,
    starttime: String,
    executable_hash: String,
}
const APPROVAL_TTL: Duration = Duration::from_secs(300);
const MAX_APPROVAL_CHALLENGES: usize = 128;
struct ApprovalChallenge {
    check_id: String,
    binding: ApprovalBinding,
    peer: ApprovalPeer,
    expires: std::time::Instant,
}
#[derive(Default)]
struct ApprovalChallenges {
    pending: BTreeMap<String, ApprovalChallenge>,
}
impl ApprovalChallenges {
    fn issue(
        &mut self,
        check_id: String,
        binding: ApprovalBinding,
        peer: ApprovalPeer,
        now: std::time::Instant,
    ) -> Result<String, String> {
        self.pending.retain(|_, challenge| challenge.expires > now);
        if self.pending.len() >= MAX_APPROVAL_CHALLENGES {
            return Err("APPROVAL_BUSY: too many pending human confirmations".into());
        }
        for _ in 0..4 {
            let mut random = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut file| file.read_exact(&mut random))
                .map_err(|e| format!("APPROVAL_CHALLENGE_INVALID: random source: {e}"))?;
            let id = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            if !self.pending.contains_key(&id) {
                self.pending.insert(
                    id.clone(),
                    ApprovalChallenge {
                        check_id,
                        binding,
                        peer,
                        expires: now + APPROVAL_TTL,
                    },
                );
                return Ok(id);
            }
        }
        Err("APPROVAL_CHALLENGE_INVALID: nonce collision".into())
    }
    fn consume(
        &mut self,
        id: &str,
        peer: Option<&ApprovalPeer>,
        binding: &ApprovalBinding,
        now: std::time::Instant,
    ) -> Result<ApprovalChallenge, String> {
        // Consume before every comparison, including an unauthorized commit.
        let challenge = self
            .pending
            .remove(id)
            .ok_or("APPROVAL_CHALLENGE_INVALID: absent or already consumed")?;
        if challenge.expires <= now
            || peer != Some(&challenge.peer)
            || binding != &challenge.binding
        {
            return Err("APPROVAL_CHALLENGE_INVALID: expired, peer or definition mismatch".into());
        }
        Ok(challenge)
    }
}
fn approval_starttime(pid: u32) -> Result<String, String> {
    let proc = std::path::PathBuf::from(format!("/proc/{pid}"));
    let metadata = std::fs::metadata(&proc).map_err(|_| "APPROVAL_PEER_REQUIRED: peer absent")?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err("APPROVAL_PEER_REQUIRED: wrong peer owner".into());
    }
    let value = std::fs::read_to_string(proc.join("stat"))
        .map_err(|_| "APPROVAL_PEER_REQUIRED: peer stat unavailable")?;
    let fields = value
        .rsplit_once(')')
        .ok_or("APPROVAL_PEER_REQUIRED: malformed peer stat")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields.len() <= 19
        || matches!(fields[0], "Z" | "X" | "x")
        || fields[19].is_empty()
        || !fields[19].bytes().all(|b| b.is_ascii_digit())
    {
        return Err("APPROVAL_PEER_REQUIRED: invalid peer lifetime".into());
    }
    Ok(fields[19].into())
}
fn approval_executable_hash(path: &Path) -> Result<String, String> {
    let mut file =
        std::fs::File::open(path).map_err(|_| "APPROVAL_PEER_REQUIRED: executable unavailable")?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file()
        || before.len() > 64 * 1024 * 1024
        || before.mode() & 0o022 != 0
        || (before.uid() != unsafe { libc::geteuid() } && before.uid() != 0)
    {
        return Err("APPROVAL_PEER_REQUIRED: untrusted executable".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.mtime() != after.mtime()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("APPROVAL_PEER_REQUIRED: executable changed".into());
    }
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn approval_terminal(pid: u32, descriptor: u32) -> bool {
    // Reopen the actual peer descriptor solely for tcgetattr; never read input.
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(format!("/proc/{pid}/fd/{descriptor}"))
    else {
        return false;
    };
    let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
    unsafe { libc::tcgetattr(file.as_raw_fd(), termios.as_mut_ptr()) == 0 }
}
fn approval_peer_requirements(
    stdin_terminal: bool,
    stdout_terminal: bool,
    actual_hash: &str,
    expected_hash: &str,
) -> Result<(), String> {
    if !stdin_terminal || !stdout_terminal || actual_hash != expected_hash {
        return Err("APPROVAL_PEER_REQUIRED: exact human-terminal CLI required".into());
    }
    Ok(())
}
fn authorize_approval_peer(pid: u32) -> Result<ApprovalPeer, String> {
    let starttime = approval_starttime(pid)?;
    let server = std::env::current_exe().map_err(|e| e.to_string())?;
    let expected = if server
        .file_name()
        .is_some_and(|name| name == "progress-checker")
    {
        server.clone()
    } else {
        server
            .parent()
            .ok_or("APPROVAL_PEER_REQUIRED: CLI sibling absent")?
            .join("progress-checker")
    };
    let executable_hash = approval_executable_hash(Path::new(&format!("/proc/{pid}/exe")))?;
    let expected_hash = approval_executable_hash(&expected)?;
    approval_peer_requirements(
        approval_terminal(pid, 0),
        approval_terminal(pid, 1),
        &executable_hash,
        &expected_hash,
    )?;
    if approval_starttime(pid)? != starttime {
        return Err("APPROVAL_PEER_REQUIRED: peer lifetime changed".into());
    }
    Ok(ApprovalPeer {
        pid,
        starttime,
        executable_hash,
    })
}
impl ApprovalPeer {
    fn recheck(&self) -> Result<(), String> {
        if authorize_approval_peer(self.pid)? != *self {
            return Err("APPROVAL_PEER_REQUIRED: peer identity changed".into());
        }
        Ok(())
    }
}

enum Message {
    Command(Box<Command>),
    Finished(
        String,
        Box<CompletedRun>,
        oneshot::Sender<Result<(), String>>,
    ),
    Start(String, oneshot::Sender<Result<(), String>>),
    Shutdown,
}
#[derive(Clone)]
struct Shared {
    snapshot: Arc<RwLock<Value>>,
    revision: watch::Sender<u64>,
    instance: String,
    monitor: Arc<Mutex<SourceWatch>>,
}
impl Shared {
    fn publish(&self, engine: &mut Engine) -> Result<(), String> {
        engine.refresh_configuration()?;
        let monitored_config_hash = engine.config().hash();
        let options = FingerprintOptions {
            extra_inputs: engine.config().fingerprint.extra_inputs.clone(),
            exclude_outputs: engine.config().fingerprint.exclude_outputs.clone(),
        };
        let next_monitor = SourceWatch::start_with_options(engine.root(), &options)
            .map_err(|error| error.to_string())?;
        *self.monitor.lock().map_err(|_| "monitor lock poisoned")? = next_monitor;
        let status = engine.status()?;
        if status.source.config_hash != monitored_config_hash
            || engine.config().hash() != monitored_config_hash
        {
            return Err(
                "FRESHNESS_PENDING: configuration changed during monitor installation".into(),
            );
        }
        let run_metadata=status.latest.iter().map(|(check_id,evidence)|{
            let metadata=if let Ok(record)=engine.run_record(&evidence.run_id){json!({"run_id":record.run_id,"started_at":record.started_at,"finished_at":record.finished_at,"duration_ms":record.duration_ms})}else{
                let started_at=evidence.run_id.split('-').nth(1).and_then(|value|value.parse::<i64>().ok()).map(|nanos|chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(nanos).to_rfc3339());
                json!({"run_id":evidence.run_id,"started_at":started_at,"finished_at":null,"duration_ms":null})
            };(check_id.clone(),metadata)
        }).collect::<serde_json::Map<String,Value>>();
        let mut next = json!({"schema_version":1,"canonical_root":engine.root(),"service_instance_id":self.instance,"config":engine.config(),"claims":engine.claims(),"claim_notes":engine.claim_notes(),"run_metadata":run_metadata,"running":status.latest.values().filter(|e|e.execution_state != checker_core::model::ExecutionState::Finished).collect::<Vec<_>>(),"health":"ready","status":status});
        let mut comparable = self
            .snapshot
            .read()
            .map_err(|_| "snapshot lock poisoned")?
            .clone();
        comparable.as_object_mut().map(|o| o.remove("revision"));
        comparable["status"]["revision"] = next["status"]["revision"].clone();
        if comparable != next {
            engine.advance_revision()?;
            let revision = engine.revision();
            next["status"]["revision"] = json!(revision);
            next["revision"] = json!(revision);
            *self
                .snapshot
                .write()
                .map_err(|_| "snapshot lock poisoned")? = next;
            self.revision.send_replace(revision);
        }
        Ok(())
    }
    fn invalidate(&self, reason: &str) {
        if let Ok(mut snapshot) = self.snapshot.write() {
            snapshot["status"]["progress"]["verified"] = json!(0);
            snapshot["status"]["progress"]["percent"] =
                if snapshot["status"]["progress"]["scoped"] == 0 {
                    Value::Null
                } else {
                    json!(0)
                };
            if let Some(milestones) = snapshot["status"]["progress"]["milestones"].as_array_mut() {
                for m in milestones {
                    m["verified"] = json!(false);
                    m["evidence_refs"] = json!([]);
                    m["blockers"] = json!([reason]);
                }
            }
            if let Some(latest) = snapshot["status"]["latest"].as_object_mut() {
                for e in latest.values_mut() {
                    e["freshness"] = json!("pending");
                }
            }
            snapshot["status"]["warnings"] = json!([reason]);
            snapshot["health"] = json!("pending");
            let revision = *self.revision.borrow();
            snapshot["revision"] = json!(revision);
            self.revision.send_replace(revision);
        }
    }
}
fn check_revision(shared: &Shared, expected: u64) -> Result<(), String> {
    if *shared.revision.borrow() != expected {
        Err("REVISION_CONFLICT".into())
    } else {
        Ok(())
    }
}
fn actor(
    mut engine: Engine,
    shared: Shared,
    receiver: mpsc::Receiver<Message>,
    sender: mpsc::Sender<Message>,
    runtime: tokio::runtime::Handle,
) -> Result<(), String> {
    shared.publish(&mut engine)?;
    let options = FingerprintOptions {
        extra_inputs: engine.config().fingerprint.extra_inputs.clone(),
        exclude_outputs: engine.config().fingerprint.exclude_outputs.clone(),
    };
    let _options = options;
    let mut active = BTreeMap::<String, CancellationToken>::new();
    let mut batches = BTreeMap::<String, Vec<String>>::new();
    let mut approvals = ApprovalChallenges::default();
    let mut shutting_down = false;
    let mut last_refresh = std::time::Instant::now();
    loop {
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(Message::Shutdown) => {
                shutting_down = true;
                for token in active.values() {
                    token.cancel();
                }
            }
            Ok(Message::Start(id, ack)) => {
                let result = engine
                    .mark_running(&id)
                    .and_then(|_| shared.publish(&mut engine));
                if let Err(error) = &result {
                    shared.invalidate(error);
                }
                let _ = ack.send(result);
            }
            Ok(Message::Finished(id, completed, ack)) => {
                active.remove(&id);
                let done = batches
                    .iter()
                    .filter(|(_, children)| children.iter().all(|id| !active.contains_key(id)))
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                for parent in done {
                    batches.remove(&parent);
                    active.remove(&parent);
                }
                let result = engine
                    .finish_run(*completed)
                    .and_then(|_| shared.publish(&mut engine));
                if let Err(error) = &result {
                    shared.invalidate(&format!("completion persistence failed: {error}"));
                }
                let _ = ack.send(result);
            }
            Ok(Message::Command(command)) => {
                let command = *command;
                let result = (|| -> Result<Value, String> {
                    if shutting_down {
                        return Err("SERVICE_STOPPING".into());
                    }
                    if matches!(
                        &command.operation,
                        Operation::Project
                            | Operation::Progress
                            | Operation::Milestones { .. }
                            | Operation::GetRun { .. }
                    ) {
                        shared.publish(&mut engine)?;
                    }
                    match command.operation {
                        Operation::ApprovalChallenge { check_id } => {
                            let peer = command.approval_peer.as_ref().ok_or(
                                "APPROVAL_PEER_REQUIRED: exact human-terminal CLI required",
                            )?;
                            peer.recheck()?;
                            if !active.is_empty() {
                                return Err("APPROVAL_BUSY: checks are active".into());
                            }
                            engine.refresh_configuration()?;
                            let binding = engine.approval_binding(&check_id)?;
                            peer.recheck()?;
                            let challenge_id = approvals.issue(
                                check_id.clone(),
                                binding.clone(),
                                peer.clone(),
                                std::time::Instant::now(),
                            )?;
                            Ok(json!({"challenge_id":challenge_id,"binding":binding,
                                "check_id":check_id,"revision":engine.revision()}))
                        }
                        Operation::ApprovalCommit {
                            challenge_id,
                            binding,
                        } => {
                            let challenge = approvals.consume(
                                &challenge_id,
                                command.approval_peer.as_ref(),
                                &binding,
                                std::time::Instant::now(),
                            )?;
                            challenge.peer.recheck()?;
                            if !active.is_empty() {
                                return Err("APPROVAL_BUSY: checks are active".into());
                            }
                            // Engine re-reads the current definition and validates exact binding.
                            engine.approve(&challenge.check_id, binding)?;
                            shared.publish(&mut engine)?;
                            Ok(json!({"approved":true,"check_id":challenge.check_id,
                                "revision":engine.revision()}))
                        }
                        Operation::SubmitPlan {
                            config,
                            reason,
                            expected_revision,
                            expected_config_hash,
                        } => {
                            check_revision(&shared, expected_revision)?;
                            if !active.is_empty() {
                                return Err("PLAN_BUSY: checks are active".into());
                            }
                            let change = engine.submit_plan(
                                config,
                                &reason,
                                engine.revision(),
                                &expected_config_hash,
                            )?;
                            let verification_warning = shared.publish(&mut engine).err();
                            if let Some(warning) = &verification_warning {
                                shared.invalidate(warning);
                            }
                            Ok(json!({"revision":engine.revision(),"change":change,
                                "config_hash":engine.config().hash(),"verification_warning":verification_warning}))
                        }
                        Operation::PlanHistory { offset, limit } => {
                            let history = engine.plan_history();
                            let entries =
                                history.iter().skip(offset).take(limit).collect::<Vec<_>>();
                            Ok(
                                json!({"entries":entries,"total":history.len(),"next_offset":offset.saturating_add(limit).min(history.len())}),
                            )
                        }
                        Operation::Project | Operation::Progress => cached_snapshot(&shared),
                        Operation::Milestones { scope } => {
                            let snapshot = cached_snapshot(&shared)?;
                            let milestones = snapshot["config"]["milestones"]
                                .as_array()
                                .ok_or("missing milestones")?
                                .iter()
                                .filter(|m| {
                                    scope.is_none_or(|v| m["in_scope"].as_bool() == Some(v))
                                })
                                .map(|m| {
                                    let mut m = m.clone();
                                    let id = m["id"].as_str().unwrap_or("").to_string();
                                    m["implementation_claim"] = if snapshot["claims"][&id].is_null()
                                    {
                                        json!("planned")
                                    } else {
                                        snapshot["claims"][&id].clone()
                                    };
                                    m["note"] = snapshot["claim_notes"][&id].clone();
                                    if let Some(derived) =
                                        snapshot["status"]["progress"]["milestones"]
                                            .as_array()
                                            .and_then(|items| {
                                                items.iter().find(|item| item["milestone_id"] == id)
                                            })
                                    {
                                        m["verification"] = derived.clone();
                                    }
                                    m
                                })
                                .collect::<Vec<_>>();
                            Ok(json!({"milestones":milestones}))
                        }
                        Operation::SetClaim {
                            milestone_id,
                            claim,
                            note,
                            expected_revision,
                        } => {
                            check_revision(&shared, expected_revision)?;
                            engine.set_claim_with_note(
                                &milestone_id,
                                claim,
                                &note,
                                engine.revision(),
                            )?;
                            shared.publish(&mut engine)?;
                            cached_snapshot(&shared)
                        }
                        Operation::RunChecks {
                            check_ids,
                            idempotency_key,
                            expected_config_hash,
                            expected_revision,
                        } => {
                            if engine.lookup_batch_request(&idempotency_key).is_none() {
                                check_revision(&shared, expected_revision)?;
                            }
                            match engine.prepare_batch(
                                &check_ids,
                                &idempotency_key,
                                &expected_config_hash,
                                engine.revision(),
                            )? {
                                PrepareBatchOutcome::Existing(acceptance) => {
                                    Ok(serde_json::to_value(acceptance)
                                        .map_err(|e| e.to_string())?)
                                }
                                PrepareBatchOutcome::Accepted(batch) => {
                                    let acceptance = batch.acceptance.clone();
                                    let token = CancellationToken::new();
                                    active.insert(acceptance.run_id.clone(), token.clone());
                                    batches.insert(
                                        acceptance.run_id.clone(),
                                        acceptance.run_ids.clone(),
                                    );
                                    for prepared in &batch.runs {
                                        active.insert(
                                            prepared.acceptance.run_id.clone(),
                                            token.clone(),
                                        );
                                    }
                                    let tx = sender.clone();
                                    runtime.spawn(async move {
                                        for prepared in batch.runs {
                                            let id = prepared.acceptance.run_id.clone();
                                            let (ack, confirmed) = oneshot::channel();
                                            if tx.send(Message::Start(id.clone(), ack)).is_err() {
                                                token.cancel();
                                                return;
                                            }
                                            if !matches!(confirmed.await, Ok(Ok(()))) {
                                                token.cancel();
                                            }
                                            let completed = prepared.execute(token.clone()).await;
                                            let (ack, confirmed) = oneshot::channel();
                                            if tx
                                                .send(Message::Finished(
                                                    id,
                                                    Box::new(completed),
                                                    ack,
                                                ))
                                                .is_err()
                                            {
                                                return;
                                            }
                                            if !matches!(confirmed.await, Ok(Ok(()))) {
                                                token.cancel();
                                            }
                                        }
                                    });
                                    shared.publish(&mut engine)?;
                                    serde_json::to_value(acceptance).map_err(|e| e.to_string())
                                }
                            }
                        }
                        Operation::CancelRun {
                            run_id,
                            expected_revision,
                        } => {
                            if engine.batch(&run_id).is_some() && !active.contains_key(&run_id) {
                                return Ok(
                                    json!({"run_id":run_id,"cancellation_requested":false,"execution_state":"finished"}),
                                );
                            }
                            check_revision(&shared, expected_revision)?;
                            let pending = engine.request_cancel(&run_id)?;
                            if !pending {
                                return Ok(
                                    json!({"run_id":run_id,"cancellation_requested":false,"execution_state":"finished"}),
                                );
                            }
                            active.get(&run_id).ok_or("RUN_NOT_ACTIVE")?.cancel();
                            shared
                                .invalidate("cancellation requested; awaiting process termination");
                            Ok(json!({"run_id":run_id,"cancellation_requested":true}))
                        }
                        Operation::GetRun { run_id } => {
                            let snapshot = cached_snapshot(&shared)?;
                            if let Some(batch) = engine.batch(&run_id) {
                                let mut value =
                                    serde_json::to_value(batch).map_err(|e| e.to_string())?;
                                let mut runs = Vec::new();
                                for child in &batch.run_ids {
                                    let item = match service_run_record(&engine,child) {
                                        Ok(record) => current_record(
                                            serde_json::to_value(record)
                                                .map_err(|e| e.to_string())?,
                                            &snapshot,
                                        ),
                                        Err(error) if !error.starts_with("RUN_NOT_FOUND:") => return Err(error),
                                        Err(_) => snapshot["status"]["latest"]
                                            .as_object()
                                            .and_then(|m| {
                                                m.values().find(|e| e["run_id"] == *child)
                                            })
                                            .cloned()
                                            .unwrap_or(
                                                json!({"run_id":child,"execution_state":"finished","outcome":"unknown","current_freshness":"pending"}),
                                            ),
                                    };
                                    let mut item = item;
                                    if let Some(result) =
                                        item.get_mut("result").and_then(Value::as_object_mut)
                                    {
                                        result.remove("stdout");
                                        result.remove("stderr");
                                    }
                                    runs.push(item);
                                }
                                value["execution_state"] = json!(if active.contains_key(&run_id) {
                                    "running"
                                } else {
                                    "finished"
                                });
                                value["runs"] = json!(runs);
                                return Ok(value);
                            }
                            if active.contains_key(&run_id) {
                                snapshot["status"]["latest"]
                                    .as_object()
                                    .and_then(|m| m.values().find(|e| e["run_id"] == run_id))
                                    .cloned()
                                    .ok_or("unknown active run".into())
                            } else {
                                let record =
                                    serde_json::to_value(service_run_record(&engine, &run_id)?)
                                        .map_err(|e| e.to_string())?;
                                Ok(current_record(record, &snapshot))
                            }
                        }
                        Operation::GetLog {
                            run_id,
                            check_id,
                            offset,
                            limit,
                        } => {
                            let child_id = if let Some(batch) = engine.batch(&run_id) {
                                let index = batch
                                    .check_ids
                                    .iter()
                                    .position(|id| id == &check_id)
                                    .ok_or("check outside batch")?;
                                batch.run_ids[index].clone()
                            } else {
                                run_id.clone()
                            };
                            let record = service_run_record(&engine, &child_id)?;
                            if record.check_id != check_id {
                                return Err("run/check identity mismatch".into());
                            }
                            let bytes = engine.read_log(
                                record
                                    .evidence
                                    .log_ref
                                    .as_deref()
                                    .ok_or("log unavailable")?,
                                record
                                    .evidence
                                    .log_sha256
                                    .as_deref()
                                    .ok_or("log unavailable")?,
                            )?;
                            let begin = usize::try_from(offset)
                                .map_err(|_| "offset too large")?
                                .min(bytes.len());
                            let end = begin.saturating_add(limit).min(bytes.len());
                            Ok(
                                json!({"run_id":run_id,"check_id":check_id,"offset":begin,"next_offset":end,"total_bytes":bytes.len(),"text":String::from_utf8_lossy(&bytes[begin..end]),"truncated":end<bytes.len()}),
                            )
                        }
                        _ => Err("operation belongs to snapshot reader".into()),
                    }
                })();
                let _ = command.response.send(result);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                shutting_down = true;
                for token in active.values() {
                    token.cancel();
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if shutting_down && active.is_empty() {
            return Ok(());
        }
        if !shutting_down {
            if shared
                .monitor
                .lock()
                .map(|mut m| m.changed().unwrap_or(true))
                .unwrap_or(true)
            {
                shared.invalidate("source changed; freshness refresh pending");
                last_refresh = std::time::Instant::now() - Duration::from_secs(2);
            }
            if last_refresh.elapsed() >= Duration::from_secs(1) {
                if let Err(error) = shared.publish(&mut engine) {
                    shared.invalidate(&error);
                }
                last_refresh = std::time::Instant::now();
            }
        }
    }
}
fn cached_snapshot(shared: &Shared) -> Result<Value, String> {
    if shared
        .monitor
        .lock()
        .map(|mut monitor| monitor.changed().unwrap_or(true))
        .unwrap_or(true)
    {
        shared.invalidate("source changed after refresh; validation pending");
    }
    let snapshot = shared
        .snapshot
        .read()
        .map_err(|_| "snapshot lock poisoned")?;
    if snapshot["health"] != "ready" {
        return Err("FRESHNESS_PENDING: source validation pending".into());
    }
    Ok(snapshot.clone())
}
fn service_run_record(
    engine: &Engine,
    run_id: &str,
) -> Result<checker_core::engine::RunRecord, String> {
    engine.run_record(run_id).map_err(|error| {
        if error.contains("os error 2") {
            format!("RUN_NOT_FOUND: {run_id}")
        } else {
            format!("STORAGE_ERROR: run record unavailable: {error}")
        }
    })
}
fn error_code(message: &str) -> String {
    for code in [
        "APPROVAL_PEER_REQUIRED",
        "APPROVAL_CHALLENGE_INVALID",
        "APPROVAL_BUSY",
        "REVISION_CONFLICT",
        "CONFIG_CONFLICT",
        "PLAN_CONFLICT",
        "PLAN_BUSY",
        "IDEMPOTENCY_CONFLICT",
        "RUN_BUSY",
        "PERMISSION_REQUIRED",
        "SERVICE_STOPPING",
        "RUN_NOT_ACTIVE",
        "FRESHNESS_PENDING",
        "RUN_NOT_FOUND",
        "STORAGE_ERROR",
    ] {
        if message.starts_with(code) {
            return code.into();
        }
    }
    if message.contains("unknown") {
        "NOT_FOUND".into()
    } else if message.contains("persist") || message.contains("I/O") {
        "STORAGE_ERROR".into()
    } else {
        "SERVICE_ERROR".into()
    }
}
fn current_record(mut record: Value, snapshot: &Value) -> Value {
    if let Some(result) = record.get_mut("result").and_then(Value::as_object_mut) {
        result.remove("stdout");
        result.remove("stderr");
    }
    record["current_freshness"] = json!(if record["evidence"]["source"]
        == snapshot["status"]["source"]
        && snapshot["health"] == "ready"
        && record["evidence"]["freshness"] == "current"
        && record["changed_during_run"] == false
    {
        "current"
    } else {
        "stale"
    });
    record
}
async fn handle(
    mut stream: UnixStream,
    shared: Shared,
    sender: mpsc::Sender<Message>,
) -> Result<(), String> {
    let credentials = stream.peer_cred().map_err(|e| e.to_string())?;
    if credentials.uid() != unsafe { libc::geteuid() } {
        return Err("wrong IPC peer".into());
    }
    let length = tokio::time::timeout(Duration::from_secs(5), stream.read_u32())
        .await
        .map_err(|_| "request timeout")?
        .map_err(|e| e.to_string())? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err("invalid IPC frame length".into());
    }
    let mut bytes = vec![0; length];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut bytes))
        .await
        .map_err(|_| "request timeout")?
        .map_err(|e| e.to_string())?;
    let request: Request = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    request.validate()?;
    if shared
        .monitor
        .lock()
        .map(|mut monitor| monitor.changed().unwrap_or(true))
        .unwrap_or(true)
    {
        shared.invalidate("source changed; freshness refresh pending");
    }
    let operation = match request.operation {
        Operation::Subscribe { after_revision } => {
            let mut changed = shared.revision.subscribe();
            if after_revision.is_some_and(|r| r == *changed.borrow()) {
                let _ = tokio::time::timeout(Duration::from_secs(20), changed.changed()).await;
            }
            Operation::Project
        }
        other => other,
    };
    let approval_peer = if matches!(
        &operation,
        Operation::ApprovalChallenge { .. } | Operation::ApprovalCommit { .. }
    ) {
        credentials
            .pid()
            .and_then(|pid| u32::try_from(pid).ok())
            .and_then(|pid| authorize_approval_peer(pid).ok())
    } else {
        None
    };
    let (tx, rx) = oneshot::channel();
    sender
        .send(Message::Command(Box::new(Command {
            operation,
            approval_peer,
            response: tx,
        })))
        .map_err(|_| "service actor stopped")?;
    let result = rx.await.map_err(|_| "service actor stopped")?;
    let mut response = Response {
        schema_version: SCHEMA_VERSION,
        request_id: request.request_id,
        service_instance_id: shared.instance.clone(),
        revision: result
            .as_ref()
            .ok()
            .and_then(|value| value["revision"].as_u64())
            .unwrap_or_else(|| *shared.revision.borrow()),
        result: result.as_ref().ok().cloned(),
        error: result.err().map(|message| ServiceError {
            code: error_code(&message),
            message,
        }),
    };
    let mut bytes = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_FRAME_BYTES {
        response.result = None;
        response.error = Some(ServiceError {
            code: "RESPONSE_TOO_LARGE".into(),
            message: "response exceeds bounded frame; select a smaller scope".into(),
        });
        bytes = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_u32(bytes.len() as u32).await?;
        stream.write_all(&bytes).await
    })
    .await
    .map_err(|_| "response write timeout")?
    .map_err(|error| error.to_string())?;
    Ok(())
}
pub async fn serve(
    root: &Path,
    state_dir: &Path,
    shutdown: CancellationToken,
) -> Result<(), String> {
    let engine = Engine::open(root, state_dir)?;
    let endpoint = Endpoint::for_root(root, state_dir)?;
    if let Ok(metadata) = std::fs::symlink_metadata(&endpoint.socket_path) {
        endpoint.validate()?;
        if std::os::unix::net::UnixStream::connect(&endpoint.socket_path).is_ok() {
            return Err("service endpoint already active".into());
        }
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err("socket ownership mismatch".into());
        }
        std::fs::remove_file(&endpoint.socket_path).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(&endpoint.socket_path).map_err(|e| e.to_string())?;
    std::fs::set_permissions(
        &endpoint.socket_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .map_err(|e| e.to_string())?;
    let socket_identity =
        std::fs::symlink_metadata(&endpoint.socket_path).map_err(|e| e.to_string())?;
    let instance = format!(
        "service-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos()
    );
    let options = FingerprintOptions {
        extra_inputs: engine.config().fingerprint.extra_inputs.clone(),
        exclude_outputs: engine.config().fingerprint.exclude_outputs.clone(),
    };
    let monitor = Arc::new(Mutex::new(
        SourceWatch::start_with_options(engine.root(), &options).map_err(|e| e.to_string())?,
    ));
    let initial_revision = engine.revision();
    let (revision, _) = watch::channel(initial_revision);
    let shared = Shared {
        snapshot: Arc::new(RwLock::new(Value::Null)),
        revision,
        instance,
        monitor,
    };
    let (tx, rx) = mpsc::channel();
    let actor_shared = shared.clone();
    let actor_tx = tx.clone();
    let runtime = tokio::runtime::Handle::current();
    let mut actor =
        tokio::task::spawn_blocking(move || actor(engine, actor_shared, rx, actor_tx, runtime));
    let mut ready = shared.revision.subscribe();
    let needs_initial = {
        let snapshot = shared
            .snapshot
            .read()
            .map_err(|_| "snapshot lock poisoned")?;
        snapshot.is_null()
    };
    if needs_initial {
        let mut actor_done = false;
        let initialization: Result<(), String> = tokio::select! {
            result=tokio::time::timeout(Duration::from_secs(45),ready.changed())=>result.map_err(|_|"service initialization timeout".to_string()).and_then(|result|result.map_err(|_|"initialization failed".to_string())),
            result=&mut actor=>{actor_done=true;result.map_err(|error|error.to_string()).and_then(|result|result).and_then(|_|Err("service actor exited before initialization".into()))},
            _=shutdown.cancelled()=>Err("SERVICE_STOPPING: shutdown during initialization".into()),
        };
        if let Err(error) = initialization {
            drop(listener);
            let _ = tx.send(Message::Shutdown);
            if !actor_done {
                let _ = actor.await;
            }
            if std::fs::symlink_metadata(&endpoint.socket_path).is_ok_and(|metadata| {
                metadata.ino() == socket_identity.ino() && metadata.dev() == socket_identity.dev()
            }) {
                let _ = std::fs::remove_file(&endpoint.socket_path);
            }
            return Err(error);
        }
    }
    eprintln!(
        "{}",
        json!({"ready":true,"socket":endpoint.socket_path,"service_instance_id":shared.instance})
    );
    let permits = Arc::new(tokio::sync::Semaphore::new(32));
    let mut completed_actor = None;
    let listener_result: Result<(), String> = loop {
        tokio::select! {
            _=shutdown.cancelled()=>break Ok(()),
            result=&mut actor=>{completed_actor=Some(result.map_err(|error|error.to_string()).and_then(|result|result));break Err("service actor stopped unexpectedly".into());},
            accepted=listener.accept()=>{
                let (stream,_)=match accepted{Ok(connection)=>connection,Err(error)=>break Err(error.to_string())};
                if let Ok(permit)=permits.clone().try_acquire_owned(){let shared=shared.clone();let tx=tx.clone();tokio::spawn(async move{let _permit=permit;let _=handle(stream,shared,tx).await;});}
            }
        }
    };
    drop(listener);
    let _ = tx.send(Message::Shutdown);
    let actor_result = match completed_actor {
        Some(result) => result,
        None => actor
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result),
    };
    let result = listener_result.and(actor_result);
    if std::fs::symlink_metadata(&endpoint.socket_path)
        .is_ok_and(|m| m.ino() == socket_identity.ino() && m.dev() == socket_identity.dev())
    {
        std::fs::remove_file(&endpoint.socket_path).map_err(|e| e.to_string())?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn nonce_fixture() -> (
        ApprovalChallenges,
        ApprovalPeer,
        ApprovalBinding,
        std::time::Instant,
    ) {
        // Supplied nonce data only: no Engine, trust store, process or terminal acceptance.
        let now = std::time::Instant::now();
        let peer = ApprovalPeer {
            pid: 42,
            starttime: "123".into(),
            executable_hash: "fixture-cli".into(),
        };
        let binding = ApprovalBinding {
            canonical_root: "/fixture".into(),
            config_hash: format!("sha256:{}", "a".repeat(64)),
            command_hash: format!("sha256:{}", "b".repeat(64)),
            argv: vec!["/usr/bin/true".into()],
            cwd: "/fixture".into(),
            environment: BTreeMap::new(),
            sandbox_profile: checker_core::security::SANDBOX_PROFILE.into(),
            executable_hash: format!("sha256:{}", "c".repeat(64)),
            sandbox_binary_hash: format!("sha256:{}", "d".repeat(64)),
        };
        let mut challenges = ApprovalChallenges::default();
        challenges.pending.insert(
            "a".repeat(64),
            ApprovalChallenge {
                check_id: "check".into(),
                binding: binding.clone(),
                peer: peer.clone(),
                expires: now + APPROVAL_TTL,
            },
        );
        (challenges, peer, binding, now)
    }
    #[test]
    fn approval_denies_pipes_and_non_cli_images() {
        for (stdin, stdout, actual) in [
            (false, false, "cli"),
            (false, true, "cli"),
            (true, false, "cli"),
            (true, true, "mcp"),
        ] {
            assert!(approval_peer_requirements(stdin, stdout, actual, "cli").is_err());
        }
    }
    #[test]
    fn approval_nonce_is_single_use_without_creating_a_grant() {
        let (mut pending, peer, binding, now) = nonce_fixture();
        assert!(
            pending
                .consume(&"a".repeat(64), Some(&peer), &binding, now)
                .is_ok()
        );
        assert!(
            pending
                .consume(&"a".repeat(64), Some(&peer), &binding, now)
                .is_err()
        );
    }
    #[test]
    fn denied_or_reused_peer_consumes_nonce() {
        for peer_kind in 0..3 {
            let (mut pending, mut peer, binding, now) = nonce_fixture();
            if peer_kind == 1 {
                peer.pid += 1;
            }
            if peer_kind == 2 {
                peer.starttime = "124".into();
            }
            let peer = if peer_kind == 0 { None } else { Some(&peer) };
            assert!(
                pending
                    .consume(&"a".repeat(64), peer, &binding, now)
                    .is_err()
            );
            assert!(pending.pending.is_empty());
        }
    }
    #[test]
    fn expired_or_changed_binding_consumes_nonce() {
        let (mut pending, peer, binding, now) = nonce_fixture();
        assert!(
            pending
                .consume(&"a".repeat(64), Some(&peer), &binding, now + APPROVAL_TTL)
                .is_err()
        );
        assert!(pending.pending.is_empty());
        let (mut pending, peer, mut binding, now) = nonce_fixture();
        binding.argv.push("different".into());
        assert!(
            pending
                .consume(&"a".repeat(64), Some(&peer), &binding, now)
                .is_err()
        );
        assert!(pending.pending.is_empty());
    }
    #[test]
    fn approval_nonce_capacity_refuses_before_randomness_or_engine_access() {
        let (mut pending, peer, binding, now) = nonce_fixture();
        pending.pending.clear();
        for index in 0..MAX_APPROVAL_CHALLENGES {
            pending.pending.insert(
                format!("{index:064x}"),
                ApprovalChallenge {
                    check_id: "check".into(),
                    binding: binding.clone(),
                    peer: peer.clone(),
                    expires: now + APPROVAL_TTL,
                },
            );
        }
        assert!(pending.issue("check".into(), binding, peer, now).is_err());
        assert_eq!(pending.pending.len(), MAX_APPROVAL_CHALLENGES);
    }
    #[test]
    fn changed_then_reverted_run_never_becomes_current_again() {
        let snapshot = json!({"health":"ready","status":{"source":{"fingerprint":"same"}}});
        for (changed, freshness, expected) in [
            (false, "current", "current"),
            (true, "current", "stale"),
            (false, "stale", "stale"),
            (false, "pending", "stale"),
        ] {
            let record = json!({"changed_during_run":changed,"evidence":{"source":{"fingerprint":"same"},"freshness":freshness}});
            assert_eq!(
                current_record(record, &snapshot)["current_freshness"],
                expected
            );
        }
        let record = json!({"changed_during_run":false,"evidence":{"source":{"fingerprint":"old"},"freshness":"current"}});
        assert_eq!(
            current_record(record, &snapshot)["current_freshness"],
            "stale"
        );
        let record = json!({"changed_during_run":false,"evidence":{"source":{"fingerprint":"same"},"freshness":"current"},"result":{"outcome":"passed","stdout":{"text":"private output"},"stderr":{"text":"private error"}}});
        let sanitized = current_record(record, &snapshot);
        assert_eq!(sanitized["result"]["outcome"], "passed");
        assert!(sanitized["result"].get("stdout").is_none());
        assert!(sanitized["result"].get("stderr").is_none());
    }
    #[test]
    fn refreshed_configuration_monitors_formerly_excluded_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("project");
        let state = directory.path().join("state");
        std::fs::create_dir_all(root.join(".progress-checker")).unwrap();
        std::fs::create_dir_all(root.join("generated")).unwrap();
        std::fs::write(root.join("generated/result.txt"), b"first").unwrap();
        let mut config = json!({"schema_version":1,"project_id":"monitor-config-test","enabled":true,"panel":{"show_on_start":true},"execution":{"max_parallel":1,"default_timeout_seconds":5},"fingerprint":{"extra_inputs":[],"exclude_outputs":["generated/**"]},"checks":[{"id":"check","argv":["/usr/bin/true"],"cwd":".","kind":"test","timeout_seconds":5}],"milestones":[{"id":"milestone","title":"Monitor test","in_scope":true,"depends_on":[],"criteria":[{"id":"criterion","description":"Check passes","check_id":"check","required":true}]}]});
        let config_path = root.join(".progress-checker/config.json");
        std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(
            std::process::Command::new("/usr/bin/git")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .args(["init", "-q"])
                .arg(&root)
                .status()
                .unwrap()
                .success()
        );
        let mut engine = Engine::open(&root, &state).unwrap();
        let options = FingerprintOptions {
            extra_inputs: engine.config().fingerprint.extra_inputs.clone(),
            exclude_outputs: engine.config().fingerprint.exclude_outputs.clone(),
        };
        let (revision, _) = watch::channel(engine.revision());
        let shared = Shared {
            snapshot: Arc::new(RwLock::new(Value::Null)),
            revision,
            instance: "monitor-test".into(),
            monitor: Arc::new(Mutex::new(
                SourceWatch::start_with_options(&root, &options).unwrap(),
            )),
        };
        shared.publish(&mut engine).unwrap();
        config["fingerprint"]["exclude_outputs"] = json!([]);
        std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        shared.publish(&mut engine).unwrap();
        assert!(cached_snapshot(&shared).is_ok());
        std::fs::write(root.join("generated/result.txt"), b"second").unwrap();
        assert!(
            cached_snapshot(&shared)
                .unwrap_err()
                .starts_with("FRESHNESS_PENDING:")
        );
    }
}
