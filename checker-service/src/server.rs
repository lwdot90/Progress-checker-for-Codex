//! One blocking actor owns the engine; socket readers consume immutable snapshots.
use crate::{
    client::Endpoint,
    protocol::{MAX_FRAME_BYTES, Operation, Request, Response, SCHEMA_VERSION, ServiceError},
};
use checker_core::{
    engine::{CompletedRun, Engine, PrepareBatchOutcome},
    fingerprint::{FingerprintOptions, SourceWatch},
};
use serde_json::{Value, json};
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
    response: oneshot::Sender<Result<Value, String>>,
}
enum Message {
    Command(Command),
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
    let (tx, rx) = oneshot::channel();
    sender
        .send(Message::Command(Command {
            operation,
            response: tx,
        }))
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
