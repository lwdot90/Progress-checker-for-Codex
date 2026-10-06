//! Service coordinator regressions: acceptance is durable before execution.
use super::*;
use std::process::Command;

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("worktree");
    let state = directory.path().join("state");
    fs::create_dir_all(root.join(".progress-checker")).unwrap();
    let config = serde_json::json!({
        "schema_version":1,"project_id":"service-engine-test","enabled":true,
        "panel":{"show_on_start":true},
        "execution":{"max_parallel":1,"default_timeout_seconds":5},
        "fingerprint":{"extra_inputs":[],"exclude_outputs":[]},
        "checks":[{"id":"check","argv":["/usr/bin/touch","execution-marker"],"cwd":".","kind":"test","timeout_seconds":5}],
        "milestones":[{"id":"milestone","title":"Service milestone","in_scope":true,"depends_on":[],
            "criteria":[{"id":"criterion","description":"Check passes","check_id":"check","required":true}]}]
    });
    fs::write(
        root.join(".progress-checker/config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    assert!(
        Command::new("/usr/bin/git")
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
    (directory, root, state)
}

fn accepted(engine: &mut Engine, key: &str) -> PreparedRun {
    let binding = engine.approval_binding("check").unwrap();
    engine.approve("check", binding).unwrap();
    let hash = engine.config().hash();
    match engine.prepare_run("check", key, &hash).unwrap() {
        PrepareOutcome::Accepted(prepared) => *prepared,
        PrepareOutcome::Existing(_) => panic!("first request must be accepted"),
    }
}

#[tokio::test]
async fn configuration_change_after_acceptance_never_executes_command() {
    let (_directory, root, state) = fixture();
    let mut engine = Engine::open(&root, &state).unwrap();
    let prepared = accepted(&mut engine, "config-change");
    engine.mark_running(&prepared.acceptance.run_id).unwrap();
    let path = root.join(".progress-checker/config.json");
    let mut config: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    config["checks"][0]["argv"] = serde_json::json!(["/usr/bin/touch", "changed-marker"]);
    fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
    let completed = prepared.execute(CancellationToken::new()).await;
    assert_eq!(completed.result.outcome, Outcome::Unknown);
    assert!(
        completed
            .result
            .reason
            .as_deref()
            .unwrap()
            .contains("configuration changed")
    );
    let status = engine.finish_run(completed).unwrap();
    assert_eq!(status.latest["check"].freshness, Freshness::Stale);
    assert_eq!(status.progress.verified, 0);
    assert!(!root.join("execution-marker").exists());
    assert!(!root.join("changed-marker").exists());
}

#[tokio::test]
async fn cancelled_queued_request_finishes_without_execution_and_cannot_be_replayed() {
    let (_directory, root, state) = fixture();
    let mut engine = Engine::open(&root, &state).unwrap();
    let prepared = accepted(&mut engine, "cancelled-request");
    let acceptance = prepared.acceptance.clone();
    let token = CancellationToken::new();
    token.cancel();
    engine.mark_running(&acceptance.run_id).unwrap();
    let status = engine.finish_run(prepared.execute(token).await).unwrap();
    assert_eq!(status.latest["check"].outcome, Some(Outcome::Cancelled));
    assert_eq!(
        status.latest["check"].execution_state,
        ExecutionState::Finished
    );
    assert!(!root.join("execution-marker").exists());
    drop(engine);
    let mut restored = Engine::open(&root, &state).unwrap();
    let revision = restored.revision();
    match restored
        .prepare_run(
            "check",
            "cancelled-request",
            &acceptance.expected_config_hash,
        )
        .unwrap()
    {
        PrepareOutcome::Existing(existing) => assert_eq!(existing.run_id, acceptance.run_id),
        PrepareOutcome::Accepted(_) => panic!("completed request must never execute twice"),
    }
    assert_eq!(restored.revision(), revision);
}

#[test]
fn running_attempt_recovery_preserves_request_identity_and_drops_log_claims() {
    let (_directory, root, state) = fixture();
    let mut engine = Engine::open(&root, &state).unwrap();
    let prepared = accepted(&mut engine, "crashed-request");
    let acceptance = prepared.acceptance.clone();
    engine.mark_running(&acceptance.run_id).unwrap();
    drop(prepared);
    drop(engine);
    let mut restored = Engine::open(&root, &state).unwrap();
    let status = restored.status().unwrap();
    assert_eq!(status.latest["check"].outcome, Some(Outcome::Unknown));
    assert!(status.latest["check"].log_ref.is_none());
    assert!(status.latest["check"].log_sha256.is_none());
    assert_eq!(status.progress.verified, 0);
    match restored
        .prepare_run("check", "crashed-request", &acceptance.expected_config_hash)
        .unwrap()
    {
        PrepareOutcome::Existing(existing) => assert_eq!(existing.run_id, acceptance.run_id),
        PrepareOutcome::Accepted(_) => panic!("crash recovery must not reexecute"),
    }
    assert!(!root.join("execution-marker").exists());
}

#[tokio::test]
async fn status_contains_log_references_without_embedding_command_output() {
    let (_directory, root, state) = fixture();
    let mut engine = Engine::open(&root, &state).unwrap();
    let prepared = accepted(&mut engine, "private-log");
    engine.mark_running(&prepared.acceptance.run_id).unwrap();
    let token = CancellationToken::new();
    token.cancel();
    let mut completed = prepared.execute(token).await;
    completed.result.stdout.text = "private-output-sentinel".into();
    completed.result.stderr.text = "private-error-sentinel".into();
    let status = engine.finish_run(completed).unwrap();
    let serialized = serde_json::to_string(&status).unwrap();
    assert!(!serialized.contains("private-output-sentinel"));
    assert!(!serialized.contains("private-error-sentinel"));
    let evidence = &status.latest["check"];
    let log = engine
        .read_log(
            evidence.log_ref.as_deref().unwrap(),
            evidence.log_sha256.as_deref().unwrap(),
        )
        .unwrap();
    assert!(
        String::from_utf8(log)
            .unwrap()
            .contains("private-output-sentinel")
    );
}

fn add_second_check(root: &Path) {
    let path = root.join(".progress-checker/config.json");
    let mut config: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    config["checks"].as_array_mut().unwrap().push(serde_json::json!({
        "id":"second","argv":["/usr/bin/touch","second-marker"],"cwd":".","kind":"test","timeout_seconds":5
    }));
    fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
}

#[test]
fn batch_permission_preflight_is_atomic_before_any_attempt_is_accepted() {
    let (_directory, root, state) = fixture();
    add_second_check(&root);
    let mut engine = Engine::open(&root, &state).unwrap();
    let binding = engine.approval_binding("check").unwrap();
    engine.approve("check", binding).unwrap();
    let revision = engine.revision();
    let hash = engine.config().hash();
    let ids = vec!["check".into(), "second".into()];
    assert!(
        matches!(engine.prepare_batch(&ids, "partial-approval", &hash, revision), Err(reason) if reason.contains("PERMISSION_REQUIRED"))
    );
    assert_eq!(engine.revision(), revision);
    assert!(engine.saved.latest.is_empty());
    assert!(engine.saved.batch_requests.is_empty());
    assert_eq!(
        fs::read_dir(engine.store.directory().join("attempts"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn batch_cancel_and_idempotency_survive_restart_without_repreparing_children() {
    let (_directory, root, state) = fixture();
    add_second_check(&root);
    let mut engine = Engine::open(&root, &state).unwrap();
    for id in ["check", "second"] {
        let binding = engine.approval_binding(id).unwrap();
        engine.approve(id, binding).unwrap();
    }
    let hash = engine.config().hash();
    let ids = vec!["check".into(), "second".into()];
    let prepared = match engine
        .prepare_batch(&ids, "batch-restart", &hash, engine.revision())
        .unwrap()
    {
        PrepareBatchOutcome::Accepted(batch) => batch,
        PrepareBatchOutcome::Existing(_) => panic!("first batch must prepare"),
    };
    let acceptance = prepared.acceptance.clone();
    assert_eq!(acceptance.run_ids.len(), 2);
    assert!(engine.request_cancel(&acceptance.run_id).unwrap());
    drop(prepared);
    drop(engine);
    let mut restored = Engine::open(&root, &state).unwrap();
    let revision = restored.revision();
    match restored
        .prepare_batch(&ids, "batch-restart", &hash, 0)
        .unwrap()
    {
        PrepareBatchOutcome::Existing(existing) => {
            assert_eq!(existing.run_id, acceptance.run_id);
            assert_eq!(existing.run_ids, acceptance.run_ids);
            assert!(existing.cancel_requested);
        }
        PrepareBatchOutcome::Accepted(_) => panic!("restart must not prepare children again"),
    }
    assert_eq!(restored.revision(), revision);
    let status = restored.status().unwrap();
    for id in ["check", "second"] {
        assert_eq!(status.latest[id].outcome, Some(Outcome::Unknown));
        assert_eq!(status.latest[id].execution_state, ExecutionState::Finished);
    }
    assert!(!root.join("execution-marker").exists());
    assert!(!root.join("second-marker").exists());
}
