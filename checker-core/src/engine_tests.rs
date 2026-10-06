use super::*;
use crate::runner::BoundedLog;
use std::process::Command;

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("worktree");
    let state = directory.path().join("state");
    fs::create_dir_all(root.join(".progress-checker")).unwrap();
    let config = serde_json::json!({
        "schema_version":1,"project_id":"engine-test","enabled":true,
        "panel":{"show_on_start":true},
        "execution":{"max_parallel":1,"default_timeout_seconds":5},
        "fingerprint":{"extra_inputs":[],"exclude_outputs":[]},
        "checks":[{"id":"check","argv":["/usr/bin/true"],"cwd":".","kind":"test","timeout_seconds":5}],
        "milestones":[{"id":"milestone","title":"Test milestone","in_scope":true,"depends_on":[],
            "criteria":[{"id":"criterion","description":"Configured check passes","check_id":"check","required":true}]}]
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

fn evidence(
    engine: &Engine,
    execution_state: ExecutionState,
    outcome: Option<Outcome>,
) -> CheckEvidence {
    CheckEvidence {
        run_id: "synthetic-run".into(),
        check_id: "check".into(),
        execution_state,
        outcome,
        freshness: Freshness::Current,
        source: engine.source().unwrap(),
        command_hash: engine.config.check("check").unwrap().hash(),
        log_ref: None,
        log_sha256: None,
    }
}

/// Synthetic authenticated records test persistence/evaluation without granting
/// command approval or starting a subprocess.
fn install_pass(engine: &mut Engine) {
    let result = RunResult {
        outcome: Outcome::Passed,
        exit_code: Some(0),
        stdout: BoundedLog {
            text: "synthetic test evidence".into(),
            truncated: false,
        },
        stderr: BoundedLog {
            text: String::new(),
            truncated: false,
        },
        reason: None,
    };
    let mut evidence = evidence(engine, ExecutionState::Finished, Some(Outcome::Passed));
    let (reference, hash) = engine
        .store
        .append_log(&evidence.run_id, &log_bytes(&result).unwrap())
        .unwrap();
    evidence.log_ref = Some(reference);
    evidence.log_sha256 = Some(hash);
    let record = RunRecord {
        schema_version: 1,
        run_id: evidence.run_id.clone(),
        check_id: evidence.check_id.clone(),
        started_at: "2026-10-03T00:00:00Z".into(),
        finished_at: "2026-10-03T00:00:01Z".into(),
        duration_ms: 1000,
        before: evidence.source.clone(),
        after: Some(evidence.source.clone()),
        changed_during_run: false,
        evidence: evidence.clone(),
        result,
    };
    engine
        .store
        .append_attempt("synthetic-run-finish", &record)
        .unwrap();
    engine
        .saved
        .claims
        .insert("milestone".into(), Claim::Implemented);
    engine.saved.latest.insert("check".into(), evidence);
    engine.persist().unwrap();
}

#[test]
fn recollected_private_rpm_inventory_invalidates_engine_evidence_and_failure_is_closed() {
    let (_directory, root, state) = fixture();
    let database = tempfile::tempdir().unwrap();
    let destination = database.path().join("rpmdb.sqlite");
    let sql = format!(
        "VACUUM INTO '{}'",
        destination.to_str().unwrap().replace('\'', "''")
    );
    // SQLite reads a consistent snapshot through a read-only host connection.
    // Every mutation below targets only the resulting private database.
    assert!(
        Command::new("/usr/bin/sqlite3")
            .env_clear()
            .args(["-readonly", "/usr/lib/sysimage/rpm/rpmdb.sqlite"])
            .arg(sql)
            .stdin(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    // Prime SQLite's WAL/shared-memory bookkeeping before the cache takes its
    // initial metadata key. These files can be created by the first query.
    assert!(
        Command::new("/usr/bin/rpm")
            .env_clear()
            .arg("--dbpath")
            .arg(database.path())
            .arg("-qa")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    crate::environment::with_test_inventory(database.path(), || {
        let before_inventory = crate::environment::package_inventory().unwrap();
        let mut engine = Engine::open(&root, &state).unwrap();
        install_pass(&mut engine);
        let before = engine.status().unwrap();
        assert_eq!(before.progress.verified, 1);
        assert!(
            Command::new("/usr/bin/rpm")
                .env_clear()
                .arg("--dbpath")
                .arg(database.path())
                .args([
                    "--noplugins",
                    "--justdb",
                    "--nodeps",
                    "--noscripts",
                    "--notriggers",
                    "-e",
                    "rpm",
                ])
                .stdin(std::process::Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        let after_inventory = crate::environment::package_inventory().unwrap();
        assert_ne!(before_inventory, after_inventory);
        let after = engine.status().unwrap();
        assert_ne!(
            before.source.environment_signature,
            after.source.environment_signature
        );
        let mut expected_source = before.source.clone();
        expected_source.environment_signature = after.source.environment_signature.clone();
        assert_eq!(
            after.source, expected_source,
            "only environment identity changed"
        );
        assert_eq!(after.latest["check"].outcome, Some(Outcome::Passed));
        assert_eq!(after.latest["check"].freshness, Freshness::Stale);
        assert_eq!(after.progress.verified, 0);
        fs::remove_dir_all(database.path()).unwrap();
        assert!(
            engine.status().is_err(),
            "unavailable inventory must never reuse cached passing evidence"
        );
    });
}

#[test]
fn implementation_claim_never_verifies_and_revision_is_enforced() {
    let (_directory, root, state) = fixture();
    let mut engine = Engine::open(&root, &state).unwrap();
    let status = engine
        .set_claim("milestone", Claim::Implemented, 0)
        .unwrap();
    assert_eq!(status.revision, 1);
    assert_eq!(status.progress.verified, 0);
    assert_eq!(
        status.progress.milestones[0].implementation_claim,
        Claim::Implemented
    );
    assert_eq!(
        engine
            .set_claim("milestone", Claim::Planned, 0)
            .unwrap_err(),
        "REVISION_CONFLICT"
    );
    assert!(engine.set_claim("missing", Claim::Implemented, 1).is_err());
    assert_eq!(engine.saved.revision, 1);
}

#[tokio::test]
async fn absent_approval_cannot_create_attempt_or_change_revision() {
    let (_directory, root, state) = fixture();
    let mut engine = Engine::open(&root, &state).unwrap();
    let failure = engine
        .run("check", CancellationToken::new())
        .await
        .unwrap_err();
    assert!(failure.contains("PERMISSION_REQUIRED"));
    assert_eq!(engine.saved.revision, 0);
    assert!(engine.saved.latest.is_empty());
    assert_eq!(
        fs::read_dir(engine.store.directory().join("attempts"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn interrupted_attempt_recovers_unknown_without_log_evidence() {
    let (_directory, root, state) = fixture();
    let mut engine = Engine::open(&root, &state).unwrap();
    let pending = evidence(&engine, ExecutionState::Running, None);
    engine.saved.latest.insert("check".into(), pending);
    engine.persist().unwrap();
    drop(engine);
    let mut restored = Engine::open(&root, &state).unwrap();
    let status = restored.status().unwrap();
    let latest = &status.latest["check"];
    assert_eq!(latest.execution_state, ExecutionState::Finished);
    assert_eq!(latest.outcome, Some(Outcome::Unknown));
    assert_eq!(latest.freshness, Freshness::Pending);
    assert!(latest.log_ref.is_none());
    assert_eq!(status.progress.verified, 0);
    assert!(!status.warnings.is_empty());
}

#[test]
fn corrupt_newest_snapshot_never_restores_backup_green() {
    let (_directory, root, state) = fixture();
    let mut engine = Engine::open(&root, &state).unwrap();
    install_pass(&mut engine);
    assert_eq!(engine.status().unwrap().progress.verified, 1);
    engine.saved.latest.get_mut("check").unwrap().outcome = Some(Outcome::Failed);
    engine.persist().unwrap();
    let snapshot = engine.store.directory().join("snapshot.json");
    drop(engine);
    fs::write(snapshot, b"corrupt latest snapshot").unwrap();
    let mut restored = Engine::open(&root, &state).unwrap();
    let status = restored.status().unwrap();
    assert_eq!(status.latest["check"].outcome, Some(Outcome::Unknown));
    assert_eq!(status.progress.verified, 0);
    assert!(!status.warnings.is_empty());
}

#[test]
fn missing_authenticated_log_cannot_produce_verification() {
    let (_directory, root, state) = fixture();
    let mut engine = Engine::open(&root, &state).unwrap();
    install_pass(&mut engine);
    assert_eq!(engine.status().unwrap().progress.verified, 1);
    let reference = engine.saved.latest["check"].log_ref.as_ref().unwrap();
    fs::remove_file(engine.store.directory().join("logs").join(reference)).unwrap();
    let status = engine.status().unwrap();
    assert_eq!(status.latest["check"].outcome, Some(Outcome::Unknown));
    assert_eq!(status.progress.verified, 0);
    assert!(!status.warnings.is_empty());
}

#[test]
fn configuration_symlinks_special_files_and_oversize_are_denied() {
    use std::os::unix::fs::symlink;
    let (_directory, root, _state) = fixture();
    let config = root.join(".progress-checker/config.json");
    let outside = root.parent().unwrap().join("outside.json");
    fs::copy(&config, &outside).unwrap();
    fs::remove_file(&config).unwrap();
    symlink(&outside, &config).unwrap();
    assert!(read_config(&root).is_err());
    fs::remove_file(&config).unwrap();
    let name = std::ffi::CString::new(config.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(read_config(&root).is_err());
    fs::remove_file(&config).unwrap();
    fs::write(&config, vec![b' '; 256 * 1024 + 1]).unwrap();
    assert!(read_config(&root).is_err());
    fs::remove_file(&config).unwrap();
    fs::remove_dir(root.join(".progress-checker")).unwrap();
    let escaped = root.parent().unwrap().join("escaped-config-directory");
    fs::create_dir(&escaped).unwrap();
    fs::copy(outside, escaped.join("config.json")).unwrap();
    symlink(escaped, root.join(".progress-checker")).unwrap();
    assert!(read_config(&root).is_err());
}

#[test]
fn accepted_request_is_durable_and_reuse_never_prepares_another_execution() {
    let (_directory, root, state) = fixture();
    let mut engine = Engine::open(&root, &state).unwrap();
    let binding = engine.approval_binding("check").unwrap();
    engine.approve("check", binding).unwrap();
    let hash = engine.config.hash();
    let accepted = match engine.prepare_run("check", "request-one", &hash).unwrap() {
        PrepareOutcome::Accepted(prepared) => prepared.acceptance.clone(),
        PrepareOutcome::Existing(_) => panic!("first request must prepare"),
    };
    assert_eq!(
        engine.saved.latest["check"].execution_state,
        ExecutionState::Queued
    );
    assert_eq!(engine.revision(), accepted.revision);
    match engine.prepare_run("check", "request-one", &hash).unwrap() {
        PrepareOutcome::Existing(existing) => assert_eq!(existing.run_id, accepted.run_id),
        PrepareOutcome::Accepted(_) => panic!("duplicate must not prepare"),
    }
    assert!(
        engine
            .prepare_run("check", "request-one", "different")
            .is_err()
    );
    assert!(engine.prepare_run("check", "request-two", &hash).is_err());
    drop(engine);
    let mut reopened = Engine::open(&root, &state).unwrap();
    assert_eq!(
        reopened.saved.latest["check"].outcome,
        Some(Outcome::Unknown)
    );
    match reopened.prepare_run("check", "request-one", &hash).unwrap() {
        PrepareOutcome::Existing(existing) => assert_eq!(existing.run_id, accepted.run_id),
        PrepareOutcome::Accepted(_) => panic!("restart must not reexecute accepted request"),
    }
}

#[test]
fn preparation_rejects_config_mismatch_before_publishing_attempt() {
    let (_directory, root, state) = fixture();
    let mut engine = Engine::open(&root, &state).unwrap();
    let revision = engine.revision();
    assert!(
        matches!(engine.prepare_run("check", "request", "wrong"), Err(message) if message == "CONFIG_CONFLICT")
    );
    assert_eq!(engine.revision(), revision);
    assert!(engine.saved.latest.is_empty());
    assert!(engine.saved.requests.is_empty());
}

#[test]
fn claim_notes_persist_and_conflicting_revision_does_not_overwrite_them() {
    let (_directory, root, state) = fixture();
    let mut engine = Engine::open(&root, &state).unwrap();
    let revision = engine.revision();
    engine
        .set_claim_with_note(
            "milestone",
            Claim::Implemented,
            "Reviewed locally",
            revision,
        )
        .unwrap();
    assert!(
        engine
            .set_claim_with_note("milestone", Claim::Planned, "conflict", revision)
            .is_err()
    );
    assert_eq!(engine.claim_notes()["milestone"], "Reviewed locally");
    drop(engine);
    let reopened = Engine::open(&root, &state).unwrap();
    assert_eq!(reopened.claim_notes()["milestone"], "Reviewed locally");
}
