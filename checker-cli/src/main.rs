//! Human-facing local checker commands. Approval is deliberately interactive.
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use checker_core::model::Claim;
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "progress-checker",
    version,
    about = "Evidence-backed local project verification"
)]
struct Cli {
    /// Project worktree containing .progress-checker/config.json.
    #[arg(long, global = true, default_value = ".")]
    root: PathBuf,
    /// Private checker state base; defaults to the per-user local data directory.
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve this project over the protected local socket until interrupted.
    Serve,
    /// Validate project configuration without executing checks.
    Validate,
    /// Show fresh verification status and current state revision as JSON.
    Status,
    /// List configured commands without executing them.
    Checks,
    /// Record a planned/implemented claim; verified is always derived.
    Claim {
        milestone: String,
        #[arg(value_enum)]
        claim: ClaimArgument,
        /// Revision returned by status; prevents lost updates.
        #[arg(long)]
        expected_revision: u64,
    },
    /// Approve one exact command interactively from a human terminal.
    Approve { check: String },
    /// Run a previously approved check; Ctrl-C cancels its process group.
    Run { check: String },
}

#[derive(Clone, Copy, ValueEnum)]
enum ClaimArgument {
    Planned,
    Implemented,
}
impl From<ClaimArgument> for Claim {
    fn from(value: ClaimArgument) -> Self {
        match value {
            ClaimArgument::Planned => Self::Planned,
            ClaimArgument::Implemented => Self::Implemented,
        }
    }
}

/// This is a terminal frontend gate, not a repository-config permission grant.
/// It rejects redirected input and has no approval flag. A terminal is not an
/// authentication boundary against another process that can create its own PTY.
fn confirm_approval(check: &str, definition: &impl serde::Serialize) -> Result<(), String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("PERMISSION_REQUIRED: approval requires an interactive human terminal".into());
    }
    println!("Review the exact command definition:");
    print_json(definition)?;
    println!(
        "Execution uses the checker sandbox with networking disabled and a restricted environment."
    );
    println!(
        "The command may read all worktree files, including ignored secrets, and modify this worktree."
    );
    println!("Approve only a command you trust with that access.");
    let challenge = format!("approve {check}");
    print!("Type {challenge:?} to approve, or anything else to cancel: ");
    io::stdout().flush().map_err(|error| error.to_string())?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|error| error.to_string())?;
    if answer.trim_end_matches(['\r', '\n']) != challenge {
        return Err("PERMISSION_REQUIRED: approval cancelled".into());
    }
    Ok(())
}

fn print_json(value: &impl serde::Serialize) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = execute(Cli::parse()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn execute(cli: Cli) -> Result<(), String> {
    use checker_core::engine::Engine;
    let state_base = match cli.state_dir {
        Some(path) => path,
        None => default_state_directory()?,
    };
    match cli.command {
        Command::Serve => serve(&cli.root, &state_base).await,
        Command::Approve { check } => approve(&cli.root, &state_base, &check).await,
        Command::Validate | Command::Checks => {
            let engine = Engine::open(&cli.root, &state_base)?;
            match cli.command {
                Command::Validate => {
                    engine.config().validate()?;
                    print_json(
                        &serde_json::json!({"valid": true, "project_id": engine.config().project_id}),
                    )
                }
                Command::Checks => print_json(&engine.config().checks),
                _ => unreachable!(),
            }
        }
        command => {
            let endpoint = checker_service::client::Endpoint::for_root(&cli.root, &state_base)
                .map_err(service_unavailable)?;
            let client = checker_service::client::Client::new(endpoint);
            match command {
                Command::Status => print_json(&status(&client).await?),
                Command::Claim {
                    milestone,
                    claim,
                    expected_revision,
                } => {
                    rpc(
                        &client,
                        checker_service::protocol::Operation::SetClaim {
                            milestone_id: milestone,
                            claim: claim.into(),
                            note: String::new(),
                            expected_revision,
                        },
                    )
                    .await?;
                    print_json(&status(&client).await?)
                }
                Command::Run { check } => run_check(&client, check).await,
                _ => unreachable!(),
            }
        }
    }
}

async fn approve(
    root: &std::path::Path,
    state: &std::path::Path,
    check: &str,
) -> Result<(), String> {
    use checker_core::{engine::Engine, security::ApprovalBinding};
    use checker_service::{
        client::{Client, Endpoint},
        protocol::Operation,
    };
    // Refuse pipes before requesting a challenge or opening private state.
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("PERMISSION_REQUIRED: approval requires an interactive human terminal".into());
    }
    if let Ok(endpoint) = Endpoint::for_root(root, state)
        && endpoint.socket_path.exists()
    {
        let client = Client::new(endpoint);
        // Never fall back to a second writer after a service error.
        let preview = approval_rpc(
            &client,
            Operation::ApprovalChallenge {
                check_id: check.into(),
            },
        )
        .await?;
        let challenge_id = preview["challenge_id"]
            .as_str()
            .ok_or("missing approval challenge")?
            .to_owned();
        let binding: ApprovalBinding =
            serde_json::from_value(preview["binding"].clone()).map_err(|e| e.to_string())?;
        if preview["check_id"].as_str() != Some(check) {
            return Err("approval preview check identity mismatch".into());
        }
        confirm_approval(check, &binding)?;
        return print_json(
            &approval_rpc(
                &client,
                Operation::ApprovalCommit {
                    challenge_id,
                    binding,
                },
            )
            .await?,
        );
    }
    let mut engine = Engine::open(root, state)?;
    let binding = engine.approval_binding(check)?;
    confirm_approval(check, &binding)?;
    engine.approve(check, binding)?;
    print_json(&serde_json::json!({"approved": check}))
}

async fn approval_rpc(
    client: &checker_service::client::Client,
    operation: checker_service::protocol::Operation,
) -> Result<serde_json::Value, String> {
    let response = client.async_call(operation).await.map_err(|error| {
        format!("Approval service unavailable: {error}. If upgrading from an older plugin, close its old sessions once and reopen with the matching plugin version. Then run approval again and review the fresh definition. No check was executed.")
    })?;
    if let Some(error) = response.error {
        return Err(format!(
            "{}: {}. Run approval again and review the fresh definition. If this service predates 0.4, reopen older plugin sessions with the matching version. An error after confirmation may leave the exact grant saved; approval itself executes no check.",
            error.code, error.message
        ));
    }
    response.result.ok_or_else(|| {
        "Approval returned no result; review a fresh approval before continuing.".into()
    })
}

async fn serve(root: &std::path::Path, state_base: &std::path::Path) -> Result<(), String> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|error| error.to_string())?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|error| error.to_string())?;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let listener_shutdown = shutdown.clone();
    let listener = tokio::spawn(async move {
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
        }
        listener_shutdown.cancel();
    });
    let result = checker_service::serve(root, state_base, shutdown).await;
    listener.abort();
    result
}

fn service_unavailable(error: String) -> String {
    format!(
        "Shared service unavailable: {error}. Start `progress-checker serve` for this root and state directory."
    )
}

async fn rpc(
    client: &checker_service::client::Client,
    operation: checker_service::protocol::Operation,
) -> Result<serde_json::Value, String> {
    let response = client
        .async_call(operation)
        .await
        .map_err(service_unavailable)?;
    if let Some(error) = response.error {
        return Err(format!("{}: {}", error.code, error.message));
    }
    response
        .result
        .ok_or_else(|| "service returned no result".into())
}

async fn status(client: &checker_service::client::Client) -> Result<serde_json::Value, String> {
    let response = client
        .async_call(checker_service::protocol::Operation::Progress)
        .await
        .map_err(service_unavailable)?;
    if let Some(error) = response.error {
        return Err(format!("{}: {}", error.code, error.message));
    }
    let snapshot = response.result.ok_or("service returned no snapshot")?;
    let mut status = snapshot
        .get("status")
        .cloned()
        .ok_or("service returned no status")?;
    status["revision"] = serde_json::json!(response.revision);
    Ok(status)
}

async fn run_check(client: &checker_service::client::Client, check: String) -> Result<(), String> {
    use checker_service::protocol::Operation;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|error| format!("cancellation signal: {error}"))?;
    let current_status = status(client).await?;
    let revision = current_status["revision"]
        .as_u64()
        .ok_or("missing status revision")?;
    let config_hash = current_status["source"]["config_hash"]
        .as_str()
        .ok_or("missing configuration identity")?
        .to_owned();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let accepted = rpc(
        client,
        Operation::RunChecks {
            check_ids: vec![check.clone()],
            idempotency_key: format!("cli-{}-{nonce}", std::process::id()),
            expected_config_hash: config_hash,
            expected_revision: revision,
        },
    )
    .await?;
    let run_id = accepted["run_id"]
        .as_str()
        .ok_or("missing accepted run identity")?
        .to_owned();
    let check_run_id = accepted["run_ids"][0]
        .as_str()
        .ok_or("missing accepted check identity")?
        .to_owned();
    let mut cancelled = false;
    loop {
        let current_status = status(client).await?;
        let evidence = &current_status["latest"][&check];
        if evidence["run_id"].as_str() == Some(&check_run_id)
            && evidence["execution_state"]
                .as_str()
                .is_some_and(|state| state == "finished")
        {
            return print_json(&current_status);
        }
        if cancelled {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        }
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
            signal = interrupt.recv() => {
                if signal.is_none() { return Err("cancellation signal stream closed".into()); }
                let current = status(client).await?;
                let expected_revision = current["revision"].as_u64().ok_or("missing status revision")?;
                rpc(client, Operation::CancelRun { run_id: run_id.clone(), expected_revision }).await?;
                cancelled = true;
            }
        }
    }
}

fn default_state_directory() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err("XDG_DATA_HOME must be absolute".into());
        }
        return Ok(path.join("progress-checker"));
    }
    let home = std::env::var_os("HOME").ok_or("HOME unavailable; supply --state-dir")?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err("HOME must be absolute; supply --state-dir".into());
    }
    Ok(home.join(".local/share/progress-checker"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_require_revision_and_cannot_request_verification() {
        assert!(
            Cli::try_parse_from(["progress-checker", "claim", "feature", "implemented"]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "progress-checker",
                "claim",
                "feature",
                "verified",
                "--expected-revision",
                "1",
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from([
            "progress-checker",
            "--root",
            "/tmp/project",
            "claim",
            "feature",
            "implemented",
            "--expected-revision",
            "7",
        ])
        .expect("valid versioned implementation claim");
        assert_eq!(cli.root, PathBuf::from("/tmp/project"));
        assert!(matches!(
            cli.command,
            Command::Claim {
                expected_revision: 7,
                claim: ClaimArgument::Implemented,
                ..
            }
        ));
    }

    #[test]
    fn approval_has_no_unattended_override_flag() {
        for option in ["--yes", "--force", "--approve"] {
            assert!(Cli::try_parse_from(["progress-checker", "approve", "build", option]).is_err());
        }
    }

    #[test]
    fn redirected_approval_is_denied_before_serializing_definition() {
        // The test child has redirected standard streams. Leave interactive test
        // invocation to the PTY smoke test rather than waiting for terminal input.
        if io::stdin().is_terminal() && io::stdout().is_terminal() {
            return;
        }
        struct NotSerializable;
        impl serde::Serialize for NotSerializable {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                panic!("approval definition must not be accessed before terminal gate");
            }
        }
        let error =
            confirm_approval("build", &NotSerializable).expect_err("redirected input is denied");
        assert!(error.starts_with("PERMISSION_REQUIRED:"));
    }
}
