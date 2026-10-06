//! One exact, externally authorized command; no shell expansion or trust writes.
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::sync::CancellationToken;

use crate::model::Outcome;
use crate::security::AuthorizedExecution;

pub const LOG_LIMIT_BYTES: usize = 64 * 1024;
const TERMINATION_GRACE: Duration = Duration::from_millis(200);
const DRAIN_GRACE: Duration = Duration::from_millis(500);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoundedLog {
    pub text: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunResult {
    pub outcome: Outcome,
    pub exit_code: Option<i32>,
    pub stdout: BoundedLog,
    pub stderr: BoundedLog,
    pub reason: Option<String>,
}

impl RunResult {
    fn empty(outcome: Outcome, reason: &str) -> Self {
        Self {
            outcome,
            exit_code: None,
            stdout: BoundedLog {
                text: String::new(),
                truncated: false,
            },
            stderr: BoundedLog {
                text: String::new(),
                truncated: false,
            },
            reason: Some(reason.into()),
        }
    }
}

/// Cancellation is supplied by the caller. Authorization is never created here.
/// Only Linux has the verified sandbox/process-lifecycle implementation.
pub async fn run_command(
    authorized: &AuthorizedExecution,
    timeout: Duration,
    cancel: CancellationToken,
) -> RunResult {
    if cancel.is_cancelled() {
        return RunResult::empty(Outcome::Cancelled, "cancelled before execution");
    }
    if timeout.is_zero() {
        return RunResult::empty(Outcome::TimedOut, "zero execution timeout");
    }
    #[cfg(target_os = "linux")]
    {
        run_linux(authorized, timeout, cancel).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = authorized;
        RunResult::empty(
            Outcome::Unknown,
            "verified sandbox unavailable on this platform",
        )
    }
}

#[cfg(target_os = "linux")]
struct ProcessGroup(u32);

#[cfg(target_os = "linux")]
impl ProcessGroup {
    fn signal(&self, signal: i32) {
        if self.0 != 0 {
            // Negative PID targets the process group created before exec. The
            // sandbox's PID-namespace init also kills detached descendants.
            unsafe {
                libc::kill(-(self.0 as i32), signal);
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.signal(libc::SIGKILL);
    }
}

#[cfg(target_os = "linux")]
async fn run_linux(
    authorized: &AuthorizedExecution,
    timeout: Duration,
    cancel: CancellationToken,
) -> RunResult {
    use std::os::fd::{AsRawFd, FromRawFd};
    let Some(deadline) = tokio::time::Instant::now().checked_add(timeout) else {
        return RunResult::empty(
            Outcome::Unknown,
            "execution timeout exceeds platform limits",
        );
    };
    // The trusted wrapper alone writes this anonymous descriptor. Bubblewrap
    // closes it in the sandbox child, so repository code cannot forge status.
    let fd = unsafe { libc::memfd_create(c"checker-sandbox-status".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return RunResult::empty(Outcome::Unknown, "sandbox status channel unavailable");
    }
    let mut status_file = unsafe { std::fs::File::from_raw_fd(fd) };
    if fd < 3 {
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return RunResult::empty(Outcome::Unknown, "sandbox status descriptor unavailable");
        }
        status_file = unsafe { std::fs::File::from_raw_fd(duplicate) };
    }
    let status_fd = status_file.as_raw_fd();
    let command = match authorized.sandbox_command_with_status_fd(status_fd) {
        Ok(command) => command,
        Err(_) => {
            return RunResult::empty(
                Outcome::Unknown,
                "authorization or restricted sandbox unavailable",
            );
        }
    };
    let mut command = tokio::process::Command::from(command);
    command
        .process_group(0)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(status_fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            return RunResult::empty(
                Outcome::Unknown,
                "authorized sandbox command could not be spawned",
            );
        }
    };
    let mut group = ProcessGroup(child.id().expect("spawned child has an id"));
    let stdout = tokio::spawn(collect(child.stdout.take().expect("piped stdout")));
    let stderr = tokio::spawn(collect(child.stderr.take().expect("piped stderr")));
    let (outcome, exit_code, mut reason, reaped) = tokio::select! {
        biased;
        _ = cancel.cancelled() => (Outcome::Cancelled, None, Some("cancelled by caller".into()), false),
        _ = tokio::time::sleep_until(deadline) => (Outcome::TimedOut, None, Some("execution timeout exceeded".into()), false),
        status = child.wait() => match status {
            Ok(status) if status.success() => (Outcome::Passed, status.code(), None, true),
            Ok(status) if status.code().is_some() => (Outcome::Failed, status.code(), None, true),
            Ok(_) => (Outcome::Unknown, None, Some("command terminated by signal".into()), true),
            Err(_) => (Outcome::Unknown, None, Some("command status unavailable".into()), false),
        },
    };
    // Bubblewrap exits only after its PID namespace has been dismantled. Never
    // signal a reaped leader's PGID: it can have been reused by an unrelated job.
    if reaped {
        group.0 = 0;
    } else {
        group.signal(libc::SIGTERM);
        let terminated = tokio::time::timeout(TERMINATION_GRACE, child.wait()).await;
        if matches!(terminated, Ok(Ok(_))) {
            group.0 = 0;
        } else {
            group.signal(libc::SIGKILL);
            match tokio::time::timeout(DRAIN_GRACE, child.wait()).await {
                Ok(Ok(_)) => group.0 = 0,
                _ => reason = Some("sandbox cleanup could not be established".into()),
            }
        }
    }
    let redaction_values = authorized.redactions();
    let redactions: Vec<&str> = redaction_values.iter().map(String::as_str).collect();
    let (stdout, stdout_ok) = finish_log(stdout, &redactions).await;
    let (stderr, stderr_ok) = finish_log(stderr, &redactions).await;
    let mut outcome =
        if outcome == Outcome::Passed && (!stdout_ok || !stderr_ok || reason.is_some()) {
            reason = Some("complete command output or cleanup could not be established".into());
            Outcome::Unknown
        } else {
            outcome
        };
    if matches!(outcome, Outcome::Passed | Outcome::Failed) {
        use std::io::{Read, Seek};
        let mut status = Vec::new();
        let read = status_file.rewind().and_then(|_| {
            (&mut status_file)
                .take(16 * 1024 + 1)
                .read_to_end(&mut status)
        });
        if read.is_err() || status.len() > 16 * 1024 || sandbox_exit_code(&status) != exit_code {
            outcome = Outcome::Unknown;
            reason = Some("sandbox setup or executable launch was not confirmed".into());
        }
    }
    RunResult {
        outcome,
        exit_code,
        stdout,
        stderr,
        reason,
    }
}

#[cfg(target_os = "linux")]
fn sandbox_exit_code(bytes: &[u8]) -> Option<i32> {
    let mut exit_code = None;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let object: serde_json::Value = serde_json::from_slice(line).ok()?;
        if !object.is_object() {
            return None;
        }
        if let Some(value) = object.get("exit-code") {
            let code = i32::try_from(value.as_i64()?).ok()?;
            if !(0..=255).contains(&code) || exit_code.replace(code).is_some() {
                return None;
            }
        }
    }
    exit_code
}

struct RawLog {
    bytes: Vec<u8>,
    truncated: bool,
    complete: bool,
}

async fn collect(mut pipe: impl AsyncRead + Unpin) -> RawLog {
    let mut log = RawLog {
        bytes: Vec::new(),
        truncated: false,
        complete: true,
    };
    let mut chunk = [0_u8; 4096];
    loop {
        match pipe.read(&mut chunk).await {
            Ok(0) => break,
            Ok(count) => {
                let keep = count.min(LOG_LIMIT_BYTES.saturating_sub(log.bytes.len()));
                log.bytes.extend_from_slice(&chunk[..keep]);
                log.truncated |= keep < count;
                // Keep draining discarded output so a verbose child cannot block.
            }
            Err(_) => {
                log.complete = false;
                break;
            }
        }
    }
    log
}

async fn finish_log(
    mut task: tokio::task::JoinHandle<RawLog>,
    secrets: &[&str],
) -> (BoundedLog, bool) {
    match tokio::time::timeout(DRAIN_GRACE, &mut task).await {
        Ok(Ok(log)) => {
            let mut text = sanitize(&log.bytes, secrets);
            let expanded = text.len() > LOG_LIMIT_BYTES;
            if expanded {
                let mut end = LOG_LIMIT_BYTES;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
            }
            (
                BoundedLog {
                    text,
                    truncated: log.truncated || expanded,
                },
                log.complete,
            )
        }
        _ => {
            task.abort();
            (
                BoundedLog {
                    text: "[output unavailable]".into(),
                    truncated: true,
                },
                false,
            )
        }
    }
}

/// Remove terminal escapes/control characters before exposing logs to any UI.
fn sanitize(bytes: &[u8], secrets: &[&str]) -> String {
    let raw = String::from_utf8_lossy(bytes);
    let mut chars = raw.chars().peekable();
    let mut clean = String::with_capacity(raw.len());
    while let Some(ch) = chars.next() {
        match ch {
            '\u{1b}' => match chars.next() {
                Some('[') => {
                    for next in chars.by_ref() {
                        if ('@'..='~').contains(&next) {
                            break;
                        }
                    }
                }
                Some(']') | Some('P') | Some('^') | Some('_') | Some('X') => {
                    while let Some(next) = chars.next() {
                        if next == '\u{7}' {
                            break;
                        }
                        if next == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            },
            '\n' | '\t' => clean.push(ch),
            ch if ch.is_control()
                || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') =>
                {}
            _ => clean.push(ch),
        }
    }
    // Approved environment values are treated conservatively as known secrets.
    for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
        clean = clean.replace(secret, "[REDACTED]");
        // A bounded capture can end in the middle of a secret. Hide that suffix.
        for (boundary, _) in secret.char_indices().rev() {
            if boundary == 0 {
                continue;
            }
            if clean.ends_with(&secret[..boundary]) {
                clean.truncate(clean.len() - boundary);
                clean.push_str("[REDACTED]");
                break;
            }
        }
    }
    clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn authorized(root: &std::path::Path, program: &str, args: &[&str]) -> AuthorizedExecution {
        use crate::security::{ApprovalBinding, LocalApproval, authorize};
        let argv = std::iter::once(program)
            .chain(args.iter().copied())
            .map(str::to_owned)
            .collect();
        let binding = ApprovalBinding::new(
            root,
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
            argv,
            root,
        )
        .unwrap();
        // Synthetic test-only approval. Production code never creates approval.
        let approval = LocalApproval {
            schema_version: 1,
            binding_digest: binding.approval_digest().unwrap(),
            binding: binding.clone(),
        };
        authorize(binding, &approval).unwrap()
    }

    #[test]
    fn strips_terminal_sequences_controls_and_redacts_secrets() {
        let output = b"\x1b[31mred\x1b[0m\x1b]52;c;private\x07 text\r\0 token-123\n";
        assert_eq!(sanitize(output, &["token-123"]), "red text [REDACTED]\n");
        assert_eq!(
            sanitize(b"partial token-", &["token-123"]),
            "partial [REDACTED]"
        );
        assert_eq!(sanitize("a\u{202e}b".as_bytes(), &[]), "ab");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_final_trusted_exit_code_confirms_successful_sandbox_launch() {
        assert_eq!(sandbox_exit_code(b"{\"child-pid\":12}\n"), None);
        assert_eq!(
            sandbox_exit_code(b"{\"child-pid\":12}\n{\"exit-code\":0}\n"),
            Some(0)
        );
        assert_eq!(sandbox_exit_code(b"{\"exit-code\":7}\n"), Some(7));
        assert_eq!(
            sandbox_exit_code(b"{\"exit-code\":0}\n{\"exit-code\":0}\n"),
            None
        );
        assert_eq!(sandbox_exit_code(b"{\"exit-code\":0}\nnot JSON\n"), None);
        assert_eq!(sandbox_exit_code(b"{\"exit-code\":256}\n"), None);
    }

    #[tokio::test]
    async fn oversized_output_is_drained_and_bounded() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let producer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            writer
                .write_all(&vec![b'x'; LOG_LIMIT_BYTES * 3])
                .await
                .unwrap();
        });
        let captured = collect(reader).await;
        producer.await.unwrap();
        assert_eq!(captured.bytes.len(), LOG_LIMIT_BYTES);
        assert!(captured.truncated && captured.complete);
    }

    #[tokio::test]
    async fn malformed_utf8_cannot_expand_past_the_display_limit() {
        let task = tokio::spawn(async {
            RawLog {
                bytes: vec![0xff; LOG_LIMIT_BYTES],
                truncated: false,
                complete: true,
            }
        });
        let (log, complete) = finish_log(task, &[]).await;
        assert!(complete && log.truncated);
        assert!(log.text.len() <= LOG_LIMIT_BYTES);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn exact_argv_preserves_shell_metacharacters_and_exit_status() {
        let root = tempfile::tempdir().unwrap();
        let auth = authorized(
            root.path(),
            "/usr/bin/python3",
            &[
                "-c",
                "import sys; print(sys.argv[1]); sys.exit(7)",
                "$(touch injected); literal",
            ],
        );
        let result = run_command(&auth, Duration::from_secs(5), CancellationToken::new()).await;
        assert_eq!(result.outcome, Outcome::Failed, "{result:?}");
        assert_eq!(result.exit_code, Some(7));
        assert_eq!(result.stdout.text, "$(touch injected); literal\n");
        assert!(!root.path().join("injected").exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sandbox_child_cannot_inherit_or_forge_wrapper_status() {
        let root = tempfile::tempdir().unwrap();
        let program = "import os,sys\nfor fd in os.listdir('/proc/self/fd'):\n try: target=os.readlink('/proc/self/fd/'+fd)\n except FileNotFoundError: continue\n if 'checker-sandbox-status' in target: sys.exit(99)\nprint('{\"exit-code\":0}',flush=True)\nsys.exit(7)";
        let auth = authorized(root.path(), "/usr/bin/python3", &["-c", program]);
        let result = run_command(&auth, Duration::from_secs(5), CancellationToken::new()).await;
        assert_eq!(result.outcome, Outcome::Failed, "{result:?}");
        assert_eq!(result.exit_code, Some(7));
        assert_eq!(result.stdout.text, "{\"exit-code\":0}\n");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timeout_drains_large_output_and_kills_detached_descendants() {
        let root = tempfile::tempdir().unwrap();
        let program = "import os,time,signal,sys\nif os.fork()==0:\n os.setsid(); signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(1); open('late-child','w').write('escaped'); os._exit(0)\nprint('x'*200000,flush=True)\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\ntime.sleep(30)";
        let auth = authorized(root.path(), "/usr/bin/python3", &["-c", program]);
        let result = run_command(&auth, Duration::from_millis(250), CancellationToken::new()).await;
        assert_eq!(result.outcome, Outcome::TimedOut, "{result:?}");
        assert!(result.stdout.truncated);
        assert_eq!(result.stdout.text.len(), LOG_LIMIT_BYTES);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!root.path().join("late-child").exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cancellation_cannot_become_a_success() {
        let root = tempfile::tempdir().unwrap();
        let auth = authorized(
            root.path(),
            "/usr/bin/python3",
            &[
                "-c",
                "import time; print('started',flush=True); time.sleep(30)",
            ],
        );
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        let cancellation = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            trigger.cancel();
        });
        let result = run_command(&auth, Duration::from_secs(5), cancel).await;
        cancellation.await.unwrap();
        assert_eq!(result.outcome, Outcome::Cancelled, "{result:?}");
        assert_eq!(result.exit_code, None);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn successful_parent_cannot_leave_a_background_writer() {
        let root = tempfile::tempdir().unwrap();
        let program = "import os,time\nif os.fork()==0:\n os.setsid(); time.sleep(1); open('late-child','w').write('escaped'); os._exit(0)\nos._exit(0)";
        let auth = authorized(root.path(), "/usr/bin/python3", &["-c", program]);
        let result = run_command(&auth, Duration::from_secs(5), CancellationToken::new()).await;
        assert_eq!(result.outcome, Outcome::Passed, "{result:?}");
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!root.path().join("late-child").exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dropping_execution_future_kills_sandbox_children() {
        let root = tempfile::tempdir().unwrap();
        let program = "import os,time\nif os.fork()==0:\n os.setsid(); time.sleep(1); open('late-child','w').write('escaped'); os._exit(0)\ntime.sleep(30)";
        let auth = authorized(root.path(), "/usr/bin/python3", &["-c", program]);
        let task = tokio::spawn(async move {
            run_command(&auth, Duration::from_secs(10), CancellationToken::new()).await
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        task.abort();
        let _ = task.await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!root.path().join("late-child").exists());
    }
}
