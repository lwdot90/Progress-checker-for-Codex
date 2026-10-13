//! Native stdio gateway candidate. Never executes or approves configured checks.
//! The backend must implement `track-project --protocol native-gateway-v1`
//! before tracking can activate. Current backend does not implement that contract.
use serde_json::{Value, json};
mod native_bridge;
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    time::timeout,
};
const MAX: usize = 256 * 1024;
const VERSION: &str = env!("CARGO_PKG_VERSION");
fn failure(code: &str, message: &str) -> Value {
    let value = json!({"error":{"code":code,"message":message}});
    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":true})
}
fn track_tool() -> Value {
    json!({"name":"checker_track_project","description":"Explicitly bind this connection to an absolute Git worktree. Preserves accepted plans; cannot approve or run checks.","inputSchema":{"type":"object","properties":{"project_root":{"type":"string","minLength":1,"maxLength":4096}},"required":["project_root"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}})
}
async fn frame<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, String> {
    let mut result = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(|e| e.to_string())?;
        if available.is_empty() {
            return if result.is_empty() {
                Ok(None)
            } else {
                Err("Truncated frame".into())
            };
        }
        let count = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |n| n + 1);
        if result.len() + count > MAX {
            return Err("Frame exceeds limit".into());
        }
        let complete = available[count - 1] == b'\n';
        result.extend_from_slice(&available[..count]);
        reader.consume(count);
        if complete {
            return Ok(Some(result));
        }
    }
}
async fn bounded_output(
    mut command: Command,
    seconds: u64,
) -> Result<(std::process::ExitStatus, Vec<u8>), String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().ok_or("Missing subprocess stdout")?;
    let result = timeout(Duration::from_secs(seconds), async {
        let mut bytes = Vec::new();
        stdout
            .take((MAX + 1) as u64)
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| e.to_string())?;
        if bytes.len() > MAX {
            return Err("Subprocess output exceeded limit".into());
        }
        let status = child.wait().await.map_err(|e| e.to_string())?;
        Ok((status, bytes))
    })
    .await
    .map_err(|_| "Subprocess timed out".to_string())?;
    if result.is_err() {
        let _ = child.kill().await;
    }
    result
}
fn reject_reparse_ancestors(path: &std::path::Path) -> Result<(), String> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err("Symlink path components are unsupported".into());
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err("Windows reparse path components are unsupported".into());
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}
fn canonical_state(path: &std::path::Path) -> Result<PathBuf, String> {
    use std::path::Component;
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err("State path must be absolute and contain no dot components".into());
    }
    reject_reparse_ancestors(path)?;
    let mut existing = path.to_path_buf();
    let mut missing = Vec::new();
    while !existing.try_exists().map_err(|e| e.to_string())? {
        missing.push(
            existing
                .file_name()
                .ok_or("No existing state ancestor")?
                .to_os_string(),
        );
        if !existing.pop() {
            return Err("No existing state ancestor".into());
        }
    }
    if !existing.is_dir() {
        return Err("State ancestor must be a directory".into());
    }
    let mut canonical = std::fs::canonicalize(existing).map_err(|e| e.to_string())?;
    for part in missing.into_iter().rev() {
        canonical.push(part);
    }
    Ok(canonical)
}
fn strict_activation_receipt(
    receipt: &Value,
    root: &std::path::Path,
    state: &std::path::Path,
) -> Result<(), String> {
    let object = receipt
        .as_object()
        .ok_or("Activation receipt must be an object")?;
    if object.len() != 4
        || object.keys().any(|key| {
            ![
                "protocol",
                "canonical_root",
                "state_directory",
                "writer_ready",
            ]
            .contains(&key.as_str())
        })
        || receipt["protocol"] != "native-gateway-v1"
        || receipt["writer_ready"] != true
    {
        return Err("Invalid native activation receipt fields".into());
    }
    let supplied_root = PathBuf::from(
        receipt["canonical_root"]
            .as_str()
            .ok_or("Invalid root receipt")?,
    );
    let supplied_state = PathBuf::from(
        receipt["state_directory"]
            .as_str()
            .ok_or("Invalid state receipt")?,
    );
    reject_reparse_ancestors(&supplied_root)?;
    reject_reparse_ancestors(&supplied_state)?;
    if supplied_root != root
        || supplied_state != state
        || std::fs::canonicalize(&supplied_root).map_err(|e| e.to_string())? != root
        || std::fs::canonicalize(&supplied_state).map_err(|e| e.to_string())? != state
    {
        return Err("Activation receipt canonical identity mismatch".into());
    }
    Ok(())
}
struct Backend {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    sequence: u64,
}
impl Backend {
    async fn exchange(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.sequence += 1;
        let id = self.sequence;
        let bytes =
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
                .map_err(|e| e.to_string())?;
        if bytes.len() >= MAX {
            return Err("Backend request too large".into());
        }
        timeout(Duration::from_secs(50), async {
            self.input
                .write_all(&bytes)
                .await
                .map_err(|e| e.to_string())?;
            self.input
                .write_all(b"\n")
                .await
                .map_err(|e| e.to_string())?;
            self.input.flush().await.map_err(|e| e.to_string())?;
            let line = frame(&mut self.output).await?.ok_or("Backend closed")?;
            let value: Value = serde_json::from_slice(&line).map_err(|e| e.to_string())?;
            if value["jsonrpc"] != "2.0" || value["id"] != id {
                return Err("Backend response identity mismatch".into());
            }
            Ok(value)
        })
        .await
        .map_err(|_| "Backend timed out".to_string())?
    }
}
struct Gateway {
    bin: PathBuf,
    state: PathBuf,
    root: Option<PathBuf>,
    backend: Option<Backend>,
    tools: Vec<Value>,
    initialized: bool,
    ready: bool,
}
impl Gateway {
    async fn stop(&mut self) {
        if let Some(mut backend) = self.backend.take() {
            let _ = backend.input.shutdown().await;
            drop(backend.input);
            if timeout(Duration::from_secs(15), backend.child.wait())
                .await
                .is_err()
            {
                let _ = backend.child.kill().await;
            }
        }
    }
    async fn track(&mut self, args: &Value) -> Result<Value, String> {
        let object = args.as_object().ok_or("Supply only project_root")?;
        if object.len() != 1 {
            return Err("Supply only project_root".into());
        }
        let raw = args["project_root"]
            .as_str()
            .ok_or("Missing project_root")?;
        if raw.len() > 4096 || !PathBuf::from(raw).is_absolute() {
            return Err("Root must be absolute".into());
        }
        reject_reparse_ancestors(std::path::Path::new(raw))?;
        let root = std::fs::canonicalize(raw).map_err(|e| e.to_string())?;
        if self.root.as_ref().is_some_and(|old| old != &root) {
            return Ok(failure(
                "PROJECT_ALREADY_BOUND",
                "Start a separate connection for another project",
            ));
        }
        let cache = self.bin.parent().ok_or("Missing plugin directory")?;
        if root.starts_with(cache)
            || cache.starts_with(&root)
            || root.starts_with(&self.state)
            || self.state.starts_with(&root)
        {
            return Err("Project must not overlap plugin or state storage".into());
        }
        if let Some(backend) = self.backend.as_mut() {
            if backend
                .child
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_some()
            {
                self.stop().await;
            }
        }
        if self.backend.is_some() {
            return Ok(
                json!({"content":[{"type":"text","text":"Already tracking"}],"structuredContent":{"canonical_root":root,"already_tracking":true},"isError":false}),
            );
        }
        // Latch before activation. A failed backend cannot redirect this connection.
        self.root = Some(root.clone());
        // Compiled backend owns Git validation, protected state ACLs, safe create-only
        // config setup, managed instructions and single-writer lifecycle. Never
        // replace this with shell commands or direct private-state writes here.
        let mut activation = Command::new(self.bin.join("progress-checker.exe"));
        activation
            .arg("--root")
            .arg(&root)
            .arg("--state-dir")
            .arg(&self.state)
            .args(["track-project", "--protocol", "native-gateway-v1"]);
        let (status, bytes) = bounded_output(activation, 30).await?;
        if !status.success() {
            return Ok(failure(
                "NATIVE_BACKEND_UNAVAILABLE",
                "Compiled backend lacks qualified native tracking activation; checks remain disabled",
            ));
        }
        let receipt: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        strict_activation_receipt(&receipt, &root, &self.state)?;
        let mut child = Command::new(self.bin.join("progress-checker-mcp.exe"))
            .arg("--root")
            .arg(&root)
            .arg("--state-dir")
            .arg(&self.state)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| e.to_string())?;
        let input = child.stdin.take().ok_or("Missing backend stdin")?;
        let output = BufReader::new(child.stdout.take().ok_or("Missing backend stdout")?);
        let mut backend = Backend {
            child,
            input,
            output,
            sequence: 0,
        };
        let initialize=backend.exchange("initialize",json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"checker-global","version":VERSION}})).await?;
        if initialize.get("error").is_some() {
            return Err("Backend initialization failed".into());
        }
        backend
            .input
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .await
            .map_err(|e| e.to_string())?;
        backend.input.flush().await.map_err(|e| e.to_string())?;
        let project = backend
            .exchange(
                "tools/call",
                json!({"name":"checker_get_project","arguments":{}}),
            )
            .await?;
        if project["result"]["isError"] == true {
            return Err("Backend project access failed".into());
        }
        self.backend = Some(backend);
        let value = json!({"canonical_root":root,"state_directory":self.state,"already_tracking":false,"project":project["result"]["structuredContent"]});
        Ok(
            json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":false}),
        )
    }
    async fn dispatch(&mut self, request: Value) -> Option<Value> {
        let object = match request.as_object() {
            Some(v) => v,
            None => {
                return Some(
                    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid request"}}),
                );
            }
        };
        let id = request.get("id").cloned();
        let valid_id = id.as_ref().is_none_or(|v| {
            v.as_i64().is_some()
                || v.as_u64().is_some()
                || v.as_str().is_some_and(|s| s.len() <= 160)
        });
        if request["jsonrpc"] != "2.0"
            || !valid_id
            || !request["method"].is_string()
            || object
                .keys()
                .any(|k| !["jsonrpc", "id", "method", "params"].contains(&k.as_str()))
        {
            return Some(
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid request"}}),
            );
        }
        let method = request["method"].as_str().unwrap();
        if id.is_none() {
            if method == "notifications/initialized" && self.initialized {
                self.ready = true;
            }
            return None;
        }
        let id = id.unwrap();
        let params = request.get("params").cloned().unwrap_or(json!({}));
        let value = if method == "ping" {
            json!({})
        } else if method == "initialize" && !self.initialized {
            if !params["protocolVersion"].is_string()
                || !params["capabilities"].is_object()
                || !params["clientInfo"].is_object()
            {
                return Some(
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"Invalid initialization"}}),
                );
            }
            self.initialized = true;
            json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"progress-checker-global","version":VERSION}})
        } else if !self.ready {
            failure("NOT_INITIALIZED", "Initialize first")
        } else if !params.is_object() {
            failure("INVALID_ARGUMENT", "Expected object")
        } else {
            let meta = params.get("_meta");
            if meta.is_some_and(|m| {
                !m.is_object() || m.get("openai/readOnly").is_some_and(|v| !v.is_boolean())
            }) {
                failure("INVALID_ARGUMENT", "Invalid metadata")
            } else {
                let read_only = params["_meta"]["openai/readOnly"]
                    .as_bool()
                    .unwrap_or(false);
                if method == "tools/list"
                    && (params
                        .as_object()
                        .unwrap()
                        .keys()
                        .any(|key| !["_meta", "cursor"].contains(&key.as_str()))
                        || params
                            .get("cursor")
                            .is_some_and(|cursor| !cursor.is_null() && cursor != ""))
                {
                    failure(
                        "INVALID_ARGUMENT",
                        "Pagination or unknown fields unsupported",
                    )
                } else if method == "tools/call"
                    && params
                        .as_object()
                        .unwrap()
                        .keys()
                        .any(|key| !["name", "arguments", "_meta"].contains(&key.as_str()))
                {
                    failure("INVALID_ARGUMENT", "Unsupported tool parameters")
                } else if method == "tools/list" {
                    let mut tools = self.tools.clone();
                    tools.push(track_tool());
                    tools.retain(|tool| !read_only || tool["annotations"]["readOnlyHint"] == true);
                    json!({"tools":tools})
                } else if method != "tools/call" {
                    failure("UNKNOWN_METHOD", "Unsupported method")
                } else if params["name"] == "checker_track_project" {
                    if read_only {
                        failure("READ_ONLY_REQUEST", "Tracking changes project files")
                    } else {
                        match self
                            .track(params.get("arguments").unwrap_or(&json!({})))
                            .await
                        {
                            Ok(v) => v,
                            Err(e) => failure("GATEWAY_ERROR", &e),
                        }
                    }
                } else if !self.tools.iter().any(|tool| tool["name"] == params["name"]) {
                    failure("INVALID_ARGUMENT", "Unknown tool")
                } else if let Some(backend) = self.backend.as_mut() {
                    match backend.exchange("tools/call", params).await {
                        Ok(mut response) => {
                            response["id"] = id;
                            return Some(response);
                        }
                        Err(e) => {
                            self.stop().await;
                            failure("GATEWAY_ERROR", &e)
                        }
                    }
                } else {
                    failure(
                        "PROJECT_NOT_TRACKED",
                        "Explicitly track the session worktree first",
                    )
                }
            }
        };
        Some(json!({"jsonrpc":"2.0","id":id,"result":value}))
    }
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
fn validate_manifest_version(manifest: &Value) -> Result<(), String> {
    if manifest["version"].as_str() != Some(VERSION) {
        return Err("Gateway and manifest version mismatch".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_gateway_version_matches_compiled_package() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert!(validate_manifest_version(&json!({"version":VERSION})).is_ok());
        assert!(validate_manifest_version(&json!({"version":"0.0.0"})).is_err());
        assert!(validate_manifest_version(&json!({"version":null})).is_err());
        assert!(validate_manifest_version(&json!({})).is_err());
    }
    #[test]
    fn activation_receipts_reject_unexpected_authority_fields() {
        let receipt = json!({"protocol":"native-gateway-v1","canonical_root":"unused","state_directory":"unused","writer_ready":true,"approved":true});
        assert!(
            strict_activation_receipt(
                &receipt,
                std::path::Path::new("unused"),
                std::path::Path::new("unused")
            )
            .is_err()
        );
        assert!(
            strict_activation_receipt(
                &json!({"protocol":"native-gateway-v1"}),
                std::path::Path::new("unused"),
                std::path::Path::new("unused")
            )
            .is_err()
        );
    }
    #[test]
    fn state_identity_refuses_relative_paths() {
        assert!(canonical_state(std::path::Path::new("relative-state")).is_err());
    }
    #[test]
    fn track_tool_never_claims_read_only() {
        assert_eq!(track_tool()["annotations"]["readOnlyHint"], false);
        assert_eq!(track_tool()["name"], "checker_track_project");
    }
}
async fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--version"] {
        println!("checker-global {VERSION}");
        return Ok(());
    }
    if args == ["--describe-platform"] {
        println!(
            "{}",
            json!({"schema_version":1,"artifact":"checker-global","version":VERSION,"target_family":std::env::consts::OS,"native_windows_candidate":true,"qualified":false,"activation_protocol":"native-gateway-v1","activation_backend_available":false,"approval_supported":false,"checks_supported":false,"transport":"MCP stdio; protected backend IPC required"})
        );
        return Ok(());
    }
    if !cfg!(windows) {
        return Err("Native Windows gateway must run on Windows".into());
    }
    let executable = std::fs::canonicalize(std::env::current_exe().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let bin = executable
        .parent()
        .ok_or("Missing binary directory")?
        .to_path_buf();
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(
            bin.parent()
                .ok_or("Missing plugin directory")?
                .join("plugin.json"),
        )
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    validate_manifest_version(&manifest)?;
    let state = match args.as_slice() {
        [] => PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA required")?)
            .join("ProgressChecker"),
        [flag, path] if flag == "--state-dir" => PathBuf::from(path),
        _ => return Err("Usage: checker-global [--state-dir ABSOLUTE_PATH]".into()),
    };
    let state = canonical_state(&state)?;
    let mut description = Command::new(bin.join("progress-checker-mcp.exe"));
    description.arg("--describe-tools");
    let (status, bytes) = bounded_output(description, 10).await?;
    if !status.success() {
        return Err("Native tool description failed".into());
    }
    let descriptions: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let tools = descriptions["tools"]
        .as_array()
        .ok_or("Invalid tool descriptions")?
        .clone();
    let mut gateway = Gateway {
        bin,
        state,
        root: None,
        backend: None,
        tools,
        initialized: false,
        ready: false,
    };
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    let result=async {while let Some(bytes)=frame(&mut input).await?{let answer=match serde_json::from_slice::<Value>(&bytes){Ok(request)=>gateway.dispatch(request).await,Err(_)=>Some(json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}))};if let Some(mut value)=answer{let mut encoded=serde_json::to_vec(&value).map_err(|e|e.to_string())?;if encoded.len()>=MAX{value=json!({"jsonrpc":"2.0","id":value["id"],"result":failure("RESPONSE_TOO_LARGE","Request a smaller scope")});encoded=serde_json::to_vec(&value).map_err(|e|e.to_string())?;}output.write_all(&encoded).await.map_err(|e|e.to_string())?;output.write_all(b"\n").await.map_err(|e|e.to_string())?;output.flush().await.map_err(|e|e.to_string())?;}}Ok::<(),String>(())}.await;
    gateway.stop().await;
    result
}
