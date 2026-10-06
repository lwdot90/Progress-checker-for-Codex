//! MCP 2025-06-18 STDIO adapter. Only the service owns runtime state and execution.
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use checker_service::{
    client::{Client, Endpoint},
    protocol::{Operation, Request, SCHEMA_VERSION},
};
use clap::Parser;
use serde_json::{Value, json};

const MAX_FRAME: usize = 256 * 1024;
const PROTOCOL: &str = "2025-06-18";

#[derive(Parser)]
#[command(name = "progress-checker-mcp", version)]
struct Cli {
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    state_dir: PathBuf,
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn tool_result(value: Value, is_error: bool) -> Value {
    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":is_error})
}
fn tool_error(code: &str, message: &str) -> Value {
    tool_result(json!({"error":{"code":code,"message":message}}), true)
}
fn response_bytes(response: &Value) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(response).map_err(|error| error.to_string())?;
    if bytes.len() < MAX_FRAME {
        return Ok(bytes);
    }
    // A bounded IPC payload appears twice in an MCP tool result: structured
    // content and its escaped text equivalent. Keep the session alive when
    // that expansion exceeds the STDIO frame limit.
    let bounded = json!({
        "jsonrpc":"2.0", "id":response["id"],
        "result":tool_error("RESPONSE_TOO_LARGE", "Tool response exceeds the bounded MCP frame size; request a smaller scope.")
    });
    let bytes = serde_json::to_vec(&bounded).map_err(|error| error.to_string())?;
    if bytes.len() < MAX_FRAME {
        return Ok(bytes);
    }
    // Dispatch bounds accepted ids to 160 bytes. Retain the frame invariant
    // here too if another caller supplies an id that cannot fit even an error.
    serde_json::to_vec(&rpc_error(
        Value::Null,
        -32600,
        "Request id exceeds the bounded response size",
    ))
    .map_err(|error| error.to_string())
}
fn object_schema(properties: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}
fn plan_config_schema() -> Value {
    fn expand(value: &Value, definitions: &Value) -> Value {
        if let Some(reference) = value
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(|reference| reference.strip_prefix("#/$defs/"))
        {
            return expand(&definitions[reference], definitions);
        }
        match value {
            Value::Object(object) => Value::Object(
                object
                    .iter()
                    .filter(|(key, _)| !["$id", "$defs", "$schema"].contains(&key.as_str()))
                    .map(|(key, value)| (key.clone(), expand(value, definitions)))
                    .collect(),
            ),
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|value| expand(value, definitions))
                    .collect(),
            ),
            _ => value.clone(),
        }
    }
    let schema: Value = serde_json::from_str(include_str!(
        "../../schemas/progress-panel-config.schema.json"
    ))
    .expect("checked-in config schema");
    expand(&schema, &schema["$defs"])
}
fn definitions() -> Vec<Value> {
    let id = json!({"type":"string","minLength":1,"maxLength":160,"pattern":"^[A-Za-z0-9_.-]+$","not":{"enum":[".",".."]}});
    let revision = json!({"type":"integer","minimum":0});
    let error = object_schema(
        json!({"code":{"type":"string"},"message":{"type":"string"}}),
        &["code", "message"],
    );
    let success = object_schema(
        json!({
            "schema_version":{"type":"integer","const":1},"request_id":{"type":"string"},
            "service_instance_id":{"type":"string"},"revision":{"type":"integer","minimum":0},
            "result":{"type":"object"}
        }),
        &[
            "schema_version",
            "request_id",
            "service_instance_id",
            "revision",
            "result",
        ],
    );
    let service_error = object_schema(
        json!({
            "schema_version":{"type":"integer","const":1},"request_id":{"type":"string"},
            "service_instance_id":{"type":"string"},"revision":{"type":"integer","minimum":0},
            "error":error
        }),
        &[
            "schema_version",
            "request_id",
            "service_instance_id",
            "revision",
            "error",
        ],
    );
    let adapter_error = object_schema(json!({"error":error}), &["error"]);
    // MCP clients may validate structuredContent for both successful and failed calls.
    // Keep adapter failures and versioned service failures explicit and exclusive.
    let output = json!({"type":"object","oneOf":[success,service_error,adapter_error]});
    let specs = [
        (
            "checker_submit_plan",
            "Submit a validated revision-checked plan and record explicit scope history. Never grants command approval.",
            object_schema(
                json!({"config":plan_config_schema(),"reason":{"type":"string","minLength":1,"maxLength":4096},"expected_revision":revision,"expected_config_hash":{"type":"string","pattern":"^sha256:[a-fA-F0-9]{64}$"}}),
                &[
                    "config",
                    "reason",
                    "expected_revision",
                    "expected_config_hash",
                ],
            ),
            false,
        ),
        (
            "checker_get_plan_history",
            "Read a bounded page of recorded plan scope changes.",
            object_schema(
                json!({"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":5}}),
                &["offset", "limit"],
            ),
            true,
        ),
        (
            "checker_get_project",
            "Read project configuration, permissions and shared snapshot identity.",
            object_schema(json!({}), &[]),
            true,
        ),
        (
            "checker_list_milestones",
            "Read milestone definitions, claims and derived verification.",
            object_schema(json!({"scope":{"type":"boolean"}}), &[]),
            true,
        ),
        (
            "checker_set_claim",
            "Set a planned or implemented claim; verification remains derived.",
            object_schema(
                json!({"milestone_id":id,"claim":{"enum":["planned","implemented"]},"note":{"type":"string","maxLength":4096},"expected_revision":revision}),
                &["milestone_id", "claim", "note", "expected_revision"],
            ),
            false,
        ),
        (
            "checker_run_checks",
            "Queue approved checks. A queued run is not passing evidence.",
            object_schema(
                json!({"check_ids":{"type":"array","items":id,"minItems":1,"maxItems":64,"uniqueItems":true},"idempotency_key":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.-]+$","not":{"enum":[".",".."]}},"expected_config_hash":{"type":"string","pattern":"^sha256:[a-fA-F0-9]{64}$"},"expected_revision":revision}),
                &[
                    "check_ids",
                    "idempotency_key",
                    "expected_config_hash",
                    "expected_revision",
                ],
            ),
            false,
        ),
        (
            "checker_get_run",
            "Read run state, outcomes, evidence and freshness.",
            object_schema(json!({"run_id":id}), &["run_id"]),
            true,
        ),
        (
            "checker_get_progress",
            "Read progress and blockers from the shared service snapshot.",
            object_schema(json!({}), &[]),
            true,
        ),
        (
            "checker_get_log",
            "Read one bounded sanitized log chunk. Full logs remain local.",
            object_schema(
                json!({"run_id":id,"check_id":id,"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":32768}}),
                &["run_id", "check_id", "offset", "limit"],
            ),
            true,
        ),
        (
            "checker_cancel_run",
            "Request cancellation of a run, or report an already terminal run.",
            object_schema(
                json!({"run_id":id,"expected_revision":revision}),
                &["run_id", "expected_revision"],
            ),
            false,
        ),
    ];
    specs.into_iter().map(|(name,description,input,read_only)| json!({
        "name":name,"description":description,"inputSchema":input,"outputSchema":output,
        "annotations":{"readOnlyHint":read_only,"destructiveHint":!read_only,"openWorldHint":false}
    })).collect()
}
fn operation(name: &str, mut arguments: Value) -> Result<Operation, String> {
    let variant = match name {
        "checker_submit_plan" => "submit_plan",
        "checker_get_plan_history" => "plan_history",
        "checker_get_project" => "project",
        "checker_list_milestones" => "milestones",
        "checker_set_claim" => "set_claim",
        "checker_run_checks" => "run_checks",
        "checker_get_run" => "get_run",
        "checker_get_progress" => "progress",
        "checker_get_log" => "get_log",
        "checker_cancel_run" => "cancel_run",
        _ => return Err("unknown tool".into()),
    };
    let object = arguments
        .as_object_mut()
        .ok_or("arguments must be an object")?;
    // Serde internally tagged unit variants discard unknown fields. Enforce the
    // discovered tool schema before decoding, including the empty-input tools.
    let definition = definitions()
        .into_iter()
        .find(|tool| tool["name"] == name)
        .ok_or("unknown tool")?;
    let properties = definition["inputSchema"]["properties"]
        .as_object()
        .expect("tool input properties are objects");
    if let Some(key) = object.keys().find(|key| !properties.contains_key(*key)) {
        return Err(format!("unexpected argument {key}"));
    }
    if object.get("scope").is_some_and(|scope| !scope.is_boolean()) {
        return Err("scope must be a boolean".into());
    }
    object.insert("operation".into(), json!(variant));
    let operation: Operation =
        serde_json::from_value(arguments).map_err(|error| error.to_string())?;
    Request {
        schema_version: SCHEMA_VERSION,
        request_id: "mcp-validation".into(),
        operation: operation.clone(),
    }
    .validate()?;
    Ok(operation)
}
/// Consume at most one capped newline frame without allocating for oversized input.
fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unterminated protocol frame",
                ))
            };
        }
        let end = chunk.iter().position(|byte| *byte == b'\n');
        let count = end.map_or(chunk.len(), |index| index + 1);
        if frame.len() + count > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "protocol frame exceeds 256 KiB",
            ));
        }
        frame.extend_from_slice(&chunk[..count]);
        reader.consume(count);
        if end.is_some() {
            return Ok(Some(frame));
        }
    }
}
fn valid_id(value: &Value) -> bool {
    value.as_str().is_some_and(|id| id.len() <= 160)
        || value.as_i64().is_some()
        || value.as_u64().is_some()
}
fn read_only_request(params: &Value) -> Result<bool, &'static str> {
    // Trace and application metadata stays opaque and bounded by the input
    // frame. The native Codex extension can restrict tools, never authorize them.
    let metadata = match params.get("_meta") {
        None | Some(Value::Null) => return Ok(false),
        Some(Value::Object(metadata)) => metadata,
        Some(_) => return Err("Invalid _meta: expected an object or null"),
    };
    match metadata.get("openai/readOnly") {
        None => Ok(false),
        Some(Value::Bool(read_only)) => Ok(*read_only),
        Some(_) => Err("Invalid openai/readOnly metadata: expected a boolean"),
    }
}
async fn dispatch(
    request: Value,
    client: &Client,
    initialized: &mut bool,
    ready: &mut bool,
) -> Option<Value> {
    let id = request.get("id").cloned();
    if request.get("jsonrpc") != Some(&json!("2.0"))
        || !request.is_object()
        || id.as_ref().is_some_and(|id| !valid_id(id))
        || request.get("method").and_then(Value::as_str).is_none()
        || request.as_object().is_some_and(|m| {
            m.keys()
                .any(|k| !["jsonrpc", "id", "method", "params"].contains(&k.as_str()))
        })
    {
        return Some(rpc_error(Value::Null, -32600, "Invalid Request"));
    }
    let method = request["method"].as_str().unwrap();
    if id.is_none() {
        if method == "notifications/initialized" && *initialized {
            *ready = true;
        }
        // Request cancellation never cancels an already returned background run.
        return None;
    }
    let id = id.unwrap();
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    let result = match method {
        "initialize" if !*initialized => {
            if params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .is_none()
                || !params.get("capabilities").is_some_and(Value::is_object)
                || !params.get("clientInfo").is_some_and(|info| {
                    info.get("name").is_some_and(Value::is_string)
                        && info.get("version").is_some_and(Value::is_string)
                })
            {
                return Some(rpc_error(id, -32602, "Invalid initialize parameters"));
            }
            *initialized = true;
            json!({"protocolVersion":PROTOCOL,"capabilities":{"tools":{"listChanged":false}},
                "serverInfo":{"name":"progress-checker","version":env!("CARGO_PKG_VERSION")},
                "instructions":"Claims are not verification. Runs require prior human approval through the local CLI; this adapter cannot approve commands."})
        }
        "ping" => json!({}),
        _ if !*ready => {
            return Some(rpc_error(
                id,
                -32000,
                "Initialize and send notifications/initialized first",
            ));
        }
        "tools/list" => {
            if !params.is_object()
                || params
                    .as_object()
                    .unwrap()
                    .keys()
                    .any(|key| !["_meta", "cursor"].contains(&key.as_str()))
            {
                return Some(rpc_error(id, -32602, "Unsupported tools/list parameters"));
            }
            let read_only = match read_only_request(&params) {
                Ok(read_only) => read_only,
                Err(message) => return Some(rpc_error(id, -32602, message)),
            };
            if let Some(cursor) = params.get("cursor").filter(|cursor| !cursor.is_null()) {
                let Some(cursor) = cursor.as_str() else {
                    return Some(rpc_error(id, -32602, "Invalid tools/list cursor"));
                };
                if !cursor.is_empty() {
                    return Some(rpc_error(
                        id,
                        -32602,
                        "Pagination is unsupported: tools/list returns one complete page",
                    ));
                }
            }
            let tools = definitions()
                .into_iter()
                .filter(|tool| !read_only || tool["annotations"]["readOnlyHint"] == true)
                .collect::<Vec<_>>();
            json!({"tools":tools})
        }
        "tools/call" => {
            if !params.is_object()
                || params
                    .as_object()
                    .unwrap()
                    .keys()
                    .any(|k| !["name", "arguments", "_meta"].contains(&k.as_str()))
            {
                return Some(rpc_error(id, -32602, "Invalid tools/call parameters"));
            }
            let read_only = match read_only_request(&params) {
                Ok(read_only) => read_only,
                Err(message) => return Some(rpc_error(id, -32602, message)),
            };
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let Some(tool) = definitions().into_iter().find(|tool| tool["name"] == name) else {
                return Some(rpc_error(id, -32602, "Unknown tool"));
            };
            if read_only && tool["annotations"]["readOnlyHint"] != true {
                return Some(json!({"jsonrpc":"2.0","id":id,"result":tool_error(
                    "READ_ONLY_REQUEST", "Mutating tools are unavailable for read-only requests"
                )}));
            }
            match operation(
                name,
                params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
            ) {
                Err(error) => tool_error("INVALID_ARGUMENT", &error),
                Ok(operation) => match client.async_call(operation).await {
                    Err(error) => tool_error("SERVICE_UNAVAILABLE", &error),
                    Ok(response) => {
                        let failed = response.error.is_some();
                        tool_result(
                            serde_json::to_value(response).expect("serializable service response"),
                            failed,
                        )
                    }
                },
            }
        }
        _ => return Some(rpc_error(id, -32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = run(cli).await;
    if let Err(error) = result {
        eprintln!("MCP adapter: {error}");
        std::process::exit(1);
    }
}
async fn run(cli: Cli) -> Result<(), String> {
    let client = Client::new(Endpoint::for_root(&cli.root, &cli.state_dir)?);
    let mut reader = io::BufReader::new(io::stdin());
    let mut writer = io::BufWriter::new(io::stdout());
    run_session(&client, &mut reader, &mut writer).await
}
async fn run_session(
    client: &Client,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<(), String> {
    let (mut initialized, mut ready) = (false, false);
    while let Some(frame) = read_frame(reader).map_err(|e| e.to_string())? {
        let response = match serde_json::from_slice(&frame) {
            Ok(request) => dispatch(request, client, &mut initialized, &mut ready).await,
            Err(_) => Some(rpc_error(Value::Null, -32700, "Parse error")),
        };
        if let Some(response) = response {
            let bytes = response_bytes(&response)?;
            writer.write_all(&bytes).map_err(|e| e.to_string())?;
            writer.write_all(b"\n").map_err(|e| e.to_string())?;
            writer.flush().map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capped_frames_and_truncated_frames_are_rejected() {
        assert!(read_frame(&mut io::Cursor::new(vec![b'x'; MAX_FRAME + 1])).is_err());
        assert!(read_frame(&mut io::Cursor::new(b"{}".to_vec())).is_err());
        assert_eq!(
            read_frame(&mut io::Cursor::new(b"{}\n".to_vec())).unwrap(),
            Some(b"{}\n".to_vec())
        );
    }
    #[test]
    fn tool_surface_excludes_approval_and_arbitrary_execution() {
        let tools = definitions();
        assert_eq!(tools.len(), 10);
        for tool in tools {
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
            assert!(tool.get("outputSchema").is_some());
        }
        assert!(operation("checker_approve", json!({})).is_err());
        assert!(operation("checker_run_checks", json!({"argv":["sh"]})).is_err());
        assert!(
            operation(
                "checker_set_claim",
                json!({"milestone_id":"x","claim":"verified","expected_revision":1})
            )
            .is_err()
        );
    }
    #[test]
    fn serialized_text_is_exact_structured_equivalent() {
        let result = tool_result(json!({"revision":3,"verified":0}), false);
        assert_eq!(
            serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap(),
            result["structuredContent"]
        );
        assert_eq!(result["isError"], false);
    }
    #[test]
    fn unreplyable_id_produces_a_bounded_null_id_error() {
        let response = json!({
            "jsonrpc":"2.0", "id":"x".repeat(MAX_FRAME), "result":{}
        });
        let bytes = response_bytes(&response).unwrap();
        assert!(bytes.len() < MAX_FRAME);
        let error: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(error["id"], Value::Null);
        assert_eq!(error["error"]["code"], -32600);
        assert_eq!(
            error["error"]["message"],
            "Request id exceeds the bounded response size"
        );
    }
    #[tokio::test]
    async fn oversized_tool_response_preserves_id_and_session_for_ping() {
        use checker_service::{
            client::{read_frame as read_ipc_frame, write_frame as write_ipc_frame},
            protocol::{MAX_FRAME_BYTES, Response},
        };
        use std::os::unix::{fs::PermissionsExt, net::UnixListener};
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

        struct TestDirectory(PathBuf);
        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = TestDirectory(std::env::temp_dir().join(format!(
            "checker-mcp-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
        std::fs::create_dir(&directory.0).unwrap();
        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = directory.0.join("service.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let service = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "adapter did not call the service"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request: Request =
                serde_json::from_slice(&read_ipc_frame(&mut stream).unwrap()).unwrap();
            assert!(matches!(request.operation, Operation::Project));
            let response = Response {
                schema_version: SCHEMA_VERSION,
                request_id: request.request_id.clone(),
                service_instance_id: "test-service".into(),
                revision: 1,
                result: Some(json!({
                    "config":{"milestones":[{"id":"m","title":"x".repeat(150_000)}]}
                })),
                error: None,
            };
            response.validate(&request.request_id).unwrap();
            let bytes = serde_json::to_vec(&response).unwrap();
            assert!(bytes.len() <= MAX_FRAME_BYTES);
            let expanded = json!({
                "jsonrpc":"2.0", "id":"large", "result":tool_result(
                    serde_json::to_value(&response).unwrap(), false
                )
            });
            assert!(serde_json::to_vec(&expanded).unwrap().len() + 1 > MAX_FRAME);
            write_ipc_frame(&mut stream, &bytes).unwrap();
        });
        let client = Client::new(Endpoint {
            canonical_root: directory.0.clone(),
            socket_path,
        });
        let large_id = "r".repeat(160);
        assert!(valid_id(&json!(large_id)));
        let requests = [
            json!({"jsonrpc":"2.0","id":"init","method":"initialize","params":{
                "protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"test","version":"1"}
            }}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":large_id,"method":"tools/call","params":{
                "name":"checker_get_project","arguments":{},"_meta":{"openai/readOnly":true,"traceparent":"opaque"}
            }}),
            json!({"jsonrpc":"2.0","id":17,"method":"ping"}),
        ];
        let mut input = io::Cursor::new(
            requests
                .iter()
                .map(|request| format!("{request}\n"))
                .collect::<String>()
                .into_bytes(),
        );
        let mut output = Vec::new();
        let result = run_session(&client, &mut input, &mut output).await;
        service.join().unwrap();
        result.unwrap();
        let frames = output
            .split_inclusive(|byte| *byte == b'\n')
            .collect::<Vec<_>>();
        assert_eq!(frames.len(), 3);
        assert!(frames.iter().all(|frame| frame.len() <= MAX_FRAME));
        let responses = frames
            .iter()
            .map(|frame| serde_json::from_slice::<Value>(frame).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses[1]["id"], large_id);
        let error = &responses[1]["result"];
        assert_eq!(error["isError"], true);
        assert_eq!(
            error["structuredContent"]["error"]["code"],
            "RESPONSE_TOO_LARGE"
        );
        assert!(error["structuredContent"]["error"]["message"].is_string());
        assert_eq!(error["structuredContent"].as_object().unwrap().len(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(error["content"][0]["text"].as_str().unwrap()).unwrap(),
            error["structuredContent"]
        );
        assert_eq!(responses[2], json!({"jsonrpc":"2.0","id":17,"result":{}}));
    }
    #[tokio::test]
    async fn lifecycle_negotiates_legacy_and_never_calls_service_before_ready() {
        let client = Client::new(Endpoint {
            canonical_root: PathBuf::from("/unused"),
            socket_path: PathBuf::from("/unused.sock"),
        });
        let (mut initialized, mut ready) = (false, false);
        let early = dispatch(
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            &client,
            &mut initialized,
            &mut ready,
        )
        .await
        .unwrap();
        assert_eq!(early["error"]["code"], -32000);
        let init = dispatch(json!({"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),&client,&mut initialized,&mut ready).await.unwrap();
        assert_eq!(init["result"]["protocolVersion"], PROTOCOL);
        assert!(!ready);
        assert!(
            dispatch(
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                &client,
                &mut initialized,
                &mut ready
            )
            .await
            .is_none()
        );
        assert!(ready);
        let tools = dispatch(
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            &client,
            &mut initialized,
            &mut ready,
        )
        .await
        .unwrap();
        assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 10);
        let bad = dispatch(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"checker_run_checks","arguments":{"argv":["sh"]}}}),&client,&mut initialized,&mut ready).await.unwrap();
        assert_eq!(bad["result"]["isError"], true);
        assert_eq!(
            bad["result"]["structuredContent"]["error"]["code"],
            "INVALID_ARGUMENT"
        );
    }
    #[tokio::test]
    async fn native_tools_list_metadata_discovers_complete_or_read_only_page() {
        let client = Client::new(Endpoint {
            canonical_root: PathBuf::from("/unused"),
            socket_path: PathBuf::from("/unused.sock"),
        });
        let native_metadata = json!({
            "traceparent":"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            "tracestate":"vendor=value", "openai/readOnly":true, "application":"preserved"
        });
        let requests = [
            json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
                "protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"codex","version":"0.160.0"}
            }}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":native_metadata}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"_meta":null,"cursor":null}}),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"_meta":{"traceparent":"opaque"},"cursor":""}}),
            json!({"jsonrpc":"2.0","id":5,"method":"tools/list","params":{"_meta":{"openai/readOnly":false}}}),
            json!({"jsonrpc":"2.0","id":6,"method":"ping"}),
        ];
        let mut input = io::Cursor::new(
            requests
                .iter()
                .map(|request| format!("{request}\n"))
                .collect::<String>()
                .into_bytes(),
        );
        let mut output = Vec::new();
        run_session(&client, &mut input, &mut output).await.unwrap();
        let responses = output
            .split_inclusive(|byte| *byte == b'\n')
            .map(|frame| {
                assert!(frame.len() <= MAX_FRAME);
                serde_json::from_slice::<Value>(frame).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 7);
        for index in [1, 3, 4, 5] {
            assert_eq!(responses[index]["result"]["tools"], json!(definitions()));
            assert!(responses[index]["result"].get("nextCursor").is_none());
        }
        let read_only = responses[2]["result"]["tools"].as_array().unwrap();
        assert_eq!(
            read_only
                .iter()
                .map(|tool| tool["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "checker_get_plan_history",
                "checker_get_project",
                "checker_list_milestones",
                "checker_get_run",
                "checker_get_progress",
                "checker_get_log",
            ]
        );
        assert!(
            read_only
                .iter()
                .all(|tool| tool["annotations"]["readOnlyHint"] == true)
        );
        assert!(responses[2]["result"].get("nextCursor").is_none());
        assert_eq!(responses[6], json!({"jsonrpc":"2.0","id":6,"result":{}}));
    }
    #[tokio::test]
    async fn tools_list_rejects_unknown_keys_and_unsupported_cursors() {
        let client = Client::new(Endpoint {
            canonical_root: PathBuf::from("/unused"),
            socket_path: PathBuf::from("/unused.sock"),
        });
        let (mut initialized, mut ready) = (true, true);
        for params in [
            json!([]),
            json!({"root":"/another-project"}),
            json!({"cursor":true}),
            json!({"cursor":"page-two"}),
        ] {
            let response = dispatch(
                json!({"jsonrpc":"2.0","id":"invalid-list","method":"tools/list","params":params}),
                &client,
                &mut initialized,
                &mut ready,
            )
            .await
            .unwrap();
            assert_eq!(response["id"], "invalid-list");
            assert_eq!(response["error"]["code"], -32602);
            if params["cursor"] == "page-two" {
                assert!(
                    response["error"]["message"]
                        .as_str()
                        .unwrap()
                        .contains("Pagination")
                );
            }
        }
        for metadata in [
            json!([]),
            json!(false),
            json!({"openai/readOnly":"true"}),
            json!({"openai/readOnly":null}),
        ] {
            for method in ["tools/list", "tools/call"] {
                let mut params = json!({"_meta":metadata});
                if method == "tools/call" {
                    params["name"] = json!("checker_get_progress");
                    params["arguments"] = json!({});
                }
                let response = dispatch(
                    json!({"jsonrpc":"2.0","id":"invalid-metadata","method":method,"params":params}),
                    &client, &mut initialized, &mut ready,
                ).await.unwrap();
                assert_eq!(response["error"]["code"], -32602);
            }
        }
    }
    #[tokio::test]
    async fn read_only_tool_calls_reject_every_mutation_before_service_io() {
        let client = Client::new(Endpoint {
            canonical_root: PathBuf::from("/unused"),
            socket_path: PathBuf::from("/unused.sock"),
        });
        let (mut initialized, mut ready) = (true, true);
        for (name, arguments) in [
            (
                "checker_submit_plan",
                json!({"config":serde_json::from_str::<Value>(include_str!("../../checker-core/examples/config.json")).unwrap(),"reason":"reviewed scope update","expected_revision":1,"expected_config_hash":format!("sha256:{}","a".repeat(64))}),
            ),
            (
                "checker_set_claim",
                json!({"milestone_id":"m","claim":"implemented","note":"","expected_revision":1}),
            ),
            (
                "checker_run_checks",
                json!({"check_ids":["c"],"idempotency_key":"once","expected_config_hash":format!("sha256:{}","a".repeat(64)),"expected_revision":1}),
            ),
            (
                "checker_cancel_run",
                json!({"run_id":"run-one","expected_revision":1}),
            ),
        ] {
            assert!(operation(name, arguments.clone()).is_ok());
            let response = dispatch(
                json!({"jsonrpc":"2.0","id":name,"method":"tools/call","params":{
                    "name":name,"arguments":arguments,"_meta":{"openai/readOnly":true,"traceparent":"opaque"}
                }}), &client, &mut initialized, &mut ready,
            ).await.unwrap();
            assert_eq!(response["id"], name);
            assert_eq!(response["result"]["isError"], true);
            assert_eq!(
                response["result"]["structuredContent"]["error"]["code"],
                "READ_ONLY_REQUEST"
            );
        }
    }
    #[test]
    fn every_tool_rejects_unknown_keys_before_deserialization() {
        for tool in definitions() {
            let name = tool["name"].as_str().unwrap();
            let error = operation(name, json!({"injected":"unexpected"})).unwrap_err();
            assert_eq!(error, "unexpected argument injected", "{name}");
        }
        assert!(operation("checker_get_project", json!({})).is_ok());
        assert!(operation("checker_get_progress", json!({})).is_ok());
        assert!(operation("checker_list_milestones", json!({"scope":null})).is_err());
        assert!(operation("checker_list_milestones", json!({"scope":true})).is_ok());
    }
}
