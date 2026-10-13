//! One-request protected native pipe bridge; not wired into activation.
//! It is deliberately read-only until the native writer and authority contract
//! are qualified. It does not expose approval or check-execution operations.
use serde_json::{Value, json};
const MAX: usize = 256 * 1024;

fn validate_public_request(bytes: &[u8]) -> Result<Value, String> {
    if bytes.is_empty() || bytes.len() > MAX {
        return Err("Native bridge request exceeds bounded public frame".into());
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let object = value
        .as_object()
        .ok_or("Native bridge request must be an object")?;
    if object.len() != 2 || !object.contains_key("operation") || !object.contains_key("request_id")
    {
        return Err("Native bridge accepts only operation and request_id".into());
    }
    let id = value["request_id"]
        .as_str()
        .ok_or("Native bridge request id must be text")?;
    if id.is_empty() || id.len() > 160 {
        return Err("Native bridge request id exceeds limit".into());
    }
    match value["operation"].as_str() {
        Some("describe_platform") | Some("ping") => Ok(value),
        _ => Err("Native bridge activation, approvals and checks are unavailable".into()),
    }
}

#[cfg(windows)]
#[allow(dead_code)]
pub fn serve_one(suffix: &str, timeout_ms: u32) -> Result<(), String> {
    use checker_core::platform::windows_ipc::BoundedPipeServer;
    let server = BoundedPipeServer::create(suffix)?;
    let (connection, bytes) = server.accept_request(timeout_ms)?;
    connection.recheck()?;
    let request = validate_public_request(&bytes)?;
    let response = json!({"request_id": request["request_id"], "result": {
        "native_writer_activated": false,
        "qualified": false,
        "approval_supported": false,
        "checks_supported": false,
        "protocol": "native-gateway-public-v1"
    }});
    let bytes = serde_json::to_vec(&response).map_err(|error| error.to_string())?;
    if bytes.len() > MAX {
        return Err("Native bridge response exceeds limit".into());
    }
    connection.recheck()?;
    connection.reply(&bytes, timeout_ms)
}

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn serve_one(_suffix: &str, _timeout_ms: u32) -> Result<(), String> {
    Err("Native protected pipe bridge requires Windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_pipe_rejects_approval_and_execution() {
        for operation in [
            "approval_commit",
            "approval_challenge",
            "run_checks",
            "track_project",
        ] {
            assert!(
                validate_public_request(
                    json!({"operation":operation,"request_id":"test"})
                        .to_string()
                        .as_bytes()
                )
                .is_err()
            );
        }
        assert!(
            validate_public_request(b"{\"operation\":\"ping\",\"request_id\":\"test\"}").is_ok()
        );
        assert!(
            validate_public_request(
                b"{\"operation\":\"ping\",\"request_id\":\"test\",\"approved\":true}"
            )
            .is_err()
        );
    }
}

/// Development-only symmetric peer inspection. Does not activate a writer.
#[cfg(windows)]
#[allow(dead_code)]
pub fn inspect_peer(
    suffix: &str,
    expected_server_image: &std::path::Path,
    request_id: &str,
    timeout_ms: u32,
) -> Result<Value, String> {
    use checker_core::platform::windows_ipc::VerifiedPipeClient;
    let request = serde_json::to_vec(&json!({
        "operation": "describe_platform", "request_id": request_id
    }))
    .map_err(|error| error.to_string())?;
    validate_public_request(&request)?;
    let client = VerifiedPipeClient::connect(suffix, expected_server_image, timeout_ms)?;
    let bytes = client.exchange(&request, timeout_ms)?;
    if bytes.len() > MAX {
        return Err("Native peer inspection reply exceeds bound".into());
    }
    let response: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let object = response
        .as_object()
        .ok_or("Invalid peer inspection reply")?;
    let result = response["result"]
        .as_object()
        .ok_or("Invalid peer capability object")?;
    if object.len() != 2
        || response["request_id"].as_str() != Some(request_id)
        || result.len() != 5
        || response["result"]["protocol"] != "native-gateway-public-v1"
        || response["result"]["native_writer_activated"] != false
        || response["result"]["qualified"] != false
        || response["result"]["approval_supported"] != false
        || response["result"]["checks_supported"] != false
    {
        return Err("Unsupported native peer capabilities; activation remains disabled".into());
    }
    Ok(response)
}
