#![cfg(feature = "development-gate")]
mod support;
use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::json;
use support::*;
use tokio::process::Command;

#[tokio::test(flavor = "multi_thread")]
async fn cli_and_official_mcp_client_call_the_running_http_service() {
    let service = global(100).await;
    let member = enrol(&service, WALLET, None).await;
    let session_path = service.dir.path().join("session");
    std::fs::write(&session_path, member.session).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_cvld"));
    command
        .args(["--url", &service.base, "--host", WALLET, "--session-file"])
        .arg(&session_path)
        .args(["development_gate", "--request", "{}"]);
    let output = command.output().await.unwrap();
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        json!({})
    );
    assert!(output.stderr.is_empty());
    let mut command = Command::new(env!("CARGO_BIN_EXE_cvld"));
    command
        .args(["--url", &service.base, "--host", WALLET, "--session-file"])
        .arg(&session_path)
        .arg("mcp");
    let transport = TokioChildProcess::new(command).unwrap();
    let mcp = ().serve(transport).await.unwrap();
    let tools = mcp.list_all_tools().await.unwrap();
    assert_eq!(tools.len(), cvld::api::ACTIONS.len());
    let result = mcp
        .call_tool(
            CallToolRequestParams::new("passport_challenge").with_arguments(serde_json::Map::new()),
        )
        .await
        .unwrap();
    assert_ne!(result.is_error, Some(true));
    let challenge: cvld::api::Bytes = result.into_typed().unwrap();
    assert_eq!(challenge.bytes.len(), 32);
    let rejected = mcp
        .call_tool(
            CallToolRequestParams::new("global_warn")
                .with_arguments(json!({"user":"opaque"}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    assert_eq!(rejected.is_error, Some(true));
    mcp.cancel().await.unwrap();
}
