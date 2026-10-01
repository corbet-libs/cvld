//! Real native door behind the ephemeral browser-test TLS endpoint.
#[path = "mod.rs"]
mod support;
use serde_json::json;
use support::*;

#[tokio::main]
async fn main() {
    let path = std::env::args().nth(1).expect("fixture output path");
    let service = global(200).await;
    let member = enrol(&service, WALLET, None).await;
    client(&service, WALLET, Some(&member.session))
        .call("development_gate", json!({}))
        .await
        .unwrap();
    let data = json!({ "upstream": service.base, "session": member.session });
    std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    tokio::signal::ctrl_c().await.unwrap();
}
