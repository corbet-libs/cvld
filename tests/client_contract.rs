#![cfg(feature = "development-gate")]
mod support;

use cvld::{client::{Client, HttpClient, action, contract}, error::Error};
use serde_json::json;
use support::*;

#[tokio::test(flavor = "multi_thread")]
async fn generated_client_forwards_real_public_member_and_root_calls() {
    let service = global(100).await;
    let mut public = Client::new(HttpClient::new(service.base.clone(), WALLET.into(), None).unwrap());
    let metadata = action("global_public").unwrap();
    assert_eq!(metadata.path(), "/v1/global_public");
    assert_eq!(metadata.schema()["x-role"], "public");
    assert_eq!(contract()["info"]["title"], "cvld");
    assert!(public.call("global_public", json!({})).await.unwrap()["issuer"].is_array());
    assert!(matches!(public.call("passport_challenge", json!({})).await, Err(Error::Unauthorized)));
    assert!(matches!(public.call("../global_public", json!({})).await, Err(Error::Invalid)));
    assert!(action("").is_none());
    let member = enrol(&service, WALLET, None).await;
    let mut member = Client::new(HttpClient::new(service.base.clone(), WALLET.into(), Some(member.session)).unwrap());
    assert!(member.call("passport_challenge", json!({})).await.is_ok());
    assert!(matches!(member.call("suspend", json!({"user":"wrong","until":NOW + 1})).await, Err(Error::Forbidden)));
    let root = enrol(&service, ROOT, Some("synthetic-operator-enrolment-capability")).await;
    let mut root = Client::new(HttpClient::new(service.base.clone(), ROOT.into(), Some(root.session)).unwrap());
    root.call("logout", json!({})).await.unwrap();
    assert!(matches!(root.call("logout", json!({})).await, Err(Error::Unauthorized)));
    assert!(matches!(HttpClient::new("https://wallet.example.test".into(), "wrong.example.test".into(), None), Err(Error::WrongHost)));
}
