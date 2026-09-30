#![cfg(feature = "development-gate")]
mod support;
use cglb::{cpsd, csgn};
use cvld::api::*;
use serde_json::json;
use support::*;

#[tokio::test(flavor = "multi_thread")]
async fn wallet_passkey_blind_passport_and_host_role_boundaries() {
    let service = global(100).await;
    let member = enrol(&service, WALLET, None).await;
    let client = client(&service, WALLET, Some(&member.session));
    client.call("development_gate", json!({})).await.unwrap();
    let public: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    let ring = csgn::KeyRing::from_cbor(&public.key_ring).unwrap();
    let signed = ring
        .verify(&public.status, csgn::Kind::RevocationListSnapshot, NOW)
        .unwrap();
    let status: cglb::Status = serde_json::from_slice(signed.payload()).unwrap();
    assert_eq!(status.epoch, 1);
    let issuer = cpsd::IssuerPublicKey::from_bytes(&public.issuer).unwrap();
    let mut rng = cpsd::rand::rngs::OsRng;
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let challenge: Bytes =
        serde_json::from_value(client.call("passport_challenge", json!({})).await.unwrap())
            .unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
    let (request, pending) = cpsd::request_issue(&mut rng, &secret, &issuer, &challenge).unwrap();
    let body = json!({"challenge":challenge.to_bytes().to_vec(), "request":request.to_bytes()});
    let issued: Bytes =
        serde_json::from_value(client.call("passport_issue", body.clone()).await.unwrap()).unwrap();
    let passport = pending
        .finish(&cpsd::BlindPassport::from_bytes(&issued.bytes).unwrap())
        .unwrap();
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&member.session),
            "passport_issue",
            body
        )
        .await,
        409
    );
    let mut pseudonyms = Vec::new();
    for name in ["community-a", "community-b"] {
        let request = cpsd::PresentationRequest::for_epoch(
            &mut rng,
            cpsd::CommunityId::new(name.as_bytes()).unwrap(),
            1,
            [cpsd::GateId::new("development").unwrap()],
            NOW,
            status.shared_expiry,
        )
        .unwrap();
        let proof = passport.present(&mut rng, &request).unwrap();
        pseudonyms
            .push(cpsd::verify(&mut rng, std::slice::from_ref(&issuer), &request, &proof).unwrap());
    }
    assert_ne!(pseudonyms[0], pseudonyms[1]);
    assert_eq!(
        call_status(
            &service,
            ROOT,
            Some(&member.session),
            "global_warn",
            json!({"user":member.user})
        )
        .await,
        401
    );
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&member.session),
            "global_warn",
            json!({"user":member.user})
        )
        .await,
        403
    );
    assert_eq!(
        call_status(
            &service,
            "api.community-a.example.test",
            Some(&member.session),
            "passport_challenge",
            json!({})
        )
        .await,
        421
    );
    assert_eq!(
        call_status(&service, WALLET, None, "passport_challenge", json!({})).await,
        401
    );
    let root = enrol(
        &service,
        ROOT,
        Some("synthetic-operator-enrolment-capability"),
    )
    .await;
    let root_client = support::client(&service, ROOT, Some(&root.session));
    assert!(
        root_client
            .call(
                "global_suspend",
                json!({"user":member.user,"until":NOW+600})
            )
            .await
            .is_err()
    );
    root_client
        .call("global_warn", json!({"user":member.user}))
        .await
        .unwrap();
    root_client
        .call(
            "global_suspend",
            json!({"user":member.user,"until":NOW+600}),
        )
        .await
        .unwrap();
    let changed: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    let signed = ring
        .verify(&changed.status, csgn::Kind::RevocationListSnapshot, NOW)
        .unwrap();
    let changed: cglb::Status = serde_json::from_slice(signed.payload()).unwrap();
    assert_eq!(changed.epoch, 2);
    assert!(client.call("passport_challenge", json!({})).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn throttle_is_aggregate_and_sessions_expire() {
    let service = global(2).await;
    assert_eq!(
        call_status(&service, WALLET, None, "global_public", json!({})).await,
        200
    );
    assert_eq!(
        call_status(&service, WALLET, None, "global_public", json!({})).await,
        200
    );
    assert_eq!(
        call_status(&service, WALLET, None, "global_public", json!({})).await,
        429
    );
    let member = enrol(&service, WALLET, None).await;
    service.clock.set(NOW + 601);
    assert_eq!(
        call_status(
            &service,
            WALLET,
            Some(&member.session),
            "passport_challenge",
            json!({})
        )
        .await,
        401
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_requires_user_verification_and_ceremonies_are_single_use() {
    use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};
    let service = global(30).await;
    let client = client(&service, WALLET, None);
    let start: Ceremony =
        serde_json::from_value(client.call("register_begin", json!({})).await.unwrap()).unwrap();
    let mut challenge: cpky::CreationChallengeResponse =
        serde_json::from_value(start.options).unwrap();
    // A hostile client weakens the browser option. The server's pending policy remains Required.
    let mut wire = serde_json::to_value(&challenge).unwrap();
    wire["publicKey"]["authenticatorSelection"]["userVerification"] = json!("discouraged");
    challenge = serde_json::from_value(wire).unwrap();
    let mut authenticator = SoftToken::new(false).unwrap().0;
    let credential = authenticator
        .perform_register(
            cpky::Url::parse(&format!("https://{WALLET}")).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    let request = json!({"ceremony":start.ceremony,"credential":credential});
    assert_eq!(
        call_status(&service, WALLET, None, "register_finish", request.clone()).await,
        409
    );
    assert_eq!(
        call_status(&service, WALLET, None, "register_finish", request).await,
        401
    );
}
