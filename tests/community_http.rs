#![cfg(feature = "development-gate")]
mod support;
use cmnt::cplc;
use cvld::api::*;
use serde_json::{Value, json};
use support::*;

fn verified_feed(
    feed: &TrustFeed,
    community: &str,
    now: u64,
) -> cplc::Snapshot<cmnt::cplc::crbk::Values> {
    let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
    let manifest = ring
        .verify(&feed.manifest, csgn::Kind::SettingsSnapshot, now)
        .unwrap();
    let manifest: cplc::TrustManifest = serde_json::from_slice(manifest.payload()).unwrap();
    assert_eq!(manifest.community, community);
    assert_eq!(manifest.revision, feed.revision);
    assert_eq!(manifest.policy_epoch, feed.policy_epoch);
    assert_eq!(manifest.key_ring, feed.key_ring);
    for (kind, bytes) in [
        (cplc::SnapshotKind::Schema, &feed.schema),
        (cplc::SnapshotKind::Communities, &feed.communities),
        (cplc::SnapshotKind::RevocationList, &feed.revocations),
    ] {
        let _: cplc::Snapshot<Value> = cplc::verify_snapshot(
            &ring,
            bytes,
            cplc::SnapshotExpectation {
                community,
                kind,
                minimum_revision: 1,
                policy_epoch: feed.policy_epoch,
                now,
            },
        )
        .unwrap();
    }
    cplc::verify_snapshot(
        &ring,
        &feed.settings,
        cplc::SnapshotExpectation {
            community,
            kind: cplc::SnapshotKind::Settings,
            minimum_revision: 1,
            policy_epoch: feed.policy_epoch,
            now,
        },
    )
    .unwrap()
}
#[tokio::test(flavor = "multi_thread")]
async fn two_communities_admission_policy_lapse_and_release_over_http() {
    let global = global(100).await;
    let (wallet, passport, public) = wallet_passport(&global).await;
    let alpha = community("alpha", &public).await;
    let beta = community("beta", &public).await;
    let mut foreign_database =
        cvld::config::CommunityConfig::read(beta.dir.path().join("config.json").to_str().unwrap())
            .unwrap();
    foreign_database.database_url =
        format!("file://{}", alpha.dir.path().join("community.db").display());
    assert!(
        cvld::service::Door::community(foreign_database, beta.clock.clone())
            .await
            .is_err()
    );
    let ah = "api.alpha.example.test";
    let bh = "api.beta.example.test";
    let a = enrol_community(&alpha, ah, &passport).await;
    let b = enrol_community(&beta, bh, &passport).await;
    let ac = client(&alpha, ah, Some(&a.session));
    let bc = client(&beta, bh, Some(&b.session));
    let mut ids = Vec::new();
    for (service, host, name, member, client) in
        [(&alpha, ah, "alpha", &a, &ac), (&beta, bh, "beta", &b, &bc)]
    {
        assert_eq!(
            call_status(service, host, Some(&wallet.session), "lobby", json!({})).await,
            401
        );
        assert_eq!(
            call_status(
                service,
                host,
                Some(&member.session),
                "passport_issue",
                json!({})
            )
            .await,
            421
        );
        assert_eq!(
            call_status(
                &global,
                WALLET,
                Some(&wallet.session),
                "credential_issue",
                json!({})
            )
            .await,
            421
        );
        let lobby: Lobby =
            serde_json::from_value(client.call("lobby", json!({})).await.unwrap()).unwrap();
        let expected = passport
            .pseudonym(&cpsd::CommunityId::new(name.as_bytes()).unwrap())
            .to_hex();
        assert_eq!(lobby.member_id, expected);
        assert_ne!(lobby.member_id, wallet.user);
        ids.push(lobby.member_id);
        assert!(
            client
                .call("handle_reserve", json!({"handle":"admin"}))
                .await
                .is_err()
        );
        client
            .call("handle_reserve", json!({"handle":"member_one"}))
            .await
            .unwrap();
        assert!(
            issue_community(service, host, member, &passport)
                .await
                .credential
                .is_none()
        );
        let sealed = cmnt::cmbr::PinV2::seal(
            &cpns::FingerprintContext {
                community: name,
                member: &expected,
                field: "restricted",
            },
            b"true",
            &cpns::Salt::from_bytes(vec![11u8; 32]).unwrap(),
        );
        client
            .call("pin_set", json!({"field":"restricted","pin":sealed}))
            .await
            .unwrap();
        let pin: PinResponse = serde_json::from_value(
            client
                .call("pin_get", json!({"field":"restricted"}))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(pin.pin.unwrap().revision, 1);
        let changed_pin = cmnt::cmbr::PinV2::seal(
            &cpns::FingerprintContext {
                community: name,
                member: &expected,
                field: "restricted",
            },
            b"false",
            &cpns::Salt::from_bytes(vec![12u8; 32]).unwrap(),
        );
        assert!(
            client
                .call(
                    "pin_change",
                    json!({"field":"restricted","pin":changed_pin,"evidence":[]})
                )
                .await
                .is_err()
        );
        let unchanged: PinResponse = serde_json::from_value(
            client
                .call("pin_get", json!({"field":"restricted"}))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(unchanged.pin.unwrap().revision, 1);
        let body = voucher(name, &expected, "synthetic-voucher", NOW + 172800);
        client.call("gate_voucher", body.clone()).await.unwrap();
        assert!(client.call("gate_voucher", body).await.is_err());
        let issued = issue_community(service, host, member, &passport).await;
        assert_eq!(issued.lobby.state, "admitted");
        let feed: TrustFeed =
            serde_json::from_value(client.call("trust_feed", json!({})).await.unwrap()).unwrap();
        verified_feed(&feed, name, NOW);
        let ring = csgn::KeyRing::from_cbor(&feed.key_ring).unwrap();
        let verified = ring
            .verify(&issued.credential.unwrap(), csgn::Kind::Credential, NOW)
            .unwrap();
        let credential: cplc::Credential = serde_json::from_slice(verified.payload()).unwrap();
        assert_eq!(credential.member, expected);
        assert_eq!(credential.community, name);
        assert_eq!(credential.policy_epoch, feed.policy_epoch);
        assert_eq!(credential.pins.len(), 1);
    }
    assert_ne!(ids[0], ids[1]);
    assert_ne!(a.user, b.user);
    assert_eq!(
        call_status(&alpha, bh, Some(&a.session), "lobby", json!({})).await,
        421
    );
    assert_eq!(
        call_status(&beta, bh, Some(&a.session), "lobby", json!({})).await,
        401
    );
    assert_eq!(
        call_status(
            &alpha,
            ah,
            Some(&a.session),
            "setting_set",
            json!({"key":"quota","value":5,"inherit":false,"effective_at":NOW+1})
        )
        .await,
        403
    );
    let admin_host = "api.admin.alpha.example.test";
    let admin = enrol(
        &alpha,
        admin_host,
        Some("synthetic-admin-enrolment-capability"),
    )
    .await;
    let admin_client = client(&alpha, admin_host, Some(&admin.session));
    let before: TrustFeed =
        serde_json::from_value(ac.call("trust_feed", json!({})).await.unwrap()).unwrap();
    let watcher = client(&alpha, ah, None);
    let revision = before.revision;
    let watch = tokio::spawn(async move {
        watcher
            .call("trust_changes", json!({"revision":revision}))
            .await
            .unwrap()
    });
    alpha.clock.set(NOW + 1);
    let after: TrustFeed = serde_json::from_value(
        admin_client
            .call(
                "setting_set",
                json!({"key":"quota","value":5,"inherit":false,"effective_at":NOW+1}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(after.policy_epoch > before.policy_epoch);
    assert!(after.revision > before.revision);
    assert_ne!(after.settings, before.settings);
    assert_eq!(verified_feed(&after, "alpha", NOW + 1).content["quota"], 5);
    let changed: Announcement = serde_json::from_value(watch.await.unwrap()).unwrap();
    assert!(changed.changed);
    assert_eq!(changed.revision, after.revision);
    assert!(admin_client.call("platform_set",json!({"setting":{"key":"quota","value":3,"inherit":false,"effective_at":NOW+2},"force":true})).await.is_err());
    let root = enrol(&alpha, ROOT, Some("synthetic-root-enrolment-capability")).await;
    let root_client = client(&alpha, ROOT, Some(&root.session));
    alpha.clock.set(NOW + 2);
    root_client.call("platform_set",json!({"setting":{"key":"quota","value":3,"inherit":false,"effective_at":NOW+2},"force":true})).await.unwrap();
    alpha.clock.set(NOW + 3);
    let forced: TrustFeed = serde_json::from_value(
        admin_client
            .call(
                "setting_set",
                json!({"key":"quota","value":8,"inherit":false,"effective_at":NOW+3}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(verified_feed(&forced, "alpha", NOW + 3).content["quota"], 3);
    let schema = community_schema("alpha", 2);
    admin_client
        .call("schema_check", json!({"schema":schema}))
        .await
        .unwrap();
    admin_client
        .call("schema_set", json!({"schema":schema}))
        .await
        .unwrap();
    let live = issue_community(&alpha, ah, &a, &passport).await;
    assert!(live.credential.is_some());
    let before_withdraw: TrustFeed =
        serde_json::from_value(ac.call("trust_feed", json!({})).await.unwrap()).unwrap();
    let proof = presentation(&alpha, ah, Some(&a.session), &passport).await;
    let lapsed: CredentialResponse = serde_json::from_value(ac.call("gate_withdraw", json!({
        "gate":"cvch", "provider":"sponsor", "credential":{"presentation":proof,"devices":vec![[42u8;32]]}
    })).await.unwrap()).unwrap();
    assert!(lapsed.credential.is_none());
    assert_eq!(lapsed.lobby.state, "lapsed");
    let lapsed_feed: TrustFeed =
        serde_json::from_value(ac.call("trust_feed", json!({})).await.unwrap()).unwrap();
    assert!(lapsed_feed.policy_epoch > before_withdraw.policy_epoch);
    // A failed gate is recoverable; an epoch invalidation must not become a permanent ban.
    ac.call(
        "gate_voucher",
        voucher("alpha", &ids[0], "replacement-voucher", NOW + 172800),
    )
    .await
    .unwrap();
    assert!(
        issue_community(&alpha, ah, &a, &passport)
            .await
            .credential
            .is_some()
    );
    assert!(
        !serde_json::from_value::<Available>(
            ac.call("handle_available", json!({"handle":"member_one"}))
                .await
                .unwrap()
        )
        .unwrap()
        .available
    );
    ac.call("passkey_revoke", json!({"credential":a.credential}))
        .await
        .unwrap();
    assert_eq!(
        call_status(&alpha, ah, Some(&a.session), "lobby", json!({})).await,
        401
    );
    alpha.clock.set(NOW + 3 * 366 * 86400);
    alpha.door.maintain().await.unwrap();
    assert!(
        serde_json::from_value::<Available>(
            client(&alpha, ah, None)
                .call("handle_available", json!({"handle":"member_one"}))
                .await
                .unwrap()
        )
        .unwrap()
        .available
    );
    // Accidentally assigning the global database to a community fails migration
    // validation; a process cannot silently acquire the other service's tables.
    let mut overlapping =
        cvld::config::CommunityConfig::read(alpha.dir.path().join("config.json").to_str().unwrap())
            .unwrap();
    overlapping.database_url = format!("file://{}", global.dir.path().join("global.db").display());
    assert!(
        cvld::service::Door::community(overlapping, global.clock.clone())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn community_public_and_expensive_actions_have_aggregate_quotas() {
    let global = global(100).await;
    let public: GlobalPublic = serde_json::from_value(
        client(&global, WALLET, None)
            .call("global_public", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let community = community_with_burst("quota", &public, 1).await;
    let host = "api.quota.example.test";
    for (action, body) in [
        ("handle_available", json!({"handle":"available_one"})),
        ("register_begin", json!({})),
        ("presentation_challenge", json!({})),
    ] {
        assert_ne!(
            call_status(&community, host, None, action, body.clone()).await,
            429
        );
        assert_eq!(call_status(&community, host, None, action, body).await, 429);
    }
}
