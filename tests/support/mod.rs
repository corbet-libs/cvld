#![allow(dead_code)]
use cvld::{
    api::*,
    cli::Client,
    config::Config,
    service::{Clock, Door},
};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

pub const NOW: u64 = 1_800_000_000;
pub const DOMAIN: &str = "example.test";
pub const WALLET: &str = "wallet.example.test";
pub const ROOT: &str = "api.root.example.test";
pub struct TestClock(pub AtomicU64);
impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
impl TestClock {
    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}
pub struct Running {
    pub base: String,
    pub door: Door,
    pub clock: Arc<TestClock>,
    pub task: tokio::task::JoinHandle<()>,
    pub dir: tempfile::TempDir,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn write(dir: &Path, name: &str, bytes: &[u8]) -> String {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path.to_str().unwrap().to_owned()
}
pub async fn global(burst: u32) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let mut rng = cpsd::rand::rngs::OsRng;
    let issuer = cpsd::IssuerKey::generate(
        &mut rng,
        cpsd::KeyId::new("global-test").unwrap(),
        vec![cpsd::GateId::new("development").unwrap()],
    )
    .unwrap();
    let policy = cglb::Policy {
        version: 1,
        scope: "global".into(),
        revision: 1,
        epoch: 1,
        shared_expiry: (NOW / 86_400 + 40) * 86_400,
        gates: vec![cglb::GatePolicy {
            gate: "development".into(),
            provider: "cglb.test".into(),
            uniqueness: true,
        }],
    };
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "policy-authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        NOW - 1,
        86_400 * 100,
    )
    .await
    .unwrap();
    let signed = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&policy).unwrap(),
            NOW,
            policy.shared_expiry + 1,
        )
        .await
        .unwrap();
    let config = Config {
        listen: "127.0.0.1:0".into(),
        domain: DOMAIN.into(),
        database_url: format!("file://{}", dir.path().join("global.db").display()),
        database_token_file: None,
        signing_seed_file: write(dir.path(), "signer", &[4; 32]),
        issuer_key_file: write(dir.path(), "issuer", &issuer.to_secret_bytes()),
        uniqueness_key_file: write(dir.path(), "unique", &[5; 32]),
        policy_file: write(dir.path(), "policy", &signed),
        policy_authority_file: write(
            dir.path(),
            "authority",
            &authority.key_ring().unwrap().to_cbor(),
        ),
        root_user: "00000000-0000-4000-8000-000000000001".into(),
        root_bootstrap_file: Some(write(
            dir.path(),
            "bootstrap",
            b"synthetic-operator-enrolment-capability",
        )),
        session_seconds: 600,
        pending_capacity: 100,
        throttle_burst: burst,
        throttle_interval_ms: 60_000,
        publication_seconds: 172800,
        signer_max_seconds: 86_400 * 100,
        development: true,
    };
    let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
    let door = Door::global(config, clock.clone()).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = cvld::api::router(door.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Running {
        base,
        door,
        clock,
        task,
        dir,
    }
}
pub fn client(service: &Running, host: &str, token: Option<&str>) -> Client {
    Client::new(service.base.clone(), host.into(), token.map(str::to_owned)).unwrap()
}
pub struct Member {
    pub authenticator: SoftToken,
    pub user: String,
    pub credential: Vec<u8>,
    pub session: String,
}
pub async fn enrol(service: &Running, host: &str, bootstrap: Option<&str>) -> Member {
    let client = client(service, host, None);
    let start: Ceremony = serde_json::from_value(
        client
            .call(
                "register_begin",
                json!({"bootstrap":bootstrap,"passport":null}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let mut authenticator = SoftToken::new(true).unwrap().0;
    let challenge: cpky::CreationChallengeResponse = serde_json::from_value(start.options).unwrap();
    let credential = authenticator
        .perform_register(
            cpky::Url::parse(&format!("https://{host}")).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    let credential_id = credential.raw_id.as_ref().to_vec();
    let user: User = serde_json::from_value(
        client
            .call(
                "register_finish",
                json!({"ceremony":start.ceremony,"credential":credential}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let session = login(
        service,
        host,
        &mut authenticator,
        &user.user,
        &credential_id,
    )
    .await;
    Member {
        authenticator,
        user: user.user,
        credential: credential_id,
        session,
    }
}
pub async fn login(
    service: &Running,
    host: &str,
    authenticator: &mut SoftToken,
    user: &str,
    credential: &[u8],
) -> String {
    let client = client(service, host, None);
    let start: Ceremony = serde_json::from_value(
        client
            .call("login_begin", json!({"user":user,"credential":credential}))
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge: cpky::RequestChallengeResponse = serde_json::from_value(start.options).unwrap();
    let credential = authenticator
        .perform_auth(
            cpky::Url::parse(&format!("https://{host}")).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    let session: Session = serde_json::from_value(
        client
            .call(
                "login_finish",
                json!({"ceremony":start.ceremony,"credential":credential}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    session.token
}
pub async fn call_status(
    service: &Running,
    host: &str,
    token: Option<&str>,
    name: &str,
    body: Value,
) -> u16 {
    let mut request = reqwest::Client::new()
        .post(format!("{}/v1/{name}", service.base))
        .header("host", host)
        .json(&body);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request.send().await.unwrap().status().as_u16()
}

/// Synthetic authenticated community for wallet-only cryptographic tests.
/// Full community tests obtain this signature and ring over the real HTTP door.
pub async fn trusted_presentation(
    passport: &cpsd::Passport,
    request: &cpsd::PresentationRequest,
) -> cpsd::Presentation {
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "synthetic-community",
        csgn::SecretKey::from_seed(&mut [8; 32]),
        NOW - 1,
        86400,
    )
    .await
    .unwrap();
    let signed = signer
        .sign(
            csgn::Kind::Credential,
            &request.to_bytes(),
            NOW,
            request.now() + 1,
        )
        .await
        .unwrap();
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        request.community().clone(),
        signer.key_ring().unwrap().clone(),
    );
    passport
        .present(&mut cpsd::rand::rngs::OsRng, &expected, &signed, NOW)
        .unwrap()
}
