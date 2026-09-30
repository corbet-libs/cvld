//! Composition, exact-host authorization and aggregate throttling.
use crate::{
    api::*,
    auth::{Auth, Grant},
    config::Config,
    error::{Error, Result},
    global::GlobalService,
};
use axum::http::HeaderMap;
use cglb::{cpsd, crlt};
use std::{
    collections::BTreeMap,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}
#[derive(Clone)]
pub struct Door {
    inner: Arc<Inner>,
}
struct Inner {
    scope: Scope,
    hosts: BTreeMap<String, Arc<Mutex<Auth>>>,
    global: Mutex<GlobalService>,
    throttle: cthl::Throttle<cthl::MemoryStore>,
    clock: Arc<dyn Clock>,
}
pub(crate) struct Context {
    pub host: String,
    pub grant: Option<Grant>,
    pub token: Option<String>,
    pub now: u64,
}
impl Context {
    pub fn subject(&self) -> Result<cglb::Subject> {
        cglb::Subject::new(
            self.grant
                .as_ref()
                .ok_or(Error::Unauthorized)?
                .user
                .to_string(),
        )
        .map_err(|_| Error::Invalid)
    }
}
impl Door {
    pub async fn global(config: Config, clock: Arc<dyn Clock>) -> Result<Self> {
        if config.domain.is_empty()
            || !config
                .domain
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
            || config.publication_seconds == 0
        {
            return Err(Error::Invalid);
        }
        let token = if let Some(path) = &config.database_token_file {
            String::from_utf8(Config::secret(path)?.to_vec()).map_err(|_| Error::Invalid)?
        } else {
            String::new()
        };
        let db = crlt::Db::open(crlt::Config::new(&config.database_url, token))
            .await
            .map_err(|_| Error::Unavailable)?;
        let now = clock.now();
        let global = GlobalService::open(&db, &config, now).await?;
        let mut hosts = BTreeMap::new();
        let wallet = format!("wallet.{}", config.domain);
        let root = format!("api.root.{}", config.domain);
        for (host, role, scope, operator) in [
            (wallet, Role::Member, "wallet", None),
            (
                root,
                Role::Root,
                "root",
                Some(uuid::Uuid::parse_str(&config.root_user).map_err(|_| Error::Invalid)?),
            ),
        ] {
            let passkeys = cpky::Passkeys::new(
                cpky::LibsqlStore::new(&db, scope, tokio::runtime::Handle::current())
                    .map_err(|_| Error::Unavailable)?,
                scope,
                &host,
                &[cpky::Url::parse(&format!("https://{host}")).map_err(|_| Error::Invalid)?],
            )
            .map_err(|_| Error::Invalid)?;
            let bootstrap = if operator.is_some() {
                config
                    .root_bootstrap_file
                    .as_ref()
                    .map(|path| {
                        Config::secret(path).and_then(|s| {
                            String::from_utf8(s.to_vec())
                                .map(zeroize::Zeroizing::new)
                                .map_err(|_| Error::Invalid)
                        })
                    })
                    .transpose()?
            } else {
                None
            };
            hosts.insert(
                host,
                Arc::new(Mutex::new(Auth::new(
                    passkeys,
                    role,
                    operator,
                    bootstrap,
                    config.pending_capacity,
                    config.session_seconds,
                )?)),
            );
        }
        let limit = cthl::Limit::new(
            config.throttle_burst,
            Duration::from_millis(config.throttle_interval_ms),
        )
        .map_err(|_| Error::Invalid)?;
        let throttle = cthl::Throttle::new(
            "global",
            ACTIONS.iter().map(|a| (a.name, limit)),
            cthl::MemoryStore::new(NonZeroUsize::new(ACTIONS.len()).ok_or(Error::Invalid)?),
        )
        .map_err(|_| Error::Invalid)?;
        Ok(Self {
            inner: Arc::new(Inner {
                scope: Scope::Global,
                hosts,
                global: Mutex::new(global),
                throttle,
                clock,
            }),
        })
    }
    /// Service maintenance uses only current state, without member activity logs.
    pub async fn maintain(&self) -> Result<()> {
        let now = self.inner.clock.now();
        let mut global = self.inner.global.lock().await;
        global
            .facade
            .prune_challenges(now, 100)
            .await
            .map_err(|_| Error::Unavailable)?;
        let fresh = global
            .facade
            .key_ring()
            .map_err(|_| Error::Unavailable)?
            .verify(
                &global.public.status,
                cglb::csgn::Kind::RevocationListSnapshot,
                now,
            )
            .map(|s| s.valid_until() > now + global.publication_seconds / 2)
            .unwrap_or(false);
        if !fresh {
            global.refresh(now).await?;
        }
        Ok(())
    }
    fn auth(&self, host: &str) -> Result<Arc<Mutex<Auth>>> {
        self.inner.hosts.get(host).cloned().ok_or(Error::WrongHost)
    }
    pub(crate) async fn authorize(&self, action: &Action, headers: &HeaderMap) -> Result<Context> {
        // Service-wide quotas cannot be evaded with forged IPs, handles or fresh tokens.
        if !matches!(
            self.inner.throttle.check(b"aggregate", action.name).await,
            Ok(cthl::Decision::Allowed)
        ) {
            return Err(Error::Throttled);
        }
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .ok_or(Error::WrongHost)?
            .to_owned();
        let auth = self.auth(&host)?;
        if action.scope != Scope::Both && action.scope != self.inner.scope {
            return Err(Error::WrongHost);
        }
        if let Some(origin) = headers.get("origin")
            && origin.to_str().ok() != Some(format!("https://{host}").as_str())
        {
            return Err(Error::Forbidden);
        }
        let now = self.inner.clock.now();
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned);
        let mut auth = auth.lock().await;
        let grant = if let Some(token) = &token {
            Some(auth.authenticate(token, now).await?)
        } else {
            None
        };
        if action.access != Access::Public {
            let grant = grant.as_ref().ok_or(Error::Unauthorized)?;
            let allowed = match action.access {
                Access::Member => grant.role == Role::Member,
                Access::Admin => grant.role == Role::Admin,
                Access::Root => grant.role == Role::Root,
                Access::Public => true,
            };
            if !allowed {
                return Err(Error::Forbidden);
            }
        }
        Ok(Context {
            host,
            grant,
            token,
            now,
        })
    }
    pub(crate) async fn register_begin(
        &self,
        ctx: Context,
        request: RegisterStart,
    ) -> Result<Ceremony> {
        self.auth(&ctx.host)?
            .lock()
            .await
            .register_begin(request, ctx.now)
            .await
    }
    pub(crate) async fn register_finish(
        &self,
        ctx: Context,
        request: RegisterFinish,
    ) -> Result<User> {
        self.auth(&ctx.host)?
            .lock()
            .await
            .register_finish(request, ctx.now)
            .await
    }
    pub(crate) async fn login_begin(&self, ctx: Context, request: User) -> Result<Ceremony> {
        self.auth(&ctx.host)?
            .lock()
            .await
            .login_begin(request, ctx.now)
            .await
    }
    pub(crate) async fn login_finish(&self, ctx: Context, request: LoginFinish) -> Result<Session> {
        self.auth(&ctx.host)?
            .lock()
            .await
            .login_finish(request, ctx.now)
            .await
    }
    pub(crate) async fn logout(&self, ctx: Context, _: Empty) -> Result<Empty> {
        self.auth(&ctx.host)?
            .lock()
            .await
            .logout(ctx.token.as_deref().ok_or(Error::Unauthorized)?);
        Ok(Empty {})
    }
    pub(crate) async fn global_public(&self, _: Context, _: Empty) -> Result<GlobalPublic> {
        let global = self.inner.global.lock().await;
        Ok(GlobalPublic {
            key_ring: global.public.key_ring.clone(),
            issuer: global.public.issuer.clone(),
            status: global.public.status.clone(),
        })
    }
    pub(crate) async fn passport_challenge(&self, ctx: Context, _: Empty) -> Result<Bytes> {
        let global = self.inner.global.lock().await;
        let challenge = global
            .facade
            .challenge(
                &mut cpsd::rand::rngs::OsRng,
                &ctx.subject()?,
                ctx.now,
                ctx.now + 60,
            )
            .await
            .map_err(|_| Error::Refused)?;
        Ok(Bytes {
            bytes: challenge.to_bytes().to_vec(),
        })
    }
    pub(crate) async fn passport_issue(
        &self,
        ctx: Context,
        request: PassportIssue,
    ) -> Result<Bytes> {
        let challenge = cpsd::IssuanceChallenge::from_bytes(
            request.challenge.try_into().map_err(|_| Error::Invalid)?,
        );
        let request =
            cpsd::IssuanceRequest::from_bytes(&request.request).map_err(|_| Error::Invalid)?;
        let global = self.inner.global.lock().await;
        let passport = global
            .facade
            .issue(
                &mut cpsd::rand::rngs::OsRng,
                &ctx.subject()?,
                &challenge,
                &request,
                ctx.now,
            )
            .await
            .map_err(|_| Error::Refused)?;
        Ok(Bytes {
            bytes: passport.to_bytes(),
        })
    }
    #[cfg(feature = "development-gate")]
    pub(crate) async fn development_gate(&self, ctx: Context, _: Empty) -> Result<Empty> {
        let global = self.inner.global.lock().await;
        let subject = ctx.subject()?;
        global
            .facade
            .run_gate(
                &cglb::development::DevelopmentGate::new(global.development_expiry),
                &subject,
                subject.as_str().as_bytes(),
                ctx.now,
            )
            .await
            .map_err(|_| Error::Refused)?;
        Ok(Empty {})
    }
    pub(crate) async fn global_warn(&self, _: Context, request: User) -> Result<Empty> {
        self.inner
            .global
            .lock()
            .await
            .facade
            .warn(&cglb::Subject::new(request.user).map_err(|_| Error::Invalid)?)
            .await
            .map_err(|_| Error::Refused)?;
        Ok(Empty {})
    }
    pub(crate) async fn global_suspend(&self, ctx: Context, request: Suspend) -> Result<Empty> {
        let mut global = self.inner.global.lock().await;
        global
            .facade
            .suspend(
                &cglb::Subject::new(request.user).map_err(|_| Error::Invalid)?,
                cglb::Suspension::Temporary {
                    until: request.until,
                },
                ctx.now,
            )
            .await
            .map_err(|_| Error::Refused)?;
        global.refresh(ctx.now).await?;
        Ok(Empty {})
    }
}
