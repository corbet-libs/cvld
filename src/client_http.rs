//! Native HTTP adapter for the generated door contract.
use super::Transport;
use crate::error::{Error, Result};
use serde_json::Value;

#[derive(Clone)]
pub struct HttpClient {
    client: reqwest::Client,
    base: String,
    host: String,
    token: Option<zeroize::Zeroizing<String>>,
}
impl HttpClient {
    pub fn new(base: String, host: String, token: Option<String>) -> Result<Self> {
        let url = reqwest::Url::parse(&base).map_err(|_| Error::Invalid)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(Error::Invalid);
        }
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            return Err(Error::Invalid);
        }
        if url.scheme() == "https" && url.host_str() != Some(host.as_str()) {
            return Err(Error::WrongHost);
        }
        let client = reqwest::Client::builder()
            .user_agent("cvld-client")
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            client,
            base: base.trim_end_matches('/').to_owned(),
            host,
            token: token.map(zeroize::Zeroizing::new),
        })
    }
    pub async fn call(&self, name: &str, request: Value) -> Result<Value> {
        let known = {
            #[cfg(feature = "server")]
            { crate::api::action(name).is_some() }
            #[cfg(not(feature = "server"))]
            { super::action(name).is_some() }
        };
        if !known {
            return Err(Error::Invalid);
        }
        let mut call = self
            .client
            .post(format!("{}/v1/{name}", self.base))
            .header("host", &self.host)
            .json(&request);
        if let Some(token) = &self.token {
            call = call.bearer_auth(token.as_str());
        }
        let mut response = call.send().await.map_err(|_| Error::Unavailable)?;
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                400 => Error::Invalid,
                401 => Error::Unauthorized,
                403 => Error::Forbidden,
                421 => Error::WrongHost,
                429 => Error::Throttled,
                409 => Error::Refused,
                _ => Error::Unavailable,
            });
        }
        const LIMIT: usize = 16 * 1024 * 1024;
        if response.content_length().is_some_and(|size| size > LIMIT as u64) {
            return Err(Error::Unavailable);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
            if chunk.len() > LIMIT - body.len() {
                return Err(Error::Unavailable);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| Error::Unavailable)
    }
}

impl Transport for HttpClient {
    async fn send(&mut self, path: &str, request: Value) -> Result<Value> {
        let name = path.strip_prefix("/v1/").ok_or(Error::Invalid)?;
        self.call(name, request).await
    }
}
