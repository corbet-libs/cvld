//! Browser Fetch adapter over maintained Gloo and Web Streams wrappers.
use super::Transport;
use crate::error::{Error, Result};
use futures_util::StreamExt;
use serde_json::Value;
use wasm_bindgen::JsCast;

/// Origin-bound browser runtime. Authentication uses an explicit opaque session;
/// ambient cookies, redirects, referrers and cached replies are disabled.
#[derive(Clone)]
pub struct BrowserClient {
    base: String,
    token: Option<zeroize::Zeroizing<String>>,
}

impl BrowserClient {
    /// Bind the exact configured HTTPS origin. HTTP is limited to loopback tests.
    /// Browsers choose Host from the URL; the native fixture override is forbidden.
    pub fn new(base: String, host: String, token: Option<String>) -> Result<Self> {
        let url = super::origin(&base, &host)?;
        if url.host_str() != Some(host.as_str()) {
            return Err(Error::WrongHost);
        }
        Ok(Self {
            base: url.origin().ascii_serialization(),
            token: token.map(zeroize::Zeroizing::new),
        })
    }

    /// Dispatch once. Any failure after Fetch starts requires reconciliation.
    pub async fn call(&self, name: &str, input: Value) -> Result<Value> {
        let action = super::action(name).ok_or(Error::Invalid)?;
        let headers = web_sys::Headers::new().map_err(|_| Error::Invalid)?;
        headers
            .set("content-type", "application/json")
            .map_err(|_| Error::Invalid)?;
        if let Some(token) = &self.token {
            headers
                .set("authorization", &format!("Bearer {}", token.as_str()))
                .map_err(|_| Error::Invalid)?;
        }
        let controller = web_sys::AbortController::new().map_err(|_| Error::Unavailable)?;
        let cancellation = CancelOnDrop(controller.clone());
        let timeout = gloo_timers::callback::Timeout::new(30_000, move || controller.abort());
        let call = gloo_net::http::Request::post(&format!("{}{}", self.base, action.path()))
            .headers(gloo_net::http::Headers::from_raw(headers))
            .redirect(web_sys::RequestRedirect::Error)
            .credentials(web_sys::RequestCredentials::Omit)
            .cache(web_sys::RequestCache::NoStore)
            .referrer_policy(web_sys::ReferrerPolicy::NoReferrer)
            .abort_signal(Some(&cancellation.0.signal()))
            .body(input.to_string())
            .map_err(|_| Error::Invalid)?;
        let response = call.send().await.map_err(|_| Error::Reconcile)?;
        let status = response.status();
        const LIMIT: usize = 16 * 1024 * 1024;
        if response
            .headers()
            .get("content-length")
            .is_some_and(|size| size.parse::<u64>().is_ok_and(|size| size > LIMIT as u64))
        {
            return Err(Error::Reconcile);
        }
        let stream = response.body().ok_or(Error::Reconcile)?;
        let mut stream = wasm_streams::ReadableStream::from_raw(stream).into_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(|_| Error::Reconcile)?
                .dyn_into::<js_sys::Uint8Array>()
                .map_err(|_| Error::Reconcile)?;
            if chunk.length() as usize > LIMIT - bytes.len() {
                return Err(Error::Reconcile);
            }
            bytes.extend_from_slice(&chunk.to_vec());
        }
        let result = super::decode_response(name, status, &bytes);
        drop(timeout);
        drop(cancellation);
        result
    }
}

// Abort Fetch and its body reader if the future is cancelled or a size/error
// guard exits early. The timer separately bounds the entire response lifetime.
struct CancelOnDrop(web_sys::AbortController);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl Transport for BrowserClient {
    async fn send(&mut self, path: &str, request: Value) -> Result<Value> {
        let name = path.strip_prefix("/v1/").ok_or(Error::Invalid)?;
        self.call(name, request).await
    }
}
