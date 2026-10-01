//! Portable client projection of this owner's generated OpenAPI contract.
//! No server authority or mutable session state is exposed by the registry.

use crate::error::{Error, Result};
use serde_json::Value;
use std::{future::Future, sync::LazyLock};

#[cfg(all(feature = "client-http", not(target_arch = "wasm32")))]
#[path = "client_http.rs"]
mod http;
#[cfg(all(feature = "client-http", not(target_arch = "wasm32")))]
pub use http::HttpClient;

static DOCUMENT: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../docs/openapi.json"))
        .expect("the checked generated door contract is JSON")
});

/// Original owner schema, including exact roles, scopes, effects and JSON types.
pub fn contract() -> &'static Value {
    &DOCUMENT
}

/// A borrowed operation from the generated contract, never a caller-built grant.
#[derive(Clone, Copy)]
pub struct Action {
    path: &'static str,
    operation: &'static Value,
}

impl Action {
    /// Owner's original HTTP path.
    pub fn path(&self) -> &'static str {
        self.path
    }

    /// Original operation schema and role/effect/scope metadata.
    pub fn schema(&self) -> &'static Value {
        self.operation
    }
}

/// Look up a public owner operation without guessing a route from input text.
pub fn action(name: &str) -> Option<Action> {
    DOCUMENT
        .get("paths")?
        .as_object()?
        .iter()
        .find_map(|(path, item)| {
            let operation = item.get("post")?;
            (operation.get("operationId")?.as_str()? == name).then_some(Action { path, operation })
        })
}

/// An authenticated HTTP runtime selected by the trusted device composition.
/// Request JSON contains public assertions and opaque signed bytes, never PRF
/// results or roots. The server independently checks all roles and authority.
pub trait Transport {
    /// Send exactly the owner's path to the selected pinned door origin.
    fn send(&mut self, path: &str, request: Value) -> impl Future<Output = Result<Value>>;
}

/// Portable generated-contract client; runtime credentials stay in its transport.
pub struct Client<T> {
    transport: T,
}

impl<T: Transport> Client<T> {
    /// Compose a runtime without manufacturing authentication or permissions.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Forward one registered operation, preserving the owner's response/error.
    pub async fn call(&mut self, name: &str, request: Value) -> Result<Value> {
        let action = action(name).ok_or(Error::Invalid)?;
        self.transport.send(action.path(), request).await
    }
}
