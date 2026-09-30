use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Supplied explicitly; loading never searches for credentials.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub domain: String,
    pub database_url: String,
    pub database_token_file: Option<String>,
    pub signing_seed_file: String,
    pub issuer_key_file: String,
    pub uniqueness_key_file: String,
    pub policy_file: String,
    pub policy_authority_file: String,
    /// Existing operator's opaque account UUID; first enrolment uses bootstrap.
    pub root_user: String,
    pub root_bootstrap_file: Option<String>,
    pub session_seconds: u64,
    pub pending_capacity: usize,
    pub throttle_burst: u32,
    pub throttle_interval_ms: u64,
    pub publication_seconds: u64,
    pub signer_max_seconds: u64,
    pub development: bool,
}
impl Config {
    pub fn read(path: &str) -> Result<Self> {
        serde_json::from_slice(&std::fs::read(path).map_err(|_| Error::Unavailable)?)
            .map_err(|_| Error::Invalid)
    }
    pub fn secret(path: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        std::fs::read(path)
            .map(zeroize::Zeroizing::new)
            .map_err(|_| Error::Unavailable)
    }
    pub fn seed(path: &str) -> Result<[u8; 32]> {
        Self::secret(path)?
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid)
    }
}
