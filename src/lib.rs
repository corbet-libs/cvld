//! cvld: the permanent door. Domain decisions belong to its composed facades.
#![forbid(unsafe_code)]
#[cfg(all(feature = "development-gate", not(debug_assertions)))]
compile_error!("development-gate is forbidden in release builds");

pub mod api;
pub mod auth;
pub mod cli;
pub mod config;
pub mod error;
pub mod global;
pub mod mcp;
pub mod service;
