//! cvld: the permanent door. Domain decisions belong to its composed facades.
#![forbid(unsafe_code)]
#[cfg(all(feature = "development-gate", not(debug_assertions)))]
compile_error!("development-gate is forbidden in release builds");

pub mod api;
mod auth;
pub mod cli;
pub mod config;
pub mod error;
mod global;
mod identity;
pub mod mcp;
pub mod service;
