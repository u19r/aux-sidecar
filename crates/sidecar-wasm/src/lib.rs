//! Wasm sidecar crate.

pub mod api;
mod api_config;
mod constants;
pub mod host;
#[cfg(target_arch = "wasm32")]
mod typescript;

#[cfg(test)]
mod api_tests;

#[cfg(test)]
mod native_auth_tests;
