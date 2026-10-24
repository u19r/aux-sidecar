//! Native sidecar process crate.

pub mod cli;
mod cli_values;
pub mod client_ip;
pub mod config;
mod constants;
pub mod errors;
pub mod handlers;
mod healthcheck;
pub mod proxy;
pub mod router;
pub mod server;
pub mod state;
pub mod transport;
pub mod transport_helpers;

#[cfg(test)]
mod cli_tests;
#[cfg(test)]
mod healthcheck_tests;
#[cfg(test)]
mod proxy_tests;
#[cfg(test)]
mod router_additional_tests;
#[cfg(test)]
pub(crate) mod router_tests;
#[cfg(test)]
mod server_tests;
#[cfg(test)]
mod transport_tests;

mod oauth_presenter;

#[cfg(test)]
mod oauth_presenter_tests;
