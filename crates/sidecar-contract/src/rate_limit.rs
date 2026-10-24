use std::{collections::HashMap, net::IpAddr};

use serde::{Deserialize, Serialize};

pub use crate::rate_limit_lease::{
    RateLimitAcquireLeaseRequest, RateLimitAcquireLeaseRequestItem, RateLimitAcquireLeaseResponse,
    RateLimitAcquireLeaseResult, RateLimitGiveBackLeaseRequest, RateLimitGiveBackLeaseRequestItem,
    RateLimitGiveBackLeaseResponse, RateLimitGiveBackLeaseResult, RateLimitLease,
};
use crate::{
    ContractResult,
    context::CacheStatus,
    rate_limit_helpers::{
        ipv6_64_identity, rate_limit_invalid, validate_non_empty, validate_positive,
        validate_rate_limit_key,
    },
};

pub const MAX_EVENTS_PER_BATCH: usize = 100;
const REGISTRY_HOURLY_WINDOW_SECONDS: u32 = 3_600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RateLimitRoute {
    pub rps: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
}

pub type RateLimitRouteConfig = HashMap<String, RateLimitRoute>;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RateLimitConfig {
    pub defaults: RateLimitRouteConfig,
    #[serde(default)]
    pub named: HashMap<String, RateLimitRouteConfig>,
    #[serde(default)]
    pub entitlement_overrides: HashMap<String, RateLimitRouteConfig>,
    #[serde(default)]
    pub org_overrides: HashMap<String, RateLimitRouteConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RateLimitConfigResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved: Option<TenantRateLimitRouteConfig>,
    pub config: TenantRateLimitConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantRateLimitConfig {
    pub defaults: TenantRateLimitRouteConfig,
    #[serde(default)]
    pub named: HashMap<String, TenantRateLimitRouteConfig>,
    #[serde(default)]
    pub entitlement_overrides: HashMap<String, TenantRateLimitRouteConfig>,
    #[serde(default)]
    pub org_overrides: HashMap<String, TenantRateLimitRouteConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantRateLimitRouteConfig {
    #[serde(default)]
    pub routes: HashMap<String, TenantRateLimitRoute>,
    #[serde(default)]
    pub route_groups: HashMap<String, TenantRateLimitRouteGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantRateLimitRoute {
    pub limit: u32,
    #[serde(default)]
    pub period: Option<TenantRateLimitPeriod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantRateLimitRouteGroup {
    pub limit: u32,
    #[serde(default)]
    pub period: Option<TenantRateLimitPeriod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
    #[serde(default)]
    pub routes: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenantRateLimitPeriod {
    #[default]
    Second,
    Minute,
    Hour,
    Day,
    Month,
}

impl RateLimitConfigResponse {
    pub fn into_rate_limit_config(self) -> RateLimitConfig {
        if let Some(resolved) = self.resolved {
            return RateLimitConfig {
                defaults: resolved.into_route_config(),
                named: HashMap::new(),
                entitlement_overrides: HashMap::new(),
                org_overrides: HashMap::new(),
            };
        }
        self.config.into_rate_limit_config()
    }
}

impl TenantRateLimitConfig {
    fn into_rate_limit_config(self) -> RateLimitConfig {
        RateLimitConfig {
            defaults: self.defaults.into_route_config(),
            named: map_route_configs(self.named),
            entitlement_overrides: map_route_configs(self.entitlement_overrides),
            org_overrides: map_route_configs(self.org_overrides),
        }
    }
}

impl TenantRateLimitRouteConfig {
    fn into_route_config(self) -> RateLimitRouteConfig {
        let mut routes = self
            .routes
            .into_iter()
            .map(|(name, route)| (name, route.into_route()))
            .collect::<RateLimitRouteConfig>();
        for group in self.route_groups.into_values() {
            let rate = group.rate();
            for route in group.routes {
                routes.entry(route).or_insert_with(|| rate.clone());
            }
        }
        routes
    }
}

impl TenantRateLimitRoute {
    fn into_route(self) -> RateLimitRoute {
        RateLimitRoute {
            rps: f64::from(self.limit) / self.period.unwrap_or_default().seconds(),
            burst: self.burst,
        }
    }
}

impl TenantRateLimitRouteGroup {
    fn rate(&self) -> RateLimitRoute {
        RateLimitRoute {
            rps: f64::from(self.limit) / self.period.unwrap_or_default().seconds(),
            burst: self.burst,
        }
    }
}

impl TenantRateLimitPeriod {
    const fn seconds(self) -> f64 {
        match self {
            Self::Second => 1.0,
            Self::Minute => 60.0,
            Self::Hour => 3_600.0,
            Self::Day => 86_400.0,
            Self::Month => 2_592_000.0,
        }
    }
}

fn map_route_configs(
    values: HashMap<String, TenantRateLimitRouteConfig>,
) -> HashMap<String, RateLimitRouteConfig> {
    values
        .into_iter()
        .map(|(name, config)| (name, config.into_route_config()))
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigResult {
    pub config: RateLimitConfig,
    pub cache_status: CacheStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitNetworkIdentity(String);

impl RateLimitNetworkIdentity {
    pub fn from_client_ip(client_ip: &str) -> ContractResult<Self> {
        let ip = client_ip
            .parse::<IpAddr>()
            .map_err(|_| rate_limit_invalid("client_ip must be a valid IP address"))?;
        Ok(Self(match ip {
            IpAddr::V4(ipv4) => ipv4.to_string(),
            IpAddr::V6(ipv6) => ipv6_64_identity(ipv6),
        }))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistryRateLimitAction {
    Pull,
    Push,
    Admin,
    Metrics,
}

impl RegistryRateLimitAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Push => "push",
            Self::Admin => "admin",
            Self::Metrics => "metrics",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryRateLimitDefaults {
    pub pull_limit_per_hour: u32,
    pub push_limit_per_hour: u32,
}

impl RegistryRateLimitDefaults {
    pub fn validate(&self) -> ContractResult<()> {
        validate_positive(self.pull_limit_per_hour, "pull_limit_per_hour")?;
        validate_positive(self.push_limit_per_hour, "push_limit_per_hour")
    }

    pub fn limit_for_action(&self, action: RegistryRateLimitAction) -> u32 {
        match action {
            RegistryRateLimitAction::Push => self.push_limit_per_hour,
            RegistryRateLimitAction::Pull
            | RegistryRateLimitAction::Admin
            | RegistryRateLimitAction::Metrics => self.pull_limit_per_hour,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryRateLimitRequest {
    pub repository: String,
    pub user_id: String,
    pub organization_id: String,
    pub client_ip: String,
    pub action: RegistryRateLimitAction,
    pub cost: u32,
    pub defaults: RegistryRateLimitDefaults,
}

impl RegistryRateLimitRequest {
    pub fn validate(&self) -> ContractResult<()> {
        validate_non_empty(&self.repository, "repository")?;
        validate_non_empty(&self.user_id, "user_id")?;
        validate_non_empty(&self.organization_id, "organization_id")?;
        validate_positive(self.cost, "cost")?;
        self.defaults.validate()?;
        self.network_identity()?;
        Ok(())
    }

    pub fn network_identity(&self) -> ContractResult<RateLimitNetworkIdentity> {
        RateLimitNetworkIdentity::from_client_ip(&self.client_ip)
    }

    pub fn hourly_limit(&self) -> u32 {
        self.defaults.limit_for_action(self.action)
    }

    pub fn window_seconds(&self) -> u32 {
        REGISTRY_HOURLY_WINDOW_SECONDS
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RateLimitParameters {
    pub limit_per_second: u32,
    pub burst: u32,
    #[serde(default = "default_lease_duration_ms")]
    pub lease_duration_ms: u32,
    #[serde(default = "default_estimated_nodes")]
    pub estimated_nodes: u32,
    #[serde(default)]
    pub giveback_grace_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitCheckRequest {
    pub params: RateLimitParameters,
    pub key: String,
    pub cost: u32,
}

impl RateLimitCheckRequest {
    pub fn validate(&self) -> ContractResult<()> {
        self.params.validate()?;
        validate_rate_limit_key(&self.key)?;
        validate_positive(self.cost, "cost")?;
        if u64::from(self.cost) > self.params.max_burst_tokens() {
            return Err(rate_limit_invalid("cost exceeds bucket capacity"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitCheckResponse {
    pub allowed: bool,
    pub remaining_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl RateLimitParameters {
    pub fn validate(&self) -> ContractResult<()> {
        if self.limit_per_second == 0 {
            return Err(rate_limit_invalid("limit_per_second must be positive"));
        }
        if self.lease_duration_ms == 0 {
            return Err(rate_limit_invalid("lease_duration_ms must be positive"));
        }
        if self.estimated_nodes == 0 {
            return Err(rate_limit_invalid("estimated_nodes must be positive"));
        }
        Ok(())
    }

    pub fn max_burst_tokens(&self) -> u64 {
        u64::from(self.limit_per_second)
            .saturating_add(u64::from(self.burst))
            .max(1)
    }
}

const fn default_lease_duration_ms() -> u32 {
    1_000
}

const fn default_estimated_nodes() -> u32 {
    1
}
