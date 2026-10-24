use std::{net::IpAddr, sync::Arc};

use serde::Deserialize;
use sidecar_contract::{
    RequestContext, RuntimeBlocklistDecisionRequest, RuntimeBlocklistDecisionResponse,
    RuntimeBlocklistMatch, RuntimeSyncKnownVersions, RuntimeSyncRequest, SyncArtifactKind,
};

use crate::{
    CachedValueState, SidecarEngineConfig, SidecarError, SidecarResult, SidecarState,
    SidecarTransport, constants::MAX_BLOCKLIST_RULES, state::current_time_millis,
};

pub(crate) async fn decide<T>(
    config: &SidecarEngineConfig,
    state: &Arc<SidecarState>,
    transport: &Arc<T>,
    context: &RequestContext,
    request: &RuntimeBlocklistDecisionRequest,
) -> SidecarResult<RuntimeBlocklistDecisionResponse>
where
    T: SidecarTransport + 'static,
{
    request.validate()?;
    let stale = local_runtime(config, state)?;
    if let Some((runtime, CachedValueState::Fresh)) = stale.as_ref() {
        return runtime.evaluate(request);
    }
    let sync_request = RuntimeSyncRequest {
        protocol_version: 1,
        known: RuntimeSyncKnownVersions::default(),
        want: vec![SyncArtifactKind::Blocklist],
        authz: None,
        entitlements: Vec::new(),
        blocklist_policy_refs: request.policy_refs.clone(),
        revocation_audiences: Vec::new(),
    };
    match crate::runtime_sync::synchronize(config, state, transport, context, sync_request, false)
        .await
    {
        Ok(_) => local_runtime(config, state)?
            .ok_or_else(|| {
                SidecarError::bad_gateway(
                    "runtime_sync_artifact_missing",
                    "runtime sync omitted required blocklist state",
                )
            })?
            .0
            .evaluate(request),
        Err(error) if error.code == "runtime_sync_unavailable" => {
            let response = transport.decide_blocklist(config, context, request).await?;
            response.validate()?;
            Ok(response)
        }
        Err(error) => Err(error),
    }
}

fn local_runtime(
    config: &SidecarEngineConfig,
    state: &SidecarState,
) -> SidecarResult<Option<(Arc<LocalBlocklistRuntime>, CachedValueState)>> {
    let Some((artifact, received_at_ms)) =
        state.shared_runtime_sync_artifact_with_age(SyncArtifactKind::Blocklist, "tenant")
    else {
        return Ok(None);
    };
    if let Some(cached) = state.local_blocklist_runtime(
        &artifact.etag,
        current_time_millis(),
        config.stale_cache_ttl,
    ) {
        return Ok(Some(cached));
    }
    let etag = artifact.etag.clone();
    let runtime = Arc::new(LocalBlocklistRuntime::compile_borrowed(&artifact.payload)?);
    state.store_local_blocklist_runtime(
        etag.clone(),
        Arc::clone(&runtime),
        received_at_ms,
        artifact.max_age_ms.unwrap_or_default(),
    );
    Ok(state.local_blocklist_runtime(&etag, current_time_millis(), config.stale_cache_ttl))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBlocklistRuntime {
    ip_ranges: Vec<IpCidr>,
    countries: Vec<String>,
}

impl LocalBlocklistRuntime {
    pub fn compile(payload: serde_json::Value) -> SidecarResult<Self> {
        let payload: BlocklistPayload = serde_json::from_value(payload).map_err(|_| invalid())?;
        Self::from_payload(payload)
    }

    pub(crate) fn compile_borrowed(payload: &serde_json::Value) -> SidecarResult<Self> {
        let payload = BlocklistPayload::deserialize(payload).map_err(|_| invalid())?;
        Self::from_payload(payload)
    }

    fn from_payload(payload: BlocklistPayload) -> SidecarResult<Self> {
        if payload.builtin_ip_ranges.len() + payload.tenant_ip_ranges.len() > MAX_BLOCKLIST_RULES
            || payload.builtin_regions.len() + payload.tenant_regions.len() > MAX_BLOCKLIST_RULES
        {
            return Err(invalid());
        }
        let ip_ranges = payload
            .builtin_ip_ranges
            .into_iter()
            .chain(payload.tenant_ip_ranges)
            .map(|record| IpCidr::parse(record.ip_range))
            .collect::<SidecarResult<Vec<_>>>()?;
        let mut countries = payload
            .builtin_regions
            .into_iter()
            .chain(payload.tenant_regions)
            .map(|record| normalize_owned_country(record.region_country))
            .collect::<SidecarResult<Vec<_>>>()?;
        countries.sort_unstable();
        countries.dedup();
        Ok(Self {
            ip_ranges,
            countries,
        })
    }

    pub fn evaluate(
        &self,
        request: &RuntimeBlocklistDecisionRequest,
    ) -> SidecarResult<RuntimeBlocklistDecisionResponse> {
        request.validate()?;
        let address = request.client_ip.parse::<IpAddr>().map_err(|_| invalid())?;
        if let Some(range) = self.ip_ranges.iter().find(|range| range.contains(address)) {
            return Ok(blocked_response(request, "ip_cidr", range.source.clone()));
        }
        if let Some(country) = request.country.as_deref() {
            let country = normalize_country(country)?;
            if self.countries.binary_search(&country).is_ok() {
                return Ok(blocked_response(request, "country", country));
            }
        }
        Ok(RuntimeBlocklistDecisionResponse {
            blocked: false,
            matches: Vec::new(),
            audit_subject: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn compile_borrowed_legacy(payload: &serde_json::Value) -> SidecarResult<Self> {
        let payload = BlocklistPayload::deserialize(payload).map_err(|_| invalid())?;
        let ip_records = payload
            .builtin_ip_ranges
            .into_iter()
            .chain(payload.tenant_ip_ranges)
            .collect::<Vec<_>>();
        let region_records = payload
            .builtin_regions
            .into_iter()
            .chain(payload.tenant_regions)
            .collect::<Vec<_>>();
        if ip_records.len() > MAX_BLOCKLIST_RULES || region_records.len() > MAX_BLOCKLIST_RULES {
            return Err(invalid());
        }
        let ip_ranges = ip_records
            .into_iter()
            .map(|record| IpCidr::parse_borrowed(&record.ip_range))
            .collect::<SidecarResult<Vec<_>>>()?;
        let mut countries = region_records
            .into_iter()
            .map(|record| normalize_country(&record.region_country))
            .collect::<SidecarResult<Vec<_>>>()?;
        countries.sort_unstable();
        countries.dedup();
        Ok(Self {
            ip_ranges,
            countries,
        })
    }
}

#[derive(Debug, Deserialize)]
struct BlocklistPayload {
    #[serde(default)]
    builtin_ip_ranges: Vec<IpRangeRecord>,
    #[serde(default)]
    tenant_ip_ranges: Vec<IpRangeRecord>,
    #[serde(default)]
    builtin_regions: Vec<RegionRecord>,
    #[serde(default)]
    tenant_regions: Vec<RegionRecord>,
}

#[derive(Debug, Deserialize)]
struct IpRangeRecord {
    ip_range: String,
}

#[derive(Debug, Deserialize)]
struct RegionRecord {
    region_country: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IpCidr {
    source: String,
    network: u128,
    prefix: u8,
    ipv6: bool,
}

impl IpCidr {
    fn parse(value: String) -> SidecarResult<Self> {
        let (address, prefix) = value.split_once('/').unwrap_or((value.as_str(), ""));
        let address = address.parse::<IpAddr>().map_err(|_| invalid())?;
        let (network, prefix, ipv6) = match address {
            IpAddr::V4(address) => {
                let prefix = if prefix.is_empty() {
                    32
                } else {
                    parse_prefix(prefix, 32)?
                };
                let value = u32::from(address);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                (u128::from(value & mask), prefix, false)
            }
            IpAddr::V6(address) => {
                let prefix = if prefix.is_empty() {
                    128
                } else {
                    parse_prefix(prefix, 128)?
                };
                let value = u128::from(address);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                (value & mask, prefix, true)
            }
        };
        Ok(Self {
            source: value,
            network,
            prefix,
            ipv6,
        })
    }

    #[cfg(test)]
    fn parse_borrowed(value: &str) -> SidecarResult<Self> {
        Self::parse(value.to_string())
    }

    fn contains(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) if !self.ipv6 => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u128::from(u32::from(address) & mask) == self.network
            }
            IpAddr::V6(address) if self.ipv6 => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(address) & mask == self.network
            }
            _ => false,
        }
    }
}

fn parse_prefix(value: &str, maximum: u8) -> SidecarResult<u8> {
    let prefix = value.parse::<u8>().map_err(|_| invalid())?;
    if prefix > maximum {
        return Err(invalid());
    }
    Ok(prefix)
}

fn normalize_country(value: &str) -> SidecarResult<String> {
    let value = value.trim().to_ascii_uppercase();
    if value.len() != 2
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        return Err(invalid());
    }
    Ok(value)
}

fn normalize_owned_country(mut value: String) -> SidecarResult<String> {
    if value.trim().len() != value.len() {
        return normalize_country(&value);
    }
    value.make_ascii_uppercase();
    if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(invalid());
    }
    Ok(value)
}

fn blocked_response(
    request: &RuntimeBlocklistDecisionRequest,
    kind: &str,
    value: String,
) -> RuntimeBlocklistDecisionResponse {
    let matches = if request.policy_refs.is_empty() {
        vec![RuntimeBlocklistMatch {
            kind: kind.to_string(),
            value,
            policy: None,
            reason: None,
        }]
    } else {
        request
            .policy_refs
            .iter()
            .map(|policy| RuntimeBlocklistMatch {
                kind: kind.to_string(),
                value: value.clone(),
                policy: Some(policy.name.clone()),
                reason: policy.reason.clone(),
            })
            .collect()
    };
    RuntimeBlocklistDecisionResponse {
        blocked: true,
        matches,
        audit_subject: None,
    }
}

fn invalid() -> SidecarError {
    SidecarError::bad_gateway(
        "runtime_sync_blocklist_invalid",
        "synchronized blocklist artifact is invalid",
    )
}
