use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(typescript_custom_section)]
const SIDECAR_TYPES: &str = r#"
export type CacheStatus = "miss" | "fresh" | "stale";

export interface LiveStatus {
  status: "live";
  version: string;
  uptime_ms: number;
}

export interface ReadyStatus {
  ready: boolean;
  reason_codes: string[];
}

export interface CapabilityStatus {
  name: string;
  version: number;
  state: "supported";
}

export interface RateLimitCheckRequest {
  params: RateLimitLeaseBatchRequest["params"];
  key: string;
  cost: number;
}

export interface RateLimitLeaseRequest {
  key: string;
  requested_tokens: number;
  min_grant_tokens: number;
}

export interface RateLimitLeaseBatchRequest {
  params: {
    limit_per_second: number;
    burst: number;
    lease_duration_ms: number;
    estimated_nodes: number;
    giveback_grace_ms: number;
  };
  leases: RateLimitLeaseRequest[];
}

export interface BlocklistDecisionRequest {
  tenant_id: string;
  org_id: string;
  product_domain: string;
  resource: string;
  action: string;
  client_ip: string;
  network_identity: string;
  country?: string;
  policy_refs: Array<{ name: string; reason?: string }>;
}

export interface BlocklistDecisionResponse {
  blocked: boolean;
  matches: Array<{ kind: string; value: string; policy?: string; reason?: string }>;
  audit_subject?: string;
}

export interface HostedLoginCompletionRequest {
  state: string;
  code?: string;
  error?: string;
  error_description?: string;
}

export interface HostedLoginRefreshRequest {
  client_id: string;
  refresh_token: string;
  scope?: string;
}

export interface SidecarPublicError {
  code: string;
  message: string;
}
"#;
