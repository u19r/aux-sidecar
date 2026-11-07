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
  resource?: string;
}

export interface NativeAuthenticationRecovery {
  code: "fraud_blocked" | "reauthentication_required" | "step_up_required";
  continuation_id: string;
  expires_at: string;
}

export interface NativeAuthenticationWarnings {
  codes: Array<"evaluation_warning" | "evaluation_degraded">;
  decision_id?: string;
}

export interface HostedLoginAuthorizationRequest {
  client_id: string;
  redirect_uri: string;
  resource?: string;
  scopes: string[];
  login_hint?: string;
}

export type HostedRecoveryGrant =
  { type: "authorization_code"; state: string; code: string; recovery: NativeAuthenticationRecovery } |
  { type: "refresh_token"; request: HostedLoginRefreshRequest; recovery: NativeAuthenticationRecovery };

export interface HostedRecoveryRequest {
  grant: HostedRecoveryGrant;
  authorization: HostedLoginAuthorizationRequest;
}

export interface HostedRecoveryResult {
  stage: { stage_handle: string; expires_at: string };
  state: string;
}

export type NativeOAuthErrorCode = "invalid_request" | "invalid_client" | "invalid_grant" |
  "unauthorized_client" | "unsupported_grant_type" | "invalid_scope" | "invalid_target" |
  "invalid_dpop_proof" | "use_dpop_nonce" | "server_error" | "temporarily_unavailable" | "unknown";

export type NativeAuthenticationFailure =
  { type: "recovery_required"; recovery: NativeAuthenticationRecovery } |
  { type: "denied"; error: NativeOAuthErrorCode } |
  { type: "retry"; retry_after_seconds: number | null };

export interface SidecarPublicError {
  code: string;
  message: string;
  authentication?: NativeAuthenticationFailure | null;
  request_id?: string | null;
}
"#;
