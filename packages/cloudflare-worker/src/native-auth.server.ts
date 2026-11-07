import { AuxFnClientError } from "./account-client.server.js";

export type NativeRecoveryCode = "fraud_blocked" | "reauthentication_required" | "step_up_required";
export type NativeWarningCode = "evaluation_warning" | "evaluation_degraded";
export interface NativeAuthenticationRecovery {
  code: NativeRecoveryCode;
  continuation_id: string;
  expires_at: string;
}
export interface NativeAuthenticationWarnings {
  codes: NativeWarningCode[];
  decision_id?: string;
}
const NATIVE_OAUTH_ERROR_CODES = [
  "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
  "unsupported_grant_type", "invalid_scope", "invalid_target", "invalid_dpop_proof",
  "use_dpop_nonce", "server_error", "temporarily_unavailable", "unknown",
] as const;
export type NativeOAuthErrorCode = typeof NATIVE_OAUTH_ERROR_CODES[number];
export type NativeAuthenticationFailure =
  { type: "recovery_required"; recovery: NativeAuthenticationRecovery } |
  { type: "denied"; error: NativeOAuthErrorCode } |
  { type: "retry"; retry_after_seconds: number | null };

/** Carries safe native protocol data; provider descriptions and credentials are excluded. */
export class AuxFnOAuthError extends AuxFnClientError {
  constructor(
    code: string,
    status: 400 | 401 | 403 | 503,
    readonly authentication: NativeAuthenticationFailure,
    readonly requestId?: string,
  ) {
    super(code, status);
  }
}

export async function readNativeOAuthFailure(response: Response): Promise<Error> {
  if (response.status === 429 || response.status >= 500) {
    const header = response.headers.get("retry-after");
    const seconds = header !== null && /^\d+$/.test(header) ? Number(header) : NaN;
    return new AuxFnOAuthError("oauth_token_retry_required", 503, {
      type: "retry",
      retry_after_seconds: Number.isSafeInteger(seconds) && seconds <= 0xffffffff ? seconds : null,
    });
  }
  if (response.status < 400) {
    return new AuxFnClientError("oauth_token_exchange_failed", 503);
  }
  const value: unknown = await response.json().catch(() => undefined);
  if (!isRecord(value) || typeof value.error !== "string") return invalidResponse();
  const requestId = value.request_id === undefined || value.request_id === null ? undefined : readNativeString(value.request_id);
  if (response.status === 400 && value.error === "invalid_grant" && value.aux_recovery !== undefined && value.aux_recovery !== null) {
    const recovery = readNativeRecovery(value.aux_recovery);
    return new AuxFnOAuthError(recovery.code, 400, { type: "recovery_required", recovery }, requestId);
  }
  const status = response.status === 401 ? 401 : response.status === 403 ? 403 : 400;
  return new AuxFnOAuthError("oauth_token_exchange_denied", status,
    { type: "denied", error: readOAuthErrorCode(value.error) }, requestId);
}

export function readNativeWarnings(value: unknown): NativeAuthenticationWarnings | undefined {
  if (value === undefined || value === null) return undefined;
  if (!isRecord(value) || !Array.isArray(value.codes) || value.codes.length < 1 || value.codes.length > 2) {
    throw invalidResponse();
  }
  const codes = value.codes.map((code: unknown): NativeWarningCode => {
    if (code !== "evaluation_warning" && code !== "evaluation_degraded") throw invalidResponse();
    return code;
  });
  return { codes, ...(value.decision_id === undefined || value.decision_id === null ? {} : { decision_id: readNativeString(value.decision_id) }) };
}

function readNativeRecovery(value: unknown): NativeAuthenticationRecovery {
  if (!isRecord(value) || (value.code !== "fraud_blocked" && value.code !== "reauthentication_required" &&
      value.code !== "step_up_required") || typeof value.expires_at !== "string" ||
      !Number.isFinite(Date.parse(value.expires_at))) {
    throw invalidResponse();
  }
  return { code: value.code, continuation_id: readNativeString(value.continuation_id), expires_at: value.expires_at };
}

function readOAuthErrorCode(value: string): NativeOAuthErrorCode {
  return NATIVE_OAUTH_ERROR_CODES.find((code) => code === value) ?? "unknown";
}

function readNativeString(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 512) throw invalidResponse();
  return value;
}

function invalidResponse(): AuxFnClientError {
  return new AuxFnClientError("oauth_token_response_invalid", 503);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export type OAuthTokenResource = "userinfo" | "customer_api";
export type OAuthRecoverySource =
  { type: "authorization_code"; code: string;
    attempt: { codeVerifier: string; redirectUri: string; resource?: OAuthTokenResource };
    recovery: NativeAuthenticationRecovery } |
  { type: "refresh_token"; refreshToken: string; recovery: NativeAuthenticationRecovery };
export interface OAuthRecoveryAuthorization {
  redirectUri: string;
  state: string;
  codeChallenge: string;
  scopes: readonly string[];
}
export interface OAuthRecoveryStage {
  stageHandle: string;
  expiresAt: string;
  tokenResource: OAuthTokenResource;
}
