/* tslint:disable */
/* eslint-disable */

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



export class SidecarClient {
    free(): void;
    [Symbol.dispose](): void;
    acquireLeases(request: any): Promise<any>;
    beginHostedLogin(request_json: string): string;
    capabilities(): any;
    checkRateLimit(request: any): Promise<any>;
    completeHostedLogin(request: any): Promise<any>;
    configureTrustedJwt(config_json: string): string;
    decideBlocklist(request: any): Promise<any>;
    decidePolicy(request: any): Promise<any>;
    evaluateAuthz(request: any): Promise<any>;
    evaluateEntitlements(request: any): Promise<any>;
    getRateLimitConfig(): Promise<any>;
    giveBackLeases(request: any): Promise<any>;
    isReady(): boolean;
    live(): any;
    constructor(fetch: Function);
    oauthChallenge(invalid_proof: boolean): string;
    ready(): any;
    refreshHostedLogin(request: any): Promise<any>;
    status(): any;
    sync(request: any): Promise<any>;
    validateAuthnJwt(request_json: string): string;
    validateOAuthAccessToken(request_json: string): string;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_sidecarclient_free: (a: number, b: number) => void;
    readonly sidecarclient_acquireLeases: (a: number, b: any) => any;
    readonly sidecarclient_beginHostedLogin: (a: number, b: number, c: number, d: number) => void;
    readonly sidecarclient_capabilities: (a: number, b: number) => void;
    readonly sidecarclient_checkRateLimit: (a: number, b: any) => any;
    readonly sidecarclient_completeHostedLogin: (a: number, b: any) => any;
    readonly sidecarclient_configureTrustedJwt: (a: number, b: number, c: number, d: number) => void;
    readonly sidecarclient_decideBlocklist: (a: number, b: any) => any;
    readonly sidecarclient_decidePolicy: (a: number, b: any) => any;
    readonly sidecarclient_evaluateAuthz: (a: number, b: any) => any;
    readonly sidecarclient_evaluateEntitlements: (a: number, b: any) => any;
    readonly sidecarclient_getRateLimitConfig: (a: number) => any;
    readonly sidecarclient_giveBackLeases: (a: number, b: any) => any;
    readonly sidecarclient_isReady: (a: number) => number;
    readonly sidecarclient_live: (a: number, b: number) => void;
    readonly sidecarclient_new: (a: any) => number;
    readonly sidecarclient_oauthChallenge: (a: number, b: number, c: number) => void;
    readonly sidecarclient_ready: (a: number, b: number) => void;
    readonly sidecarclient_refreshHostedLogin: (a: number, b: any) => any;
    readonly sidecarclient_status: (a: number, b: number) => void;
    readonly sidecarclient_sync: (a: number, b: any) => any;
    readonly sidecarclient_validateAuthnJwt: (a: number, b: number, c: number, d: number) => void;
    readonly sidecarclient_validateOAuthAccessToken: (a: number, b: number, c: number, d: number) => void;
    readonly __wasm_bindgen_func_elem_21655: (a: number, b: number, c: number, d: any) => void;
    readonly __wasm_bindgen_func_elem_21657: (a: number, b: number, c: any, d: any) => void;
    readonly __wasm_bindgen_func_elem_810: (a: number, b: number) => void;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export4: (a: number) => void;
    readonly __wbindgen_export5: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_export6: (a: number, b: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export7: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
