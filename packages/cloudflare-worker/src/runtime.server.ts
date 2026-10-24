import init, { SidecarClient } from "../wasm/sidecar_wasm.js";
import sidecarModule from "../wasm/sidecar_wasm_bg.wasm";

export interface AuxSidecarWorkerEnv {
  AUXFN_BASE_URL: string;
  AUXFN_ISSUER: string;
  AUXFN_RESOURCE_AUDIENCE: string;
  AUXFN_RUNTIME_API_KEY: string;
  AUXFN_JWKS_JSON: string;
  AUXFN_TENANT_DOMAIN?: string;
}

// Compiling WASM is configuration-free. Configured clients and credentials are instance-owned.
let initialization: Promise<unknown> | undefined;

/** Owns one account's configured engine, local caches and serialized WASM access. */
export class AuxSidecar {
  private readonly bindings: AuxSidecarWorkerEnv;
  private client: Promise<SidecarClient> | undefined;
  private tail: Promise<void> = Promise.resolve();

  constructor(env: AuxSidecarWorkerEnv) {
    this.bindings = { ...env };
  }

  /** The callback completes before the next operation may borrow this engine. */
  async run<T>(operation: (client: SidecarClient) => T | Promise<T>): Promise<T> {
    const previous = this.tail;
    let release = (): void => undefined;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      this.client ??= this.createClient();
      return await operation(await this.client);
    } finally {
      release();
    }
  }

  private async createClient(): Promise<SidecarClient> {
    initialization ??= init({ module_or_path: sidecarModule });
    await initialization;
    const env = this.bindings;
    const client = new SidecarClient(async (input: RequestInfo | URL, options?: RequestInit) => {
      const headers = new Headers(options?.headers);
      headers.set("X-API-Key", env.AUXFN_RUNTIME_API_KEY);
      if (env.AUXFN_TENANT_DOMAIN) headers.set("CF-Connecting-Host", env.AUXFN_TENANT_DOMAIN);
      return fetch(input, { ...options, headers });
    });
    const configured: unknown = JSON.parse(
      client.configureTrustedJwt(
        JSON.stringify({
          base_url: env.AUXFN_BASE_URL,
          issuer: env.AUXFN_ISSUER,
          jwks: JSON.parse(env.AUXFN_JWKS_JSON),
          resource_audiences: [env.AUXFN_RESOURCE_AUDIENCE],
          tenant_domain: env.AUXFN_TENANT_DOMAIN,
          authz_local_mode: "enforced",
          authz_remote_fallback: "cache_miss",
        }),
      ),
    );
    if (
      typeof configured !== "object" ||
      configured === null ||
      !("configured" in configured) ||
      configured.configured !== true
    ) {
      throw new Error("sidecar_configuration_failed");
    }
    return client;
  }
}
