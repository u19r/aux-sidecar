import { env, exports } from "cloudflare:workers";
import { beforeAll, afterAll, vi, describe, expect, it } from "vitest";

import corpus from "../../../target/dpop-adapter-corpus.json";

import { AuxSidecar, type AuxSidecarWorkerEnv } from "../src/index";

describe("Aux Sidecar Worker middleware", () => {
  beforeAll(() => {
    const bindings: AuxSidecarWorkerEnv = env;
    bindings.AUXFN_ISSUER = corpus.issuer;
    bindings.AUXFN_RESOURCE_AUDIENCE = corpus.audience;
    bindings.AUXFN_JWKS_JSON = JSON.stringify(corpus.jwks);
    vi.spyOn(Date, "now").mockReturnValue(corpus.now_seconds * 1000);
  });
  afterAll(() => vi.restoreAllMocks());

  it("enforces the same independent OpenSSL corpus through the Fetch adapter", async () => {
    for (const entry of corpus.cases) {
      if (entry.request_method !== undefined) {
        // Cloudflare Fetch rejects extension methods before an HTTP Request can exist.
        // Prove that transport restriction and the same Worker WASM decision separately.
        expect(() => new Request(corpus.target_uri, { method: entry.request_method })).toThrow(
          /Invalid HTTP method/,
        );
        const sidecar = new AuxSidecar(env);
        const decision = await sidecar.run((client) =>
          JSON.parse(
            client.validateOAuthAccessToken(
              JSON.stringify({
                request: {
                  scheme: "DPoP",
                  token: corpus.access_token,
                  proof: entry.proof,
                  method: entry.request_method,
                  target_uri: corpus.target_uri,
                },
              }),
            ),
          ),
        );
        expect("claims" in decision, entry.name).toBe(entry.accepted);
        continue;
      }
      const response = await exports.default.fetch(
        new Request(corpus.target_uri, {
          method: entry.request_method ?? "GET",
          headers: { authorization: `DPoP ${corpus.access_token}`, dpop: entry.proof },
        }),
      );
      expect(response.status, entry.name).toBe(entry.accepted ? 200 : 401);
      if (!entry.accepted)
        expect(response.headers.get("www-authenticate"), entry.name).toContain(
          'error="invalid_dpop_proof"',
        );
    }
  });

  it("given distinct account configurations when beginning login then each uses its own issuer", async () => {
    const first = new AuxSidecar({
      ...env,
      AUXFN_ISSUER: "https://tenant.example.com",
      AUXFN_BASE_URL: "https://tenant.example.com",
    });
    const second = new AuxSidecar({
      ...env,
      AUXFN_ISSUER: "https://second-account.example.com",
      AUXFN_BASE_URL: "https://second-account.example.com",
    });
    const request = JSON.stringify({
      client_id: "example-client",
      redirect_uri: "http://127.0.0.1:18897/auth/callback",
      scopes: ["openid"],
    });
    const firstLogin = await first.run((client) => JSON.parse(client.beginHostedLogin(request)));
    const secondLogin = await second.run((client) => JSON.parse(client.beginHostedLogin(request)));
    expect(firstLogin.code ?? firstLogin.error?.code).toBeUndefined();
    expect(secondLogin.code ?? secondLogin.error?.code).toBeUndefined();
    expect(new URL(firstLogin.login_url).origin).toBe("https://tenant.example.com");
    expect(new URL(secondLogin.login_url).origin).toBe("https://second-account.example.com");
  });

  it("given distinct signing keys when validating then each runtime keeps its own trust", async () => {
    const accepted = corpus.cases.find((entry) => entry.accepted && entry.request_method === undefined);
    if (accepted === undefined) throw new Error("proof corpus must contain a normal accepted case");
    const trusted = new AuxSidecar(env);
    const other = new AuxSidecar({ ...env, AUXFN_JWKS_JSON: '{"keys":[]}' });
    const request = JSON.stringify({ request: {
      scheme: "DPoP", token: corpus.access_token, proof: accepted.proof, method: "GET", target_uri: corpus.target_uri,
    } });
    const first = await trusted.run((client) => JSON.parse(client.validateOAuthAccessToken(request)));
    const second = await other.run((client) => JSON.parse(client.validateOAuthAccessToken(request)));
    expect("claims" in first).toBe(true);
    expect("claims" in second).toBe(false);
  });

  it("given concurrent accounts when syncing then each sends its own credential and tenant", async () => {
    const calls: Array<{
      host: string;
      key: string | null;
      tenant: string | null;
      authority: string | null;
    }> = [];
    const upstream = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, options) => {
      const headers = new Headers(options?.headers);
      calls.push({
        host: new URL(String(input)).host,
        key: headers.get("X-API-Key"),
        tenant: headers.get("X-Tenant-Domain"),
        authority: headers.get("CF-Connecting-Host"),
      });
      await Promise.resolve();
      return Response.json({
        protocol_version: 1,
        server_time: "2026-10-24T12:00:00Z",
        refresh_after_ms: 5000,
        artifacts: [],
        unchanged: [],
        capabilities: {
          authz: 1,
          rate_limit: 1,
          entitlements: 1,
          blocklist: 1,
          combined_policy: 1,
        },
      });
    });
    try {
      const first = new AuxSidecar({
        ...env,
        AUXFN_BASE_URL: "https://first.example",
        AUXFN_TENANT_DOMAIN: "first.example",
        AUXFN_RUNTIME_API_KEY: "first-runtime-fixture",
      });
      const second = new AuxSidecar({
        ...env,
        AUXFN_BASE_URL: "https://second.example",
        AUXFN_TENANT_DOMAIN: "second.example",
        AUXFN_RUNTIME_API_KEY: "second-runtime-fixture",
      });
      const request = {
        protocol_version: 1,
        known: {},
        want: ["rate_limit_config"],
        entitlements: [],
        blocklist_policy_refs: [],
      };
      await Promise.all([
        first.run((client) => client.sync(request)),
        second.run((client) => client.sync(request)),
      ]);
      expect(calls).toEqual([
        {
          host: "first.example",
          key: "first-runtime-fixture",
          tenant: "first.example",
          authority: "first.example",
        },
        {
          host: "second.example",
          key: "second-runtime-fixture",
          tenant: "second.example",
          authority: "second.example",
        },
      ]);
      const status = await first.run((client) => JSON.stringify(client.status()));
      expect(status).not.toContain("first-runtime-fixture");
    } finally {
      upstream.mockRestore();
    }
  });

  it("given a rejected operation when another is queued then the next operation still runs", async () => {
    const runtime = new AuxSidecar(env);
    const order: string[] = [];
    const failed = runtime.run(async () => {
      order.push("first");
      await Promise.resolve();
      throw new Error("fixture-operation-failed");
    });
    const next = runtime.run(() => {
      order.push("second");
    });
    await expect(failed).rejects.toThrow("fixture-operation-failed");
    await next;
    expect(order).toEqual(["first", "second"]);
  });

  it("rejects coalesced proof headers and malformed schemes before protected work", async () => {
    const proof = corpus.cases[0]?.proof;
    if (proof === undefined) throw new Error("proof corpus must contain a case");
    const headers = new Headers({ authorization: `DPoP ${corpus.access_token}` });
    headers.append("dpop", proof);
    headers.append("dpop", proof);
    const duplicate = await exports.default.fetch(new Request(corpus.target_uri, { headers }));
    expect(duplicate.status).toBe(401);
    expect(duplicate.headers.get("www-authenticate")).toContain('error="invalid_dpop_proof"');
    const malformed = await exports.default.fetch(
      new Request(corpus.target_uri, { headers: { authorization: "DPoP extra token" } }),
    );
    expect(malformed.status).toBe(400);
  });
  it("fails closed before invoking an upstream handler when credentials are missing", async () => {
    const bindings: AuxSidecarWorkerEnv = env;
    expect(bindings.AUXFN_BASE_URL).toContain("tenant.example.com");
    const response = await exports.default.fetch(new Request("https://worker.example/protected"));

    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBe('DPoP algs="ES256", Bearer');
    expect(await response.text()).not.toContain("AUXFN_RUNTIME_API_KEY");
  });

  it("does not expose the private sidecar control API", async () => {
    const response = await exports.default.fetch(
      new Request("https://worker.example/sidecar/status"),
    );

    expect(response.status).toBe(401);
  });

  it("fails closed for an invalid bearer token without disclosing configuration", async () => {
    const response = await exports.default.fetch(
      new Request("https://worker.example/protected", {
        headers: { authorization: "Bearer invalid-fixture-token" },
      }),
    );

    expect(response.status).toBe(401);
    const body = await response.text();
    expect(body).not.toContain("tenant.example.com");
    expect(body).not.toContain("AUXFN_RUNTIME_API_KEY");
  });
});
