import { afterEach, describe, expect, it, vi } from "vitest";
import nativeCases from "../../../crates/sidecar-fixtures/assets/native-auth.v1.json";
import { AuxFnOAuthClient, AuxFnOAuthError, AuxFnClientError } from "../src/index";

const issuer = "https://seller.example";
const scope = "auxfn:billing:read";
const options = { apiBaseUrl: "http://127.0.0.1:18940", tenantDomain: "seller.example",
  clientId: "example-client", resourceScope: scope };

afterEach(() => vi.restoreAllMocks());

describe("native authentication outcomes", () => {
  it.each(nativeCases)("given native $name when refreshing then preserve its typed outcome without provider text", async (item) => {
    mockNative(async () => Response.json({ ...item.body, ...(item.status === 200 ? { scope } : {}) }, {
      status: item.status,
      headers: item.retry_after_seconds === null ? {} : { "retry-after": String(item.retry_after_seconds) },
    }));
    const client = new AuxFnOAuthClient(options);
    if (item.status === 200) {
      expect((await client.refreshToken("original-refresh")).auxWarnings).toEqual(item.expected_warnings);
    } else {
      const error = await captureOAuthError(client.refreshToken("original-refresh"));
      expect(error.code).toBe(item.expected_code);
      expect(error.status).toBe(item.expected_status);
      expect(error.authentication).toEqual(item.expected_authentication);
      expect(JSON.stringify(error)).not.toContain("must_not_copy_provider_diagnostic");
    }
  });

  it("given held refresh when staging and exchanging replacement code then retain client resource and original proof", async () => {
    const hold = nativeCases.find(item => item.name === "step_up_required");
    if (!hold) throw new Error("recovery corpus missing");
    let staged = false;
    mockNative(async (url, init) => {
      const headers = new Headers(init?.headers);
      expect(headers.has("authorization")).toBe(false);
      expect(headers.has("x-api-key")).toBe(false);
      if (url.pathname === "/oauth2/recovery/stage") {
        expect(init?.method).toBe("POST");
        const body = readStageBody(init);
        expect(body.grant).toMatchObject({ grant_type: "refresh_token", client_id: options.clientId,
          refresh_token: "held-refresh", resource: issuer, scope,
          continuation_id: hold.body.aux_recovery?.continuation_id });
        expect(body.authorization).toMatchObject({ client_id: options.clientId,
          state: "new-browser-state", code_challenge: "new-pkce-challenge", code_challenge_method: "S256",
          resource: [issuer], redirect_uri: "https://app.example/callback" });
        staged = true;
        return Response.json({ stage_handle: "a".repeat(64), expires_at: "2099-01-01T00:00:00Z" });
      }
      const form = new URLSearchParams(String(init?.body));
      if (form.get("grant_type") === "refresh_token") return Response.json(hold.body, { status: 400 });
      expect(staged).toBe(true);
      expect(form.get("resource")).toBe(issuer);
      expect(form.get("code_verifier")).toBe("new-pkce-verifier");
      return Response.json({ access_token: "native-replacement", token_type: "Bearer", expires_in: 300, scope });
    });
    const client = new AuxFnOAuthClient(options);
    const held = await captureOAuthError(client.refreshToken("held-refresh"));
    if (held.authentication.type !== "recovery_required") throw new Error("typed recovery missing");
    const stage = await client.stageRecovery({ type: "refresh_token", refreshToken: "held-refresh",
      recovery: held.authentication.recovery }, { redirectUri: "https://app.example/callback",
      state: "new-browser-state", codeChallenge: "new-pkce-challenge", scopes: [scope] });
    expect(stage.tokenResource).toBe("customer_api");
    expect(await client.exchangeAuthorizationCode("native-replacement-code", {
      redirectUri: "https://app.example/callback", codeVerifier: "new-pkce-verifier", resource: stage.tokenResource,
    })).toMatchObject({ accessToken: "native-replacement" });
  });

  it("given held identity code when staging then retain original PKCE and UserInfo target", async () => {
    const hold = nativeCases.find(item => item.name === "reauthentication_required");
    if (!hold) throw new Error("recovery corpus missing");
    mockNative(async (url, init) => {
      if (url.pathname !== "/oauth2/recovery/stage") return Response.json(hold.body, { status: 400 });
      const body = readStageBody(init);
      expect(body.grant).toMatchObject({ grant_type: "authorization_code", client_id: options.clientId,
        code: "original-code", code_verifier: "original-pkce", redirect_uri: "https://app.example/callback",
        resource: `${issuer}/userinfo` });
      expect(body.authorization.resource).toEqual([`${issuer}/userinfo`]);
      return Response.json({ stage_handle: "a".repeat(64), expires_at: "2099-01-01T00:00:00Z" });
    });
    const client = new AuxFnOAuthClient(options);
    const attempt = { codeVerifier: "original-pkce", redirectUri: "https://app.example/callback" };
    const held = await captureOAuthError(client.exchangeAuthorizationCode("original-code", attempt));
    if (held.authentication.type !== "recovery_required") throw new Error("typed recovery missing");
    expect((await client.stageRecovery({ type: "authorization_code", code: "original-code", attempt,
      recovery: held.authentication.recovery }, { redirectUri: attempt.redirectUri, state: "replacement-state",
      codeChallenge: "replacement-challenge", scopes: ["openid"] })).tokenResource).toBe("userinfo");
  });

  it.each([{ codes: [] }, { codes: ["fake_clean_evidence"] }, { codes: ["evaluation_warning", "evaluation_degraded", "evaluation_warning"] }])(
    "given malformed native warning when parsing success then do not treat it as clean evidence", async (aux_warnings) => {
      mockNative(async () => Response.json({ access_token: "fixture-access", token_type: "Bearer", expires_in: 300, scope, aux_warnings }));
      await expect(new AuxFnOAuthClient(options).refreshToken("original-refresh"))
        .rejects.toMatchObject({ code: "oauth_token_response_invalid", status: 503 });
    });
});

async function captureOAuthError(promise: Promise<unknown>): Promise<AuxFnOAuthError> {
  const error: unknown = await promise.then(() => undefined, (error: unknown) => error);
  if (!(error instanceof AuxFnOAuthError)) throw new Error("expected safe native OAuth failure");
  expect(error).toBeInstanceOf(AuxFnClientError);
  return error;
}

function mockNative(handler: (url: URL, init: RequestInit | undefined) => Promise<Response>): void {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = new URL(String(input));
    expect(init?.redirect).toBe("manual");
    if (url.pathname === "/.well-known/oauth-protected-resource") {
      return Response.json({ resource: issuer, authorization_servers: [issuer], scopes_supported: [scope] });
    }
    if (url.pathname === "/.well-known/openid-configuration") {
      return Response.json({ issuer, userinfo_endpoint: `${issuer}/userinfo` });
    }
    return handler(url, init);
  });
}

function readStageBody(init: RequestInit | undefined): { grant: Record<string, unknown>; authorization: Record<string, unknown> } {
  const value: unknown = JSON.parse(String(init?.body));
  if (!isRecord(value) || !isRecord(value.grant) || !isRecord(value.authorization)) throw new Error("stage body missing");
  return { grant: value.grant, authorization: value.authorization };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
