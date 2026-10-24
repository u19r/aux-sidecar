import { afterEach, describe, expect, it, vi } from "vitest";
import { AuxFnOAuthClient, AuxFnClientError } from "../src/index";

const issuer = "https://seller.example";
const scope = "auxfn:billing:read";
const options = {
  apiBaseUrl: "http://127.0.0.1:18940",
  tenantDomain: "seller.example",
  clientId: "example-client",
  resourceScope: scope,
};
const validResource = {
  resource: issuer,
  authorization_servers: [issuer],
  scopes_supported: [scope],
};

afterEach(() => vi.restoreAllMocks());

describe("AuxFn public-client OAuth protocol", () => {
  it.each([
    "http://remote.example", "ftp://localhost", "not a URL",
    "https://user:password@seller.example", "https://seller.example/path",
    "https://seller.example?query=1", "https://seller.example#fragment",
  ])("given unsafe API origin %s when constructing then credentials cannot be sent", (apiBaseUrl) => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    expect(() => new AuxFnOAuthClient({ ...options, apiBaseUrl }))
      .toThrow("auxfn_connection_invalid");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("given one grant when selecting identity and native authority then audiences remain separate", async () => {
    const forms: URLSearchParams[] = [];
    mockProvider(async (url, init) => {
      expect(init?.redirect).toBe("manual");
      const headers = new Headers(init?.headers);
      expect(headers.get("X-Tenant-Domain")).toBe(options.tenantDomain);
      expect(headers.get("CF-Connecting-Host")).toBe(options.tenantDomain);
      if (url.pathname === "/userinfo") {
        expect(headers.get("Authorization")).toBe("Bearer identity-access");
        return Response.json({ sub: "person-one" });
      }
      const form = tokenForm(init);
      forms.push(form);
      return Response.json({
        access_token: forms.length === 1 ? "identity-access" : "native-access",
        refresh_token: "rotated-refresh",
        token_type: "Bearer",
        expires_in: 300,
        ...(form.get("scope") ? { scope: form.get("scope") } : {}),
      });
    });
    const client = new AuxFnOAuthClient(options);
    const identity = await client.exchangeAuthorizationCode("one-time-code", {
      codeVerifier: "stored-pkce",
      redirectUri: "https://app.example/auth/callback",
    });
    expect(await client.fetchIdentity(identity.accessToken)).toEqual({ subject: "person-one" });
    expect(await client.refreshToken("approved-refresh")).toMatchObject({
      accessToken: "native-access",
      refreshToken: "rotated-refresh",
    });
    expect(forms[0]?.get("resource")).toBe(`${issuer}/userinfo`);
    expect(forms[0]?.get("code_verifier")).toBe("stored-pkce");
    expect(forms[0]?.get("redirect_uri")).toBe("https://app.example/auth/callback");
    expect(forms[1]?.get("resource")).toBe(issuer);
    expect(forms[1]?.get("scope")).toBe(scope);
  });

  it("given downgraded discovery when exchanging then no credentials are sent", async () => {
    let requests = 0;
    const insecureIssuer = "http://seller.example";
    mockProvider(async () => {
      requests += 1;
      return Response.json({});
    }, { ...validResource, resource: insecureIssuer, authorization_servers: [insecureIssuer] }, {
      issuer: insecureIssuer, userinfo_endpoint: `${insecureIssuer}/userinfo`,
    });
    await expect(new AuxFnOAuthClient(options).refreshToken("approved-refresh"))
      .rejects.toMatchObject({ code: "oauth_resource_configuration_invalid", status: 503 });
    expect(requests).toBe(0);
  });

  it.each([
    { ...validResource, resource: "https://foreign.example" },
    { ...validResource, authorization_servers: ["https://foreign.example"] },
    { ...validResource, authorization_servers: [issuer, "https://foreign.example"] },
    { ...validResource, scopes_supported: ["openid"] },
    { ...validResource, resource: "malformed" },
    { ...validResource, resource: `${issuer}/customer` },
    { ...validResource, resource: `${issuer}/?customer=other` },
    { ...validResource, resource: "https://credential@seller.example" },
  ])(
    "given mismatched metadata %j when exchanging then no token request is sent",
    async (metadata) => {
      let tokens = 0;
      mockProvider(async () => {
        tokens += 1;
        return Response.json({});
      }, metadata);
      await expect(
        new AuxFnOAuthClient(options).refreshToken("approved-refresh"),
      ).rejects.toMatchObject({ code: "oauth_resource_configuration_invalid", status: 503 });
      expect(tokens).toBe(0);
    },
  );

  it.each([
    { issuer: "https://foreign.example", userinfo_endpoint: "https://foreign.example/userinfo" },
    { issuer: `${issuer}/oauth`, userinfo_endpoint: `${issuer}/userinfo` },
    { issuer, userinfo_endpoint: "https://foreign.example/userinfo" },
    { issuer, userinfo_endpoint: `${issuer}/userinfo?other=resource` },
  ])(
    "given mismatched OIDC metadata %j when exchanging then no token request is sent",
    async (oidc) => {
      let tokens = 0;
      mockProvider(
        async () => {
          tokens += 1;
          return Response.json({});
        },
        validResource,
        oidc,
      );
      await expect(
        new AuxFnOAuthClient(options).refreshToken("approved-refresh"),
      ).rejects.toMatchObject({ code: "oauth_resource_configuration_invalid", status: 503 });
      expect(tokens).toBe(0);
    },
  );

  it("given a provider retaining its refresh token when renewed then the approved token is retained", async () => {
    mockProvider(async () =>
      Response.json({
        access_token: "native-access",
        token_type: "Bearer",
        expires_in: 300,
        scope,
      }),
    );
    expect(await new AuxFnOAuthClient(options).refreshToken("retained-refresh")).toMatchObject({
      refreshToken: "retained-refresh",
    });
  });

  it.each([
    { token_type: "DPoP" },
    { expires_in: 0 },
    { expires_in: 0.5 },
    { scope: "openid" },
    { access_token: "" },
    { refresh_token: "" },
    { refresh_token: 5 },
  ])(
    "given an invalid token field %j when refreshing then no usable token set is returned",
    async (invalid) => {
      mockProvider(async () =>
        Response.json({
          access_token: "native-access",
          token_type: "Bearer",
          expires_in: 300,
          scope,
          ...invalid,
        }),
      );
      await expect(
        new AuxFnOAuthClient(options).refreshToken("approved-refresh"),
      ).rejects.toMatchObject({ code: "oauth_token_response_invalid", status: 503 });
    },
  );

  it.each([
    [400, 401],
    [401, 401],
    [429, 503],
    [500, 503],
    [503, 503],
  ])(
    "given token endpoint HTTP%d when exchanging then the stable failure status is %d",
    async (upstream, status) => {
      mockProvider(async () =>
        Response.json({ error: "private-provider-detail" }, { status: upstream }),
      );
      const error = await new AuxFnOAuthClient(options)
        .refreshToken("approved-refresh")
        .catch((value: unknown) => value);
      expect(error).toBeInstanceOf(AuxFnClientError);
      expect(error).toMatchObject({ code: "oauth_token_exchange_failed", status });
      expect(String(error)).not.toContain("private-provider-detail");
    },
  );

  it("given malformed successful JSON when exchanging then the response is rejected", async () => {
    mockProvider(async () => new Response("not-json", { status: 200 }));
    await expect(
      new AuxFnOAuthClient(options).refreshToken("approved-refresh"),
    ).rejects.toMatchObject({ code: "oauth_token_response_invalid", status: 503 });
  });

  it("given failed discovery when retried then the failed promise is not retained", async () => {
    const fetch = mockProvider(async () => Response.json({}));
    fetch.mockRejectedValueOnce(new Error("private-network-detail"));
    const client = new AuxFnOAuthClient(options);
    await expect(client.oauthResources()).rejects.toMatchObject({
      code: "auxfn_request_failed",
      status: 503,
    });
    expect(await client.oauthResources()).toEqual({
      userInfo: `${issuer}/userinfo`,
      customerApi: issuer,
    });
  });
});

function mockProvider(
  protocol: (url: URL, init: RequestInit | undefined) => Promise<Response>,
  metadata: unknown = validResource,
  oidc: unknown = { issuer, userinfo_endpoint: `${issuer}/userinfo` },
) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.pathname === "/.well-known/oauth-protected-resource") return Response.json(metadata);
    if (url.pathname === "/.well-known/openid-configuration") return Response.json(oidc);
    return protocol(url, init);
  });
}

function tokenForm(init: RequestInit | undefined): URLSearchParams {
  if (!(init?.body instanceof URLSearchParams)) throw new Error("expected OAuth form body");
  return init.body;
}
