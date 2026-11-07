import { readNativeOAuthFailure, readNativeWarnings, type NativeAuthenticationWarnings, type OAuthRecoverySource, type OAuthRecoveryAuthorization, type OAuthRecoveryStage, type OAuthTokenResource } from "./native-auth.server.js";
import { AuxFnAccountClient, parseAccountUrl, type AuxFnAccountConnection } from "./account-client.server.js";

/** Account authority is configured by the server, never derived from the login callback. */
export interface AuxFnOAuthOptions extends AuxFnAccountConnection {
  clientId: string;
  resourceScope: string;
}

export interface OAuthTokenSet {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  auxWarnings?: NativeAuthenticationWarnings;
}

/** Recover this attempt from durable storage only after verifying browser-bound OAuth state. */
export interface OAuthAttempt {
  codeVerifier: string;
  redirectUri: string;
  /** Preserve this target with a staged recovery callback. Initial identity exchange defaults to UserInfo. */
  resource?: OAuthTokenResource;
}

export interface OAuthResources {
  readonly userInfo: string;
  readonly customerApi: string;
}

/** Owns AuxFn discovery and public-client exchanges; applications own browser state and sessions. */
export class AuxFnOAuthClient extends AuxFnAccountClient {
  private readonly clientId: string;
  private readonly resourceScope: string;
  private resources: Promise<OAuthResources> | undefined;

  constructor(options: AuxFnOAuthOptions) {
    super(options);
    this.clientId = options.clientId;
    this.resourceScope = options.resourceScope;
  }

  async oauthResources(): Promise<OAuthResources> {
    this.resources ??= this.discoverResources().catch((error: unknown) => {
      this.resources = undefined;
      throw error;
    });
    return this.resources;
  }

  /** Uses the saved PKCE attempt and its native resource target; initial identity exchange defaults to UserInfo. */
  async exchangeAuthorizationCode(code: string, attempt: OAuthAttempt): Promise<OAuthTokenSet> {
    const resources = await this.oauthResources();
    return this.exchangeToken(
      new URLSearchParams({
        grant_type: "authorization_code",
        client_id: this.clientId,
        code,
        redirect_uri: attempt.redirectUri,
        code_verifier: attempt.codeVerifier,
        resource: attempt.resource === "customer_api" ? resources.customerApi : resources.userInfo,
      }),
    );
  }

  /** Selects the approved native resource without presenting its token to UserInfo. */
  async refreshToken(refreshToken: string): Promise<OAuthTokenSet & { refreshToken: string }> {
    const resources = await this.oauthResources();
    const tokens = await this.exchangeToken(
      new URLSearchParams({
        grant_type: "refresh_token",
        client_id: this.clientId,
        refresh_token: refreshToken,
        resource: resources.customerApi,
        scope: this.resourceScope,
      }),
    );
    return { ...tokens, refreshToken: tokens.refreshToken ?? refreshToken };
  }

  /** Stage the original held source; native browser binding and proof still own recovery. */
  async stageRecovery(source: OAuthRecoverySource, authorization: OAuthRecoveryAuthorization): Promise<OAuthRecoveryStage> {
    const resources = await this.oauthResources();
    const tokenResource = source.type === "refresh_token" ? "customer_api" : source.attempt.resource ?? "userinfo";
    const resource = tokenResource === "customer_api" ? resources.customerApi : resources.userInfo;
    const response = await this.sendJson("/oauth2/recovery/stage", { method: "POST", body: {
      grant: this.prepareRecoveryGrant(source, resource),
      authorization: this.prepareRecoveryAuthorization(authorization, resource),
    } });
    if (!response.ok) throw await readNativeOAuthFailure(response);
    const value = await this.readJson(response, "oauth_recovery_stage_invalid");
    const stageHandle = this.readString(value, "stage_handle", "oauth_recovery_stage_invalid");
    const expiresAt = this.readString(value, "expires_at", "oauth_recovery_stage_invalid");
    if (stageHandle.length !== 64 || !Number.isFinite(Date.parse(expiresAt))) {
      throw this.createProtocolError("oauth_recovery_stage_invalid", 503);
    }
    return { stageHandle, expiresAt, tokenResource };
  }

  private prepareRecoveryGrant(source: OAuthRecoverySource, resource: string): Record<string, unknown> {
    return source.type === "authorization_code" ? {
      grant_type: "authorization_code", client_id: this.clientId, code: source.code,
      redirect_uri: source.attempt.redirectUri, code_verifier: source.attempt.codeVerifier,
      resource, continuation_id: source.recovery.continuation_id,
    } : {
      grant_type: "refresh_token", client_id: this.clientId, refresh_token: source.refreshToken,
      scope: this.resourceScope, resource, continuation_id: source.recovery.continuation_id,
    };
  }

  private prepareRecoveryAuthorization(authorization: OAuthRecoveryAuthorization, resource: string): Record<string, unknown> {
    return { response_type: "code", client_id: this.clientId,
      redirect_uri: authorization.redirectUri, state: authorization.state,
      code_challenge: authorization.codeChallenge, code_challenge_method: "S256",
      scope: authorization.scopes.join(" "), resource: [resource] };
  }

  async fetchIdentity(accessToken: string): Promise<{ subject: string }> {
    const payload = await this.requestJson("/userinfo", { authorization: `Bearer ${accessToken}` });
    return { subject: this.readString(payload, "sub", "userinfo_invalid") };
  }

  private async discoverResources(): Promise<OAuthResources> {
    const [resource, oidc] = await Promise.all([
      this.requestJson("/.well-known/oauth-protected-resource"),
      this.requestJson("/.well-known/openid-configuration"),
    ]);
    const issuer = this.parseMetadataUrl(oidc.issuer);
    const customerApi = this.parseMetadataUrl(resource.resource);
    const userInfo = this.parseMetadataUrl(oidc.userinfo_endpoint);
    if (
      issuer.host !== this.connection.tenantDomain ||
      issuer.pathname !== "/" ||
      issuer.search !== "" ||
      customerApi.origin !== issuer.origin ||
      customerApi.pathname !== "/" ||
      customerApi.search !== "" ||
      userInfo.href !== new URL("/userinfo", issuer).href ||
      !Array.isArray(resource.authorization_servers) ||
      resource.authorization_servers.length !== 1 ||
      resource.authorization_servers[0] !== oidc.issuer ||
      !Array.isArray(resource.scopes_supported) ||
      !resource.scopes_supported.includes(this.resourceScope)
    ) {
      throw this.createProtocolError("oauth_resource_configuration_invalid", 503);
    }
    return { userInfo: String(oidc.userinfo_endpoint), customerApi: String(resource.resource) };
  }

  private async exchangeToken(body: URLSearchParams): Promise<OAuthTokenSet> {
    const response = await this.sendForm("/oauth2/token", body);
    if (!response.ok) {
      throw await readNativeOAuthFailure(response);
    }
    return this.parseTokenSet(
      await this.readJson(response, "oauth_token_response_invalid"),
      body.get("scope"),
    );
  }

  private parseTokenSet(
    value: Record<string, unknown>,
    expectedScope: string | null,
  ): OAuthTokenSet {
    const accessToken = this.readString(value, "access_token", "oauth_token_response_invalid");
    const expiresIn = value.expires_in;
    if (
      value.token_type !== "Bearer" ||
      (expectedScope !== null && value.scope !== expectedScope) ||
      typeof expiresIn !== "number" ||
      !Number.isSafeInteger(expiresIn) ||
      expiresIn <= 0 ||
      (value.refresh_token !== undefined &&
        (typeof value.refresh_token !== "string" || value.refresh_token.length === 0))
    ) {
      throw this.createProtocolError("oauth_token_response_invalid", 503);
    }
    const warnings = readNativeWarnings(value.aux_warnings);
    return {
      accessToken,
      expiresIn,
      ...(warnings === undefined ? {} : { auxWarnings: warnings }),
      ...(typeof value.refresh_token === "string" ? { refreshToken: value.refresh_token } : {}),
    };
  }

  private parseMetadataUrl(value: unknown): URL {
    if (typeof value !== "string")
      throw this.createProtocolError("oauth_resource_configuration_invalid", 503);
    try {
      return parseAccountUrl(value);
    } catch {
      throw this.createProtocolError("oauth_resource_configuration_invalid", 503);
    }
  }

  private readString(value: Record<string, unknown>, key: string, code: string): string {
    const entry = value[key];
    if (typeof entry !== "string" || entry.length === 0) throw this.createProtocolError(code, 503);
    return entry;
  }
}
