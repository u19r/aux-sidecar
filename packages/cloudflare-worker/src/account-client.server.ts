export interface AuxFnAccountConnection {
  apiBaseUrl: string;
  tenantDomain: string;
}

export interface JsonRequestOptions {
  method?: "GET" | "POST" | "DELETE";
  body?: unknown;
  authorization?: string;
  serviceToken?: string;
  signal?: AbortSignal;
}

/** Stable transport failures never include a credential or provider response body. */
export class AuxFnClientError extends Error {
  constructor(
    readonly code: string,
    readonly status: 401 | 403 | 503,
  ) {
    super(code);
  }
}

/** Binds account protocol requests to one server-selected API address and tenant. */
export class AuxFnAccountClient {
  protected readonly connection: Readonly<AuxFnAccountConnection>;

  constructor(connection: AuxFnAccountConnection) {
    const url = parseAccountUrl(connection.apiBaseUrl);
    if (url.pathname !== "/" || url.search) {
      throw new AuxFnClientError("auxfn_connection_invalid", 503);
    }
    this.connection = { apiBaseUrl: url.origin, tenantDomain: connection.tenantDomain };
  }

  protected createProtocolError(code: string, status: 401 | 403 | 503): Error {
    return new AuxFnClientError(code, status);
  }

  protected async requestJson(
    path: string,
    options: JsonRequestOptions = {},
  ): Promise<Record<string, unknown>> {
    const response = await this.sendJson(path, options);
    if (!response.ok) {
      throw this.createProtocolError(
        response.status === 403 ? "authorization_denied" : "auxfn_request_failed",
        response.status === 401 ? 401 : response.status === 403 ? 403 : 503,
      );
    }
    return this.readJson(response, "auxfn_request_failed");
  }

  protected async sendJson(path: string, options: JsonRequestOptions): Promise<Response> {
    const hasBody = options.body !== undefined;
    const headers = this.buildHeaders(hasBody ? "application/json" : undefined);
    if (options.authorization) headers.set("Authorization", options.authorization);
    if (options.serviceToken) headers.set("X-API-Key", options.serviceToken);
    return this.fetchResponse(path, {
      method: options.method ?? "GET",
      headers,
      ...(hasBody ? { body: JSON.stringify(options.body) } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
    });
  }

  protected async sendForm(path: string, body: URLSearchParams): Promise<Response> {
    return this.fetchResponse(path, {
      method: "POST",
      headers: this.buildHeaders("application/x-www-form-urlencoded"),
      body,
    });
  }

  protected async readJson(response: Response, code: string): Promise<Record<string, unknown>> {
    const value: unknown = await response.json().catch(() => undefined);
    if (!isRecord(value)) {
      throw this.createProtocolError(code, 503);
    }
    return value;
  }

  private async fetchResponse(path: string, options: RequestInit): Promise<Response> {
    return fetch(new URL(path, this.connection.apiBaseUrl), { ...options, redirect: "manual" }).catch(() => {
      throw this.createProtocolError("auxfn_request_failed", 503);
    });
  }

  private buildHeaders(contentType?: string): Headers {
    const headers = new Headers({
      Accept: "application/json",
      "X-Tenant-Domain": this.connection.tenantDomain,
      "CF-Connecting-Host": this.connection.tenantDomain,
    });
    if (contentType) headers.set("Content-Type", contentType);
    return headers;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseAccountUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AuxFnClientError("auxfn_connection_invalid", 503);
  }
  const isLoopback = url.hostname === "localhost" || url.hostname === "[::1]" ||
    /^127(?:\.\d{1,3}){3}$/.test(url.hostname);
  if ((url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback)) ||
      url.username || url.password || url.hash) {
    throw new AuxFnClientError("auxfn_connection_invalid", 503);
  }
  return url;
}
