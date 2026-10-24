export async function checkRateLimit(request) {
  const response = await fetch("http://127.0.0.1:2773/sidecar/rate_limit/check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
    signal: AbortSignal.timeout(2000)
  });
  if (!response.ok) throw new Error(`sidecar_error:${response.status}`);
  return response.json();
}

// Pass the actual API Gateway/ALB event. externalBaseUrl is operator configuration,
// including any public mapping prefix; it is never the extension's loopback URL.
export async function validateOAuthRequest(event, externalBaseUrl) {
  const base = new URL(externalBaseUrl);
  if (base.protocol !== "https:" || base.username || base.password || base.search || base.hash) throw new Error("invalid_external_base");
  const method = event.requestContext?.http?.method ?? event.httpMethod;
  const path = event.rawPath ?? event.path;
  if (typeof method !== "string" || typeof path !== "string" || !path.startsWith("/")) throw new Error("missing_original_request_context");
  if (!event.requestContext?.http && !event.requestContext?.elb && !event.requestContext?.domainName) throw new Error("missing_gateway_context");
  const authorization = originalHeader(event, "authorization");
  const [presentedScheme, presentedToken, extra] = (authorization ?? "").split(" ");
  const validAuthorization = /^(Bearer|DPoP)$/i.test(presentedScheme ?? "") && presentedToken && extra === undefined;
  const scheme = validAuthorization ? presentedScheme : "Bearer";
  const token = authorization === undefined ? undefined : validAuthorization ? presentedToken : "!";
  let proof = originalHeader(event, "dpop");
  // Preserve malformed presence using an impossible compact value. The shared bridge owns challenges.
  if (proof !== undefined && (proof.length === 0 || proof.length > 24 * 1024 || /[\s,]/.test(proof))) proof = "!";
  const target = base.href.replace(/\/$/, "") + "/" + path.slice(1);
  const response = await fetch("http://127.0.0.1:2773/sidecar/oauth/validate_access_token", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ scheme, token, proof, method, target_uri: target }),
    signal: AbortSignal.timeout(2000)
  });
  return { status: response.status, challenge: response.headers.get("www-authenticate"), body: await response.json() };
}

function originalHeader(event, name) {
  const multiple = Object.entries(event.multiValueHeaders ?? {}).filter(([key]) => key.toLowerCase() === name);
  if (multiple.length > 0) {
    if (multiple.length !== 1 || !Array.isArray(multiple[0][1]) || multiple[0][1].length !== 1) return "!";
    return typeof multiple[0][1][0] === "string" ? multiple[0][1][0] : "!";
  }
  const values = Object.entries(event.headers ?? {}).filter(([key]) => key.toLowerCase() === name);
  if (values.length > 1) return "!";
  return values.length === 0 ? undefined : typeof values[0][1] === "string" ? values[0][1] : "!";
}
