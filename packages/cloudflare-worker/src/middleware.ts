import { SidecarClient } from "../wasm/sidecar_wasm.js";
import { AuxSidecar, type AuxSidecarWorkerEnv } from "./runtime.server.js";

export function withAuxSidecar(
  next: (request: Request, env: AuxSidecarWorkerEnv, ctx: ExecutionContext) => Promise<Response>,
): ExportedHandlerFetchHandler<AuxSidecarWorkerEnv> {
  const clients = new WeakMap<AuxSidecarWorkerEnv, AuxSidecar>();
  return async (request, env, ctx) => {
    let runtime = clients.get(env);
    if (runtime === undefined) {
      runtime = new AuxSidecar(env);
      clients.set(env, runtime);
    }
    const refusal = await runtime.run((client) => validateRequest(request, client));
    return refusal ?? next(request, env, ctx);
  };
}

function validateRequest(request: Request, sidecar: SidecarClient): Response | undefined {
  const presenter = parsePresenter(request, sidecar);
  if (presenter instanceof Response) return presenter;
  const result: unknown = JSON.parse(
    sidecar.validateOAuthAccessToken(
      JSON.stringify({
        request: {
          ...presenter,
          method: request.method,
          target_uri: request.url,
        },
      }),
    ),
  );
  if (typeof result !== "object" || result === null) {
    return new Response("validation unavailable", { status: 502 });
  }
  if ("claims" in result) return undefined;
  const status =
    "status_code" in result &&
    typeof result.status_code === "number" &&
    result.status_code >= 400 &&
    result.status_code <= 599
      ? result.status_code
      : 502;
  const headers = new Headers();
  if ("www_authenticate" in result && typeof result.www_authenticate === "string")
    headers.set("www-authenticate", result.www_authenticate);
  return new Response("authorization failed", { status, headers });
}

/** Validates the HTTP presenter before entering the shared token/proof verifier. */
function parsePresenter(
  request: Request,
  sidecar: SidecarClient,
): { token: string; scheme: string; proof: string | null } | Response {
  const authorization = request.headers.get("authorization");
  if (authorization === null) {
    return new Response("unauthorized", {
      status: 401,
      headers: { "www-authenticate": sidecar.oauthChallenge(false) },
    });
  }
  const [scheme, token, extra] = authorization.split(" ");
  if (
    extra !== undefined ||
    token === undefined ||
    token.length === 0 ||
    scheme === undefined ||
    !/^(Bearer|DPoP)$/i.test(scheme)
  ) {
    return new Response("invalid request", { status: 400 });
  }
  const proof = request.headers.get("dpop");
  if (proof !== null && (proof.length === 0 || proof.length > 24 * 1024 || /[\s,]/.test(proof))) {
    return new Response("unauthorized", {
      status: 401,
      headers: { "www-authenticate": sidecar.oauthChallenge(true) },
    });
  }
  return { token, scheme, proof };
}
