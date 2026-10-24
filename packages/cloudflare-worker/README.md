# Aux Sidecar for Cloudflare Workers

This package supplies the shared Rust/WASM engine, an account-bound runtime, and optional HTTP
access-token middleware. The package contains its WASM and licenses; applications do not copy
WASM glue or install a global fetch hook.

## Create one runtime for each account configuration

```ts
import { AuxSidecar, type AuxSidecarWorkerEnv } from "@auxfn/sidecar-cloudflare-worker";

function createRuntime(env: AuxSidecarWorkerEnv): AuxSidecar {
  return new AuxSidecar(env);
}
```

Create the runtime in your application's existing lifecycle owner and reuse it for that account.
Its `run` callback borrows the configured client for one operation:

```ts
const result: unknown = await runtime.run((client) => client.evaluateAuthz(request));
```

`request` is the resource, action and subject evaluation described by the Sidecar contract. The
application must enforce the returned decision before changing its resource. Token authentication
alone does not grant an application permission.

`run` serializes operations on the same WASM client and releases the queue even when an operation
fails. Different runtime instances have independent queues, caches and transport capabilities.
Do not retain the borrowed client beyond its callback. WASM compilation is shared because it has
no account configuration; configured clients are never shared between instances.

Supply these server bindings:

| Binding | Purpose |
| --- | --- |
| `AUXFN_BASE_URL` | The account's AuxFn API address. |
| `AUXFN_ISSUER`, `AUXFN_JWKS_JSON` | The token issuer and its trusted signing keys. |
| `AUXFN_RESOURCE_AUDIENCE` | The application resource audience. |
| `AUXFN_TENANT_DOMAIN` | The account's tenant routing domain. |
| `AUXFN_RUNTIME_API_KEY` | A runtime credential with the service bindings needed by the chosen operations. |

Store the runtime credential through Worker secret bindings. Each instance captures its own
configuration and fetch capability. Credentials stay in the JavaScript host closure, outside WASM
configuration and status output. Create a new runtime when rotating those bindings.
Local authorization is enforced; a missing policy snapshot may be fetched from AuxFn with the
configured runtime authority. Unavailable policy is not permission to allow a mutation.

The engine's hosted-login helpers currently accept loopback callbacks. A deployed browser
application still needs its own durable OAuth-attempt and session owner, cookie/CSRF protection,
and the appropriate hosted authorization flow.

## Exchange application OAuth credentials

`AuxFnOAuthClient` owns account metadata validation, tenant headers, PKCE code exchange, UserInfo,
and selection of an approved native resource. It does not store browser state, cookies or tokens.
Register the public PKCE client and approve its native resource scope before using it.

```ts
import { AuxFnOAuthClient } from "@auxfn/sidecar-cloudflare-worker";

const oauth = new AuxFnOAuthClient({
  apiBaseUrl: "https://your-account.auxfn.com",
  tenantDomain: "your-account.auxfn.com",
  clientId: "example-client",
  resourceScope: "auxfn:billing:read",
});
```

After validating browser-bound OAuth state, recover the original verifier and redirect URI from
durable storage. Exchange the code with that stored attempt, resolve identity, then select native
customer authority from the approved refresh grant:

```ts
const identity = await oauth.exchangeAuthorizationCode(code, verifiedStoredAttempt);
const person = await oauth.fetchIdentity(identity.accessToken);
if (!identity.refreshToken) throw new Error("refresh_grant_missing");
const customer = await oauth.refreshToken(identity.refreshToken);
```

`fetchIdentity` returns the OIDC `subject`; interpret it using the client's registered subject
policy. A public subject can identify the AuxFn person; a pairwise subject is specific to the
registered client and must not be treated as the canonical person ID.

Request `offline_access` in the authorization flow when native delegation and later renewal are
needed. Store the resulting native tokens in the application session, bound to the selected person
and organization. Present the identity token only to UserInfo; present the native token to the
approved customer API. The client verifies discovery agreement before exchanging credentials and
validates token type, scope, expiry and refresh responses. A transient token-service error remains
503; a rejected credential returns 401. Provider bodies and credentials are excluded from errors.

The application still owns one-time OAuth state, PKCE-attempt persistence, redirect handling,
cookies, CSRF and current-organization checks. Subclasses may override `createProtocolError` to
retain an existing application error contract while sharing the protocol and transport implementation.

## Protect a Worker HTTP handler

```ts
import { withAuxSidecar } from "@auxfn/sidecar-cloudflare-worker";

export default {
  fetch: withAuxSidecar(async () => new Response("Authenticated")),
};
```

The middleware validates the access token and any DPoP proof before invoking the handler. It
retains a runtime per immutable Worker environment binding object. Perform application-specific
authorization in the handler. The private `/sidecar/*` control API is never exposed by this package.
Cold isolate starts create fresh caches; no timer or `waitUntil` task is needed for correctness.

## Build and consume the verified package locally

From the Sidecar repository, run `scripts/package-cloudflare-worker.sh`. The producer builds WASM,
checks TypeScript, runs the real Worker tests and deployment dry run, then emits an npm archive
and `artifact-receipt.json` under `target/cloudflare-worker-package`.
The receipt identifies the archive checksum and records whether source changes were present;
it does not claim a dirty checkout is the recorded Git commit alone.

Install that npm archive as a locked file dependency until a registry release is available.
The package ships compiled JavaScript and declarations, so consumers do not need the producer's
TypeScript version. Raw WASM consumers construct `SidecarClient` with an explicit fetch function;
there is no ambient `__auxSidecarFetch` compatibility path.
