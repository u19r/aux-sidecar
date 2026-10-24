# Aux Sidecar

Aux Sidecar is a small local HTTP service that lets your application ask AuxFn for runtime
decisions without embedding AuxFn service code. It is intended to run beside your backend, worker,
registry, gateway, or command-line tool.

## Security Boundary

The native sidecar HTTP service is a private local component. Do not expose `/sidecar/*` routes to
the public internet, a public load balancer, or an untrusted network.

The sidecar holds your AuxFn runtime API key and uses that key when it calls AuxFn. Any process that
can reach the sidecar can ask it to use that API-key authority. Keep the bind address on loopback
(`127.0.0.1`) or on a private container, pod, task, or host network that only the colocated
application can reach. For Docker, Kubernetes, or other orchestrators, expose the sidecar only to the
trusted application that is meant to call it. Do not publish the sidecar port through ingress,
firewall rules, or host port mappings except for local development demos.

If a sidecar port is accidentally exposed to an untrusted network, remove the exposure, rotate the
runtime API key, and review sidecar and AuxFn audit logs for unexpected runtime calls.

Use it when your application needs one or more of these checks:

- authorization decisions;
- rate-limit leases;
- entitlement evaluation;
- runtime blocklist decisions;
- combined registry policy decisions;
- JWT validation for tokens issued by your AuxFn tenant;
- OAuth access-token validation for a known resource audience;
- hosted-login helper endpoints for command-line tools.

## Required Configuration

The sidecar needs a tenant URL, a runtime API key, and an explicit audience policy to start:

| Argument              | Environment              | Meaning                                                                                                             |
| --------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| `--base-url`          | `AUX_BASE_URL`           | Your AuxFn tenant subdomain URL, for example `https://acme.auxfn.example`.                                          |
| `--api-key`           | `AUX_API_KEY`            | A runtime API key allowed to call the AuxFn runtime service you use.                                                |
| `--resource-audience` | `AUX_RESOURCE_AUDIENCES` | The protected API audience accepted for OAuth access tokens. Repeat the argument or use comma-separated env values. |

If this sidecar deployment will never validate OAuth access tokens, pass `--no-audience-check` or
set `AUX_NO_AUDIENCE_CHECK=true`. This opt-out is explicit because skipping audience validation is
not safe for resource-server token checks.

Example:

```sh
sidecar \
  --base-url https://acme.auxfn.example \
  --api-key "$AUX_API_KEY" \
  --resource-audience api://orders
```

The same configuration can be supplied through environment variables:

```sh
export AUX_BASE_URL=https://acme.auxfn.example
export AUX_API_KEY=ak_live_...
export AUX_RESOURCE_AUDIENCES=api://orders
sidecar
```

`AUX_BASE_URL` is the connection address for AuxFn runtime calls and the tenant JWKS endpoint.
It normally equals the public account URL and supplies the default expected JWT issuer. If a
local or VPC connection uses a different address, set `AUX_ISSUER` (or `--issuer`) to the exact
issuer from discovery and set `AUX_TENANT_DOMAIN` for account routing. Token validation and browser
login URLs use that issuer; backend requests continue to use `AUX_BASE_URL`. Production connection
URLs must use HTTPS; HTTP is accepted only for localhost or loopback development targets.

The API key identifies the calling service and organization authorization on the AuxFn side. The
sidecar does not require a separate organization id.

## Optional Configuration

| Argument                     | Environment                    | Default                           | Meaning                                                                                                                                                      |
| ---------------------------- | ------------------------------ | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--bind-addr`                | `AUX_BIND_ADDR`                | `127.0.0.1:9001`                  | Address where your application calls the sidecar.                                                                                                            |
| `--unsafe-bind-non-loopback` | `AUX_UNSAFE_BIND_NON_LOOPBACK` | unset                             | Required to bind the native HTTP sidecar outside loopback. Use only with private network policy that restricts callers to the trusted colocated application. |
| `--no-audience-check`        | `AUX_NO_AUDIENCE_CHECK`        | unset                             | Explicitly disables OAuth resource-audience validation. Cannot be combined with `--resource-audience`.                                                       |
| `--issuer`                   | `AUX_ISSUER`                   | base URL without a trailing slash | Exact expected JWT issuer from account discovery; also supplies the public hosted-login origin. Use when the backend connection address differs.             |
| `--login-redirect-url`       | `AUX_LOGIN_REDIRECT_URL`       | unset                             | URL your app should use when authn JWT validation needs to trigger login.                                                                                    |
| `--jwt-clock-skew-seconds`   | `AUX_JWT_CLOCK_SKEW_SECONDS`   | `0`                               | Allowed JWT clock skew, at most 60 seconds.                                                                                                                  |
| `--cache-ttl-seconds`        | `AUX_CACHE_TTL_SECONDS`        | `60`                              | Fresh runtime-config cache duration.                                                                                                                         |
| `--stale-cache-ttl-seconds`  | `AUX_STALE_CACHE_TTL_SECONDS`  | `300`                             | Stale runtime-config cache duration when AuxFn is temporarily unavailable.                                                                                   |
| `--upstream-url`             | `AUX_UPSTREAM_URL`             | unset                             | HTTP upstream for whole-upstream or route-aware proxying.                                                                                                    |
| `--external-base-url`        | `AUX_EXTERNAL_BASE_URL`        | unset                             | Trusted public HTTPS request base, required for the plaintext proxy; separate from the upstream and tenant issuer.                                           |
| `--route-policy-path`        | `AUX_ROUTE_POLICY_PATH`        | unset                             | OpenAPI 3.1 route policy compiled once before the proxy accepts traffic.                                                                                     |
| `--config-path`              | `AUX_CONFIG_PATH`              | unset                             | Local runtime policy/config JSON file for offline or controlled local operation.                                                                             |
| `--preset`                   | `AUX_SIDECAR_PRESET`           | `kubernetes`                      | Deployment defaults: `worker`, `lambda`, `kubernetes`, `proxy`, or `embedded`; explicit fields still win.                                                    |

Use `--resource-audience` for normal deployments. The issuer identifies the tenant, but the
audience identifies the protected API that the token was minted for. Accepting OAuth access tokens
without an audience check can let a token minted for one API be reused against another API.

## OAuth DPoP presenters

OAuth validation receives the authorization scheme, exact token, actual method, trusted public
request target, and optional DPoP proof together. A verified `cnf.jkt` requires a matching ES256
proof with `ath`; an ordinary unbound token retains Bearer behavior. Unsupported confirmation
never becomes Bearer. Every request validates its proof, including access-token cache hits,
before forwarding or other policy effects. The native, embedded, WASM, Worker and Lambda paths
share the same validator and authentication challenges.

Set `--external-base-url https://api.example/orders` separately from the upstream listener.
The proxy joins actual request paths beneath that public base; caller-supplied forwarding headers
cannot replace it. A reverse proxy using auth-request supplies original method and URI only through
its trusted private boundary. Workers use the actual Fetch Request. The maintained JavaScript and
Python Lambda clients require explicit external HTTPS context and support API Gateway and ALB.
Keep the internal bridge private as described above. Custom bridge callers must provide the full
presenter; validating only a token is insufficient.

Resource proofs have an inclusive 60-second age window and five seconds of future tolerance.
There is no resource nonce or accepted-jti store: a copied proof can replay for the same token,
method and normalized target within that window. HTTPS and application idempotency remain necessary.
AS nonce recovery belongs to the OAuth client at the token endpoint.

## HTTP Route Enforcement

Set `--upstream-url` together with `--route-policy-path` to protect an HTTP application with one
startup-compiled OpenAPI 3.1 document. The document may be a complete OpenAPI document or a compact
object containing `paths`; references must be local `#/...` references. Each operation declares
`x-aux-authn` with `public` or `bearer` mode. Bearer operations may add `x-aux-authz` for required
scopes, bounded JSON claim predicates, and optional `action`/`resource` templates. An optional
`x-aux-fallback` applies only after exact and unambiguous path-template matching.

```yaml
openapi: 3.1.0
info: { title: orders, version: 1.0.0 }
paths:
  /orders/{order_id}:
    get:
      operationId: getOrder
      parameters:
        - in: path
          name: order_id
          required: true
          schema: { type: string, format: uuid }
      x-aux-authn: { mode: bearer, audiences: [api://orders] }
      x-aux-authz:
        required_scopes: [orders.read]
        claims:
          all:
            - { path: $.tenant_tier, equals: enterprise }
```

The sidecar validates the original bearer JWT, checks local revocation state, evaluates every
configured condition, and forwards the unchanged `Authorization` header only after allow. Public
operations reject an invalid supplied bearer; unmatched enforcing routes are denied unless the
explicit fallback allows them. Opaque TCP forwarding, remote references, identity-header minting,
and hot reload are not supported.

## Calling The Sidecar

By default the sidecar listens on `http://127.0.0.1:9001`.

Liveness and readiness checks:

```sh
curl http://127.0.0.1:9001/sidecar/live
curl --fail http://127.0.0.1:9001/sidecar/ready
```

Authorization evaluation:

```sh
curl http://127.0.0.1:9001/sidecar/authz/evaluate \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer <end-user-token>' \
  -H 'x-forwarded-for: 203.0.113.10' \
  -d '{
    "subject": { "type": "user", "id": "user_123" },
    "resource": { "type": "document", "id": "doc_456" },
    "action": { "name": "read" },
    "context": {}
  }'
```

OAuth access-token validation:

```sh
sidecar \
  --base-url https://acme.auxfn.example \
  --api-key "$AUX_API_KEY" \
  --resource-audience api://orders

curl http://127.0.0.1:9001/sidecar/oauth/validate_access_token \
  -H 'content-type: application/json' \
  -d '{ "scheme": "Bearer", "token": "<oauth-access-token>", "method": "GET", "target_uri": "https://api.example/orders" }'
```

## Hosted Login For Command-Line Tools

Hosted-login routes are for applications that are building command-line tools which need to sign in
to an AuxFn-protected backend. This is a local OAuth helper API, separate from the native
`sidecar` process command-line arguments used to launch the server.

`/sidecar/hosted_login/begin` accepts redirect URIs that target localhost or a loopback IP address.
Remote redirect targets are rejected because the route stores PKCE state in the local sidecar
process.

These routes implement the client-side helper pieces of the OAuth authorization-code with PKCE
flow:

- `POST /sidecar/hosted_login/begin` creates the hosted-login URL and stores a short-lived PKCE
  session in the sidecar process.
- `POST /sidecar/hosted_login/complete` exchanges the callback code for tokens and validates the
  returned access token.
- `POST /sidecar/hosted_login/refresh` exchanges a refresh token for a new access token and validates
  it.

The hosted-login and token endpoints are AuxFn-specific. The flow is OIDC/OAuth-shaped, but this
sidecar is not a generic OIDC client for arbitrary identity providers. It expects your AuxFn tenant
subdomain as the issuer and uses that tenant's AuxFn OAuth endpoints.

If your command-line tool uses access tokens to call your own backend, configure
`--resource-audience` to the audience registered for that backend. In that setup, the protected
backend is the resource server; the sidecar is a local verifier/helper that checks the token before
your application trusts it.

## Runtime Routes

The sidecar exposes these local routes:

| Route                                       | Purpose                                                                         |
| ------------------------------------------- | ------------------------------------------------------------------------------- |
| `GET /sidecar/live`                         | Process liveness; never performs upstream I/O.                                  |
| `GET /sidecar/ready`                        | Required synchronized-state readiness; never initiates synchronization.         |
| `GET /sidecar/status`                       | Private sanitized operational and cache status.                                 |
| `GET /sidecar/health`                       | Deprecated compatibility alias for `/sidecar/live`.                             |
| `POST /sidecar/sync`                        | Apply the versioned runtime synchronization contract.                           |
| `POST /sidecar/rate_limit/check`            | Consume locally leased rate-limit tokens.                                       |
| `GET /sidecar/rate_limit/config`            | Load runtime rate-limit configuration.                                          |
| `POST /sidecar/rate_limit/lease`            | Acquire rate-limit leases.                                                      |
| `POST /sidecar/rate_limit/return`           | Return unused rate-limit lease capacity.                                        |
| `POST /sidecar/authz/evaluate`              | Evaluate one authorization decision.                                            |
| `POST /sidecar/entitlements/evaluate`       | Evaluate entitlement keys.                                                      |
| `POST /sidecar/authn/validate_jwt`          | Validate an AuxFn-issued authentication JWT.                                    |
| `POST /sidecar/oauth/validate_access_token` | Validate the complete Bearer or DPoP OAuth presenter for a configured audience. |
| `POST /sidecar/blocklist/decision`          | Evaluate a runtime blocklist decision.                                          |
| `POST /sidecar/policy/decision`             | Evaluate a combined runtime policy decision.                                    |
| `POST /sidecar/hosted_login/begin`          | Start hosted-login PKCE flow for a command-line tool.                           |
| `POST /sidecar/hosted_login/complete`       | Complete hosted-login PKCE flow for a command-line tool.                        |
| `POST /sidecar/hosted_login/refresh`        | Refresh hosted login tokens.                                                    |

Do not log API keys, bearer tokens, raw JWTs, refresh tokens, private key material, or customer PII.

## Build from source

Install the Rust toolchain declared in `rust-toolchain.toml`, Node.js 22 or later, and OpenSSL
for the independent authentication test corpus.

```sh
cargo build --workspace --locked
cargo test --workspace --locked -- --test-threads=1
cargo run --locked -p sidecar -- --help
```

The embedded Rust API is provided by `sidecar-core`; HTTP integration is provided by `sidecar`.
Build WebAssembly with `scripts/wasm-build.sh` after installing `wasm-bindgen-cli` at the version
recorded for `wasm-bindgen` in `Cargo.lock` and adding the `wasm32-unknown-unknown` Rust target.
The [Cloudflare Worker package](packages/cloudflare-worker/README.md),
[Lambda examples](examples/lambda/README.md), [nginx configuration](examples/nginx/README.md),
and [Caddy configuration](examples/caddy/README.md) describe the supported deployment adapters.
Container sources are in `docker/`; Kubernetes charts are in `charts/`.
