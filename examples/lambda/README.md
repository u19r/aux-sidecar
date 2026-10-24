# AWS Lambda external extension

Attach the architecture-matching Aux Sidecar layer and configure `AUX_BASE_URL`, `AUX_API_KEY`,
and either `AUX_RESOURCE_AUDIENCES` or `AUX_NO_AUDIENCE_CHECK=true`. The extension registers for
`INVOKE` and `SHUTDOWN`, then serves the shared sidecar router at `127.0.0.1:2773` for the lifetime
of the warm execution environment. It does not rely on background work while Lambda is frozen.

For container-image functions, copy the same `aux-sidecar` executable to
`/opt/extensions/aux-sidecar`; Lambda layers cannot be attached to container-image functions.

See `client.py` and `client.mjs` for loopback calls. Rust functions can instead embed
`sidecar-core` and call `SidecarEngine` directly without serialization.
