# Caddy `forward_auth`

The `forward_auth` subrequest uses the private Aux Sidecar Unix socket and an explicit header
allowlist. Mount only the socket directory into Caddy and the sidecar; never publish `/sidecar/*`.
