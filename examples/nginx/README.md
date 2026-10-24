# nginx `auth_request`

Run Aux Sidecar with `--preset proxy --proxy-policy-path
/etc/aux-sidecar/proxy-policy.json`. The internal auth subrequest uses the private Unix socket,
forwards no body, and only sends explicitly mapped original-request/context headers. Do not expose
the socket directory to untrusted containers.
