#!/usr/bin/env bash
set -euo pipefail

scripts/wasm-build.sh
node - <<'NODE'
const wasm = require("./target/sidecar-wasm-node/sidecar_wasm.js");
const client = new wasm.SidecarClient(globalThis.fetch.bind(globalThis));
if (!client.isReady()) {
  throw new Error("sidecar wasm client is not ready");
}
const configuration = JSON.parse(client.configureTrustedJwt(JSON.stringify({
  issuer: "https://tenant.example.com",
  base_url: "https://tenant.example.com",
  jwks: { keys: [] },
  resource_audiences: ["api://orders"]
})));
if (configuration.configured !== true) {
  throw new Error("sidecar wasm configuration failed");
}
const response = JSON.parse(client.beginHostedLogin(JSON.stringify({
  client_id: "sidecar-canary-hosted-login",
  redirect_uri: "http://127.0.0.1:8787/callback",
  scopes: ["openid"]
})));
if (!response.login_url || !response.login_url.includes("state=")) {
  throw new Error("sidecar wasm beginHostedLogin did not return a login URL with state");
}
NODE
