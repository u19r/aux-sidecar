import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { execFileSync, spawn } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { validateOAuthRequest } from "./client.mjs";

// Real local HTTP bridge transport and real shared WASM verifier; Lambda lifecycle is tested in Rust.
test("given API Gateway and ALB requests when JS and Python adapters present the corpus then decisions and challenges agree", async () => {
  const root = fileURLToPath(new URL("../../", import.meta.url));
  const corpus = JSON.parse(execFileSync(process.execPath, [root + "scripts/dpop-adapter-corpus.mjs", "--emit"], { encoding: "utf8" }));
  const require = createRequire(import.meta.url);
  const { SidecarClient } = require(root + "target/sidecar-wasm-node/sidecar_wasm.js");
  const client = new SidecarClient(globalThis.fetch.bind(globalThis));
  assert.equal(JSON.parse(client.configureTrustedJwt(JSON.stringify({ issuer: corpus.issuer, base_url: corpus.issuer, jwks: corpus.jwks, resource_audiences: [corpus.audience] }))).configured, true);
  const originalNow = Date.now;
  Date.now = () => corpus.now_seconds * 1000;
  const targets = [];
  const bridge = createServer((request, response) => {
    assert.equal(request.url, "/sidecar/oauth/validate_access_token");
    const chunks = [];
    request.on("data", chunk => chunks.push(chunk));
    request.on("end", () => {
      const presenter = JSON.parse(Buffer.concat(chunks).toString());
      targets.push(presenter.target_uri);
      const result = JSON.parse(client.validateOAuthAccessToken(JSON.stringify({ request: presenter })));
      response.writeHead(result.status_code ?? 200, { "content-type": "application/json", ...(result.www_authenticate ? { "www-authenticate": result.www_authenticate } : {}) });
      response.end(JSON.stringify(result));
    });
  });
  await new Promise(resolve => bridge.listen(2773, "127.0.0.1", resolve));
  try {
    const target = new URL(corpus.target_uri);
    for (const entry of corpus.cases) {
      for (const context of [ { requestContext: { http: { method: entry.request_method ?? "GET" } }, rawPath: target.pathname }, { requestContext: { elb: {} }, httpMethod: entry.request_method ?? "GET", path: target.pathname } ]) {
        const result = await validateOAuthRequest({ ...context, headers: { authorization: `DPoP ${corpus.access_token}`, dpop: entry.proof } }, target.origin);
        assert.equal(result.status, entry.accepted ? 200 : 401, entry.name);
        if (!entry.accepted) assert.match(result.challenge, /DPoP .*error="invalid_dpop_proof"/, entry.name);
      }
    }
    await assert.rejects(validateOAuthRequest({ headers: {} }, target.origin), /missing_original_request_context/);
    const malformed = await validateOAuthRequest({ requestContext: { http: { method: "GET" } }, rawPath: target.pathname, headers: { authorization: `DPoP ${corpus.access_token}`, dpop: "one,two" } }, target.origin);
    assert.equal(malformed.status, 401); assert.match(malformed.challenge, /invalid_dpop_proof/);
    const duplicate = await validateOAuthRequest({ requestContext: { http: { method: "GET" } }, rawPath: target.pathname, multiValueHeaders: { authorization: [`DPoP ${corpus.access_token}`], dpop: [corpus.cases[0].proof, corpus.cases[0].proof] } }, target.origin);
    assert.equal(duplicate.status, 401); assert.match(duplicate.challenge, /invalid_dpop_proof/);
    const missing = await validateOAuthRequest({ requestContext: { http: { method: "GET" } }, rawPath: target.pathname }, target.origin);
    assert.equal(missing.status, 401); assert(!missing.challenge.includes("error="));
    await validateOAuthRequest({ requestContext: { http: { method: "GET" } }, rawPath: "/a" }, target.origin + "/prefix//");
    assert.equal(targets.at(-1), target.origin + "/prefix//a");
    const python = spawn("python3", ["-B", fileURLToPath(new URL("dpop-corpus.py", import.meta.url))], { stdio: ["pipe", "pipe", "pipe"] });
    let errors = ""; python.stderr.on("data", chunk => { errors += chunk; });
    python.stdin.end(JSON.stringify(corpus));
    const exit = await new Promise((resolve, reject) => { python.once("exit", resolve); python.once("error", reject); });
    assert.equal(exit, 0, errors);
    assert.equal(targets.at(-1), target.origin + "/prefix//a");
  } finally {
    Date.now = originalNow; bridge.closeAllConnections(); await new Promise(resolve => bridge.close(resolve));
  }
});
