import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { mkdirSync, writeFileSync } from "node:fs";
import { bindDpopCorpus, loadDpopCorpus } from "./dpop-corpus.mjs";

// Both issuer signatures and presenter proofs are produced by Node/OpenSSL, without AuxFn helpers.
export function adapterCorpus() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const now = Math.floor(Date.now() / 1000);
  const issuer = "https://corpus-issuer.example";
  const audience = "corpus-resource";
  const sourceCorpus = loadDpopCorpus();
  const jkt = sourceCorpus.expected_jkt;
  const header = { typ: "at+jwt", alg: "RS256", kid: "corpus-issuer" };
  const claims = { iss: issuer, aud: audience, sub: "corpus-user", tenant: "corpus-tenant", client_id: "corpus-client", token_type: "access_token", principal_type: "user", scope: "read", jti: "corpus-token", iat: now, exp: now + 300, cnf: { jkt } };
  const input = Buffer.from(JSON.stringify(header)).toString("base64url") + "." + Buffer.from(JSON.stringify(claims)).toString("base64url");
  const token = input + "." + sign("sha256", Buffer.from(input), privateKey).toString("base64url");
  return { ...bindDpopCorpus(sourceCorpus, now, token), issuer, audience, jwks: { keys: [{ ...publicKey.export({ format: "jwk" }), alg: "RS256", use: "sig", kid: "corpus-issuer" }] } };
}

const corpus = adapterCorpus();
if (process.argv[2] === "--emit") {
  process.stdout.write(JSON.stringify(corpus));
} else if (process.argv[2] === "--fixture") {
  mkdirSync(dirname(process.argv[3]), { recursive: true });
  writeFileSync(process.argv[3], JSON.stringify(corpus));
} else {
  const require = createRequire(import.meta.url);
  const { SidecarClient } = require("../target/sidecar-wasm-node/sidecar_wasm.js");
  const client = new SidecarClient(globalThis.fetch.bind(globalThis));
  const originalNow = Date.now;
  Date.now = () => corpus.now_seconds * 1000;
  try {
    assert.equal(JSON.parse(client.configureTrustedJwt(JSON.stringify({ issuer: corpus.issuer, base_url: corpus.issuer, jwks: corpus.jwks, resource_audiences: [corpus.audience] }))).configured, true);
    for (const entry of corpus.cases) {
      const result = JSON.parse(client.validateOAuthAccessToken(JSON.stringify({ request: { scheme: "DPoP", token: corpus.access_token, proof: entry.proof, method: entry.request_method ?? "GET", target_uri: corpus.target_uri } })));
      assert.equal("claims" in result, entry.accepted, entry.name);
      if (!entry.accepted) {
        assert.equal(result.status_code, 401, entry.name);
        assert.equal(result.code, "invalid_dpop_proof", entry.name);
        assert.match(result.www_authenticate, /DPoP .*error="invalid_dpop_proof"/, entry.name);
      }
    }
    console.log(`WASM adapter: ${corpus.cases.length} independent corpus cases passed`);
  } finally { Date.now = originalNow; }
}
