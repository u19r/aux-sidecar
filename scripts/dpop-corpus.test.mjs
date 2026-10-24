import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import test from "node:test";
import { bindDpopCorpus, loadDpopCorpus } from "./dpop-corpus.mjs";

const corpus = loadDpopCorpus();
const now = corpus.now_seconds + 86400;
const token = "adapter.issuer.token";
const rebound = bindDpopCorpus(corpus, now, token);

test("given the published corpus when binding an adapter token then preserves every case and byte boundary", () => {
  assert.equal(rebound.cases.length, corpus.cases.length);
  assert.equal(rebound.expected_jkt, corpus.expected_jkt);
  for (let index = 0; index < corpus.cases.length; index++) {
    const original = corpus.cases[index];
    const result = rebound.cases[index];
    assert.equal(result.name, original.name);
    assert.equal(result.accepted, original.accepted);
    const before = original.proof.split(".");
    const after = result.proof.split(".");
    assert.equal(after[0], before[0], original.name);
    assert.equal(result.proof.length, original.proof.length, original.name);
    if (before.length === 3) {
      assert.equal(
        Buffer.from(after[1], "base64url").length,
        Buffer.from(before[1], "base64url").length,
        original.name,
      );
      assert.equal(
        Buffer.from(after[2], "base64url").length,
        Buffer.from(before[2], "base64url").length,
        original.name,
      );
    }
  }
});

test("given signed proof fixtures when rebinding then keeps signatures valid and exact fractional time limits", () => {
  const valid = rebound.cases.find((entry) => entry.name === "valid ES256").proof.split(".");
  const header = JSON.parse(Buffer.from(valid[0], "base64url").toString());
  const payload = JSON.parse(Buffer.from(valid[1], "base64url").toString());
  assert.equal(payload.iat, now);
  assert.equal(payload.ath, createHash("sha256").update(token).digest("base64url"));
  assert.equal(
    verify(
      "sha256",
      Buffer.from(valid.slice(0, 2).join(".")),
      { key: createPublicKey({ key: header.jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" },
      Buffer.from(valid[2], "base64url"),
    ),
    true,
  );
  const fractional = rebound.cases.find((entry) => entry.name === "fraction above future bound");
  assert.match(
    Buffer.from(fractional.proof.split(".")[1], "base64url").toString(),
    new RegExp(`"iat":${now + 5}\\.00000000000000001`),
  );
});
