import { execFileSync } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** The pinned crate owns the corpus; the adapter only binds time and its issuer token. */
export function loadDpopCorpus() {
  const metadata = JSON.parse(
    execFileSync("cargo", ["metadata", "--locked", "--format-version", "1"], {
      cwd: fileURLToPath(new URL("../", import.meta.url)),
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    }),
  );
  const dependency = metadata.packages.find(
    (entry) =>
      entry.name === "oauth-dpop" &&
      entry.source?.startsWith("git+https://github.com/u19r/aux-common?"),
  );
  if (!dependency)
    throw new Error("The adapter corpus requires the pinned GitHub oauth-dpop dependency.");
  return JSON.parse(
    readFileSync(
      join(dirname(dependency.manifest_path), "fixtures/independent-corpus.json"),
      "utf8",
    ),
  );
}

export function bindDpopCorpus(corpus, nowSeconds, accessToken) {
  const privateCase = corpus.cases.find((entry) => entry.name === "private embedded key");
  if (!privateCase) throw new Error("The pinned corpus omitted its published fixture signing key.");
  const header = JSON.parse(Buffer.from(privateCase.proof.split(".")[0], "base64url").toString());
  const privateKey = createPrivateKey({ key: header.jwk, format: "jwk" });
  const binding = {
    privateKey,
    publicKey: createPublicKey(privateKey),
    timeShift: nowSeconds - corpus.now_seconds,
    originalHash: createHash("sha256").update(corpus.access_token).digest("base64url"),
    tokenHash: createHash("sha256").update(accessToken).digest("base64url"),
  };
  return {
    ...corpus,
    now_seconds: nowSeconds,
    access_token: accessToken,
    cases: corpus.cases.map((entry) => ({ ...entry, proof: bindProof(entry.proof, binding) })),
  };
}

function bindProof(proof, binding) {
  const parts = proof.split(".");
  if (parts.length !== 3) return proof;
  const [header, encodedPayload, signature] = parts;
  // Preserve raw JSON, duplicate members, padding, and deliberately malformed signatures.
  const payload = Buffer.from(encodedPayload, "base64url")
    .toString()
    .replaceAll(`"ath":"${binding.originalHash}"`, `"ath":"${binding.tokenHash}"`)
    .replace(
      /"iat":(\d+)(\.\d+)?(?=[,}\s])/g,
      (_, seconds, fraction = "") => `"iat":${Number(seconds) + binding.timeShift}${fraction}`,
    );
  const input = `${header}.${Buffer.from(payload).toString("base64url")}`;
  const oldSignature = Buffer.from(signature, "base64url");
  const isSignedFixture =
    oldSignature.length === 64 &&
    verify(
      "sha256",
      Buffer.from(`${header}.${encodedPayload}`),
      { key: binding.publicKey, dsaEncoding: "ieee-p1363" },
      oldSignature,
    );
  const reboundSignature = isSignedFixture
    ? sign("sha256", Buffer.from(input), {
        key: binding.privateKey,
        dsaEncoding: "ieee-p1363",
      }).toString("base64url")
    : signature;
  return `${input}.${reboundSignature}`;
}
