import { createServer } from "node:http";

const server = createServer((request, response) => {
  if (
    request.method !== "POST" ||
    request.url !== "/runtime/local/sync" ||
    request.headers["x-api-key"] !== "worker-backend-fixture-secret" ||
    request.headers["x-tenant-domain"] !== "worker-fixture.example"
  ) {
    response.writeHead(400, { "content-type": "application/json" });
    response.end(JSON.stringify({ code: "fixture_request_invalid" }));
    return;
  }
  let body = "";
  request.setEncoding("utf8");
  request.on("data", (chunk) => { body += chunk; });
  request.on("end", () => {
    const payload = JSON.parse(body);
    if (payload.protocol_version !== 1 || !payload.want.includes("rate_limit_config")) {
      response.writeHead(400, { "content-type": "application/json" });
      response.end(JSON.stringify({ code: "fixture_payload_invalid" }));
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      protocol_version: 1,
      server_time: "2026-07-11T12:00:00Z",
      refresh_after_ms: 5000,
      artifacts: [{
        kind: "rate_limit_config",
        key: "tenant",
        version: "fixture-v1",
        etag: "fixture-etag-v1",
        immutable: false,
        max_age_ms: 5000,
        payload: { config: { routes: [] }, resolved: null }
      }],
      unchanged: [],
      capabilities: { authz: 1, rate_limit: 1, entitlements: 1, blocklist: 1, combined_policy: 1 }
    }));
  });
});

server.listen(18787, "127.0.0.1");
