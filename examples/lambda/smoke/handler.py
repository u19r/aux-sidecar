import json
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COUNTS = {"sync": 0, "lease": 0}
LOCK = threading.Lock()


class RuntimeFixture(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/runtime/local/sync":
            with LOCK:
                COUNTS["sync"] += 1
            time.sleep(0.5)
            artifacts = [{
                "kind": kind, "key": "tenant", "version": "fixture-v1",
                "etag": "fixture-v1-" + kind, "immutable": True, "payload": {}
            } for kind in request.get("want", [])]
            self.respond({
                "protocol_version": 1, "server_time": "2026-07-11T22:00:00Z",
                "refresh_after_ms": 60000, "artifacts": artifacts, "unchanged": [],
                "capabilities": {"authz": 1, "rate_limit": 1, "entitlements": 1,
                                 "blocklist": 1, "combined_policy": 1},
            })
            return
        if self.path == "/rate-limit/runtime/leases/acquire":
            with LOCK:
                COUNTS["lease"] += 1
                call = COUNTS["lease"]
            denied = call % 2 == 0
            self.respond({"results": [{
                "key": item["key"],
                "lease": None if denied else {
                    "key": item["key"], "lease_id": f"lambda-{call}",
                    "granted_tokens": 1, "expires_at_ms": int(time.time() * 1000) + 60000,
                },
                "retry_after_ms": 1000 if denied else None,
            } for item in request.get("leases", [])]})
            return
        self.send_response(404)
        self.end_headers()

    def respond(self, value):
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


threading.Thread(
    target=ThreadingHTTPServer(("127.0.0.1", 18079), RuntimeFixture).serve_forever,
    daemon=True,
).start()


def fetch(path):
    error = None
    for _ in range(50):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:2773{path}", timeout=0.5) as response:
                return response.status, json.loads(response.read())
        except Exception as current:
            error = current
            time.sleep(0.02)
    raise error


def post(path, value):
    request = urllib.request.Request(
        f"http://127.0.0.1:2773{path}",
        data=json.dumps(value).encode(),
        headers={"content-type": "application/json", "x-forwarded-for": "127.0.0.1"},
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status, json.loads(response.read())


def handler(_event, _context):
    live_status, _live = fetch("/sidecar/live")
    status_code, status = fetch("/sidecar/status")
    sync_request = {
        "protocol_version": 1, "known": {}, "want": ["jwks"],
        "entitlements": [], "blocklist_policy_refs": [],
    }
    before_sync = COUNTS["sync"]
    with ThreadPoolExecutor(max_workers=20) as pool:
        sync_results = list(pool.map(lambda _: post("/sidecar/sync", sync_request), range(20)))
    rate_request = {
        "params": {"limit_per_second": 1, "burst": 0, "lease_duration_ms": 1000,
                   "estimated_nodes": 1, "giveback_grace_ms": 0},
        "key": f"lambda-smoke-{COUNTS['lease']}", "cost": 1,
    }
    _allowed_status, allowed = post("/sidecar/rate_limit/check", rate_request)
    _denied_status, denied = post("/sidecar/rate_limit/check", rate_request)
    return {
        "live_status": live_status,
        "status_code": status_code,
        "preset": status.get("preset"),
        "secret_fields_absent": "api_key" not in status and "base_url" not in status,
        "sync_responses": len(sync_results),
        "sync_upstream_calls": COUNTS["sync"] - before_sync,
        "lease_allowed": allowed.get("allowed"),
        "lease_denied": not denied.get("allowed", True),
    }
