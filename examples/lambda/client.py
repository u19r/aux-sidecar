import json
import urllib.request
import urllib.error


def check_rate_limit(request: dict) -> dict:
    body = json.dumps(request).encode("utf-8")
    call = urllib.request.Request(
        "http://127.0.0.1:2773/sidecar/rate_limit/check",
        data=body,
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(call, timeout=2) as response:
        return json.load(response)


def validate_oauth_request(event: dict, external_base_url: str) -> dict:
    from urllib.parse import urlsplit
    base = urlsplit(external_base_url)
    if base.scheme != "https" or not base.hostname or base.username or base.password or base.query or base.fragment:
        raise ValueError("invalid external base")
    context = event.get("requestContext", {})
    method = context.get("http", {}).get("method", event.get("httpMethod"))
    path = event.get("rawPath", event.get("path"))
    if not method or not isinstance(path, str) or not path.startswith("/") or not any(name in context for name in ("http", "elb", "domainName")):
        raise ValueError("missing original gateway request context")
    authorization = _original_header(event, "authorization")
    parts = (authorization or "").split(" ")
    valid_authorization = len(parts) == 2 and parts[0].lower() in ("bearer", "dpop") and bool(parts[1])
    scheme = parts[0] if valid_authorization else "Bearer"
    token = None if authorization is None else parts[1] if valid_authorization else "!"
    proof = _original_header(event, "dpop")
    if proof is not None and (not proof or len(proof) > 24 * 1024 or any(character.isspace() or character == "," for character in proof)):
        proof = "!"  # Impossible compact value: the shared bridge owns the challenge.
    request = {"scheme": scheme, "token": token, "proof": proof, "method": method,
               "target_uri": external_base_url.removesuffix("/") + "/" + path[1:]}
    call = urllib.request.Request("http://127.0.0.1:2773/sidecar/oauth/validate_access_token", data=json.dumps(request).encode(), headers={"content-type": "application/json"})
    try:
        response = urllib.request.urlopen(call, timeout=2)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return {"status": response.code, "challenge": response.headers.get("www-authenticate"), "body": json.load(response)}


def _original_header(event, name):
    values = [value for key, value in event.get("multiValueHeaders", {}).items() if key.lower() == name]
    if values:
        if len(values) != 1 or not isinstance(values[0], list) or len(values[0]) != 1:
            return "!"
        return values[0][0] if isinstance(values[0][0], str) else "!"
    values = [value for key, value in event.get("headers", {}).items() if key.lower() == name]
    if len(values) > 1:
        return "!"
    return None if not values else values[0] if isinstance(values[0], str) else "!"
