"""Independent Python Lambda event adapter acceptance against the local HTTP verifier bridge."""
import json
import sys
from urllib.parse import urlsplit
from client import validate_oauth_request

corpus = json.load(sys.stdin)
target = urlsplit(corpus["target_uri"])
origin = f"{target.scheme}://{target.netloc}"
for case in corpus["cases"]:
    contexts = [
        {"requestContext": {"http": {"method": case.get("request_method", "GET")}}, "rawPath": target.path},
        {"requestContext": {"elb": {}}, "httpMethod": case.get("request_method", "GET"), "path": target.path},
    ]
    for context in contexts:
        result = validate_oauth_request({**context, "headers": {"authorization": "DPoP " + corpus["access_token"], "dpop": case["proof"]}}, origin)
        assert result["status"] == (200 if case["accepted"] else 401), case["name"]
        if not case["accepted"]:
            assert 'error="invalid_dpop_proof"' in result["challenge"], case["name"]
try:
    validate_oauth_request({"headers": {}}, origin)
    raise AssertionError("missing context accepted")
except ValueError:
    pass

result = validate_oauth_request({"requestContext": {"http": {"method": "GET"}}, "rawPath": "/a"}, origin + "/prefix//")
assert result["status"] == 401
