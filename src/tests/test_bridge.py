import base64
import telos.bridge as bridge


def test_bridge_rejects_unlisted_endpoint_before_network(monkeypatch):
    payload = {
        "url": "http://localhost:11434/api/tags",
        "allowed_endpoints": ["http://other.local:11434"],
        "transport": {"allow_loopback": True},
    }
    seen = {}
    def fake_request(method, url, **kwargs):
        decision = kwargs["authorizer"]._policy.evaluate(
            bridge.EndpointPurpose.MODEL_EGRESS,
            type("I", (), {"is_public": False, "endpoint": bridge.endpoint_from_url(url)})(),
        )
        seen["decision"] = decision
        if decision != "allowed":
            raise ValueError(decision)
    monkeypatch.setattr(bridge, "request", fake_request)
    try:
        bridge.handle(payload)
    except ValueError as exc:
        assert str(exc) == "endpoint_not_permitted"
    assert seen["decision"] == "endpoint_not_permitted"


def test_bridge_decodes_request_body_and_encodes_response(monkeypatch):
    class Response:
        status = 200
        headers = (("content-type", "application/json"),)
        body = b'{"ok":true}'
        final_url = "http://localhost:11434/api/generate"
    captured = {}
    def fake_request(method, url, **kwargs):
        captured["body"] = kwargs["body"]
        return Response()
    monkeypatch.setattr(bridge, "request", fake_request)
    body = b'{"model":"x"}'
    result = bridge.handle({
        "method": "POST",
        "url": "http://localhost:11434/api/generate",
        "allowed_endpoints": ["http://localhost:11434"],
        "transport": {"allow_loopback": True},
        "body_base64": base64.b64encode(body).decode("ascii"),
    })
    assert captured["body"] == body
    assert base64.b64decode(result["body_base64"]) == b'{"ok":true}'
