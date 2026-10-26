"""D3: exposure policy, not-ready vocabulary, proxy isolation, local-only egress."""
import dataclasses
import ipaddress
import socket
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import telos.transport as transport
from telos import (
    EndpointAuthorizer, EndpointPolicyError, EndpointPurpose, EndpointUseRequest,
    ExposurePolicy, ServingCode, TransportPolicy, build_error_body, endpoint_from_url,
    local_only_authorizer, resolve_endpoint, serving_error, validate_error_body,
)

LOOPBACK = str(ipaddress.IPv4Address(0x7F000001))


# ---- 1. exposure policy -------------------------------------------------
def test_default_policy_exposes_nothing():
    p = ExposurePolicy()
    for m, path in [("GET", "/healthz"), ("POST", "/verify"), ("GET", "/")]:
        d = p.decide(m, path)
        assert not d.exposed and d.code == "serving.route_not_exposed" and d.status == 404


def test_verify_readiness_only_allows_exactly_three_routes():
    p = ExposurePolicy.verify_readiness_only("/v1/verify")
    assert p.routes == {("GET", "/healthz"), ("GET", "/readyz"), ("POST", "/v1/verify")}
    assert all(p.decide(m, r).exposed for m, r in p.routes)


@pytest.mark.parametrize("method,path", [
    ("POST", "/healthz"), ("get", "/healthz"), ("GET", "/healthz/"), ("GET", "/HEALTHZ"),
    ("GET", "/healthz?x=1"), ("GET", "/v1/verify"), ("POST", "/v1/effects"),
    ("POST", "/v1/verify/../effects"), ("GET", "//healthz"), ("GET", "/healthz%2f"),
    ("GET", ""), (None, "/healthz"), ("GET", None), (b"GET", b"/healthz"), ("GET", 5),
])
def test_routes_outside_policy_are_not_exposed(method, path):
    d = ExposurePolicy.verify_readiness_only("/v1/verify").decide(method, path)
    assert not d.exposed and d.code == ServingCode.ROUTE_NOT_EXPOSED.value and d.status == 404


@pytest.mark.parametrize("bad", [
    {("GET", "*")}, {("GET", "/a*")}, {("get", "/a")}, {("GET", "a")}, {("TRACE", "/a")},
    {("GET", "/a?b")}, {("GET", "/a b")}, {("GET", "/a/../b")}, {("GET",)}, {"/a"},
])
def test_malformed_route_entries_are_refused(bad):
    with pytest.raises(ValueError):
        ExposurePolicy(frozenset(bad))


@pytest.mark.parametrize("path,method", [
    ("/healthz", "GET"), ("/readyz", "GET"), ("verify", "POST"), ("/v", "BOGUS"), ("/x?y", "POST"),
])
def test_verify_route_must_be_valid_and_distinct(path, method):
    with pytest.raises(ValueError):
        ExposurePolicy.verify_readiness_only(path, method)


def test_policy_is_immutable_and_has_no_host_field():
    p = ExposurePolicy.verify_readiness_only("/v1/verify")
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.routes = frozenset()
    assert [f.name for f in dataclasses.fields(p)] == ["routes"]
    assert isinstance(p.routes, frozenset)
    with pytest.raises(TypeError):
        ExposurePolicy(frozenset(), "host.example")  # no host / extra parameter exists


# ---- 2. vocabulary and error body --------------------------------------
def test_serving_codes_and_statuses_are_stable():
    assert ServingCode.NOT_READY == "serving.not_ready" and ServingCode.NOT_READY.http_status == 503
    assert ServingCode.DISABLED == "serving.disabled" and ServingCode.DISABLED.http_status == 503
    assert ServingCode.ROUTE_NOT_EXPOSED == "serving.route_not_exposed"
    assert ServingCode.ROUTE_NOT_EXPOSED.http_status == 404


def test_error_body_shape_is_exact():
    cid = str(uuid.uuid4())
    body = build_error_body("serving.not_ready", cid)
    assert body == {"error": {"code": "serving.not_ready", "correlation_id": cid}}
    with_ref = build_error_body("deny.revoked_grant", cid, receipt_ref="opaque-1")
    assert with_ref == {"error": {"code": "deny.revoked_grant", "correlation_id": cid},
                        "receipt_ref": "opaque-1"}
    assert validate_error_body(body) and validate_error_body(with_ref)


def test_error_body_refuses_extra_fields_and_bad_input():
    cid = str(uuid.uuid4())
    with pytest.raises(TypeError):
        build_error_body("serving.not_ready", cid, detail="x")
    for code in ["serving.ready", "", "grant.revoked", "SERVING.NOT_READY"]:
        with pytest.raises(ValueError):
            build_error_body(code, cid)
    for bad in ["", "not-a-uuid", None, 5]:
        with pytest.raises(ValueError):
            build_error_body("serving.not_ready", bad)
    for ref in ["", "bad\nref", 7]:
        with pytest.raises(ValueError):
            build_error_body("serving.not_ready", cid, receipt_ref=ref)


def test_validate_error_body_rejects_extras_and_wrong_shapes():
    cid = str(uuid.uuid4())
    good = {"error": {"code": "serving.disabled", "correlation_id": cid}}
    assert validate_error_body(good)
    assert not validate_error_body({**good, "message": "x"})
    assert not validate_error_body({"error": {**good["error"], "path": "/p"}})
    assert not validate_error_body({"error": {"code": "serving.disabled"}})
    assert not validate_error_body({"error": {"code": "nope", "correlation_id": cid}})
    assert not validate_error_body({"error": {"code": "serving.disabled", "correlation_id": 1}})
    assert not validate_error_body({"receipt_ref": "x"})
    assert not validate_error_body("body")


def test_serving_error_returns_status_and_body():
    status, body = serving_error(ServingCode.NOT_READY)
    assert status == 503 and validate_error_body(body)
    status, body = serving_error("serving.route_not_exposed", str(uuid.uuid4()))
    assert status == 404 and body["error"]["code"] == "serving.route_not_exposed"
    with pytest.raises(ValueError):
        serving_error("serving.unknown")


# ---- 3. proxy isolation and TLS-only credential redirects ---------------
def test_trust_env_true_is_refused_and_default_is_false():
    assert TransportPolicy().trust_env is False
    for bad in (True, 1, "yes"):
        with pytest.raises(ValueError):
            TransportPolicy(trust_env=bad)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def _serve():
    srv = HTTPServer((LOOPBACK, 0), _Handler)
    srv.hits = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _resolver(host, port):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (LOOPBACK, port))]


@pytest.mark.parametrize("var", ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                                 "http_proxy", "https_proxy", "all_proxy", "no_proxy"])
def test_proxy_environment_does_not_affect_request(monkeypatch, var):
    target, fake_proxy = _serve(), _serve()
    try:
        proxy_url = f"http://{LOOPBACK}:{fake_proxy.server_port}"
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            monkeypatch.setenv(name, proxy_url)
        monkeypatch.setenv(var, proxy_url if "NO" not in var.upper() else "*")
        port = target.server_port
        auth = EndpointAuthorizer.from_exact_rules(
            {EndpointPurpose.HEALTH_PROBE: {("http", "svc.test", port)}})
        resp = transport.request(
            "GET", f"http://svc.test:{port}/ping", authorizer=auth,
            transport_policy=TransportPolicy(), actor_id="a", workflow_id="w",
            purpose=EndpointPurpose.HEALTH_PROBE, run_id="r", resolver=_resolver, timeout=5.0)
        assert resp.status == 200 and resp.body == b"ok"
        assert target.hits == ["/ping"]   # connected directly to the pinned target
        assert fake_proxy.hits == []      # the proxy named in the environment was never used
    finally:
        target.shutdown(); fake_proxy.shutdown()
        target.server_close(); fake_proxy.server_close()


def test_transport_never_imports_proxy_env_readers():
    import inspect
    src = inspect.getsource(transport)
    assert not any(w in src for w in ("getproxies", "os.environ", "getenv", "urlopen"))


def test_credential_redirect_to_cleartext_public_http_is_refused(monkeypatch):
    class Resp:
        status = 302
        def getheaders(self): return [("Location", "http://two.example/next")]
        def read(self, amt=None): return b""
    seen = []
    class Conn:
        def __init__(self, host, port, pinned_ip, timeout): pass
        def request(self, method, path, body=None, headers=None): seen.append(dict(headers or {}))
        def getresponse(self): return Resp()
        def close(self): pass
    monkeypatch.setattr(transport, "_PinnedHTTPSConnection", Conn)
    def public(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (str(ipaddress.IPv4Address(0x5DB8D822)), port))]
    auth = EndpointAuthorizer.from_exact_rules({EndpointPurpose.MODEL_EGRESS: {
        ("https", "one.example", 443), ("http", "two.example", 80)}})
    with pytest.raises(EndpointPolicyError) as exc:
        transport.request(
            "GET", "https://one.example/start", authorizer=auth,
            transport_policy=TransportPolicy(allow_public=True, allow_loopback=False),
            actor_id="a", workflow_id="w", purpose=EndpointPurpose.MODEL_EGRESS, run_id="r",
            headers={"Authorization": "Bearer t"}, resolver=public)
    assert exc.value.code == "https_required"
    assert len(seen) == 1  # the http:// hop was never dialled


# ---- 4. local-only egress preset ---------------------------------------
@pytest.mark.parametrize("purpose", list(EndpointPurpose))
def test_local_only_authorizer_allows_no_host(purpose):
    auth = local_only_authorizer()
    for scheme, host, port in [("https", "api.example", 443), ("http", "svc.test", 80)]:
        ident = resolve_endpoint(endpoint_from_url(f"{scheme}://{host}:{port}"),
                                 allow_public=True, allow_private=True, allow_loopback=True, resolver=_resolver)
        d = auth.authorize(EndpointUseRequest("a", "w", purpose, ident, "r"))
        assert not d.allowed and d.reason_code == "unknown_purpose" and d.expires_at is None
        assert not auth.is_current(d)


def test_local_only_authorizer_blocks_transport_before_dial():
    with pytest.raises(EndpointPolicyError) as exc:
        transport.request(
            "GET", "http://svc.test:9/x", authorizer=local_only_authorizer(),
            transport_policy=TransportPolicy(), actor_id="a", workflow_id="w",
            purpose=EndpointPurpose.MODEL_EGRESS, run_id="r", resolver=_resolver)
    assert exc.value.code == "purpose_denied"
