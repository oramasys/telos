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
    """The default policy exposes no route."""
    p = ExposurePolicy()
    for m, path in [("GET", "/healthz"), ("POST", "/verify"), ("GET", "/")]:
        d = p.decide(m, path)
        assert not d.exposed and d.code == "serving.route_not_exposed" and d.status == 404


def test_verify_readiness_only_allows_exactly_three_routes():
    """The readiness preset allows exactly the two probes and one verify route."""
    p = ExposurePolicy.verify_readiness_only("/v1/verify")
    assert p.routes == {("GET", "/healthz"), ("GET", "/readyz"), ("POST", "/v1/verify")}
    assert all(p.decide(m, r).exposed for m, r in p.routes)


@pytest.mark.parametrize("method,path", [
    ("POST", "/healthz"), ("get", "/healthz"), ("GET", "/healthz/"), ("GET", "/HEALTHZ"),
    ("GET", "/healthz?x=1"), ("GET", "/v1/verify"), ("POST", "/v1/effects"),
    ("POST", "/v1/verify/../effects"), ("GET", "//healthz"), ("GET", "/healthz%2f"),
    ("GET", ""), (None, "/healthz"), ("GET", None), (b"GET", b"/healthz"), ("GET", 5),
    ([], "/healthz"), ({}, "/healthz"), ({"GET"}, "/healthz"), (["GET"], ["/healthz"]),
])
def test_routes_outside_policy_are_not_exposed(method, path):
    """Anything outside the policy, including malformed input, is refused with 404."""
    d = ExposurePolicy.verify_readiness_only("/v1/verify").decide(method, path)
    assert not d.exposed and d.code == ServingCode.ROUTE_NOT_EXPOSED.value and d.status == 404


@pytest.mark.parametrize("bad", [
    {("GET", "*")}, {("GET", "/a*")}, {("get", "/a")}, {("GET", "a")}, {("TRACE", "/a")},
    {("GET", "/a?b")}, {("GET", "/a b")}, {("GET", "/a/../b")}, {("GET",)}, {"/a"},
])
def test_malformed_route_entries_are_refused(bad):
    """Malformed route entries make the policy constructor raise."""
    with pytest.raises(ValueError):
        ExposurePolicy(frozenset(bad))


@pytest.mark.parametrize("path,method", [
    ("/healthz", "GET"), ("/readyz", "GET"), ("verify", "POST"), ("/v", "BOGUS"), ("/x?y", "POST"),
])
def test_verify_route_must_be_valid_and_distinct(path, method):
    """The verify route must be valid and differ from readiness routes."""
    with pytest.raises(ValueError):
        ExposurePolicy.verify_readiness_only(path, method)


def test_policy_is_immutable_and_has_no_host_field():
    """The policy is frozen and carries no host, URL or provider field."""
    p = ExposurePolicy.verify_readiness_only("/v1/verify")
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.routes = frozenset()
    assert [f.name for f in dataclasses.fields(p)] == ["routes"]
    assert isinstance(p.routes, frozenset)
    with pytest.raises(TypeError):
        ExposurePolicy(frozenset(), "host.example")  # no host / extra parameter exists


# ---- 2. vocabulary and error body --------------------------------------
def test_serving_codes_and_statuses_are_stable():
    """Serving codes and their HTTP statuses are fixed."""
    assert ServingCode.NOT_READY == "serving.not_ready" and ServingCode.NOT_READY.http_status == 503
    assert not hasattr(ServingCode, "DISABLED") and len(ServingCode) == 2
    assert ServingCode.ROUTE_NOT_EXPOSED == "serving.route_not_exposed"
    assert ServingCode.ROUTE_NOT_EXPOSED.http_status == 404


def test_error_body_shape_is_exact():
    """The error body has exactly the contract shape."""
    cid = str(uuid.uuid4())
    body = build_error_body("serving.not_ready", cid)
    assert body == {"error": {"code": "serving.not_ready", "correlation_id": cid}}
    with_ref = build_error_body("deny.revoked_grant", cid, receipt_ref="opaque-1")
    assert with_ref == {"error": {"code": "deny.revoked_grant", "correlation_id": cid,
                                  "receipt_ref": "opaque-1"}}
    assert "receipt_ref" not in with_ref
    assert validate_error_body(body, status=503) and validate_error_body(with_ref, status=403)


def test_error_body_refuses_extra_fields_and_bad_input():
    """The builder refuses unknown codes, bad ids and bad receipt refs."""
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
    """The validator rejects extra fields and wrong shapes."""
    cid = str(uuid.uuid4())
    good = {"error": {"code": "serving.not_ready", "correlation_id": cid}}
    assert validate_error_body(good, status=503)
    assert not validate_error_body({**good, "message": "x"}, status=503)
    assert not validate_error_body({"error": {**good["error"], "path": "/p"}}, status=503)
    assert not validate_error_body({"error": {"code": "serving.not_ready"}}, status=503)
    assert not validate_error_body({"error": {"code": "nope", "correlation_id": cid}}, status=503)
    assert not validate_error_body({"error": {"code": "serving.not_ready", "correlation_id": 1}}, status=503)
    assert not validate_error_body({"receipt_ref": "x"}, status=503)
    assert not validate_error_body({**good, "receipt_ref": "x"}, status=503)  # sibling placement refused
    assert not validate_error_body("body", status=503)


@pytest.mark.parametrize("err", [
    {"code": ["serving.not_ready"], "correlation_id": str(uuid.uuid4())},
    {"code": {"a": 1}, "correlation_id": str(uuid.uuid4())},
    {"code": "serving.not_ready", "correlation_id": "not-a-uuid"},
    {"code": "serving.not_ready", "correlation_id": ""},
    {"code": "serving.not_ready", "correlation_id": [str(uuid.uuid4())]},
])
def test_validate_error_body_rejects_malformed_fields_without_raising(err):
    """Malformed code or correlation_id types and values return False, never raise."""
    assert validate_error_body({"error": err}, status=503) is False


@pytest.mark.parametrize("ref", [["x"], "", 5, "bad\nref", {"a": 1}])
def test_validate_error_body_rejects_invalid_receipt_ref(ref):
    """An invalid receipt_ref is rejected; a valid one is accepted."""
    err = {"code": "serving.not_ready", "correlation_id": str(uuid.uuid4())}
    assert validate_error_body({"error": {**err, "receipt_ref": "r-1"}}, status=503) is True
    assert validate_error_body({"error": {**err, "receipt_ref": ref}}, status=503) is False


def test_serving_error_returns_status_and_body():
    """serving_error returns the fixed status and a valid body."""
    status, body = serving_error(ServingCode.NOT_READY)
    assert status == 503 and validate_error_body(body, status=status)
    status, body = serving_error("serving.route_not_exposed", str(uuid.uuid4()))
    assert status == 404 and body["error"]["code"] == "serving.route_not_exposed"
    with pytest.raises(ValueError):
        serving_error("serving.unknown")


# ---- 3. proxy isolation and TLS-only credential redirects ---------------
def test_trust_env_true_is_refused_and_default_is_false():
    """trust_env=True is refused and the default is False."""
    assert TransportPolicy().trust_env is False
    for bad in (True, 1, "yes"):
        with pytest.raises(ValueError):
            TransportPolicy(trust_env=bad)


class _Handler(BaseHTTPRequestHandler):
    """Loopback request handler that records the paths it serves."""
    def do_GET(self):
        """Record the path and reply 200 with body ok."""
        self.server.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        """Suppress request logging."""
        pass


def _serve():
    """Start a loopback HTTP server on an ephemeral port and return it."""
    srv = HTTPServer((LOOPBACK, 0), _Handler)
    srv.hits = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _resolver(host, port):
    """Resolver stub that maps every host to loopback."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (LOOPBACK, port))]


@pytest.mark.parametrize("var", ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                                 "http_proxy", "https_proxy", "all_proxy", "no_proxy"])
def test_proxy_environment_does_not_affect_request(monkeypatch, var):
    """Proxy environment variables never route or alter a request."""
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
    """The transport source never reads proxy settings from the environment."""
    import inspect
    src = inspect.getsource(transport)
    assert not any(w in src for w in ("getproxies", "os.environ", "getenv", "urlopen"))


def test_credential_redirect_to_cleartext_public_http_is_refused(monkeypatch):
    """A credentialed redirect to cleartext public HTTP is refused before dialling."""
    class Resp:
        """Stub redirect response."""
        status = 302
        def getheaders(self):
            """Return a Location redirect header."""
            return [("Location", "http://two.example/next")]
        def read(self, amt=None):
            """Return an empty body."""
            return b""
    seen = []
    class Conn:
        """Stub connection that records headers and never dials."""
        def __init__(self, host, port, pinned_ip, timeout):
            """Accept and ignore the connection arguments."""
        def request(self, method, path, body=None, headers=None):
            """Record the request headers."""
            seen.append(dict(headers or {}))
        def getresponse(self):
            """Return the stub response."""
            return Resp()
        def close(self):
            """Do nothing."""
            pass
    monkeypatch.setattr(transport, "_PinnedHTTPSConnection", Conn)
    def public(host, port):
        """Resolver stub that maps every host to a public address."""
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
    """The local-only authorizer denies every purpose."""
    auth = local_only_authorizer()
    for scheme, host, port in [("https", "api.example", 443), ("http", "svc.test", 80)]:
        ident = resolve_endpoint(endpoint_from_url(f"{scheme}://{host}:{port}"),
                                 allow_public=True, allow_private=True, allow_loopback=True, resolver=_resolver)
        d = auth.authorize(EndpointUseRequest("a", "w", purpose, ident, "r"))
        assert not d.allowed and d.reason_code == "unknown_purpose" and d.expires_at is None
        assert not auth.is_current(d)


def test_local_only_authorizer_blocks_transport_before_dial():
    """The local-only authorizer blocks transport before any dial."""
    with pytest.raises(EndpointPolicyError) as exc:
        transport.request(
            "GET", "http://svc.test:9/x", authorizer=local_only_authorizer(),
            transport_policy=TransportPolicy(), actor_id="a", workflow_id="w",
            purpose=EndpointPurpose.MODEL_EGRESS, run_id="r", resolver=_resolver)
    assert exc.value.code == "purpose_denied"


def test_deny_status_table_matches_contract():
    """Every deny code has the contract HTTP status and none is outside the closed set."""
    from telos.serving import DENY_STATUS, PUBLIC_ERROR_CODES
    assert DENY_STATUS == {
        "deny.malformed_grant": 400, "deny.unauthorized_caller": 401,
        "deny.grant_conflict": 409, "deny.unknown_key": 403, "deny.revoked_grant": 403,
        "deny.missing_capability_record": 403,
        "deny.revocation_stale": 503, "deny.verifier_unavailable": 503,
    }
    assert set(DENY_STATUS) <= PUBLIC_ERROR_CODES


def test_serving_disabled_is_not_a_public_code():
    """serving.disabled is removed: the validator and builder both refuse it."""
    cid = str(uuid.uuid4())
    assert not validate_error_body({"error": {"code": "serving.disabled", "correlation_id": cid}}, status=503)
    with pytest.raises(ValueError):
        build_error_body("serving.disabled", cid)


def test_grant_conflict_is_public_with_status_409_only():
    """deny.grant_conflict is a public code fixed at 409; any other status is refused."""
    from telos.serving import DENY_STATUS
    cid = str(uuid.uuid4())
    body = build_error_body("deny.grant_conflict", cid)
    assert DENY_STATUS["deny.grant_conflict"] == 409
    assert validate_error_body(body, status=409)
    for status in (200, 400, 401, 403, 404, 500, 503):
        assert validate_error_body(body, status=status) is False


def test_validate_error_body_requires_status_and_checks_it():
    """status is a required keyword; a deny code with the wrong status is rejected."""
    cid = str(uuid.uuid4())
    body = build_error_body("deny.revoked_grant", cid)
    with pytest.raises(TypeError):
        validate_error_body(body)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        validate_error_body(body, 403)  # type: ignore[misc]
    assert validate_error_body(body, status=403)
    assert validate_error_body(body, status=401) is False
    assert validate_error_body(body, status=True) is False  # bool is not an HTTP status


def test_validate_error_body_accepts_http_status_enum():
    """An HTTPStatus member equal to the fixed status conforms; a bool never does."""
    from http import HTTPStatus

    body = build_error_body("deny.grant_conflict", str(uuid.uuid4()))
    assert validate_error_body(body, status=HTTPStatus.CONFLICT)
    assert validate_error_body(body, status=HTTPStatus.FORBIDDEN) is False
    assert validate_error_body(body, status=False) is False
