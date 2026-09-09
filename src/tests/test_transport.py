import socket
import pytest
import telos.transport as transport
from telos import EndpointAuthorizer, EndpointPolicyError, EndpointPurpose, TransportPolicy

def resolver_to(address):
    def resolver(host, port):
        fam = socket.AF_INET6 if ":" in address else socket.AF_INET
        sockaddr = (address, port, 0, 0) if fam == socket.AF_INET6 else (address, port)
        return [(fam, socket.SOCK_STREAM, 0, "", sockaddr)]
    return resolver

def test_pinned_http_connection_dials_vetted_ip(monkeypatch):
    calls = []
    fake_sock = object()
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: calls.append((addr, timeout)) or fake_sock)
    conn = transport._PinnedHTTPConnection("model.internal", 80, "10.0.0.5", 2.5)
    conn.connect()
    assert conn.sock is fake_sock
    assert calls == [(("10.0.0.5", 80), 2.5)]

def test_pinned_https_preserves_original_hostname_for_sni(monkeypatch):
    calls = []
    fake_raw = object()
    fake_tls = object()
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: fake_raw)
    class Context:
        def wrap_socket(self, raw, server_hostname):
            calls.append((raw, server_hostname))
            return fake_tls
    conn = transport._PinnedHTTPSConnection("model.internal", 443, "10.0.0.5", 2.0, context=Context())
    conn.connect()
    assert conn.sock is fake_tls
    assert calls == [(fake_raw, "model.internal")]

def test_public_cleartext_is_denied_before_dial():
    auth = EndpointAuthorizer.from_exact_rules({EndpointPurpose.MODEL_EGRESS: {("http", "api.example", 80)}})
    with pytest.raises(EndpointPolicyError) as exc:
        transport.authorize_url("http://api.example", authorizer=auth, transport_policy=TransportPolicy(allow_public=True, allow_loopback=False), actor_id="gateway", workflow_id="egress", purpose=EndpointPurpose.MODEL_EGRESS, run_id="r", resolver=resolver_to("93.184.216.34"))
    assert exc.value.code == "https_required"

def test_redirect_target_is_reauthorized_and_reclassified(monkeypatch):
    responses = [(302, [("Location", "http://metadata.example/latest")], b"")]
    class FakeResponse:
        def __init__(self, status, headers, body): self.status, self._headers, self._body = status, headers, body
        def getheaders(self): return self._headers
        def read(self): return self._body
    class FakeConn:
        def __init__(self, host, port, pinned_ip, timeout): self.host = host
        def request(self, *args, **kwargs): pass
        def getresponse(self): return FakeResponse(*responses.pop(0))
        def close(self): pass
    monkeypatch.setattr(transport, "_PinnedHTTPConnection", FakeConn)
    auth = EndpointAuthorizer.from_exact_rules({EndpointPurpose.HEALTH_PROBE: {("http", "start.internal", 80), ("http", "metadata.example", 80)}})
    def resolver(host, port):
        address = "10.0.0.5" if host == "start.internal" else "169.254.169.254"
        return resolver_to(address)(host, port)
    with pytest.raises(EndpointPolicyError) as exc:
        transport.request("GET", "http://start.internal", authorizer=auth, transport_policy=TransportPolicy(allow_private=True, allow_loopback=False), actor_id="gateway", workflow_id="readiness", purpose=EndpointPurpose.HEALTH_PROBE, run_id="r", resolver=resolver)
    assert exc.value.code == "metadata_denied"

def test_environment_proxy_is_not_consulted(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    assert not hasattr(transport, "getproxies")
