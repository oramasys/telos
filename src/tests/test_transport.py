import socket,ssl,pytest
import telos.transport as transport
from telos import EndpointAuthorizer,EndpointPolicyError,EndpointPurpose,TransportPolicy
def resolver_to(address):
    def resolver(host,port):
        fam=socket.AF_INET6 if ":" in address else socket.AF_INET;sockaddr=(address,port,0,0) if fam==socket.AF_INET6 else (address,port);return [(fam,socket.SOCK_STREAM,0,"",sockaddr)]
    return resolver
def test_pinned_http_connection_dials_vetted_ip(monkeypatch):
    calls = []
    class Sock:
        def getpeername(self): return ("10.0.0.5", 80)
    fake_sock = Sock()
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: calls.append((addr, timeout)) or fake_sock)
    conn = transport._PinnedHTTPConnection("model.internal", 80, "10.0.0.5", 2.5)
    conn.connect()
    assert conn.sock is fake_sock
    assert calls == [(("10.0.0.5", 80), 2.5)]
def test_pinned_https_preserves_original_hostname_for_sni(monkeypatch):
    calls = []
    class RawSock:
        def getpeername(self): return ("10.0.0.5", 443)
    fake_raw = RawSock()
    fake_tls = object()
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: fake_raw)
    class Context:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True
        def wrap_socket(self, raw, server_hostname):
            calls.append((raw, server_hostname))
            return fake_tls
    conn = transport._PinnedHTTPSConnection("model.internal", 443, "10.0.0.5", 2.0, context=Context())
    conn.connect()
    assert conn.sock is fake_tls
    assert calls == [(fake_raw, "model.internal")]
def test_public_cleartext_is_denied_before_dial():
    a=EndpointAuthorizer.from_exact_rules({EndpointPurpose.MODEL_EGRESS:{("http","api.example",80)}})
    with pytest.raises(EndpointPolicyError) as exc:transport.authorize_url("http://api.example",authorizer=a,transport_policy=TransportPolicy(allow_public=True,allow_loopback=False),actor_id="gateway",workflow_id="egress",purpose=EndpointPurpose.MODEL_EGRESS,run_id="r",resolver=resolver_to("93.184.216.34"))
    assert exc.value.code=="https_required"
def test_redirect_target_is_reauthorized_and_reclassified(monkeypatch):
    responses=[(302,[("Location","http://metadata.example/latest")],b"")]
    class R:
        def __init__(self,status,headers,body):self.status,self._headers,self._body=status,headers,body
        def getheaders(self):return self._headers
        def read(self):return self._body
    class C:
        def __init__(self,host,port,pinned_ip,timeout):pass
        def request(self,*a,**k):pass
        def getresponse(self):return R(*responses.pop(0))
        def close(self):pass
    monkeypatch.setattr(transport,"_PinnedHTTPConnection",C);a=EndpointAuthorizer.from_exact_rules({EndpointPurpose.HEALTH_PROBE:{("http","start.internal",80),("http","metadata.example",80)}})
    def resolver(host,port):return resolver_to("10.0.0.5" if host=="start.internal" else "169.254.169.254")(host,port)
    with pytest.raises(EndpointPolicyError) as exc:transport.request("GET","http://start.internal",authorizer=a,transport_policy=TransportPolicy(allow_private=True,allow_loopback=False),actor_id="gateway",workflow_id="readiness",purpose=EndpointPurpose.HEALTH_PROBE,run_id="r",resolver=resolver)
    assert exc.value.code=="metadata_denied"
def test_environment_proxy_is_not_consulted(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY","http://127.0.0.1:9");monkeypatch.setenv("HTTPS_PROXY","http://127.0.0.1:9");assert not hasattr(transport,"getproxies")

def test_pinned_http_connection_rechecks_connected_peer(monkeypatch):
    class Sock:
        def getpeername(self): return ("1.1.1.1", 80)
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: Sock())
    conn = transport._PinnedHTTPConnection("example.com", 80, "8.8.8.8", 2.0)
    with pytest.raises(EndpointPolicyError) as exc:
        conn.connect()
    assert exc.value.code == "peer_pin_mismatch"


def test_302_switches_post_to_get_and_drops_body(monkeypatch):
    seen=[]
    responses=[(302,[("Location","https://two.example/next")],b""),(200,[],b"ok")]
    class Resp:
        def __init__(self,status,headers,body): self.status,self._headers,self._body=status,headers,body
        def getheaders(self): return self._headers
        def read(self): return self._body
    class Conn:
        def __init__(self,host,port,pinned_ip,timeout): self.host=host
        def request(self,method,path,body=None,headers=None): seen.append((self.host,method,path,body,dict(headers or {})))
        def getresponse(self): return Resp(*responses.pop(0))
        def close(self): pass
    monkeypatch.setattr(transport,"_PinnedHTTPSConnection",Conn)
    auth=EndpointAuthorizer.from_exact_rules({EndpointPurpose.MODEL_EGRESS:{("https","one.example",443),("https","two.example",443)}})
    def resolver(host,port): return resolver_to("93.184.216.34" if host=="one.example" else "1.1.1.1")(host,port)
    result=transport.request("POST","https://one.example/start",authorizer=auth,transport_policy=TransportPolicy(allow_public=True,allow_loopback=False),actor_id="gateway",workflow_id="egress",purpose=EndpointPurpose.MODEL_EGRESS,run_id="r",headers={"Authorization":"Bearer x","Cookie":"a=b","Proxy-Authorization":"Basic z","Host":"evil.example"},body=b"payload",resolver=resolver)
    assert result.body==b"ok"
    assert seen[0][1:4]==("POST","/start",b"payload")
    assert seen[0][4]["Host"]=="one.example"
    assert seen[1][1:4]==("GET","/next",None)
    assert "Authorization" not in seen[1][4]
    assert "Cookie" not in seen[1][4]
    assert "Proxy-Authorization" not in seen[1][4]
    assert seen[1][4]["Host"]=="two.example"


def test_307_preserves_method_and_body(monkeypatch):
    seen=[]
    responses=[(307,[("Location","/next")],b""),(200,[],b"ok")]
    class Resp:
        def __init__(self,status,headers,body): self.status,self._headers,self._body=status,headers,body
        def getheaders(self): return self._headers
        def read(self): return self._body
    class Conn:
        def __init__(self,host,port,pinned_ip,timeout): pass
        def request(self,method,path,body=None,headers=None): seen.append((method,path,body))
        def getresponse(self): return Resp(*responses.pop(0))
        def close(self): pass
    monkeypatch.setattr(transport,"_PinnedHTTPSConnection",Conn)
    auth=EndpointAuthorizer.from_exact_rules({EndpointPurpose.MODEL_EGRESS:{("https","one.example",443)}})
    transport.request("PATCH","https://one.example/start",authorizer=auth,transport_policy=TransportPolicy(allow_public=True,allow_loopback=False),actor_id="gateway",workflow_id="egress",purpose=EndpointPurpose.MODEL_EGRESS,run_id="r",body=b"payload",resolver=resolver_to("93.184.216.34"))
    assert seen[1]==("PATCH","/next",b"payload")


def test_cancel_check_denies_before_resolution_or_network():
    called = []
    def resolver(host, port):
        called.append((host, port))
        raise AssertionError("resolver must not run after cancellation")
    auth = EndpointAuthorizer.from_exact_rules({
        EndpointPurpose.MODEL_EGRESS: {("https", "api.example", 443)}
    })
    with pytest.raises(EndpointPolicyError) as exc:
        transport.request(
            "GET",
            "https://api.example",
            authorizer=auth,
            transport_policy=TransportPolicy(allow_public=True, allow_loopback=False),
            actor_id="gateway",
            workflow_id="egress",
            purpose=EndpointPurpose.MODEL_EGRESS,
            run_id="r",
            resolver=resolver,
            cancel_check=lambda: True,
        )
    assert exc.value.code == "cancelled"
    assert called == []
