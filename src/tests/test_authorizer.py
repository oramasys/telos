import socket
from telos import EndpointAuthorizer, EndpointPurpose, EndpointRef, EndpointUseRequest, resolve_endpoint

def resolver(host, port):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", port))]

def identity():
    return resolve_endpoint(EndpointRef("https", "model.internal", 443), allow_public=False, allow_private=True, allow_loopback=False, resolver=resolver)

def test_exact_endpoint_is_allowed_and_recorded():
    auth = EndpointAuthorizer.from_exact_rules({EndpointPurpose.HEALTH_PROBE: {("https", "model.internal", 443)}})
    decision = auth.authorize(EndpointUseRequest("gateway", "readiness", EndpointPurpose.HEALTH_PROBE, identity(), "run-1"))
    assert decision.allowed
    assert len(auth.records) == 1

def test_unknown_purpose_is_denied():
    auth = EndpointAuthorizer.from_exact_rules({})
    decision = auth.authorize(EndpointUseRequest("gateway", "readiness", EndpointPurpose.HEALTH_PROBE, identity(), "run-1"))
    assert not decision.allowed
    assert decision.reason_code == "unknown_purpose"
