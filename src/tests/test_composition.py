import socket
import pytest
from telos import EndpointAuthorizer, EndpointPolicyError, EndpointPurpose, TransportPolicy, authorize_url

def private_resolver(host, port):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", port))]

def public_resolver(host, port):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", port))]

def test_transport_safe_does_not_imply_semantic_allow():
    auth = EndpointAuthorizer.from_exact_rules({})
    with pytest.raises(EndpointPolicyError) as exc:
        authorize_url("https://model.internal", authorizer=auth, transport_policy=TransportPolicy(allow_private=True, allow_loopback=False), actor_id="gateway", workflow_id="readiness", purpose=EndpointPurpose.HEALTH_PROBE, run_id="r", resolver=private_resolver)
    assert exc.value.code == "purpose_denied"

def test_semantic_allow_does_not_bypass_transport_denial():
    auth = EndpointAuthorizer.from_exact_rules({EndpointPurpose.MODEL_EGRESS: {("https", "api.example", 443)}})
    with pytest.raises(EndpointPolicyError) as exc:
        authorize_url("https://api.example", authorizer=auth, transport_policy=TransportPolicy(allow_public=False, allow_loopback=False), actor_id="gateway", workflow_id="egress", purpose=EndpointPurpose.MODEL_EGRESS, run_id="r", resolver=public_resolver)
    assert exc.value.code == "public_denied"
