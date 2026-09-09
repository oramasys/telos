import socket
import pytest
from telos import EndpointPolicyError, EndpointRef, resolve_endpoint

def fake(addresses):
    def resolver(host, port):
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6 if ":" in a else 0, "", (a, port, 0, 0) if ":" in a else (a, port)) for a in addresses]
    return resolver

def test_dns_to_loopback_is_denied_for_remote_profile():
    with pytest.raises(EndpointPolicyError) as exc:
        resolve_endpoint(EndpointRef("https", "attacker.example", 443), allow_public=True, allow_private=False, allow_loopback=False, resolver=fake(["127.0.0.1"]))
    assert exc.value.code == "loopback_denied"

def test_mixed_trust_class_answers_fail_closed():
    with pytest.raises(EndpointPolicyError):
        resolve_endpoint(EndpointRef("https", "mixed.example", 443), allow_public=True, allow_private=True, allow_loopback=False, resolver=fake(["93.184.216.34", "10.0.0.1"]))
