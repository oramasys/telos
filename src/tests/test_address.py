import pytest
from telos import EndpointPolicyError, assert_address_allowed, parse_ip


def deny(address):
    return assert_address_allowed(address, allow_public=True, allow_private=False, allow_loopback=False)


def test_metadata_denied_even_when_public_allowed():
    with pytest.raises(EndpointPolicyError) as exc:
        deny("169.254.169.254")
    assert exc.value.code == "metadata_denied"


def test_ipv4_mapped_ipv6_is_classified_as_ipv4():
    assert str(parse_ip("::ffff:127.0.0.1")) == "127.0.0.1"


def test_loopback_requires_explicit_profile():
    with pytest.raises(EndpointPolicyError) as exc:
        deny("127.0.0.1")
    assert exc.value.code == "loopback_denied"


def test_private_requires_explicit_profile():
    with pytest.raises(EndpointPolicyError) as exc:
        deny("10.0.0.1")
    assert exc.value.code == "private_denied"


def test_multicast_and_unspecified_fail_closed():
    for address, code in [("0.0.0.0", "unspecified_denied"), ("224.0.0.1", "multicast_denied")]:
        with pytest.raises(EndpointPolicyError) as exc:
            deny(address)
        assert exc.value.code == code


def test_transition_mechanism_networks_are_always_denied():
    for address in ("192.88.99.1", "2001::1", "2002::1"):
        with pytest.raises(EndpointPolicyError) as exc:
            assert_address_allowed(address, allow_public=True, allow_private=True, allow_loopback=True)
        assert exc.value.code == "transition_network_denied"
