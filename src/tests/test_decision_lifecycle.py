"""R4 T1: endpoint-use decisions expire, so admission re-checks them at every
execution boundary instead of trusting a decision forever."""
import socket
from datetime import UTC, datetime, timedelta

import pytest

from telos import EndpointAuthorizer, EndpointPurpose, EndpointRef, EndpointUseRequest, resolve_endpoint
from telos.policy import EndpointPolicy


def resolver(host, port):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", port))]


def identity():
    return resolve_endpoint(EndpointRef("https", "model.internal", 443), allow_public=False,
                            allow_private=True, allow_loopback=False, resolver=resolver)


class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 10, tzinfo=UTC)

    def __call__(self):
        return self.now


RULES = {EndpointPurpose.HEALTH_PROBE: {("https", "model.internal", 443)}}


def request():
    return EndpointUseRequest("gateway", "readiness", EndpointPurpose.HEALTH_PROBE, identity(), "run-1")


def test_allowed_decision_expires_after_the_ttl():
    clock = Clock()
    auth = EndpointAuthorizer(EndpointPolicy.from_exact_rules(RULES), decision_ttl=timedelta(seconds=10), clock=clock)
    decision = auth.authorize(request())
    assert decision.expires_at == clock.now + timedelta(seconds=10)
    assert auth.is_current(decision)
    clock.now += timedelta(seconds=10)
    assert not auth.is_current(decision)


def test_denied_decision_is_never_current():
    auth = EndpointAuthorizer.from_exact_rules({}, clock=Clock())
    decision = auth.authorize(request())
    assert not decision.allowed
    assert not auth.is_current(decision)


def test_decision_without_expiry_is_not_current():
    clock = Clock()
    auth = EndpointAuthorizer.from_exact_rules(RULES, clock=clock)
    decision = auth.authorize(request())
    from dataclasses import replace
    assert not auth.is_current(replace(decision, expires_at=None))


def test_ttl_and_clock_are_validated():
    with pytest.raises(ValueError):
        EndpointAuthorizer.from_exact_rules(RULES, decision_ttl=timedelta(0))
    naive = EndpointAuthorizer.from_exact_rules(RULES, clock=lambda: datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        naive.authorize(request())
