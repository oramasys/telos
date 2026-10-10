"""R4 T1: endpoint-use decisions expire, so admission re-checks them at every
execution boundary instead of trusting a decision forever."""
import socket
from datetime import UTC, datetime, timedelta

import pytest

from telos import EndpointAuthorizer, EndpointPurpose, EndpointRef, EndpointUseDecision, EndpointUseRequest, resolve_endpoint
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


def test_is_current_rejects_a_caller_constructed_future_decision():
    clock = Clock()
    auth = EndpointAuthorizer.from_exact_rules(RULES, clock=clock)
    forged = EndpointUseDecision(
        allowed=True,
        reason_code="allowed",
        policy_version="telos-policy-v2",
        decision_ref="forged",
        endpoint=identity(),
        expires_at=clock.now + timedelta(minutes=1),
    )
    assert not auth.is_current(forged)


def test_policy_epoch_change_invalidates_an_issued_decision():
    auth = EndpointAuthorizer.from_exact_rules(RULES, clock=Clock())
    decision = auth.authorize(request())
    auth.revoke()
    assert not auth.is_current(decision)


def test_ttl_and_clock_are_validated():
    with pytest.raises(ValueError):
        EndpointAuthorizer.from_exact_rules(RULES, decision_ttl=timedelta(0))
    naive = EndpointAuthorizer.from_exact_rules(RULES, clock=lambda: datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        naive.authorize(request())


# --- review fixes -------------------------------------------------------------


def test_is_current_returns_false_for_naive_expiry_instead_of_crashing():
    from dataclasses import replace

    clock = Clock()
    auth = EndpointAuthorizer.from_exact_rules(RULES, clock=clock)
    decision = auth.authorize(request())
    assert not auth.is_current(replace(decision, expires_at=datetime(2030, 1, 1)))


def test_dialer_uses_the_authorizers_clock_for_freshness():
    import asyncio

    from telos.dialer import SecureDialer
    from test_dialer import FakeConnector, FakeResolver
    from test_dialer import request as dial_request

    endpoint = EndpointRef("http", "ollama.local", 11434)
    past = Clock()
    past.now = datetime(2001, 1, 1, tzinfo=UTC)  # frozen far before wall-clock now
    auth = EndpointAuthorizer.from_exact_rules({EndpointPurpose.HEALTH_PROBE: {endpoint.key}}, clock=past)
    connector = FakeConnector("127.0.0.1")
    dialer = SecureDialer(authorizer=auth, resolver=FakeResolver({endpoint.host: ["127.0.0.1"]}).resolve,
                          connector=connector)
    result = asyncio.run(dialer.dial(dial_request(endpoint)))
    assert result.reason_code != "authorization_expired"
    assert connector.calls


def test_concurrent_authorizations_are_all_current():
    import threading

    auth = EndpointAuthorizer.from_exact_rules(RULES, clock=Clock())
    decisions = []
    lock = threading.Lock()

    def worker():
        for _ in range(200):
            d = auth.authorize(request())
            with lock:
                decisions.append(d)

    import sys

    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)  # switch threads constantly so a lost update shows up
    try:
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(old)
    assert len(decisions) == 1600
    assert all(auth.is_current(d) for d in decisions)


def test_dialer_asks_is_current_even_without_expiry():
    from dataclasses import replace

    from telos.dialer import _decision_is_expired

    auth = EndpointAuthorizer.from_exact_rules(RULES, clock=Clock())
    decision = replace(auth.authorize(request()), expires_at=None)

    class Revoked:
        def is_current(self, _decision):
            return False

    assert _decision_is_expired(decision, Revoked())
    assert not _decision_is_expired(decision, object())  # no is_current: old fallback
