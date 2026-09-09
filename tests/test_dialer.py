from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from telos import EndpointAuthorizer, EndpointPurpose, EndpointRef
from telos.dialer import ConnectedPeer, SecureDialRequest, SecureDialer


@dataclass
class FakeResolver:
    answers: dict[str, list[str]]
    calls: list[str] = field(default_factory=list)

    async def resolve(self, host: str) -> list[str]:
        self.calls.append(host)
        return self.answers.get(host, [])


@dataclass
class FakeConnector:
    peer_address: str
    calls: list[tuple[EndpointRef, str, EndpointPurpose, float]] = field(default_factory=list)

    async def connect(
        self,
        *,
        endpoint: EndpointRef,
        pinned_address: str,
        purpose: EndpointPurpose,
        timeout_seconds: float,
    ) -> ConnectedPeer:
        self.calls.append((endpoint, pinned_address, purpose, timeout_seconds))
        return ConnectedPeer("provider:test", self.peer_address)


def authorizer(endpoint: EndpointRef) -> EndpointAuthorizer:
    return EndpointAuthorizer.from_exact_rules(
        {EndpointPurpose.HEALTH_PROBE: {endpoint.key}}, version="dialer-test-v1"
    )


def request(endpoint: EndpointRef, *, allow_public: bool = False) -> SecureDialRequest:
    return SecureDialRequest(
        endpoint=endpoint,
        purpose=EndpointPurpose.HEALTH_PROBE,
        actor_id="gateway",
        workflow_id="gateway_lifecycle",
        run_id="run-1",
        allow_public=allow_public,
        allow_private=True,
        allow_loopback=True,
        timeout_seconds=0.5,
    )


@pytest.mark.asyncio
async def test_mixed_dns_answer_rejects_before_connector_invocation() -> None:
    endpoint = EndpointRef("http", "ollama.local", 11434)
    resolver = FakeResolver({endpoint.host: ["127.0.0.1", "169.254.169.254"]})
    connector = FakeConnector("127.0.0.1")
    dialer = SecureDialer(
        authorizer=authorizer(endpoint), resolver=resolver.resolve, connector=connector
    )

    result = await dialer.dial(request(endpoint))

    assert not result.allowed
    assert result.reason_code == "metadata_denied"
    assert connector.calls == []


@pytest.mark.asyncio
async def test_ipv4_mapped_ipv6_metadata_is_rejected_before_connector_invocation() -> None:
    endpoint = EndpointRef("http", "ollama.local", 11434)
    resolver = FakeResolver({endpoint.host: ["::ffff:169.254.169.254"]})
    connector = FakeConnector("169.254.169.254")
    dialer = SecureDialer(
        authorizer=authorizer(endpoint), resolver=resolver.resolve, connector=connector
    )

    result = await dialer.dial(request(endpoint))

    assert not result.allowed
    assert result.reason_code == "metadata_denied"
    assert connector.calls == []


@pytest.mark.asyncio
async def test_connected_peer_must_equal_vetted_pin() -> None:
    endpoint = EndpointRef("http", "ollama.local", 11434)
    resolver = FakeResolver({endpoint.host: ["127.0.0.1"]})
    connector = FakeConnector("127.0.0.2")
    dialer = SecureDialer(
        authorizer=authorizer(endpoint), resolver=resolver.resolve, connector=connector
    )

    result = await dialer.dial(request(endpoint))

    assert not result.allowed
    assert result.reason_code == "peer_pin_mismatch"
    assert connector.calls[0][1] == "127.0.0.1"


@pytest.mark.asyncio
async def test_success_returns_identity_decision_and_provider_ref() -> None:
    endpoint = EndpointRef("http", "ollama.local", 11434)
    resolver = FakeResolver({endpoint.host: ["127.0.0.1"]})
    connector = FakeConnector("127.0.0.1")
    dialer = SecureDialer(
        authorizer=authorizer(endpoint), resolver=resolver.resolve, connector=connector
    )

    result = await dialer.dial(request(endpoint))

    assert result.allowed
    assert result.reason_code == "dialed"
    assert result.provider_ref == "provider:test"
    assert result.endpoint_identity is not None
    assert result.endpoint_identity.resolved_addresses == ("127.0.0.1",)
    assert result.decision is not None
    assert result.decision.policy_version == "dialer-test-v1"
