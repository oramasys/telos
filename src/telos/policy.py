"""Deny-by-default semantic endpoint-use policy."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import EndpointPurpose, EndpointRef


@dataclass(frozen=True, slots=True)
class PurposeRule:
    allowed_endpoints: frozenset[tuple[str, str, int]]
    allow_public: bool = False

    def permits(self, endpoint: EndpointRef) -> bool:
        if endpoint.is_public and not self.allow_public:
            return False
        return endpoint.key in self.allowed_endpoints


@dataclass(frozen=True, slots=True)
class EndpointPolicy:
    version: str
    rules: dict[EndpointPurpose, PurposeRule]

    def evaluate(self, purpose: EndpointPurpose, endpoint: EndpointRef) -> str:
        rule = self.rules.get(purpose)
        if rule is None:
            return "unknown_purpose"
        if not rule.permits(endpoint):
            return "endpoint_not_permitted"
        return "allowed"

    @classmethod
    def from_exact_rules(
        cls,
        rules: dict[EndpointPurpose, set[tuple[str, str, int]]],
        *,
        version: str = "telos-policy-v1",
    ) -> "EndpointPolicy":
        if not version.strip():
            raise ValueError("policy version is required")
        return cls(
            version=version,
            rules={purpose: PurposeRule(frozenset(endpoints)) for purpose, endpoints in rules.items()},
        )

