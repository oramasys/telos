"""Semantic endpoint-use authorizer and redacted in-memory decision record."""
from __future__ import annotations
from datetime import UTC, datetime
from secrets import token_urlsafe
from .contracts import DecisionRecord, EndpointPurpose, EndpointUseDecision, EndpointUseRequest
from .policy import EndpointPolicy

class EndpointAuthorizer:
    def __init__(self, policy: EndpointPolicy) -> None:
        self._policy = policy
        self._records: list[DecisionRecord] = []
    @classmethod
    def from_exact_rules(cls, rules: dict[EndpointPurpose, set[tuple[str, str, int]]], *, version: str = "telos-policy-v2") -> "EndpointAuthorizer":
        return cls(EndpointPolicy.from_exact_rules(rules, version=version))
    def authorize(self, request: EndpointUseRequest) -> EndpointUseDecision:
        reason_code = self._policy.evaluate(request.purpose, request.endpoint)
        decision = EndpointUseDecision(
            allowed=reason_code == "allowed",
            reason_code=reason_code,
            policy_version=self._policy.version,
            decision_ref=token_urlsafe(18),
            endpoint=request.endpoint,
        )
        self._records.append(DecisionRecord(request=request, decision=decision, recorded_at=datetime.now(UTC)))
        return decision
    @property
    def records(self) -> tuple[DecisionRecord, ...]:
        return tuple(self._records)
