"""Semantic endpoint-use authorizer and redacted in-memory decision record."""
from __future__ import annotations
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from .contracts import DecisionRecord, EndpointPurpose, EndpointUseDecision, EndpointUseRequest
from .policy import EndpointPolicy

class EndpointAuthorizer:
    def __init__(
        self,
        policy: EndpointPolicy,
        *,
        decision_ttl: timedelta = timedelta(minutes=5),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if decision_ttl <= timedelta(0):
            raise ValueError("decision_ttl must be positive")
        self._policy = policy
        self._records: list[DecisionRecord] = []
        self._ttl = decision_ttl
        self._clock = clock or (lambda: datetime.now(UTC))
    @classmethod
    def from_exact_rules(
        cls,
        rules: dict[EndpointPurpose, set[tuple[str, str, int]]],
        *,
        version: str = "telos-policy-v2",
        decision_ttl: timedelta = timedelta(minutes=5),
        clock: Callable[[], datetime] | None = None,
    ) -> "EndpointAuthorizer":
        return cls(EndpointPolicy.from_exact_rules(rules, version=version), decision_ttl=decision_ttl, clock=clock)
    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Telos clock must return an aware UTC datetime")
        return now.astimezone(UTC)
    def authorize(self, request: EndpointUseRequest) -> EndpointUseDecision:
        reason_code = self._policy.evaluate(request.purpose, request.endpoint)
        allowed = reason_code == "allowed"
        now = self._now()
        decision = EndpointUseDecision(
            allowed=allowed,
            reason_code=reason_code,
            policy_version=self._policy.version,
            decision_ref=token_urlsafe(18),
            endpoint=request.endpoint,
            # Allowed decisions expire (R4 T1): callers re-check before every
            # execution boundary instead of trusting a decision forever.
            expires_at=now + self._ttl if allowed else None,
        )
        self._records.append(DecisionRecord(request=request, decision=decision, recorded_at=now))
        return decision
    def is_current(self, decision: EndpointUseDecision) -> bool:
        """True only for an allowed decision that has an expiry still in the future."""
        return decision.allowed and decision.expires_at is not None and self._now() < decision.expires_at
    @property
    def records(self) -> tuple[DecisionRecord, ...]:
        return tuple(self._records)
