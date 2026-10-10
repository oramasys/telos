"""Semantic endpoint-use authorizer and redacted in-memory decision record."""
from __future__ import annotations
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from threading import Lock
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
        self._epoch = 1
        self._issued: dict[str, EndpointUseDecision] = {}
        # One lock for pruning, issuing, revoking and checking, so concurrent
        # authorize() calls can never drop another call's issued decision.
        self._lock = Lock()
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
        with self._lock:
            # Prune expired entries in place and issue under the same lock, so the
            # epoch on the decision is the one current at issuance and concurrent
            # calls can never drop each other's entries.
            for ref in [r for r, d in self._issued.items()
                        if d.expires_at is None or now >= d.expires_at]:
                del self._issued[ref]
            decision = EndpointUseDecision(
                allowed=allowed,
                reason_code=reason_code,
                policy_version=self._policy.version,
                decision_ref=token_urlsafe(18),
                endpoint=request.endpoint,
                # Allowed decisions expire (R4 T1): callers re-check before every
                # execution boundary instead of trusting a decision forever.
                expires_at=now + self._ttl if allowed else None,
                authority_epoch=self._epoch,
            )
            if allowed:
                self._issued[decision.decision_ref] = decision
            self._records.append(DecisionRecord(request=request, decision=decision, recorded_at=now))
        return decision

    def revoke(self) -> int:
        with self._lock:
            self._epoch += 1
            self._issued.clear()
            return self._epoch

    def is_current(self, decision: EndpointUseDecision) -> bool:
        """True only for an allowed decision that has an expiry still in the future."""
        expires_at = decision.expires_at
        with self._lock:
            issued = self._issued.get(decision.decision_ref)
            epoch = self._epoch
        return (
            issued == decision
            and decision.allowed
            and decision.authority_epoch == epoch
            and expires_at is not None
            and expires_at.tzinfo is not None
            and expires_at.utcoffset() is not None
            and self._now() < expires_at
        )
    @property
    def records(self) -> tuple[DecisionRecord, ...]:
        return tuple(self._records)
