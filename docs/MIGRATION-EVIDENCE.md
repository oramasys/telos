# Tripwire/Telos Clean-Room Migration Evidence

Telos restores the accepted 2026-08-29 design. The v2 implementation is clean-room: historical implementations define behavior vectors and security invariants but are not runtime dependencies.

## v1 evidence

- `diazMelgarejo/Perpetua-Tools/packages/endpoint-policy/` — independently packaged endpoint policy, Apache-2.0.
- `src/utils/endpoint_policy_core.py` — endpoint identity/policy primitive.
- `src/utils/ssrf_fetch_policy.py` — pre-flight SSRF policy.
- `src/utils/ssrf_pinned_adapter.py` — Layer-2 connection-time IP pinning.
- `.agent/memory/semantic/DECISIONS.md` — 2026-08-21 three-layer SSRF/pinned-transport decision.

## v2 evidence

- `oramasys/Claude-Desktop-LLM/src/policy/endpoint-policy.ts` — Node implementation of URL validation, destination classification, DNS checks, connection-time pinning, redirect revalidation, and Host/SNI preservation.
- original Telos scaffold — semantic endpoint-use authorization contracts and deny-by-default purpose policy.

## Canonical result

The union of these responsibilities lives in `oramasys/telos`. Provider packages consume Telos and must not maintain independent endpoint-security implementations.
