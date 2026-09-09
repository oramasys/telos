# Telos

Telos is the **canonical endpoint-security authority for Oramasys** and the v2 successor to the original Tripwire SSRF/dialer/socket-pinning design.

The accepted 2026-08-29 architecture is authoritative: Telos owns endpoint-specific security end to end. The September semantic-only scaffold was implementation drift and did not supersede that design.

## Authority

Telos owns:

- URL parsing and canonical endpoint identity;
- IP/CIDR and special-use destination classification;
- SSRF and cloud-metadata protections;
- DNS resolution and rebinding/TOCTOU resistance;
- connection-time IP pinning;
- redirect revalidation;
- proxy isolation;
- TLS destination identity, Host, and SNI preservation;
- purpose-scoped endpoint-use authorization;
- reusable safe transport primitives for provider adapters.

Provider packages own provider protocol and lifecycle semantics, not endpoint-security primitives. `oramasys/Claude-Desktop-LLM/src/policy/endpoint-policy.ts` and the v1 Perpetua-Tools endpoint-policy/SSRF stack are migration evidence, not permanent competing v2 authorities. v2 has no runtime dependency on v1 PT.

Telos uses the Apache License 2.0, matching the endpoint-policy package authority it replaces.
