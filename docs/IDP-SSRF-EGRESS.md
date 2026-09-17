# Design — Telos owns IdP / SSRF egress for optional auth providers

**Date:** 2026-09-16
**Status:** DESIGN (draft). Local auth-surface work remains elsewhere; Telos
implementation of an IdP policy pack and Oramasys wiring may land later.
**Invariant:** Local Bearer/gossip remain root of trust. Absence of an IdP
provider never disables local auth. Telos owns **where** outbound IdP / JWKS /
token / userinfo HTTP may go — not operator identity itself.

This design sits under the accepted 2026-08-29 Tripwire/Telos split recorded in
`BOUNDARIES.md` and `ERRATA-2026-09-10.md`. Semantic permission
(`EndpointAuthorizer` / `EndpointPurpose`) and transport safety
(`TransportPolicy`, resolve-then-recheck, pin, redirect revalidation) remain
separate decisions **inside Telos**. Neither decision is evidence of the other
(`docs/BOUNDARIES.md`). orama-system Gate-0 ADR `docs/v2/62-*` (Telos/Phylax):
Telos is the sole v2 endpoint-security authority; compose semantic allow **and**
transport safety before dial; v1 PT SSRF is golden evidence only (no runtime
import).

Catalog purpose IDs in this document are **not** live `EndpointPurpose` enum
members. `src/telos/contracts.py` currently defines only `config_read`,
`health_probe`, and `model_egress`. This PR does not add enum members.

---

## Normative references / practices

Open-source SSRF and egress libraries, plus orama-system `docs/v2/` invariants.
None of these couple deferral to a Telos product version string.

**OWASP SSRF Prevention Cheat Sheet.** Allowlist scheme, host, and port. Resolve
A and AAAA, validate every address, then connect to a validated IP (pin) so DNS
rebinding / TOCTOU (CWE-350) cannot swap PLACE after NAME was checked.

**OWASP API Top 10 API7:2023 (SSRF).** Disable redirects or revalidate every
hop. Use a maintained URL parser. Isolate fetch from the rest of the app.

**OSS egress libraries** (egressweave, ssrf-guard, drawbridge, ressrf,
go-egress-proxy). Exact host allowlists (no wildcards). Pin after validate.
Fail closed if any resolved address is mixed/private/unsafe. Ignore ambient
`HTTP_PROXY` / `HTTPS_PROXY` / `trust_env` for IdP paths (client allowlists
are incompatible with a blind proxy). Revalidate redirects; strip
credential-shaped headers on cross-origin hops.

**ADR / deferred-feature practice.** Reservation is an append-only decision
with stable IDs. The unlock trigger is implementation registration (the three
steps in §2) — not a product version string.

**orama-system `docs/v2/` (execute, do not duplicate authority):**

- Gate-0 ADR `docs/v2/62-*` — Telos sole endpoint-security authority; semantic
  allow ≠ transport-safe; compose both before dial; v1 PT SSRF evidence-only.
- SSRF defense-in-depth `docs/v2/plans/2026-08-20-ssrf-defense-in-depth.md` —
  keep L1 pre-flight deny + L2 pin transport composed; L3 OS egress floor is
  separate infrastructure.
- Agentic security controls `docs/v2/32-agentic-security-controls.md` —
  deny-by-default; fixed-purpose calls prefer no redirects (revalidate if
  followed).
- Peer mesh auth `docs/v2/49-peer-mesh-auth-tls-v2-plan.md` — Bearer is the
  forever path; OAuth is optional. IdP absence must never disable local auth.

---

## 1. Ownership split

| Component | Owns | Does not own |
|-----------|------|--------------|
| **S-AuthZ / AuthManager** | Inbound HTTP capability, Bearer, optional provider *verify* of already-fetched material | Opening sockets to Google / X / JWKS / relays |
| **Auth providers (Google / X)** | OAuth/OIDC protocol logic, claim checks, binding subject | Raw `httpx` / `urllib` / equivalent to the public internet |
| **BUZZ NIP-98** | Offline signature verify (no egress in MVP) | Relay dial / enrichment (reserved later → Telos; see Deferred catalog) |
| **BitChat Noise** | Local BLE / in-process radio; no cloud IdP | WAN egress |
| **Telos** | Purpose-scoped allowlist of destinations (URL / IP / DNS / TLS pin policy), SSRF deny-by-default, DNS rebinding defenses, reusable `request()` / `authorize_url()` primitives | Deciding if Bearer is valid |
| **Phylax** | Artifact / runtime admission | IdP endpoints |
| **Agate** | Hardware placement | Identity / egress |

Telos does not become an identity provider. Providers that need network remain
optional and must not dial around Telos.

---

## 2. Operating model

Callers that need JWKS, OIDC discovery, token, or userinfo material use Telos
transport — not a direct client. Profile/userinfo is a **separate purpose**
(least privilege); do not smuggle it under a vague OAuth purpose. Shape
(illustrative; not a new public API in this PR):

```text
Provider needs JWKS / OIDC discovery / token / userinfo
        │
        ▼
telos.request(method, url,
              purpose=<registered EndpointPurpose>,
              authorizer=…, transport_policy=…, resolver=…)
        │
        ├─ purpose string not on EndpointPurpose → DENY (bridge ValueError)
        ├─ purpose member with no policy rule → DENY (unknown_purpose)
        ├─ URL host/IP not in purpose allowlist → DENY (endpoint_not_permitted / SSRF)
        ├─ public destination and scheme not https → DENY (https_required)
        ├─ any A/AAAA result unsafe / mixed private → DENY
        ├─ redirect hop fails the same checks → DENY
        └─ ALLOW → dial pinned PLACE; TLS/Host/SNI use endpoint NAME; return bytes
```

**Dual fail-closed:** (1) unknown enum string is rejected in `bridge._purpose`
(`ValueError`); (2) a constructed member with no policy rule evaluates
`unknown_purpose`. Either path is a deny. If Telos is unavailable, optional IdP
providers return `None` / auth miss. **Bearer still works** (orama-system
`docs/v2/49-*`). Enabling `ORAMA_AUTH_GOOGLE` / `ORAMA_AUTH_X` (or successors)
without a fully registered Telos purpose must not fall back to raw internet
dial.

**Default composition (Oramasys, later wiring):** if `ORAMA_TELOS_EGRESS=0` or
Telos is not installed, providers that require network stay disabled
(`is_configured=False`) rather than dialing raw. IdP fetch must not honor
ambient `HTTP_PROXY` / `HTTPS_PROXY` (`trust_env=False` or equivalent).

Loopback HTTP remains a Telos transport-profile choice for tests, not an IdP
purpose exception. IdP purposes in production are HTTPS public destinations
only. Fixed-purpose IdP calls **prefer no redirects**; if a hop is followed,
revalidate scheme/host/port/address class on every hop.

### Registration (required before any catalog ID is usable)

Until **all three** steps land, the ID remains unusable and Telos stays
deny-by-default (bridge reject and/or `unknown_purpose`):

1. Add the purpose ID to `EndpointPurpose` in `src/telos/contracts.py`.
2. Register allowlist entries for that member in the Telos policy pack.
3. Wire Oramasys providers to `telos.request(..., purpose=...)` with the
   registered enum value.

A policy pack cannot invent enum members. `bridge._purpose` constructs
`EndpointPurpose` from the caller string and rejects unknown values.

---

## 3. Purpose catalog (Google / X IdP only)

These IDs are the **active catalog for this design**. They are intended
`EndpointPurpose` string values after the three registration steps above. They
are **not** live enum members today. Hosts are **examples for operators to
confirm at implementation time** — exact hosts, no wildcards — not a live
allowlist and not a LAN topology.

| Purpose ID | Allowed hosts (examples) | Used by |
|------------|--------------------------|---------|
| `idp-google-oidc-discovery` | `accounts.google.com` | Google OIDC metadata |
| `idp-google-jwks` | `www.googleapis.com` (JWKS / certs path only) | ID token verify |
| `idp-google-token` | `oauth2.googleapis.com` | Google token endpoint (code exchange, if server-side) |
| `idp-google-userinfo` | `openidconnect.googleapis.com` (official OIDC `userinfo_endpoint`) | Google userinfo (`/v1/userinfo`) |
| `idp-x-oauth` | `api.x.com` / `x.com` (confirm at impl) | X OAuth authorize + token (not userinfo) |
| `idp-x-userinfo` | prefer `api.x.com` (`/2/users/me`); `api.twitter.com` is a legacy alias (confirm at impl) | X userinfo |

Rules for IdP purposes:

- String not on `EndpointPurpose` → deny (`bridge._purpose` / `ValueError`).
- Enum member with no policy rule → deny (`unknown_purpose`).
- Exact host/scheme/port identity after Telos normalization; path constraints
  (JWKS path, userinfo path) belong in the policy pack, not in provider-local
  fetch. One capability per purpose ID.
- No RFC1918, link-local, unspecified, multicast, or cloud-metadata addresses
  (`169.254.169.254`, `100.100.100.200`, and other Telos metadata/special-use
  denials) for IdP purposes. If any resolved address is unsafe, deny the whole
  lookup (mixed-result fail closed).
- IP literals denied unless an operator explicitly allowlists that identity for
  that purpose (IdP catalog does not).

---

## 4. Deferred catalog (Nostr / BUZZ relay)

These IDs are reserved; reservation is not authorization. Implementing them
uses the same three registration steps — not a Telos version gate.

They are not live `EndpointPurpose` members. Reservation is append-only with
stable IDs (ADR / deferred-feature practice).

BUZZ NIP-98 MVP remains **offline signature verify only** — no relay dial in
this PR or in the MVP.

| Purpose ID | Status | Notes |
|------------|--------|-------|
| `nostr-relay-read` | reserved | Optional later relay read; operator allowlist only when implemented |
| `nostr-relay-write` | reserved | Optional later relay write; not live |
| `nostr-relay-enrich` | reserved | Optional later BUZZ enrichment via Telos; not live |

---

## 5. Integration points (later; not this PR)

1. Complete the three registration steps in §2 for each Google/X catalog ID
   that will be enabled.
2. Inject Telos transport (`request` / composition factory) into Google/X
   providers. Providers own protocol; Telos owns the socket. Userinfo uses
   `idp-google-userinfo` / `idp-x-userinfo` after those IDs are registered —
   never `idp-x-oauth` / token purposes.
3. Default factory: no Telos egress → network IdP stays disabled; no ambient
   proxy for IdP.
4. Unit tests (consumer): mock Telos deny → provider soft-fail; Bearer path
   green.
5. Operators enable Google/X flags only after enum members **and** policy rules
   exist for those purposes.
6. Telos CI later: contract tests deny SSRF fixtures (metadata, private,
   mixed A/AAAA, rebinding, off-allowlist redirect, proxy env) for these
   purposes.

Does **not** block local-crypto / header remediation on the auth surface. Network
IdP paths should already be fail-closed or Telos-bound before those flags are
enabled in production.

---

## 6. SSRF checklist (Telos)

Existing Telos primitives already own most of this path (`address.py`,
`resolver.py`, `transport.py`, `policy.py`). The IdP pack must keep L1+L2
composed and fail-closed (orama-system `docs/v2/plans/2026-08-20-ssrf-defense-in-depth.md`).
L3 OS egress is a separate floor.

- [ ] Allowlist scheme + host + port; exact hosts, no wildcards
- [ ] Deny IP literals unless explicitly allowlisted for a purpose
- [ ] Resolve all A and AAAA; validate every address; fail closed on mixed/unsafe
      results; then pin dial to vetted PLACE (NAME remains Host / SNI)
- [ ] Prefer no redirects for fixed-purpose IdP; if followed, revalidate every
      hop; drop credential-shaped headers on cross-origin redirects
- [ ] Ignore ambient `HTTP_PROXY` / `HTTPS_PROXY` / `trust_env` on IdP paths
- [ ] Timeout (whole call, including hops) + `max_body_bytes`
- [ ] HTTPS required for public IdP destinations
- [ ] Redact tokens and credential headers in Telos audit / decision logs

---

## 7. Phasing

| Phase | Deliverable |
|-------|-------------|
| **Design (this doc)** | Ownership + Google/X purpose catalog + Deferred Nostr IDs reserved |
| **telos `EndpointPurpose` + policy pack** | Steps 1–2 of registration for Google/X catalog IDs; exact HTTPS identities; deny-by-default remainder |
| **oramasys wiring** | Step 3: providers call `telos.request(..., purpose=...)` only; no raw dial fallback |
| **CI** | Contract tests deny SSRF fixtures for IdP purposes |
| **Deferred (later)** | Nostr relay purposes + optional BUZZ relay enrichment via Telos (IDs reserved in Deferred catalog; same three registration steps, not a version gate) |

---

*End of design.*
