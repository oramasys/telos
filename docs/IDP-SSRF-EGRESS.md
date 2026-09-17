# Design — Telos owns IdP / SSRF egress for optional auth providers

**Date:** 2026-09-16
**Status:** DESIGN (draft). Local auth-surface work remains elsewhere; Telos
implementation of an IdP policy pack and Oramasys wiring may land later.
**Invariant:** Local Bearer/gossip remain root of trust. Absence of an IdP
provider never disables local auth. Telos owns **where** outbound IdP / JWKS /
token HTTP may go — not operator identity itself.

This design sits under the accepted 2026-08-29 Tripwire/Telos split recorded in
`BOUNDARIES.md` and `ERRATA-2026-09-10.md`. Semantic permission
(`EndpointAuthorizer` / `EndpointPurpose`) and transport safety
(`TransportPolicy`, resolve-then-recheck, pin, redirect revalidation) remain
separate decisions **inside Telos**. Neither decision is evidence of the other
(`docs/BOUNDARIES.md`).

Catalog purpose IDs in this document are **not** live `EndpointPurpose` enum
members. `src/telos/contracts.py` currently defines only `config_read`,
`health_probe`, and `model_egress`. This PR does not add enum members.

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
transport — not a direct client. Shape (illustrative; not a new public API in
this PR):

```text
Provider needs JWKS / OIDC discovery / token / userinfo
        │
        ▼
telos.request(method, url,
              purpose=<registered EndpointPurpose>,
              authorizer=…, transport_policy=…, resolver=…)
        │
        ├─ purpose string not on EndpointPurpose → DENY (unknown_purpose / fail closed)
        ├─ purpose member with no policy rule → DENY (unknown_purpose)
        ├─ URL host/IP not in purpose allowlist → DENY (endpoint_not_permitted / SSRF)
        ├─ public destination and scheme not https → DENY (https_required)
        ├─ resolved address not allowed by TransportPolicy → DENY
        ├─ redirect hop fails the same checks → DENY
        └─ ALLOW → dial pinned PLACE; TLS/Host/SNI use endpoint NAME; return bytes
```

**Fail closed:** if Telos is unavailable, the purpose is missing, or transport
denies, optional IdP providers return `None` / auth miss. **Bearer still
works.** Enabling `ORAMA_AUTH_GOOGLE` / `ORAMA_AUTH_X` (or successors) without a
fully registered Telos purpose must not fall back to raw internet dial.

**Default composition (Oramasys, later wiring):** if `ORAMA_TELOS_EGRESS=0` or
Telos is not installed, providers that require network stay disabled
(`is_configured=False`) rather than dialing raw.

Loopback HTTP remains a Telos transport-profile choice for tests, not an IdP
purpose exception. IdP purposes in production are HTTPS public destinations
only.

### Registration (required before any catalog ID is usable)

Until **all three** steps land, the ID remains unusable and Telos stays
deny-by-default (`unknown_purpose` / fail closed):

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
confirm at implementation time**, not a live allowlist and not a LAN topology.

| Purpose ID | Allowed hosts (examples) | Used by |
|------------|--------------------------|---------|
| `idp-google-oidc-discovery` | `accounts.google.com` | Google OIDC metadata |
| `idp-google-jwks` | `www.googleapis.com` (JWKS path only) | ID token verify |
| `idp-google-token` | `oauth2.googleapis.com` | Google token endpoint (code exchange, if server-side) |
| `idp-google-userinfo` | `openidconnect.googleapis.com` | Google userinfo |
| `idp-x-oauth` | `api.x.com` / `x.com` (confirm at impl) | X OAuth authorize + token |
| `idp-x-userinfo` | `api.twitter.com` / `api.x.com` (confirm at impl) | X userinfo |

Rules for IdP purposes:

- String not on `EndpointPurpose` → deny (`unknown_purpose` / fail closed).
- Enum member with no policy rule → deny (`unknown_purpose`).
- Exact host/scheme/port identity after Telos normalization; path constraints
  (JWKS path only) belong in the policy pack, not in provider-local fetch.
- No RFC1918, link-local, unspecified, multicast, or cloud-metadata addresses
  (`169.254.169.254`, `100.100.100.200`, and other Telos metadata/special-use
  denials) for IdP purposes.
- IP literals denied unless an operator explicitly allowlists that identity for
  that purpose (IdP catalog does not).

---

## 4. Deferred catalog (Nostr / BUZZ relay)

These purpose IDs are **reserved for later**. They are not live
`EndpointPurpose` members. Registering them is a later explicit implementation
(same three steps as §2). Do not treat reservation as authorization.

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
   `idp-google-userinfo` / `idp-x-userinfo` after those IDs are registered.
3. Default factory: no Telos egress → network IdP stays disabled.
4. Unit tests (consumer): mock Telos deny → provider soft-fail; Bearer path
   green.
5. Operators enable Google/X flags only after enum members **and** policy rules
   exist for those purposes.
6. Telos CI later: contract tests deny SSRF fixtures (metadata, private,
   rebinding, off-allowlist redirect) for these purposes.

Does **not** block local-crypto / header remediation on the auth surface. Network
IdP paths should already be fail-closed or Telos-bound before those flags are
enabled in production.

---

## 6. SSRF checklist (Telos)

Existing Telos primitives already own most of this path (`address.py`,
`resolver.py`, `transport.py`, `policy.py`). The IdP pack must keep them
composed and fail-closed:

- [ ] Deny IP literals unless explicitly allowlisted for a purpose
- [ ] Resolve DNS then re-check allowlist and address class (TOCTOU / rebinding)
- [ ] Block redirects to off-list hosts; drop credential-shaped headers on
      cross-origin redirects (existing transport behavior)
- [ ] Timeout (whole call, including hops) + `max_body_bytes`
- [ ] HTTPS required for public IdP destinations
- [ ] Connection-time pin: PLACE is the vetted IP; NAME is Host / SNI
- [ ] Redact tokens and credential headers in Telos audit / decision logs

---

## 7. Phasing

| Phase | Deliverable |
|-------|-------------|
| **Design (this doc)** | Ownership + Google/X purpose catalog + Deferred Nostr IDs reserved |
| **telos `EndpointPurpose` + policy pack** | Steps 1–2 of registration for Google/X catalog IDs; exact HTTPS identities; deny-by-default remainder |
| **oramasys wiring** | Step 3: providers call `telos.request(..., purpose=...)` only; no raw dial fallback |
| **CI** | Contract tests deny SSRF fixtures for IdP purposes |
| **Deferred (later)** | Nostr relay purposes + optional BUZZ relay enrichment via Telos (IDs reserved in Deferred catalog) |

---

*End of design.*
