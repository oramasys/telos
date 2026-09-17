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

Current `EndpointPurpose` values (`config_read`, `health_probe`, `model_egress`)
are unchanged by this design. The purpose IDs below are the **catalog to
register** in a later deny-by-default policy pack. Unregistered purposes stay
`unknown_purpose` and fail closed.

---

## 1. Ownership split

| Component | Owns | Does not own |
|-----------|------|--------------|
| **S-AuthZ / AuthManager** | Inbound HTTP capability, Bearer, optional provider *verify* of already-fetched material | Opening sockets to Google / X / JWKS / relays |
| **Auth providers (Google / X)** | OAuth/OIDC protocol logic, claim checks, binding subject | Raw `httpx` / `urllib` / equivalent to the public internet |
| **BUZZ NIP-98** | Offline signature verify (no egress in MVP) | Relay enrichment (optional later → Telos) |
| **BitChat Noise** | Local BLE / in-process radio; no cloud IdP | WAN egress |
| **Telos** | Purpose-scoped allowlist of destinations (URL / IP / DNS / TLS pin policy), SSRF deny-by-default, DNS rebinding defenses, reusable `request()` / `authorize_url()` primitives | Deciding if Bearer is valid |
| **Phylax** | Artifact / runtime admission | IdP endpoints |
| **Agate** | Hardware placement | Identity / egress |

Telos does not become an identity provider. Providers that need network remain
optional and must not dial around Telos.

---

## 2. Operating model

Callers that need JWKS, token, or userinfo material use Telos transport — not a
direct client. Shape (illustrative; not a new public API in this PR):

```text
Provider needs JWKS / token / userinfo
        │
        ▼
telos.request(method, url,
              purpose=<registered EndpointPurpose>,
              authorizer=…, transport_policy=…, resolver=…)
        │
        ├─ purpose not registered → DENY (unknown_purpose / purpose_denied)
        ├─ URL host/IP not in purpose allowlist → DENY (endpoint_not_permitted / SSRF)
        ├─ public destination and scheme not https → DENY (https_required)
        ├─ resolved address not allowed by TransportPolicy → DENY
        ├─ redirect hop fails the same checks → DENY
        └─ ALLOW → dial pinned PLACE; TLS/Host/SNI use endpoint NAME; return bytes
```

**Fail closed:** if Telos is unavailable, the purpose is missing, or transport
denies, optional IdP providers return `None` / auth miss. **Bearer still
works.** Enabling `ORAMA_AUTH_GOOGLE` / `ORAMA_AUTH_X` (or successors) without a
registered Telos purpose must not fall back to raw internet dial.

**Default composition (Oramasys, later wiring):** if `ORAMA_TELOS_EGRESS=0` or
Telos is not installed, providers that require network stay disabled
(`is_configured=False`) rather than dialing raw.

Loopback HTTP remains a Telos transport-profile choice for tests, not an IdP
purpose exception. IdP purposes in production are HTTPS public destinations
only.

---

## 3. Purpose catalog (initial)

These IDs are the intended `EndpointPurpose` values for a later policy pack.
Hosts are **examples for operators to confirm at implementation time**, not a
live allowlist and not a LAN topology.

| Purpose ID | Allowed hosts (examples) | Used by |
|------------|--------------------------|---------|
| `idp-google-oidc-discovery` | `accounts.google.com` | Google metadata |
| `idp-google-jwks` | `www.googleapis.com` (JWKS path only) | ID token verify |
| `idp-google-token` | `oauth2.googleapis.com` | code exchange (if server-side) |
| `idp-x-oauth` | `api.x.com` / `x.com` (confirm at impl) | X OAuth |
| `nostr-relay-read` | operator allowlist only | Optional BUZZ enrichment (**not MVP**) |

Rules for IdP purposes:

- Unknown purpose → deny.
- Exact host/scheme/port identity after Telos normalization; path constraints
  (JWKS path only) belong in the policy pack, not in provider-local fetch.
- No RFC1918, link-local, unspecified, multicast, or cloud-metadata addresses
  (`169.254.169.254`, `100.100.100.200`, and other Telos metadata/special-use
  denials) for IdP purposes.
- IP literals denied unless an operator explicitly allowlists that identity for
  that purpose (IdP catalog does not).
- `nostr-relay-read` is out of the BUZZ NIP-98 MVP (offline verify only).

---

## 4. Integration points (later; not this PR)

1. Inject Telos transport (`request` / composition factory) into Google/X
   providers. Providers own protocol; Telos owns the socket.
2. Default factory: no Telos egress → network IdP stays disabled.
3. Unit tests (consumer): mock Telos deny → provider soft-fail; Bearer path
   green.
4. Operators register purposes in Telos policy before enabling Google/X flags.
5. Telos CI later: contract tests deny SSRF fixtures (metadata, private,
   rebinding, off-allowlist redirect) for these purposes.

Does **not** block local-crypto / header remediation on the auth surface. Network
IdP paths should already be fail-closed or Telos-bound before those flags are
enabled in production.

---

## 5. SSRF checklist (Telos)

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

## 6. Phasing

| Phase | Deliverable |
|-------|-------------|
| **Design (this doc)** | Ownership + purpose catalog |
| **telos policy pack** | Register IdP purposes; exact HTTPS identities; deny-by-default remainder |
| **oramasys wiring** | Providers call Telos transport only; no raw dial fallback |
| **CI** | Contract tests deny SSRF fixtures for IdP purposes |

---

*End of design.*
