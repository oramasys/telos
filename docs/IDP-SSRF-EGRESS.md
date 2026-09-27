# Design — Telos owns IdP / SSRF egress for optional auth providers

**Date:** 2026-09-16
**Research and contract review:** 2026-09-17 UTC
**Status:** DESIGN, Step 1 of 3 landed. `EndpointPurpose` now carries the six
Google/X catalog members (Step 1) -- they grant no access by themselves,
since no trusted request-profile pack (Step 2) or Oramasys wiring (Step 3)
exists yet. Local auth-surface work remains elsewhere.
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

Catalog purpose IDs are now live `EndpointPurpose` members (Step 1,
`src/telos/contracts.py`). Registering the enum grants no access by itself:
`EndpointPolicy.evaluate()` still returns `unknown_purpose` for every one of
them until Step 2 (a trusted request-profile pack) exists -- proven directly
by `src/tests/test_contracts.py`. Steps 2 and 3 remain outstanding.

---

## Normative references / practices

Open-source SSRF and egress libraries, plus orama-system `docs/v2/` invariants.
None of these couple deferral to a Telos product version string.

**OWASP SSRF Prevention Cheat Sheet.** Allowlist the expected scheme, host, and
port; resolve and validate all IPv4/IPv6 answers; and isolate the fetch path.
Connection pinning is Telos's additional defense against a DNS change between
validation and connect, not a blanket claim about OWASP's prescribed client.

**OWASP API Top 10 API7:2023 (SSRF).** Disable HTTP redirects, use a maintained
URL parser, constrain remote origins/schemes/ports, and isolate resource
fetching. Telos sets `max_redirects=0` for catalog operations.

**Source-specific OSS precedents (not a consensus claim).**
[Smokescreen][smokescreen] separates a service/client hostname ACL from
resolved-address checks. [Forge][forge] expands named capability bundles into
a runtime allowlist. [Plecto Proxy ADR 000036][plecto] is the closest precedent
for operator-owned exact `(scheme, host, port)` entries, validating every
resolved address, IP-pinned dialing with the original TLS name, and no
redirects. [OAG][oag] documents deny-before-allow and fresh policy evaluation
for redirect requests. [Drawbridge][drawbridge] documents all-answer
validation, pinning, redirect checks, credential stripping, and proxy
environment isolation. These projects have different wildcard, private-address,
proxy, and redirect options; Telos deliberately selects the stricter
public-only, exact-origin, no-redirect profile here. PT `.agent` and Orama
`docs/v2` remain the authority for repository-specific decisions.

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
  deny-by-default; fixed-purpose calls disable redirects unless a separately
  reviewed revalidation contract exists.
- Peer mesh auth `docs/v2/49-peer-mesh-auth-tls-v2-plan.md` — Bearer is the
  forever path; OAuth is optional. IdP absence must never disable local auth.

---

## 1. Ownership split

| Component | Owns | Does not own |
|-----------|------|--------------|
| **S-AuthZ / AuthManager** | Inbound HTTP capability, Bearer, optional provider *verify* of already-fetched material | Opening sockets to Google / X / JWKS / relays |
| **Auth providers (Google / X)** | OAuth/OIDC protocol logic, claim checks, binding subject | Raw `httpx` / `urllib` / equivalent to the public internet |
| **BUZZ NIP-98** | Offline signature verify (no egress in MVP) | Relay dial / enrichment (reserved for a separate future design) |
| **BitChat Noise** | Local BLE / in-process radio; no cloud IdP | WAN egress |
| **Telos** | Purpose-scoped endpoint authorization, SSRF defense, DNS/socket pinning, TLS hostname verification, reusable `request()` / `authorize_url()` primitives; planned IdP method/path profiles | Deciding if Bearer is valid |
| **Phylax** | Artifact / runtime admission | IdP endpoints |
| **Agate** | Hardware placement | Identity / egress |

Telos does not become an identity provider. Providers that need network remain
optional and must not dial around Telos.

---

## 2. Operating model

Callers that need JWKS, OIDC discovery, token, or userinfo material use Telos
transport. Profile/userinfo is a **separate purpose**. The chosen design is a
small, trusted IdP composition layer inside Telos that reuses its existing
identity, resolver, authorizer, and pinned transport. A second fetch library or
proxy would add another enforcement boundary without closing the gaps below.

### Trusted profiles, constrained provider calls

At startup, trusted composition selects a reviewed, immutable policy snapshot.
Each enabled operation binds one registered purpose to its exact HTTPS origin,
method, path, permitted query/header/body fields, and bounded transport profile.
Providers receive only their bound operations; an inbound request cannot choose
another provider's purpose or inject a policy. Missing or unknown operation /
purpose fails closed; there is **no `model_egress` default** on an IdP path.

The provider supplies protocol values such as an authorization code or access
token. It cannot supply or widen `allowed_endpoints`, `allowed_hosts`,
`allow_remote`, `transport`, `authorizer`, `resolver`, proxy/TLS settings, or
resource limits. Reject such overrides at the IdP boundary. Policy changes
require a reviewed deployment configuration change, never request data or
discovery metadata. Tests inject transport doubles through trusted composition
only; production does not accept a caller-selected resolver or connector.

For each operation, the future Telos composition must:

1. Validate the bound purpose and complete profile before DNS or socket work;
   build the request from the profile and permitted protocol fields.
2. Enforce exact normalized origin **and** method/path/query constraints. Reject
   credentials in URLs, fragments, alternate paths, and ambiguous encodings;
   never authorize by string prefix or by hostname alone.
3. Resolve and validate every A/AAAA answer under the public-only profile.
   Semantic authorization and transport denial remain independent gates; any
   denial wins, even for an allowlisted hostname.
4. Call `telos.request` with the profile's explicit enum, authorizer, resolver,
   and transport policy. Dial the vetted IP (PLACE); verify the connected peer
   and TLS certificate, preserving the normalized hostname (NAME) for Host/SNI.
5. Return bounded response bytes to the provider for protocol/claim validation.
   Destination authorization does not authenticate the user or issuer claims.

**Current implementation boundary:** these are IdP implementation requirements,
not claims that a policy-pack file alone activates them:

| Primitive today | Gap to close before IdP activation |
| --- | --- |
| `bridge._purpose` rejects unknown enum strings | The generic `bridge.handle` defaults an omitted purpose to `model_egress` and builds policy from caller-supplied endpoints, hosts, and transport flags. Do not expose this raw payload as the IdP API. An IdP bridge entry point must enforce the same trusted profile as an in-process call. |
| `EndpointPolicy` returns `unknown_purpose` for an absent rule | Use the trusted pack; constructing a rule from the request itself defeats this gate. Registering an enum alone grants nothing. |
| `EndpointRef` / `PurposeRule` match `(scheme, host, port)` | They contain no method/path/query constraint. Add a Telos-owned request-profile check without changing origin identity or moving endpoint security into providers. |
| Pinned transport checks DNS answers, peer IP, Host/SNI and redirect destinations | Set the IdP profile explicitly; generic transport defaults and header stripping alone do not implement the IdP credential policy. |

If Telos or a complete profile is unavailable, optional network IdP providers
return `None` / auth miss. **Bearer still works** (orama-system `docs/v2/49-*`).
Enabling `ORAMA_AUTH_GOOGLE` / `ORAMA_AUTH_X` (or successors) without the full
registration must not fall back to raw internet dial.

**Default composition (Oramasys, later wiring):** if `ORAMA_TELOS_EGRESS=0` or
Telos is not installed, providers that require network stay disabled
(`is_configured=False`) rather than dialing raw. IdP fetch must not honor
ambient `HTTP_PROXY` / `HTTPS_PROXY` (`trust_env=False` or equivalent).

Production IdP profiles require `allow_public=True`, `allow_private=False`,
`allow_loopback=False`, `require_https_for_public=True`, and `max_redirects=0`.
Tests use injected doubles; they do not enable a production loopback exception.
Disable redirects for all catalog operations. In particular, token POST bodies
may contain credentials: stripping Authorization on a 307/308 cross-origin hop
does not prevent body replay. Any later redirect exception requires its own
review, same-purpose method/path/origin/address revalidation, and a rule that
never forwards credentials in headers or bodies to another origin.

### Registration (required before any catalog ID is usable)

Until **all three** steps land and their acceptance tests pass, the ID remains
unusable by the IdP composition. Step 1 has landed for all six catalog IDs;
steps 2 and 3 remain outstanding for every one of them:

1. ~~Add the purpose ID to `EndpointPurpose` in `src/telos/contracts.py`.~~ **Done.**
2. Register that member's complete trusted profile in Telos: exact origin,
   enforced method/path/query constraints, credential handling, public-only
   transport, no redirects, and bounded requests/responses.
3. Wire Oramasys providers through the bound Telos operation, which calls
   `telos.request(..., purpose=...)` with the registered enum and trusted pack.
   Both in-process and bridge callers must use this boundary.

A policy pack cannot invent enum members. `bridge._purpose` constructs
`EndpointPurpose` from the caller string and rejects unknown values.

---

## 3. Purpose catalog (Google / X IdP only)

These IDs are the **active catalog for this design**, and are now live
`EndpointPurpose` string values (Step 1, landed). They grant no access without
the request-profile pack from Step 2, not yet built. The endpoint baseline
below was checked against [Google's discovery document][google-discovery],
[Google OIDC guidance][google-oidc], [X OAuth documentation][x-oauth], and
[X Users Me][x-me] on 2026-09-17 UTC. Reconfirm it when implementing; this
table is not a live allowlist. Every origin is exactly `(https, host, 443)`,
without wildcards.

| Purpose ID | Host | Method and exact path | Used by |
| --- | --- | --- | --- |
| `idp-google-oidc-discovery` | `accounts.google.com` | `GET /.well-known/openid-configuration` | OIDC metadata |
| `idp-google-jwks` | `www.googleapis.com` | `GET /oauth2/v3/certs` | ID token verification keys |
| `idp-google-token` | `oauth2.googleapis.com` | `POST /token` | Server-side code exchange; refresh only if enabled |
| `idp-google-userinfo` | `openidconnect.googleapis.com` | `GET /v1/userinfo` | Google userinfo |
| `idp-x-token` | `api.x.com` | `POST /2/oauth2/token` | Server-side code exchange; refresh only if enabled |
| `idp-x-userinfo` | `api.x.com` | `GET /2/users/me` | X user context |

**Browser authorization is separate from server egress.** Providers construct
Google's `https://accounts.google.com/o/oauth2/v2/auth` or X's
`https://x.com/i/oauth2/authorize` navigation URL and send the user through the
browser flow. Telos must not server-fetch these pages. Provider code retains
state/PKCE/nonce, registered callback validation, and OAuth scope decisions;
`x.com` is not an IdP server-egress origin.

**Catalog correction:** the earlier draft's `idp-x-oauth` grouped browser
authorization and token exchange. It is superseded by `idp-x-token` for server
HTTP and the browser flow above. Preserve the old ID as historical provenance;
do not register it or silently alias it to another purpose. `api.twitter.com`
remains a historical compatibility reference, not an automatic allowlist entry
or fallback; supporting it later requires an explicitly reviewed exact profile.

Rules for IdP purposes:

- String not on `EndpointPurpose` → deny (`bridge._purpose` / `ValueError`).
- Enum member with no rule in the trusted pack → deny (`unknown_purpose`).
- Exact host/scheme/port identity after Telos normalization; path constraints
  and HTTP methods are enforced by the planned Telos request-profile check,
  not by today's origin-only `PurposeRule`. One capability per purpose ID.
- Construct the exact catalog path rather than accepting caller URL/path
  substitutions. No query parameters by default; any needed X field selectors
  require profile-defined names and constrained values. Put tokens in permitted
  headers or form bodies, never URL query strings or logs.
- Fetched discovery metadata may select only endpoints already authorized for
  the corresponding operation. Check the expected issuer; a new `jwks_uri`,
  `token_endpoint`, or `userinfo_endpoint` cannot expand the pack. Untrusted
  token claims / `jku` / `x5u` headers must not initiate arbitrary key fetches.
  Provider libraries must use the injected Telos operation for any key refresh.
- No RFC1918, link-local, unspecified, multicast, or cloud-metadata addresses
  (`169.254.169.254`, `100.100.100.200`, and other Telos metadata/special-use
  denials) for IdP purposes. If any resolved address is unsafe, deny the whole
  lookup (mixed-result fail closed).
- IP-literal URLs are denied for these IdP profiles. Destination classification
  comes from Telos resolution evidence, never a caller's `is_public` assertion.

---

## 4. Integration points (later; not this PR)

1. Complete the three registration steps in §2 for each Google/X catalog ID
   that will be enabled.
2. Inject the bound Telos operations into Google/X providers. Providers own
   protocol; Telos owns the profile enforcement and socket. Userinfo uses
   `idp-google-userinfo` / `idp-x-userinfo` after those IDs are registered —
   never token purposes or the superseded `idp-x-oauth` ID.
3. Default factory: no Telos egress → network IdP stays disabled; no ambient
   proxy for IdP.
4. Bound timeout, response size, and request size in the trusted profile. Prove
   the deadline covers DNS, connect/TLS, and response reads; existing socket
   timeouts alone do not prove a whole-call bound. Respect provider cache
   lifetimes for discovery/JWKS; unknown keys may trigger only a bounded refresh
   through the same profile, never an alternate URL or retry loop.
5. Enable an operation only after all three registration steps and the tests in
   §5 pass. Missing profiles disable only network IdP, not local Bearer/gossip.
6. Keep endpoint/security tests in Telos and protocol/Bearer continuity tests in
   the consumer. Reuse existing golden vectors as evidence; do not import PT or
   create provider-local copies of URL/DNS/pinning enforcement.

Does **not** block local-crypto / header remediation on the auth surface. Network
IdP paths should already be fail-closed or Telos-bound before those flags are
enabled in production.

---

## 5. Implementation acceptance checks

Existing Telos primitives already own most of this path (`address.py`,
`resolver.py`, `transport.py`, `policy.py`). The IdP pack must keep L1+L2
composed and fail-closed (orama-system `docs/v2/plans/2026-08-20-ssrf-defense-in-depth.md`).
L3 OS egress is a separate floor.

These are **future activation gates**, not completed IdP tests in this PR.
Use deterministic resolver/socket doubles and record the actual command,
commit, and result; a Host-header assertion alone does not prove TLS SNI.

| Test boundary | Required evidence before activation |
| --- | --- |
| Registration | Missing/unknown purpose, missing pack, and superseded `idp-x-oauth` fail; no default to `model_egress`. |
| Caller authority | Attempts to supply another operation, origin, allowlist, resolver, or transport override fail before DNS/dial in both in-process and bridge paths. |
| Request profile | Correct host with wrong port, method, path, query, fragment, userinfo, or ambiguous path encoding is denied; `x.com` browser authorization is never server-fetched. |
| Discovery/key lookup | Off-profile metadata URLs and JWT key URLs cannot trigger fetches; unexpected metadata issuer fails; key refresh remains bounded. |
| DNS and transport | Metadata/special-use, private/loopback, IPv4-mapped IPv6 and mixed A/AAAA answers fail even for an allowlisted name. Rebinding cannot change the dial target. |
| TLS and pin | Assert vetted peer IP, authoritative Host, original NAME as SNI, and certificate verification independently. |
| Redirect/credential | 301/302/303/307/308 cannot cause a second request for any IdP operation; token POST body and credential headers never leak to a redirect target. |
| Proxy and limits | Ambient proxy variables cannot reroute traffic; oversized bodies, slow DNS/reads and expired deadlines fail within the configured bounds. |
| Local continuity | Disabled/missing Telos, denied fetches, IdP outage and invalid provider material grant no IdP identity while independent Bearer/gossip tests stay green. |
| Redaction | Audit records contain purpose/decision evidence without tokens, codes, credential headers, or secret form bodies. |

Run the project suite under its existing **80% minimum coverage** gate; stricter
component thresholds remain binding. Documentation CI success is not evidence
that the future IdP boundary is implemented.

---

## 6. Phasing

| Phase | Deliverable |
|-------|-------------|
| **Design (this doc)** | Ownership + Google/X purpose catalog |
| **Telos enum + request profiles** | Step 1 done (enum members landed, grant no access). Step 2 outstanding for selected Google/X operations: exact identities, method/path enforcement and trusted public-only/no-redirect composition |
| **Oramasys wiring** | Step 3: bound operations call Telos with explicit purpose; no raw bridge policy, direct socket, or missing-purpose fallback |
| **Activation evidence** | Telos and consumer acceptance checks in §5 pass before enabling network IdP |

---

*End of design.*

[google-discovery]: https://accounts.google.com/.well-known/openid-configuration
[google-oidc]: https://developers.google.com/identity/openid-connect/openid-connect
[x-oauth]: https://docs.x.com/fundamentals/authentication/oauth-2-0/authorization-code
[x-me]: https://docs.x.com/x-api/users/get-my-user
[smokescreen]: https://github.com/stripe/smokescreen/blob/82f05bfded5885914108d3f6eb9bf91ebd871728/README.md
[forge]: https://docs.initializ.ai/docs/developer/forge/security/egress-control#capability-bundles
[plecto]: https://github.com/Kaikei-e/PlectoProxy/blob/main/docs/ADR/000036.md
[oag]: https://github.com/mustafadakhel/oag/blob/main/docs/concepts.md
[drawbridge]: https://github.com/tachyon-oss/drawbridge/blob/37ae282209728039bebca9aab51d2306dc10272c/README.md
