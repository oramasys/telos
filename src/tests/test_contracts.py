"""Step 1 of docs/IDP-SSRF-EGRESS.md's 3-step registration: live
EndpointPurpose members for the Google/X IdP catalog. Steps 2 (request-profile
enforcement) and 3 (Oramasys wiring) are separate, later work -- these tests
prove Step 1 alone does what the doc requires: the enum values exist and
match the catalog exactly, and adding them grants no access by itself."""
import pytest
from telos import EndpointAuthorizer, EndpointPurpose, EndpointRef, EndpointUseRequest, resolve_endpoint
import socket


def resolver(host, port):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("142.250.0.1", port))]


def identity(host="accounts.google.com"):
    return resolve_endpoint(
        EndpointRef("https", host, 443),
        allow_public=True, allow_private=False, allow_loopback=False,
        resolver=resolver,
    )


CATALOG = {
    EndpointPurpose.IDP_GOOGLE_OIDC_DISCOVERY: "idp-google-oidc-discovery",
    EndpointPurpose.IDP_GOOGLE_JWKS: "idp-google-jwks",
    EndpointPurpose.IDP_GOOGLE_TOKEN: "idp-google-token",
    EndpointPurpose.IDP_GOOGLE_USERINFO: "idp-google-userinfo",
    EndpointPurpose.IDP_X_TOKEN: "idp-x-token",
    EndpointPurpose.IDP_X_USERINFO: "idp-x-userinfo",
}


@pytest.mark.parametrize("member,expected_value", CATALOG.items(), ids=[m.name for m in CATALOG])
def test_idp_purpose_member_matches_the_design_doc_catalog(member, expected_value):
    assert member.value == expected_value


def test_idp_x_oauth_is_not_a_registered_member():
    """The design doc supersedes idp-x-oauth with idp-x-token for server
    HTTP plus a browser-only authorization flow. The old ID is historical
    provenance in the doc only -- it must not exist as a live enum value,
    registered, or silently aliased."""
    values = {m.value for m in EndpointPurpose}
    assert "idp-x-oauth" not in values


@pytest.mark.parametrize("member", CATALOG, ids=[m.name for m in CATALOG])
def test_idp_purpose_member_grants_no_access_without_a_registered_rule(member):
    """Registering an enum alone grants nothing (design doc Step 1 vs 2):
    with no trusted profile for these purposes yet, every one of them must
    still deny exactly like any other unregistered purpose."""
    auth = EndpointAuthorizer.from_exact_rules({})
    decision = auth.authorize(
        EndpointUseRequest("provider", "idp-flow", member, identity(), "run-1")
    )
    assert not decision.allowed
    assert decision.reason_code == "unknown_purpose"


def test_google_and_x_purposes_do_not_fall_back_to_model_egress():
    """bridge._purpose defaults an omitted purpose string to MODEL_EGRESS
    (see bridge.py) -- confirm the new IdP members are genuinely distinct
    values, not accidentally aliased to it, since an IdP call silently
    authorized under model_egress's rules would be the exact fallback the
    design doc's Step 1 boundary explicitly forbids."""
    for member in CATALOG:
        assert member != EndpointPurpose.MODEL_EGRESS
        assert member.value != EndpointPurpose.MODEL_EGRESS.value
