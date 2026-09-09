"""Telos: canonical endpoint-security authority for Oramasys."""
from .address import assert_address_allowed, is_metadata_address, is_public_address, parse_ip
from .authorizer import EndpointAuthorizer
from .contracts import AuthorizedEndpoint, DecisionRecord, EndpointIdentity, EndpointPurpose, EndpointRef, EndpointUseDecision, EndpointUseRequest, TelosPort
from .dialer import ConnectedPeer, SecureDialConnector, SecureDialRequest, SecureDialResult, SecureDialer
from .errors import EndpointPolicyError, TelosError
from .identity import endpoint_from_url
from .policy import EndpointPolicy, PurposeRule
from .resolver import resolve_endpoint
from .transport import TelosResponse, TransportPolicy, authorize_url, request

__all__ = [
    "AuthorizedEndpoint", "ConnectedPeer", "DecisionRecord", "EndpointAuthorizer",
    "EndpointIdentity", "EndpointPolicy", "EndpointPolicyError", "EndpointPurpose",
    "EndpointRef", "EndpointUseDecision", "EndpointUseRequest", "PurposeRule",
    "SecureDialConnector", "SecureDialRequest", "SecureDialResult", "SecureDialer",
    "TelosError", "TelosPort", "TelosResponse", "TransportPolicy",
    "assert_address_allowed", "authorize_url", "endpoint_from_url",
    "is_metadata_address", "is_public_address", "parse_ip", "request",
    "resolve_endpoint",
]
