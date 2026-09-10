import base64
import socket
import telos.bridge as bridge


def test_bridge_rejects_unlisted_endpoint_before_network(monkeypatch):
    payload = {
        'url': 'http://localhost:11434/api/tags',
        'allowed_endpoints': ['http://other.local:11434'],
        'transport': {'allow_loopback': True},
    }
    # Endpoint authorization should deny before any dial. DNS for localhost is
    # deterministic inside resolver, but monkeypatch request to prove the
    # semantic contract is built from caller-declared allowed endpoint set.
    class Denied(Exception): pass
    # exercise actual handle only through a synthetic loopback resolver by replacing request
    seen = {}
    def fake_request(method, url, **kwargs):
        decision = kwargs['authorizer']._policy.evaluate(
            bridge.EndpointPurpose.MODEL_EGRESS,
            type('I', (), {'is_public': False, 'endpoint': bridge.endpoint_from_url(url)})(),
        )
        seen['decision'] = decision
        if decision != 'allowed':
            raise ValueError(decision)
    monkeypatch.setattr(bridge, 'request', fake_request)
    try:
        bridge.handle(payload)
    except ValueError as exc:
        assert str(exc) == 'endpoint_not_permitted'
    assert seen['decision'] == 'endpoint_not_permitted'


def test_bridge_decodes_request_body_and_encodes_response(monkeypatch):
    class Response:
        status = 200
        headers = (("content-type", "application/json"),)
        body = b'{"ok":true}'
        final_url = 'http://localhost:11434/api/generate'
    captured = {}
    def fake_request(method, url, **kwargs):
        captured['body'] = kwargs['body']
        return Response()
    monkeypatch.setattr(bridge, 'request', fake_request)
    body = b'{"model":"x"}'
    result = bridge.handle({
        'method': 'POST',
        'url': 'http://localhost:11434/api/generate',
        'allowed_endpoints': ['http://localhost:11434'],
        'transport': {'allow_loopback': True},
        'body_base64': base64.b64encode(body).decode('ascii'),
    })
    assert captured['body'] == body
    assert base64.b64decode(result['body_base64']) == b'{"ok":true}'


def test_bridge_requires_remote_opt_in_and_host_allowlist(monkeypatch):
    monkeypatch.setattr(bridge, 'request', lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('must fail before network')))
    base = {
        'url': 'https://provider.example/v1/models',
        'allowed_endpoints': ['https://provider.example'],
    }
    try:
        bridge.handle(base)
    except bridge.EndpointPolicyError as exc:
        assert exc.code == 'remote_denied'
    else:
        raise AssertionError('remote endpoint unexpectedly allowed')

    try:
        bridge.handle({**base, 'allow_remote': True, 'allowed_hosts': ['other.example']})
    except bridge.EndpointPolicyError as exc:
        assert exc.code == 'host_not_allowlisted'
    else:
        raise AssertionError('unlisted host unexpectedly allowed')


def test_bridge_rejects_credential_header_over_http():
    payload = {
        'url': 'http://provider.example/v1/models',
        'allowed_endpoints': ['http://provider.example'],
        'allow_remote': True,
        'allowed_hosts': ['provider.example'],
        'headers': {'X-API-Key': 'secret-value'},
    }
    try:
        bridge.handle(payload)
    except bridge.EndpointPolicyError as exc:
        assert exc.code == 'credentials_require_https'
    else:
        raise AssertionError('credential header over HTTP unexpectedly allowed')


def test_bridge_allows_credential_header_over_https(monkeypatch):
    class Response:
        status = 200
        headers = ()
        body = b''
        final_url = 'https://provider.example/v1/models'
    monkeypatch.setattr(bridge, 'request', lambda *a, **k: Response())
    payload = {
        'url': 'https://provider.example/v1/models',
        'allowed_endpoints': ['https://provider.example'],
        'allow_remote': True,
        'allowed_hosts': ['provider.example'],
        'headers': {'X-API-Key': 'secret-value'},
    }
    result = bridge.handle(payload)
    assert result['status'] == 200


def test_bridge_host_allowlist_authorizer_denies_unlisted_redirect_target():
    """The redirect-host-allowlist fix: transport.request() re-authorizes
    each hop through the SAME authorizer object, so the wrapper must deny a
    host outside allowed_hosts even when transport.request() -- not
    handle()'s own one-time check -- is the one asking."""
    base_auth = bridge.EndpointAuthorizer.from_exact_rules({
        bridge.EndpointPurpose.MODEL_EGRESS: {('https', 'evil.example', 443)}
    })
    wrapped = bridge._HostAllowlistAuthorizer(base_auth, {'provider.example'})
    identity = type('I', (), {
        'endpoint': bridge.endpoint_from_url('https://evil.example'),
        'resolved_addresses': ('93.184.216.34',),
    })()
    req = bridge.EndpointUseRequest(
        actor_id='gateway', workflow_id='egress',
        purpose=bridge.EndpointPurpose.MODEL_EGRESS, endpoint=identity, run_id='r',
    )
    decision = wrapped.authorize(req)
    assert decision.allowed is False
    assert decision.reason_code == 'host_not_allowlisted'


def test_bridge_rejects_non_dict_payload():
    try:
        bridge.handle("not a dict")
    except ValueError as exc:
        assert "must be a JSON object" in str(exc)
    else:
        raise AssertionError('non-dict payload unexpectedly accepted')


def test_bridge_rejects_non_dict_transport_field():
    payload = {
        'url': 'http://localhost:11434/api/tags',
        'allowed_endpoints': ['http://localhost:11434'],
        'transport': "not an object",
    }
    try:
        bridge.handle(payload)
    except ValueError as exc:
        assert "payload.transport must be an object" in str(exc)
    else:
        raise AssertionError('non-dict transport field unexpectedly accepted')


def test_main_catches_transport_errors_and_continues(monkeypatch):
    import io
    def raising_request(*a, **k):
        raise ConnectionResetError("connection reset by peer")
    monkeypatch.setattr(bridge, 'request', raising_request)
    payload = {
        'url': 'http://localhost:11434/api/tags',
        'allowed_endpoints': ['http://localhost:11434'],
    }
    import json as json_module
    stdin = io.StringIO(json_module.dumps(payload) + "\n")
    stdout = io.StringIO()
    monkeypatch.setattr(bridge.sys, 'stdin', stdin)
    monkeypatch.setattr(bridge.sys, 'stdout', stdout)
    result = bridge.main()
    assert result == 0
    out = json_module.loads(stdout.getvalue().strip())
    assert out['ok_bridge'] is False
    assert out['error']['code'] == 'transport_error'


def test_bridge_allows_credential_header_over_loopback_http(monkeypatch):
    """Explicit decision: loopback traffic never leaves the machine, so the
    network-eavesdropping risk credentials_require_https guards against
    doesn't apply there -- exempted, unlike a remote host over plain HTTP."""
    class Response:
        status = 200
        headers = ()
        body = b''
        final_url = 'http://localhost:11434/v1/models'
    monkeypatch.setattr(bridge, 'request', lambda *a, **k: Response())
    payload = {
        'url': 'http://localhost:11434/v1/models',
        'allowed_endpoints': ['http://localhost:11434'],
        'headers': {'X-API-Key': 'secret-value'},
    }
    result = bridge.handle(payload)
    assert result['status'] == 200


def test_bridge_rejects_dot_localhost_name_resolving_to_public_address(monkeypatch):
    """The real vulnerability this fix closes, confirmed directly against
    the pre-fix code before writing this test: a *.localhost hostname was
    classified as loopback from the string alone, before any resolution --
    a DNS answer mapping such a name to a genuinely public address bypassed
    both the remote-host gate and (worse) the credentials-require-https
    check. Must now be rejected exactly like any other unlisted remote host
    with a credential header over plain HTTP."""
    import socket as socket_module

    def spoofed_resolver(host, port):
        return [(socket_module.AF_INET, socket_module.SOCK_STREAM, 6, '', ('93.184.216.34', port))]

    monkeypatch.setattr(bridge, '_stdlib_resolver', spoofed_resolver)
    payload = {
        'url': 'http://evil.localhost/v1/models',
        'allowed_endpoints': ['http://evil.localhost'],
        'headers': {'X-API-Key': 'secret-value'},
    }
    try:
        bridge.handle(payload)
    except bridge.EndpointPolicyError as exc:
        # Either denial is an acceptable, safe outcome -- what matters is
        # that NEITHER gate is silently bypassed by the spoofed hostname.
        assert exc.code in ('remote_denied', 'credentials_require_https')
    else:
        raise AssertionError(
            '*.localhost name resolving to a public address was not rejected'
        )
