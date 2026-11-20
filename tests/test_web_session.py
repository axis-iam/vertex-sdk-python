from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from bff_fixture import VECTORS, Fixture

from axis_vertex.errors import IamConfigError
from axis_vertex.web_session import SessionError, parse_view
from axis_vertex.web_session.http import HostRequest, dispatch, parse_body
from axis_vertex.web_session.models import obj, text


def test_frozen_c0_hashes_and_browser_vectors() -> None:
    root = Path(__file__).parent / 'fixtures/connected-app-bff'
    manifest = json.loads((root / 'SHA256SUMS.json').read_text())
    for name, digest in manifest['files'].items():
        path = root / ('contract.md' if name.endswith('.md') else Path(name).name)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    for vector in VECTORS['viewVectors']:
        if vector['accept']:
            assert parse_view(vector['value']) == vector['value'], vector['id']
        else:
            with pytest.raises(SessionError):
                parse_view(vector['value'])


@pytest.mark.asyncio
async def test_hosted_bootstrap_pkce_nonce_cookie_rotation_and_replay() -> None:
    f = Fixture()
    try:
        with pytest.raises(SessionError, match='SESSION_REQUIRED'):
            await f.session.hosted_login(None)
        bootstrap = await f.session.bootstrap(None)
        old_cookie = text(bootstrap.cookie)
        r = await f.hosted_record(old_cookie)
        with pytest.raises(SessionError, match='CALLBACK_BINDING_INVALID'):
            await f.session.callback(old_cookie, {'code': 'controlled-code', 'state': 'wrong'})
        with pytest.raises(SessionError, match='VALIDATION_ERROR'):
            await f.session.callback(old_cookie,
                {'code': 'controlled-code',
                'state': r.data['oauth_state'],
                'error': 'bad'})
        result = await f.session.callback(old_cookie,
            {'code': 'controlled-code',
            'state': r.data['oauth_state']})
        assert result.status == 302 and result.location == '/'
        assert result.cookie != old_cookie
        view = (await f.session.session(result.cookie)).body
        assert view['csrfToken'] != bootstrap.body['csrfToken']
        assert obj(view['profile'])['id'] == f.subject
        assert 'controlled-' not in json.dumps(view)
        assert 'controlled-' not in repr(await f.store.read(text(result.cookie)))
        with pytest.raises(SessionError):
            await f.session.callback(old_cookie,
                {'code': 'controlled-code',
                'state': r.data['oauth_state']})
        assert len(f.forms) == 1
    finally:
        await f.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('bad',
    ['audience',
    'subject',
    'nonce',
    'signature',
    'issuer',
    'expiry',
    'azp'])
async def test_oidc_id_token_client_audience_subject_and_nonce_fail_closed(bad: str) -> None:
    import jwt
    f = Fixture()
    try:
        bootstrap = await f.session.bootstrap(None)
        r = await f.hosted_record(text(bootstrap.cookie))
        original = f.token
        if bad == 'audience':
            f.audience = f.config.resource_audience
        elif bad == 'subject':
            f.subject = '019b0000-0000-7000-8000-000000000098'
        elif bad == 'nonce':
            f.nonce = 'wrong'
        else:
            def token() -> dict[str, object]:
                v = original()
                claims = jwt.decode(v['id_token'], options={'verify_signature': False})
                if bad == 'issuer':
                    claims['iss'] = 'https://different.example.test'
                if bad == 'expiry':
                    claims['exp'] = 1
                if bad == 'azp':
                    claims['azp'] = 'wrong'
                v['id_token'] = jwt.encode(claims, f.key if bad != 'signature' else
                    __import__('cryptography.hazmat.primitives.asymmetric.rsa',
                        fromlist=['generate_private_key']).generate_private_key(public_exponent=65537,
                        key_size=2048),

                    algorithm='RS256', headers={'kid': 'controlled-key'})
                return v
            f.token = token
        with pytest.raises(SessionError):
            await f.session.callback(r.key,
                {'code': 'controlled-code',
                'state': r.data['oauth_state']})
        assert await f.store.read(r.key) is None
    finally:
        await f.close()


@pytest.mark.asyncio
async def test_custom_password_mfa_complete_registration_recovery_and_safe_errors() -> None:
    f = Fixture()
    f.mfa = True
    try:
        bootstrap = await f.session.bootstrap(None)
        cookie = text(bootstrap.cookie)
        csrf = text(bootstrap.body['csrfToken'])
        origin = f.config.origin
        async def action(name: str, body: dict[str, object]) -> dict[str, object]:
            return (await f.session.login_action(cookie, name, body, origin, csrf)).body
        assert (await action('start', {}))['state'] == 'AUTHENTICATING'
        with pytest.raises(SessionError, match='AUTHENTICATION_FAILED') as error:
            await action('authenticate',
                {'method': 'PASSWORD',
                'identifier': {'kind': 'EMAIL',
                'value': 'reader@example.test'},
                'password': 'wrong'})
        assert error.value.__context__ is None
        assert (await action('authenticate',
            {'method': 'PASSWORD',
            'identifier': {'kind': 'EMAIL',
            'value': 'reader@example.test'},
            'password': 'valid'}))['state'] == 'MFA_REQUIRED'
        assert (await action('mfa',
            {'method': 'TOTP',
            'code': '123456'}))['nextAction'] == 'complete'
        result = await f.session.login_action(cookie, 'complete', {}, origin, csrf)
        assert 'profile' in result.body and result.cookie != cookie
        assert 'controlSecret' not in json.dumps(result.body)
        b = await f.session.bootstrap(None)
        c, t = text(b.cookie), text(b.body['csrfToken'])
        registration = await f.session.registration(c,
            'start',
            {'identifier': {'kind': 'EMAIL',
            'value': 'reader@example.test'},
            'password': 'valid'},
            origin,
            t)
        assert registration.status == 202
        assert 'controlSecret' not in registration.body
        ref = text(registration.body['registrationId'])
        assert ref != '019b0000-0000-7000-8000-000000000088'
        await f.session.registration(c, 'get', {}, None, None, ref)
        await f.session.registration(c, 'challenges', {}, origin, t, ref)
        completed = await f.session.registration(c, 'complete', {'code': '123456'}, origin, t, ref)
        assert completed.body['status'] == 'COMPLETED'
        assert 'profile' not in (await f.session.session(c)).body
        await f.session.password_reset(c, False, {'email': 'reader@example.test'}, origin, t)
        await f.session.password_reset(c,
            True,
            {'token': 'controlled-reset-proof',
            'newPassword': 'valid'},
            origin,
            t)
    finally:
        await f.close()


@pytest.mark.asyncio
async def test_provider_code_continuation_magic_cancel_and_binding() -> None:
    f = Fixture()
    try:
        b = await f.session.bootstrap(None)
        cookie, csrf = text(b.cookie), text(b.body['csrfToken'])
        await f.session.login_action(cookie, 'start', {}, f.config.origin, csrf)
        await f.session.login_action(cookie,
            'authorize',
            {'providerId': f.transaction_id},
            f.config.origin,
            csrf)
        f.transaction_state = 'MFA_REQUIRED'
        continuation = {'kind': 'AUTH_CONTINUATION',
            'auth_transaction_id': f.transaction_id,
            'state': f.state}
        with pytest.raises(SessionError):
            await f.session.callback(cookie, {**continuation, 'auth_transaction_id': 'wrong'})
        assert (await f.session.callback(cookie, continuation)).status == 302
        assert (await f.session.session(cookie)).body['state'] == 'MFA_REQUIRED'
        await f.session.login_action(cookie,
            'mfa',
            {'method': 'TOTP',
            'code': '123456'},
            f.config.origin,
            csrf)
        result = await f.session.callback(cookie, {'code': 'controlled-code', 'state': f.state})
        assert result.cookie != cookie
        b = await f.session.bootstrap(None)
        cookie, csrf = text(b.cookie), text(b.body['csrfToken'])
        await f.session.login_action(cookie, 'start', {}, f.config.origin, csrf)
        await f.session.login_action(cookie,
            'challenges',
            {'method': 'EMAIL_MAGIC_LINK',
            'identifier': {'kind': 'EMAIL',
            'value': 'reader@example.test'}},
            f.config.origin,
            csrf)
        with pytest.raises(SessionError):
            await f.session.login_action(cookie,
                'magic',
                {'transactionId': f.transaction_id,
                'state': 'wrong',
                'proof': 'proof'},
                f.config.origin,
                csrf)
        await f.session.login_action(cookie,
            'magic',
            {'transactionId': f.transaction_id,
            'state': f.state,
            'proof': 'proof'},
            f.config.origin,
            csrf)
        cancelled = await f.session.login_action(cookie, 'cancel', {}, f.config.origin, csrf)
        assert cancelled.clear_cookie
        with pytest.raises(SessionError):
            await f.session.login_action(cookie, 'complete', {}, f.config.origin, csrf)
    finally:
        await f.close()


@pytest.mark.asyncio
async def test_finite_host_routes_csrf_strict_json_and_dependency_failures() -> None:
    f = Fixture()
    try:
        b = await f.session.bootstrap(None)
        for origin, csrf in [(None,
            None),
            ('https://evil.example',
            b.body['csrfToken']),
            (f.config.origin,
            'bad')]:
            result = await dispatch(f.session,
                HostRequest('POST',
                '/session/login',
                b.cookie,
                origin,
                csrf))
            assert result.status == 403
        result = await dispatch(f.session,
            HostRequest('GET',
            '/session',
            b.cookie,
            authorization='bad'))
        assert result.status == 401
        assert (await dispatch(f.session,
            HostRequest('GET',
            '/proxy/arbitrary',
            b.cookie))).status == 404
        for raw in [b'{"method":1,"method":2}', b'{"x":NaN}', b'[]', b'bad']:
            with pytest.raises(SessionError):
                parse_body(raw, 'application/json')
        cookie = await f.hosted()
        f.fail_path = '/api/v1/auth/session/validity'
        with pytest.raises(SessionError) as e:
            await f.session.session(cookie)
        assert e.value.status == 503 and 'upstream-text' not in str(e.value)
        assert await f.store.read(cookie) is not None
        f.fail_status = 401
        with pytest.raises(SessionError):
            await f.session.session(cookie)
        assert await f.store.read(cookie) is None
    finally:
        await f.close()


def test_configuration_explicit_provider_and_no_implicit_modes() -> None:
    f = Fixture()
    try:
        for fields in [{'origin': 'http://app.example.test'},
            {'replicas': 2},
            {'absolute_ttl': float('inf')}]:
            from dataclasses import replace
            with pytest.raises(IamConfigError):
                config = replace(f.config, **fields)
                from axis_vertex.web_session import ServerSession
                ServerSession(config, f.store)
        with pytest.raises(IamConfigError):
            from axis_vertex.web_session import ServerSession
            ServerSession(f.config, None)
        assert 'client-credential' not in repr(f.config)
    finally:
        f.store.close()


@pytest.mark.asyncio
async def test_capability_public_snapshot_types_and_rate_limit_metadata() -> None:
    import httpx
    from bff_fixture import public_record

    from axis_vertex.web_session.capabilities import parse_capabilities

    f = Fixture()
    try:
        view = (await f.session.capabilities()).body
        assert view["methods"][0]["enabled"] is True
        assert view["methods"][0]["availableForLogin"] is False
        assert (await f.session.capabilities(True)).body["minPasswordLength"] == 1
        value = public_record("AuthMethodsPublicResponse")
        with pytest.raises(SessionError):
            parse_capabilities("AuthMethodsPublicResponse", {**value, "controlSecret": "forbidden"})
        value["methods"][0]["availableForLogin"] = "false"
        with pytest.raises(SessionError):
            parse_capabilities("AuthMethodsPublicResponse", value)
        for retry, expected in [("7", 7), ("secret-value", None), ("999999999", None)]:
            async def rate_limit(request, retry=retry):
                return httpx.Response(429, headers={"Retry-After": retry})
            client = httpx.AsyncClient(transport=httpx.MockTransport(rate_limit))
            from axis_vertex.web_session import ServerSession
            session = ServerSession(f.config, f.store, http_client=client)
            result = await dispatch(session, HostRequest("GET", "/auth-methods", None))
            assert result.status == 429 and result.retry_after == expected
            await client.aclose()
    finally:
        await f.close()
