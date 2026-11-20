"""Task-isolated OAuth/OIDC fixture; never contacts or reconfigures shared IAM."""
from __future__ import annotations

import copy
import json
import time
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from axis_vertex.web_session import (
    MemorySessionStore,
    ServerSession,
    SessionConfig,
    SyncServerSession,
)
from axis_vertex.web_session.models import JsonObject, Record, text, timestamp

VECTORS = json.loads((Path(__file__).parent / 'fixtures/connected-app-bff/c0-v1.json').read_text())
WIRE = json.loads(
    (Path(__file__).parent / 'fixtures/connected-app-bff/wire-records.json').read_text())


def public_record(name: str) -> JsonObject:
    records = {r["record"]: r for r in WIRE["records"]}
    schema = records[name]
    result = {}
    for component in schema["components"]:
        kind, key = component.rsplit(" ", 1)
        if key in schema["nullable"]:
            value = None
        elif kind == "boolean":
            value = key != "availableForLogin"
        elif kind == "int":
            value = 1
        elif kind == "String":
            value = "connected-web" if key == "clientId" else "public"
        elif kind == "UUID":
            value = "019b0000-0000-7000-8000-000000000001"
        elif kind in WIRE["enumValues"]:
            value = WIRE["enumValues"][kind][0]
        elif kind.startswith("List<"):
            item = kind[5:-1].rsplit(".", 1)[-1]
            value = [public_record(item)] if item in records else []
        else:
            value = public_record(kind)
        result[key] = value
    return result


class Fixture:
    def __init__(self):
        self.now = time.time()
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.profile = copy.deepcopy(VECTORS['viewVectors'][0]['value']['profile'])
        self.profile['authenticationContext']['authTime'] = timestamp(self.now)
        self.permissions = {'applicationId': self.profile['authenticationContext']['applicationId'],
                            'organizationId': None,
                                'roles': ['reader'],
                                'permissions': ['documents:read']}
        self.calls: list[tuple[str, str]] = []
        self.forms: list[dict[str, list[str]]] = []
        self.nonce = ''
        self.state = ''
        self.transaction_id = '019b0000-0000-7000-8000-000000000099'
        self.transaction_state = 'AUTHENTICATING'
        self.mfa = False
        self.rt = True
        self.audience = 'connected-web'
        self.subject = self.profile['id']
        self.fail_path: str | None = None
        self.fail_status = 503
        self.config = SessionConfig(issuer='https://iam.example.test', client_id='connected-web',
            client_secret='isolated-fixture-client-credential', resource_audience='urn:resource',
            origin='https://app.example.test',
                callback_uri='https://app.example.test/auth/callback')
        self.store = MemorySessionStore(clock=lambda: self.now)
        self.http = httpx.AsyncClient(transport=httpx.MockTransport(self.handle))
        self.session = ServerSession(self.config,
            self.store,
            http_client=self.http,
            clock=lambda: self.now)

    def sync(self) -> SyncServerSession:
        return SyncServerSession(self.config, self.store,
            sync_http_client_factory=lambda: httpx.AsyncClient(
                transport=httpx.MockTransport(self.handle)),

            clock=lambda: self.now)

    def token(self) -> JsonObject:
        identity = jwt.encode({'iss': self.config.issuer, 'aud': self.audience, 'sub': self.subject,
            'exp': int(time.time()) + 300, 'iat': int(time.time()), 'nonce': self.nonce},
            self.key, algorithm='RS256', headers={'kid': 'controlled-key'})
        return {'access_token': 'controlled-access', 'token_type': 'Bearer', 'expires_in': 300,
                'id_token': identity,
                    **({'refresh_token': 'controlled-refresh'} if self.rt else {})}

    def view(self) -> JsonObject:
        return {'transactionId': self.transaction_id, 'state': self.transaction_state,
            'expiresAt': timestamp(self.now + 300), 'nextAction': {
                'AUTHENTICATING': 'authenticate', 'AWAITING_PROVIDER': 'authorize',
                'MFA_REQUIRED': 'mfa',
                    'AUTHENTICATED': 'complete',
                    'CANCELLED': 'none'}[self.transaction_state]}

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        if path == self.fail_path:
            return httpx.Response(self.fail_status, json={'error': 'upstream-text-secret-ignored'})
        if path == '/.well-known/openid-configuration':
            return httpx.Response(200, json={'issuer': self.config.issuer,
                'jwks_uri': self.config.issuer + '/jwks',
                    'id_token_signing_alg_values_supported': ['RS256']})
        if path == '/jwks':
            key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
            return httpx.Response(200,
                json={'keys': [{**key,
                'kid': 'controlled-key',
                'alg': 'RS256'}]})
        if path == '/oauth2/token':
            assert request.headers['authorization'].startswith('Basic ')
            form = parse_qs(request.content.decode())
            self.forms.append(form)
            if form['grant_type'] == ['authorization_code']:
                assert len(form['code_verifier'][0]) == 43
                assert form['redirect_uri'] == [self.config.callback_uri]
            return httpx.Response(200, json=self.token())
        if path == '/api/v1/auth/me':
            assert request.headers['authorization'] == 'Bearer controlled-access'
            return httpx.Response(200, json=self.profile)
        if path == '/api/v1/auth/me/permissions':
            return httpx.Response(200, json=self.permissions)
        if path == '/api/v1/auth/session/validity':
            c = self.profile['authenticationContext']
            return httpx.Response(200,
                json={'applicationId': c['applicationId'],
                'clientId': c['clientId'],

                'sessionId': c['sessionId'], 'expiresAt': timestamp(self.now + 3600),
                'idleExpiresAt': timestamp(self.now + 3600),
                    'accessExpiresAt': timestamp(self.now + 300)})
        if path in {'/api/v1/auth/logout', '/oauth2/revoke'}:
            return httpx.Response(204 if path.endswith('/logout') else 200)
        if path.startswith('/api/v1/apps/'):
            return httpx.Response(200, json=public_record(
                "AuthPolicyPublicResponse" if path.endswith("/auth-policy")
                else "AuthMethodsPublicResponse"))
        if path == '/api/v1/auth/transactions':
            body = json.loads(request.content)
            assert set(body) == {'client_id', 'entryMode', 'redirect_uri', 'scope', 'state',
                                 'nonce', 'code_challenge', 'code_challenge_method'}
            self.nonce, self.state = body['nonce'], body['state']
            self.transaction_state = 'AUTHENTICATING'
            return httpx.Response(201, json={k: v for k, v in {
                **self.view(),
                    'controlSecret': 'controlled-transaction-secret'}.items() if k != 'state'})
        if path.startswith('/api/v1/auth/transactions/'):
            assert request.headers['Authentication-Transaction'] == 'controlled-transaction-secret'
            suffix = path.rsplit('/', 1)[-1]
            body = json.loads(request.content) if request.content else {}
            if suffix == 'authenticate':
                if body.get('password') == 'wrong':
                    return httpx.Response(401,
                        json={'error': 'AUTHENTICATION_FAILED',
                        'message': 'sensitive ignored'})
                self.transaction_state = 'MFA_REQUIRED' if self.mfa else 'AUTHENTICATED'
            elif suffix == 'mfa':
                assert 'Idempotency-Key' in request.headers
                self.transaction_state = 'AUTHENTICATED'
            elif suffix == 'complete':
                assert 'Idempotency-Key' in request.headers
                assert self.transaction_state == 'AUTHENTICATED'
                return httpx.Response(200,
                    json={'kind': 'authorization_code',
                    'code': 'controlled-code',

                                                'state': self.state, 'expiresIn': 60})
            elif suffix == 'challenges':
                return httpx.Response(200, json={k: v for k, v in {**self.view(),
                    'challengeExpiresAt': timestamp(self.now + 120),
                        'cooldownSeconds': 30}.items() if k != 'state'})
            elif suffix == 'authorize':
                self.transaction_state = 'AWAITING_PROVIDER'
                return httpx.Response(200,
                    json={'authorizationUrl': 'https://provider.example.test/authorize',

                                                'expiresAt': timestamp(self.now + 300)})
            elif suffix == 'cancel':
                self.transaction_state = 'CANCELLED'
            return httpx.Response(200, json=self.view())
        if path.startswith('/api/v1/auth/signup'):
            complete = path.endswith('/complete')
            if path == '/api/v1/auth/signup':
                assert 'Idempotency-Key' in request.headers
            else:
                assert request.headers['Registration-Client'] == self.config.client_id
                if request.method == 'GET':
                    assert (request.headers['Registration-Control'] ==
                            'controlled-registration-secret')
                else:
                    assert (json.loads(request.content)['controlSecret'] ==
                            'controlled-registration-secret')
            return httpx.Response(201 if complete else 202, json={
                'registrationId': '019b0000-0000-7000-8000-000000000088',
                'status': 'COMPLETED' if complete else 'PENDING_VERIFICATION',
                'expiresAt': timestamp(self.now + 200),
                    'nextAction': 'none' if complete else 'VERIFY_EMAIL',

                'controlSecret': None if complete else 'controlled-registration-secret',
                    'nextChallengeAt': None})
        if path.startswith('/api/v1/auth/password/'):
            if path.endswith('/reset'):
                assert request.headers['Password-Reset-Client'] == self.config.client_id
            else:
                assert json.loads(request.content)['client_id'] == self.config.client_id
            return httpx.Response(204)
        raise AssertionError(f'unexpected controlled endpoint: {request.method} {path}')

    async def hosted(self) -> str:
        b = await self.session.bootstrap(None)
        r = await self.hosted_record(text(b.cookie))
        result = await self.session.callback(r.key,
            {'code': 'controlled-code',
            'state': r.data['oauth_state']})
        return text(result.cookie)

    async def hosted_record(self, cookie: str) -> Record:
        await self.session.hosted_login(cookie)
        r = await self.store.read(cookie)
        assert r is not None
        self.nonce = text(r.data['nonce'])
        return r

    async def close(self) -> None:
        await self.http.aclose()
        self.store.close()
