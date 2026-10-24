from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path

import httpx
import jwt
import pytest

from axis_vertex import IamApiError, IamClient, IamConfig, PermissionDefinition, UnauthorizedError
from axis_vertex.testing import MockIamServer

COMPATIBILITY_FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures/permission-compatibility-vectors.json").read_text()
)


@pytest.mark.asyncio
@pytest.mark.skipif(
    os.getenv("IAM_PERMISSION_COMPATIBILITY_E2E") != "1", reason="live fixture disabled"
)
async def test_permission_compatibility_real_backend_e2e() -> None:
    client_id = os.environ["IAM_COMPAT_CLIENT_ID"]
    client = IamClient(
        IamConfig(
            endpoint=os.environ["IAM_COMPAT_ISSUER"],
            client_id=client_id,
            client_secret=os.environ["IAM_COMPAT_CLIENT_SECRET"],
            resource_audience="api://m7d",
        )
    )
    assert await client.resolve_permissions([]) == frozenset()
    snapshot = await client.list_permissions()
    assert {(item.resource, item.action) for item in snapshot} == {
        ("orders", "write"),
        ("orders", "*"),
        ("*", "*"),
    }
    assert await client.resolve_permissions(["m7d_reader"]) == frozenset(
        {"orders:write", "orders:*", "*:*"}
    )
    await client.close()


@pytest.mark.asyncio
async def test_verify_token_and_authenticate_resolves_permissions() -> None:
    server = MockIamServer().given_role("admin", "orders:*", "users:read")
    client = server.client()
    token = server.issue_token(
        "user-1",
        roles=["admin"],
        extra_claims={
            "app_id": "app-1",
            "email": "user@example.com",
            "amr": ["pwd", "mfa"],
            "acr": "urn:iam:acr:mfa",
        },
    )

    claims = await client.verify_token(token)
    context = await client.authenticate(token)

    assert claims.subject == "user-1"
    assert context.user_id == "user-1"
    assert context.permissions == frozenset({"orders:*", "users:read"})
    assert context.has_permission("orders", "create")
    assert server.resolve_calls == 1

    await client.close()


@pytest.mark.asyncio
async def test_mock_server_returns_configured_non_empty_permission_snapshot() -> None:
    server = MockIamServer().given_snapshot_permissions(
        PermissionDefinition("orders", "read", "Read orders"),
        PermissionDefinition("orders", "write", "Write orders"),
    )
    client = server.client()

    snapshot = await client.list_permissions()

    assert [(item.resource, item.action) for item in snapshot] == [
        ("orders", "read"),
        ("orders", "write"),
    ]
    assert server.list_calls == 1
    await client.close()


@pytest.mark.asyncio
async def test_verify_token_accepts_resource_audience() -> None:
    server = MockIamServer(resource_audience="api://socratiq")
    client = server.client()
    token = server.issue_token("user-1", extra_claims={"app_id": "app-1"})

    claims = await client.verify_token(token)

    assert claims.application_id == "app-1"

    await client.close()


@pytest.mark.asyncio
async def test_verify_token_rejects_client_id_as_access_token_audience() -> None:
    server = MockIamServer(resource_audience="api://socratiq")
    client = server.client()
    token = server.issue_token(
        "user-1",
        extra_claims={
            "aud": server.client_id,
            "app_id": "app-1",
        },
    )

    with pytest.raises(UnauthorizedError):
        await client.verify_token(token)

    await client.close()


@pytest.mark.asyncio
async def test_verify_token_rejects_expired_and_malformed_tokens() -> None:
    server = MockIamServer()
    client = server.client()

    with pytest.raises(UnauthorizedError):
        await client.verify_token(server.expired_token())
    with pytest.raises(UnauthorizedError):
        await client.verify_token("not-a-jwt")

    await client.close()


@pytest.mark.asyncio
async def test_permission_resolution_and_profile_are_cached() -> None:
    server = MockIamServer().given_role("reader", "posts:read")
    server.given_profile(
        "u1",
        {
            "id": "u1",
            "email": "u1@example.com",
            "username": "alice",
            "status": "ACTIVE",
            "emailVerified": True,
            "roles": ["reader"],
            "metadata": {"displayName": "Alice"},
        },
    )
    client = server.client()
    token = server.issue_token("u1", roles=["reader"])

    assert await client.resolve_permissions(["reader"]) == frozenset({"posts:read"})
    assert await client.resolve_permissions(["reader"]) == frozenset({"posts:read"})
    assert server.resolve_calls == 1

    first = await client.get_me(token)
    second = await client.get_me(token)
    fresh = await client.get_me(token, bypass_cache=True)
    assert first.username == "alice"
    assert second.username == "alice"
    assert fresh.metadata["displayName"] == "Alice"
    assert server.me_calls == 2

    await client.close()


@pytest.mark.asyncio
async def test_zero_role_resolution_returns_locally_without_network() -> None:
    server = MockIamServer()
    client = server.client()

    assert await client.resolve_permissions([]) == frozenset()
    assert server.resolve_calls == 0

    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {"applicationId": "app", "clientId": "mock-client", "permissions": []},
        {"applicationId": "app", "clientId": "mock-client", "roles": [], "fallback": True},
        {
            "applicationId": "app",
            "clientId": "mock-client",
            "roles": [{"key": "admin", "name": "Admin", "permissions": ["orders"]}],
        },
        {
            "applicationId": "app",
            "clientId": "mock-client",
            "roles": [
                {"key": "admin", "name": "Admin", "permissions": ["orders:read", "orders:read"]}
            ],
        },
    ],
)
async def test_confidential_snapshot_rejects_malformed_contract(body: object) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    client = IamClient(
        IamConfig(
            endpoint="https://mock.test",
            client_id="mock-client",
            client_secret="secret",
            resource_audience="api://mock",
        ),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(IamApiError):
        await client.list_permissions()
    await client.close()


@pytest.mark.asyncio
async def test_permission_compatibility_exhausts_shared_reject_vectors() -> None:
    for section, method in (
        ("snapshot", "list"),
        ("resolve", "resolve"),
    ):
        for vector in COMPATIBILITY_FIXTURE[section]["reject"]:

            def handler(_: httpx.Request, body: object = vector["body"]) -> httpx.Response:
                return httpx.Response(200, json=body)

            client = IamClient(
                IamConfig(
                    endpoint="https://mock.test",
                    client_id="orders-service",
                    client_secret="secret",
                    resource_audience="api://mock",
                ),
                http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            )
            with pytest.raises(IamApiError, match="invalid"):
                if method == "list":
                    await client.list_permissions()
                else:
                    await client.resolve_permissions(["admin"])
            await client.close()

    for vector in COMPATIBILITY_FIXTURE["snapshot"]["rawReject"]:

        def raw_handler(_: httpx.Request, body: str = vector["body"]) -> httpx.Response:
            return httpx.Response(200, content=body)

        client = IamClient(
            IamConfig(
                endpoint="https://mock.test",
                client_id="orders-service",
                client_secret="secret",
                resource_audience="api://mock",
            ),
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(raw_handler)),
        )
        with pytest.raises(IamApiError, match="invalid"):
            await client.list_permissions()
        await client.close()


@pytest.mark.asyncio
async def test_permission_snapshot_accepts_canonical_uuid_and_wildcard_grants() -> None:
    body = COMPATIBILITY_FIXTURE["snapshot"]["valid"]

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    client = IamClient(
        IamConfig(
            endpoint="https://mock.test",
            client_id="orders-service",
            client_secret="secret",
            resource_audience="api://mock",
        ),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    snapshot = await client.list_permissions()
    assert {item.resource + ":" + item.action for item in snapshot} == {
        "orders:read",
        "orders:*",
        "*:*",
    }
    await client.close()


@pytest.mark.asyncio
async def test_permission_resolve_accepts_wildcard_grants() -> None:
    body = COMPATIBILITY_FIXTURE["resolve"]["valid"]

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    client = IamClient(
        IamConfig(
            endpoint="https://mock.test",
            client_id="orders-service",
            client_secret="secret",
            resource_audience="api://mock",
        ),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    assert await client.resolve_permissions(["admin"]) == frozenset(
        {"orders:read", "orders:*", "*:*"}
    )
    await client.close()


@pytest.mark.asyncio
async def test_account_org_invitation_helpers_use_bearer_or_public_requests() -> None:
    seen: list[tuple[str, str, str | None, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            (
                request.method,
                request.url.path,
                request.headers.get("authorization"),
                request.headers.get("x-iam-client-id"),
            )
        )
        if request.url.path == "/api/v1/auth/me/security":
            assert request.headers.get("authorization") == "Bearer user-token"
            assert "x-iam-client-id" not in request.headers
            return httpx.Response(
                200,
                json={
                    "emailVerified": True,
                    "passwordCredentialPresent": True,
                    "mfaEnrolled": False,
                    "totpEnrolled": False,
                    "webAuthnEnrolled": False,
                    "activeSessionCount": 2,
                },
            )
        if request.url.path == "/api/v1/auth/email/verification/send":
            assert "authorization" not in request.headers
            assert request.content == b'{"email":"user@example.com","client_id":"mock-client"}'
            return httpx.Response(
                200,
                json={
                    "message": "If eligible, a verification email has been sent.",
                    "retryAfterSeconds": 60,
                },
            )
        if request.url.path == "/api/v1/auth/email/verification/verify":
            assert request.content == b'{"token":"verify-token"}'
            return httpx.Response(
                200, json={"message": "Email verified", "retryAfterSeconds": None}
            )
        if request.url.path == "/api/v1/auth/password/change":
            assert request.headers.get("authorization") == "Bearer user-token"
            assert "x-iam-client-id" not in request.headers
            assert b'"currentPassword":"old-pass"' in request.content
            return httpx.Response(204)
        if request.url.path == "/api/v1/auth/password/forgot":
            assert "authorization" not in request.headers
            assert b'"client_id":"mock-client"' in request.content
            return httpx.Response(204)
        if request.url.path == "/api/v1/auth/password/reset":
            assert b'"token":"reset-token"' in request.content
            return httpx.Response(204)
        if request.url.path == "/api/v1/auth/sessions" and request.method == "GET":
            assert request.headers.get("authorization") == "Bearer user-token"
            assert "x-iam-client-id" not in request.headers
            return httpx.Response(
                200,
                json=[
                    {
                        "sessionId": "sid-current",
                        "ipAddress": "127.0.0.1",
                        "userAgent": "pytest",
                        "deviceId": None,
                        "createdAt": "2026-07-07T00:00:00Z",
                        "lastSeenAt": "2026-07-07T01:00:00Z",
                        "current": True,
                    }
                ],
            )
        if request.url.path == "/api/v1/auth/sessions/sid-current":
            assert request.method == "DELETE"
            return httpx.Response(204)
        if request.url.path == "/api/v1/auth/sessions" and request.method == "DELETE":
            return httpx.Response(204)
        if request.url.path == "/api/v1/auth/logout":
            assert request.headers.get("authorization") == "Bearer user-token"
            assert not request.content
            return httpx.Response(204)
        if request.url.path == "/api/v1/auth/me/organizations":
            return httpx.Response(
                200,
                json=[
                    {
                        "organizationId": "org-1",
                        "name": "Acme",
                        "slug": "acme",
                        "role": "ADMIN",
                        "joinedAt": "2026-07-06T00:00:00Z",
                        "current": True,
                    }
                ],
            )
        if request.url.path == "/api/v1/auth/me/permissions":
            assert request.url.params["organizationId"] == "org-1"
            assert request.headers.get("authorization") == "Bearer user-token"
            return httpx.Response(
                200,
                json={
                    "applicationId": "app-1",
                    "organizationId": "org-1",
                    "roles": ["admin"],
                    "permissions": ["orders:read", "orders:*"],
                },
            )
        if request.url.path == "/api/v1/auth/me/permissions:check":
            assert request.headers.get("authorization") == "Bearer user-token"
            assert b'"permission":"orders:write"' in request.content
            return httpx.Response(
                200,
                json={
                    "applicationId": "app-1",
                    "organizationId": "org-1",
                    "permission": "orders:write",
                    "allowed": True,
                    "roles": ["admin"],
                },
            )
        if request.url.path == "/api/v1/auth/me/organizations/current":
            assert request.headers.get("authorization") == "Bearer user-token"
            assert b'"organizationId":"org-2"' in request.content
            return httpx.Response(
                202,
                json={
                    "organizationId": "org-2",
                    "continuation": "REFRESH_OR_REAUTHENTICATE_WITH_ORGANIZATION",
                    "tokenRefreshRequired": True,
                    "message": "refresh",
                },
            )
        if request.url.path.startswith(
            "/api/v1/auth/organization-invitations/"
        ) and request.url.path.endswith("/accept"):
            assert "authorization" not in request.headers
            return httpx.Response(
                202,
                json={
                    "status": "LOGIN_REQUIRED",
                    "continuation": "LOGIN_OR_REGISTER_THEN_RETRY_ACCEPT",
                    "applicationId": "app-1",
                    "organizationId": "org-1",
                    "organizationName": "Acme",
                    "role": "MEMBER",
                },
            )
        if request.url.path.startswith("/api/v1/auth/organization-invitations/"):
            assert "authorization" not in request.headers
            return httpx.Response(
                200,
                json={
                    "applicationId": "app-1",
                    "applicationName": "Demo",
                    "organizationId": "org-1",
                    "organizationName": "Acme",
                    "inviteeEmail": "a***@example.com",
                    "role": "MEMBER",
                    "status": "PENDING",
                    "expiresAt": "2026-07-08T00:00:00Z",
                },
            )
        return httpx.Response(404, json={"error": "not_found"})

    client = IamClient(
        IamConfig(
            endpoint="https://mock-iam.test",
            client_id="mock-client",
            client_secret="mock-secret",
            resource_audience="api://mock-app",
        ),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )

    security = await client.get_account_security_summary("Bearer user-token")
    sent = await client.send_email_verification("user@example.com")
    verified = await client.verify_email("verify-token")
    await client.change_password(
        "user-token",
        current_password="old-pass",
        new_password="new-pass",
    )
    await client.request_password_reset(
        "user@example.com",
        redirect_uri="https://app.example.com/reset",
    )
    await client.reset_password("reset-token", new_password="new-pass")
    sessions = await client.list_account_sessions("user-token")
    await client.revoke_account_session("user-token", "sid-current")
    await client.revoke_other_account_sessions("user-token")
    await client.logout_account("user-token")
    organizations = await client.list_account_organizations("user-token")
    switched = await client.switch_account_organization("user-token", "org-2")
    member = await client.has_account_organization_membership("user-token", "org-1")
    summary = await client.get_account_permission_summary("user-token", organization_id="org-1")
    check = await client.check_account_permission(
        "user-token", "orders:write", organization_id="org-1"
    )
    preview = await client.preview_organization_invitation("public-token")
    accepted = await client.accept_organization_invitation("public-token")

    assert security.active_session_count == 2
    assert sent.retry_after_seconds == 60
    assert verified.message == "Email verified"
    assert sessions[0].current is True
    assert organizations[0].organization_id == "org-1"
    assert switched.token_refresh_required is True
    assert member is True
    assert summary.permissions == ("orders:read", "orders:*")
    assert check.allowed is True
    assert preview.organization_name == "Acme"
    assert accepted.status == "LOGIN_REQUIRED"
    assert len(seen) == 17

    await client.close()


@pytest.mark.asyncio
async def test_permission_resolution_payload_uses_backend_client_id_contract() -> None:
    server = MockIamServer().given_role("reader", "posts:read")
    client = server.client()

    assert await client.resolve_permissions(["reader"]) == frozenset({"posts:read"})

    async with server.http_client() as raw:
        response = await raw.post(
            f"{server.url}/open/v1/permissions:resolve",
            auth=(server.client_id, server.client_secret),
            json={"client_id": server.client_id, "roles": ["reader"]},
        )
    assert response.status_code == 403
    assert (
        jwt.decode(
            server.issue_token("u1", extra_claims={"app_id": "app-1"}),
            options={"verify_signature": False},
        )["aud"]
        == server.resource_audience
    )

    await client.close()


@pytest.mark.asyncio
async def test_token_factory_can_issue_expired_token_directly() -> None:
    server = MockIamServer()
    client = server.client()
    token = server.tokens.issue_token("u1", expires_delta=timedelta(seconds=-1))

    with pytest.raises(UnauthorizedError):
        await client.verify_token(token)

    await client.close()


@pytest.mark.asyncio
async def test_identity_profile_write_retires_username_and_preserves_null_email() -> None:
    import inspect

    from axis_vertex.profile import UserProfile

    assert "username" not in inspect.signature(IamClient.update_account_profile).parameters
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.url.path == "/api/v1/auth/me/profile"
        assert request.headers["Authorization"] == "Bearer user-token"
        assert json.loads(request.content) == {"displayName": "Display"}
        return httpx.Response(
            200,
            json={"userId": "u1", "email": None, "username": None, "emailVerified": False},
        )

    config = IamConfig(endpoint="https://iam.invalid", client_id="client", client_secret="test", resource_audience="api://test")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = IamClient(config, http_client=http_client)
        profile = await client.update_account_profile("user-token", display_name="Display")
        assert isinstance(profile, UserProfile)
        assert profile.email is None
        assert profile.username is None
        assert profile.email_verified is False
        assert len(requests) == 1
