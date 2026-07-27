from __future__ import annotations

import base64
from collections.abc import Awaitable, Callable
from urllib.parse import parse_qs

import httpx
import pytest

import axis_vertex.portal_open_api as portal_api
from axis_vertex import (
    ORGANIZATION_INVITATIONS_READ_SCOPE,
    ORGANIZATION_INVITATIONS_WRITE_SCOPE,
    ORGANIZATION_MEMBERS_READ_SCOPE,
    ORGANIZATION_MEMBERS_WRITE_SCOPE,
    ORGANIZATIONS_READ_SCOPE,
    ORGANIZATIONS_WRITE_SCOPE,
    PERMISSIONS_READ_SCOPE,
    PERMISSIONS_WRITE_SCOPE,
    PORTAL_OPEN_API_READ_SCOPE,
    PORTAL_OPEN_API_WRITE_SCOPE,
    REGISTRATION_GRANTS_READ_SCOPE,
    REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE,
    REGISTRATION_GRANTS_WRITE_SCOPE,
    ROLE_PERMISSIONS_READ_SCOPE,
    ROLE_PERMISSIONS_WRITE_SCOPE,
    ROLES_READ_SCOPE,
    ROLES_WRITE_SCOPE,
    USER_ROLES_READ_SCOPE,
    USER_ROLES_WRITE_SCOPE,
    AuthorizationPageOptions,
    CreateOrganizationInvitationRequest,
    CreateOrganizationRequest,
    CreatePermissionRequest,
    CreateRegistrationGrantRequest,
    CreateRoleRequest,
    CreateUserRoleRequest,
    OrganizationInvitationListOptions,
    OrganizationListOptions,
    OrganizationMemberListOptions,
    PortalOpenApiClient,
    PortalOpenApiConfig,
    PortalOpenApiError,
    PortalOpenApiTokenError,
    RegistrationGrantListOptions,
    UpdateOrganizationRequest,
    UpdatePermissionRequest,
    UpdateRoleRequest,
    UserRoleCondition,
)


class PortalOpenApiMock:
    def __init__(self) -> None:
        self.token_requests: list[tuple[str, str, str]] = []
        self.portal_requests: list[httpx.Request] = []
        self.token_handler: Callable[[httpx.Request], httpx.Response] | None = None
        self.portal_handler: Callable[[httpx.Request], httpx.Response] | None = None
        self._token_counter = 0

    def client(self, *, token_skew_seconds: float = 0) -> PortalOpenApiClient:
        return PortalOpenApiClient(
            PortalOpenApiConfig(
                issuer="https://auth.example.test",
                portal_endpoint="https://portal.example.test",
                client_id="m2m-client",
                client_secret="m2m-secret",
                token_skew_seconds=token_skew_seconds,
            ),
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(self._handle)),
        )

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://auth.example.test/oauth2/token":
            if self.token_handler is not None:
                return self.token_handler(request)
            return self._default_token(request)
        if str(request.url).startswith("https://portal.example.test/open/v1/"):
            self.portal_requests.append(request)
            if self.portal_handler is not None:
                return self.portal_handler(request)
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404, json={"error": "not_found"})

    def _default_token(self, request: httpx.Request) -> httpx.Response:
        assert _basic_auth(request) == "m2m-client:m2m-secret"
        body = parse_qs(request.content.decode("utf-8"))
        grant_type = _single(body, "grant_type")
        scope = _single(body, "scope")
        self.token_requests.append((grant_type, scope, request.headers.get("authorization", "")))
        self._token_counter += 1
        return httpx.Response(
            200,
            json={
                "access_token": f"{scope}-token-{self._token_counter}",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": scope,
            },
            headers={"content-type": "application/json"},
        )


@pytest.mark.asyncio
async def test_get_uses_read_scope_and_portal_request_is_bearer_only() -> None:
    server = PortalOpenApiMock()
    client = server.client()

    result = await client.request_json("GET", "/open/v1/stats")

    assert result == {"ok": True}
    assert [(grant, scope) for grant, scope, _auth in server.token_requests] == [
        ("client_credentials", PORTAL_OPEN_API_READ_SCOPE)
    ]
    portal_request = server.portal_requests[0]
    assert portal_request.headers["authorization"] == "Bearer portal:openapi:read-token-1"
    assert "basic " not in portal_request.headers["authorization"].lower()
    assert "x-iam-client-id" not in portal_request.headers
    assert "x-application-id" not in portal_request.headers
    assert "x-app-key" not in portal_request.headers

    await client.close()


@pytest.mark.asyncio
async def test_write_uses_write_scope_and_read_write_token_cache_is_separate() -> None:
    server = PortalOpenApiMock()
    client = server.client()

    await client.request_json("GET", "/open/v1/roles")
    await client.request_json("GET", "/open/v1/roles")
    await client.request_json("POST", "/open/v1/roles", json={"name": "editor"})
    await client.request_json("POST", "/open/v1/roles", json={"name": "writer"})

    assert [scope for _grant, scope, _auth in server.token_requests] == [
        PORTAL_OPEN_API_READ_SCOPE,
        PORTAL_OPEN_API_WRITE_SCOPE,
    ]
    assert server.portal_requests[0].headers["authorization"] == (
        "Bearer portal:openapi:read-token-1"
    )
    assert server.portal_requests[1].headers["authorization"] == (
        "Bearer portal:openapi:read-token-1"
    )
    assert server.portal_requests[2].headers["authorization"] == (
        "Bearer portal:openapi:write-token-2"
    )
    assert server.portal_requests[3].headers["authorization"] == (
        "Bearer portal:openapi:write-token-2"
    )

    await client.close()


@pytest.mark.asyncio
async def test_token_cache_uses_expires_in_minus_skew() -> None:
    server = PortalOpenApiMock()
    client = server.client(token_skew_seconds=300)

    await client.request_json("GET", "/open/v1/stats")
    await client.request_json("GET", "/open/v1/stats")

    assert [scope for _grant, scope, _auth in server.token_requests] == [
        PORTAL_OPEN_API_READ_SCOPE,
        PORTAL_OPEN_API_READ_SCOPE,
    ]

    await client.close()


@pytest.mark.asyncio
async def test_token_error_is_typed() -> None:
    server = PortalOpenApiMock()

    def invalid_scope(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={"error": "invalid_scope", "error_description": "scope is required"},
            headers={"content-type": "application/json"},
        )

    server.token_handler = invalid_scope
    client = server.client()

    with pytest.raises(PortalOpenApiTokenError) as exc:
        await client.request_json("GET", "/open/v1/stats")

    assert exc.value.status_code == 400
    assert exc.value.code == "invalid_scope"

    await client.close()


@pytest.mark.asyncio
async def test_rejects_missing_or_wrong_token_scope() -> None:
    server = PortalOpenApiMock()

    def wrong_scope(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "access_token": "token",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": PORTAL_OPEN_API_READ_SCOPE,
            },
            headers={"content-type": "application/json"},
        )

    server.token_handler = wrong_scope
    client = server.client()

    with pytest.raises(PortalOpenApiTokenError) as exc:
        await client.request_json("POST", "/open/v1/roles", json={"name": "editor"})

    assert exc.value.code == "invalid_scope"

    await client.close()


@pytest.mark.asyncio
async def test_portal_api_error_is_typed() -> None:
    server = PortalOpenApiMock()

    def forbidden(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"code": "OPEN_API_SCOPE_INSUFFICIENT", "message": "forbidden"},
            headers={"content-type": "application/json"},
        )

    server.portal_handler = forbidden
    client = server.client()

    with pytest.raises(PortalOpenApiError) as exc:
        await client.request_json("GET", "/open/v1/stats")

    assert exc.value.status_code == 403
    assert exc.value.code == "OPEN_API_SCOPE_INSUFFICIENT"

    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header_name",
    ["Authorization", "X-IAM-Client-Id", "X-Application-Id", "X-App-Key"],
)
async def test_rejects_non_open_v1_paths_methods_and_stale_headers(header_name: str) -> None:
    server = PortalOpenApiMock()
    client = server.client()

    with pytest.raises(PortalOpenApiError, match="/open/v1/"):
        await client.request_json("GET", "/api/v1/users")
    with pytest.raises(PortalOpenApiError, match="Unsupported"):
        await client.request_json("HEAD", "/open/v1/stats")
    with pytest.raises(PortalOpenApiError) as exc:
        await client.request_json("GET", "/open/v1/stats", headers={header_name: "old"})

    assert exc.value.code == "invalid_portal_header"
    assert server.token_requests == []
    assert server.portal_requests == []

    await client.close()


@pytest.mark.asyncio
async def test_empty_response_body_returns_none() -> None:
    server = PortalOpenApiMock()
    server.portal_handler = lambda _request: httpx.Response(204)
    client = server.client()

    assert await client.request_json("DELETE", "/open/v1/roles/role-1") is None

    await client.close()


@pytest.mark.asyncio
async def test_registration_grant_helpers_use_exact_scopes_and_reject_double_proof() -> None:
    server = PortalOpenApiMock()

    def response(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                201,
                json={
                    "grant": _grant("EMAIL_LINK"),
                    "registrationGrantToken": "test-token",
                    "registrationAccessCode": "12345678",
                },
            )
        return httpx.Response(200, json={"content": [], "page": _page()})

    server.portal_handler = response
    client = server.client()
    await client.list_registration_grants()
    with pytest.raises(PortalOpenApiError, match="Invalid registration grant response"):
        await client.create_registration_grant(CreateRegistrationGrantRequest(type="EMAIL_LINK"))
    await client.list_registration_grant_redemptions("123e4567-e89b-12d3-a456-426614174000")
    assert [scope for _grant_type, scope, _auth in server.token_requests] == [
        REGISTRATION_GRANTS_READ_SCOPE,
        REGISTRATION_GRANTS_WRITE_SCOPE,
        REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE,
    ]
    await client.close()


@pytest.mark.asyncio
async def test_registration_grant_list_encodes_filters_and_parses_org_invitation() -> None:
    server = PortalOpenApiMock()
    server.portal_handler = lambda _request: httpx.Response(
        200, json={"content": [_grant("ORG_INVITATION")], "page": _page()}
    )
    client = server.client()

    result = await client.list_registration_grants(
        RegistrationGrantListOptions(
            type="ORG_INVITATION", status="ACTIVE", search="a+b & c", page=2, size=25
        )
    )

    assert result.content[0].type == "ORG_INVITATION"
    assert str(server.portal_requests[0].url) == (
        "https://portal.example.test/open/v1/registration-grants?"
        "type=ORG_INVITATION&status=ACTIVE&search=a%2Bb+%26+c&page=2&size=25"
    )
    assert [scope for _grant_type, scope, _auth in server.token_requests] == [
        REGISTRATION_GRANTS_READ_SCOPE
    ]
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("grant_type", "proof_key", "absent_key"),
    [
        ("EMAIL_LINK", "registrationGrantToken", "registrationAccessCode"),
        ("ACCESS_CODE", "registrationAccessCode", "registrationGrantToken"),
    ],
)
async def test_registration_grant_create_accepts_null_nonmatching_proof(
    grant_type: str, proof_key: str, absent_key: str
) -> None:
    server = PortalOpenApiMock()

    def response(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            201,
            json={
                "grant": _grant(grant_type),
                proof_key: "fake-one-time-proof",
                absent_key: None,
            },
        )

    server.portal_handler = response
    client = server.client()
    created = await client.create_registration_grant(
        CreateRegistrationGrantRequest(type=grant_type)  # type: ignore[arg-type]
    )

    assert created.grant.type == grant_type
    assert getattr(created, _snake(proof_key)) == "fake-one-time-proof"
    assert getattr(created, _snake(absent_key)) is None
    assert server.portal_requests[0].method == "POST"
    assert server.portal_requests[0].content == (f'{{"type":"{grant_type}"}}').encode()
    assert [scope for _grant_type, scope, _auth in server.token_requests] == [
        REGISTRATION_GRANTS_WRITE_SCOPE
    ]
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "grant_type,proofs",
    [
        ("EMAIL_LINK", {"registrationGrantToken": None, "registrationAccessCode": None}),
        (
            "EMAIL_LINK",
            {"registrationGrantToken": "fake-token", "registrationAccessCode": "fake-code"},
        ),
        ("EMAIL_LINK", {"registrationGrantToken": "", "registrationAccessCode": None}),
        ("EMAIL_LINK", {"registrationGrantToken": None, "registrationAccessCode": "fake-code"}),
        (
            "ORG_INVITATION",
            {"registrationGrantToken": "fake-token", "registrationAccessCode": None},
        ),
    ],
)
async def test_registration_grant_create_rejects_invalid_proof_contract_without_leaking(
    grant_type: str, proofs: dict[str, str | None]
) -> None:
    server = PortalOpenApiMock()
    server.portal_handler = lambda _request: httpx.Response(
        201, json={"grant": _grant(grant_type), **proofs}
    )
    client = server.client()

    with pytest.raises(PortalOpenApiError) as exc:
        await client.create_registration_grant(CreateRegistrationGrantRequest(type="EMAIL_LINK"))

    assert exc.value.code == "invalid_registration_grant_response"
    assert "fake-token" not in str(exc.value)
    assert "fake-code" not in str(exc.value)
    await client.close()


@pytest.mark.asyncio
async def test_registration_grant_detail_lifecycle_revoke_and_redemption_vectors() -> None:
    server = PortalOpenApiMock()

    def response(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/redemptions"):
            return httpx.Response(200, json={"content": [], "page": _page()})
        return httpx.Response(200, json=_grant("ORG_INVITATION"))

    server.portal_handler = response
    client = server.client()
    grant_id = "019f4cca-88f8-7e77-a67d-4a6a2a68b803"
    assert (await client.get_registration_grant(grant_id)).type == "ORG_INVITATION"
    await client.pause_registration_grant(grant_id)
    await client.resume_registration_grant(grant_id)
    await client.revoke_registration_grant(grant_id)
    await client.revoke_registration_grant(grant_id, "expired request")
    await client.list_registration_grant_redemptions(grant_id, page=1, size=10)

    assert [
        (request.method, request.url.path, request.url.query, request.content)
        for request in server.portal_requests
    ] == [
        ("GET", f"/open/v1/registration-grants/{grant_id}", b"", b""),
        ("POST", f"/open/v1/registration-grants/{grant_id}/pause", b"", b""),
        ("POST", f"/open/v1/registration-grants/{grant_id}/resume", b"", b""),
        ("POST", f"/open/v1/registration-grants/{grant_id}/revoke", b"", b""),
        (
            "POST",
            f"/open/v1/registration-grants/{grant_id}/revoke",
            b"",
            b'{"reason":"expired request"}',
        ),
        ("GET", f"/open/v1/registration-grants/{grant_id}/redemptions", b"page=1&size=10", b""),
    ]
    assert [scope for _grant_type, scope, _auth in server.token_requests] == [
        REGISTRATION_GRANTS_READ_SCOPE,
        REGISTRATION_GRANTS_WRITE_SCOPE,
        REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE,
    ]
    await client.close()


@pytest.mark.asyncio
async def test_registration_grant_uuidv7_is_accepted_and_noncanonical_ids_fail_locally() -> None:
    server = PortalOpenApiMock()
    server.portal_handler = lambda _request: httpx.Response(200, json=_grant("EMAIL_LINK"))
    client = server.client()

    await client.get_registration_grant("019f4cca-88f8-7e77-a67d-4a6a2a68b803")
    with pytest.raises(PortalOpenApiError) as exc:
        await client.get_registration_grant("019f4cca88f87e77a67d4a6a2a68b803")
    assert exc.value.code == "invalid_registration_grant_id"
    assert len(server.portal_requests) == 1
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [403, 404, 409])
async def test_registration_grant_backend_errors_propagate(status: int) -> None:
    server = PortalOpenApiMock()
    server.portal_handler = lambda _request: httpx.Response(
        status, json={"error": "CONTRACT_ERROR", "message": "safe error"}
    )
    client = server.client()

    with pytest.raises(PortalOpenApiError) as exc:
        await client.get_registration_grant("019f4cca-88f8-7e77-a67d-4a6a2a68b803")
    assert exc.value.status_code == status
    assert exc.value.code == "CONTRACT_ERROR"
    await client.close()


@pytest.mark.asyncio
async def test_registration_grant_exact_scope_token_cache_isolation() -> None:
    server = PortalOpenApiMock()
    client = server.client()

    for scope in (
        REGISTRATION_GRANTS_READ_SCOPE,
        REGISTRATION_GRANTS_WRITE_SCOPE,
        REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE,
    ):
        await client.get_machine_token(scope)
    for scope in (
        REGISTRATION_GRANTS_READ_SCOPE,
        REGISTRATION_GRANTS_WRITE_SCOPE,
        REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE,
    ):
        await client.get_machine_token(scope)

    assert [scope for _grant_type, scope, _auth in server.token_requests] == [
        REGISTRATION_GRANTS_READ_SCOPE,
        REGISTRATION_GRANTS_WRITE_SCOPE,
        REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE,
    ]
    await client.close()


@pytest.mark.asyncio
async def test_organization_management_helpers_use_exact_scopes_and_conditional_headers() -> None:
    server = PortalOpenApiMock()
    organization_id = "123e4567-e89b-42d3-a456-426614174000"
    invitation_id = "223e4567-e89b-42d3-a456-426614174000"
    membership_id = "323e4567-e89b-42d3-a456-426614174000"

    def response(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/open/v1/organizations" and request.method == "GET":
            return httpx.Response(
                200, json={"content": [_organization(organization_id)], "page": _page()}
            )
        if path == "/open/v1/organizations":
            return httpx.Response(201, json=_organization(organization_id), headers={"ETag": '"7"'})
        if path.endswith("/invitations"):
            if request.method == "GET":
                return httpx.Response(
                    200, json={"content": [_invitation(invitation_id)], "page": _page()}
                )
            return httpx.Response(201, json=_invitation(invitation_id))
        if "/invitations/" in path:
            if request.method == "DELETE":
                return httpx.Response(204)
            return httpx.Response(200, json=_invitation(invitation_id))
        if path.endswith("/members"):
            return httpx.Response(200, json={"content": [_member(membership_id)], "page": _page()})
        if "/members/" in path:
            if request.method == "DELETE":
                return httpx.Response(204)
            return httpx.Response(200, json=_member(membership_id))
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(200, json=_organization(organization_id), headers={"ETag": '"7"'})

    server.portal_handler = response
    client = server.client()
    organizations = await client.list_organizations(
        OrganizationListOptions(
            search="acme & co",
            page=1,
            size=10,
            sort=("name", "slug"),
            direction=("ASC", "DESC"),
        )
    )
    assert organizations.content[0].slug == "acme"
    created = await client.create_organization(
        CreateOrganizationRequest(name="Acme", slug="acme"), idempotency_key="org-create-1"
    )
    assert created.etag == '"7"'
    await client.get_organization(organization_id)
    await client.update_organization(
        organization_id,
        UpdateOrganizationRequest(name="Acme Inc."),
        if_match='"7"',
    )
    await client.delete_organization(organization_id, if_match='"8"')
    await client.list_organization_invitations(
        organization_id,
        OrganizationInvitationListOptions(status="PENDING", page=1, size=10),
    )
    await client.create_organization_invitation(
        organization_id,
        CreateOrganizationInvitationRequest(
            email="member@example.test", role="ADMIN", send_email=False
        ),
        idempotency_key="invite-create-1",
    )
    await client.get_organization_invitation(organization_id, invitation_id)
    await client.resend_organization_invitation(organization_id, invitation_id)
    await client.cancel_organization_invitation(organization_id, invitation_id)
    await client.list_organization_members(
        organization_id, OrganizationMemberListOptions(search="member", page=1, size=10)
    )
    await client.get_organization_member(organization_id, membership_id)
    await client.update_organization_member_role(
        organization_id, membership_id, "ADMIN", if_match='"2"'
    )
    await client.remove_organization_member(organization_id, membership_id)

    assert [scope for _grant_type, scope, _auth in server.token_requests] == [
        ORGANIZATIONS_READ_SCOPE,
        ORGANIZATIONS_WRITE_SCOPE,
        ORGANIZATION_INVITATIONS_READ_SCOPE,
        ORGANIZATION_INVITATIONS_WRITE_SCOPE,
        ORGANIZATION_MEMBERS_READ_SCOPE,
        ORGANIZATION_MEMBERS_WRITE_SCOPE,
    ]
    requests = server.portal_requests
    assert str(requests[0].url) == (
        "https://portal.example.test/open/v1/organizations?"
        "search=acme+%26+co&page=1&size=10&sort=name&sort=slug&direction=ASC&direction=DESC"
    )
    assert requests[1].headers["idempotency-key"] == "org-create-1"
    assert requests[3].headers["if-match"] == '"7"'
    assert requests[4].headers["if-match"] == '"8"'
    assert requests[6].headers["idempotency-key"] == "invite-create-1"
    assert requests[12].headers["if-match"] == '"2"'
    assert requests[7].url.path == (
        f"/open/v1/organizations/{organization_id}/invitations/{invitation_id}"
    )
    assert requests[10].url.path == f"/open/v1/organizations/{organization_id}/members"
    await client.close()


@pytest.mark.asyncio
async def test_organization_invitation_retry_after_and_last_owner_conflict_are_typed() -> None:
    server = PortalOpenApiMock()
    organization_id = "123e4567-e89b-42d3-a456-426614174000"
    invitation_id = "223e4567-e89b-42d3-a456-426614174000"
    membership_id = "323e4567-e89b-42d3-a456-426614174000"
    server.portal_handler = lambda _request: httpx.Response(
        429,
        json={"error": "CONFLICT", "message": "terminal invitation"},
        headers={"Retry-After": "30"},
    )
    client = server.client()

    with pytest.raises(PortalOpenApiError) as exc:
        await client.resend_organization_invitation(organization_id, invitation_id)
    assert exc.value.status_code == 429
    assert exc.value.retry_after == "30"

    client.clear_token_cache()
    server.portal_handler = lambda _request: httpx.Response(
        400,
        json={"error": "BAD_REQUEST", "message": "Cannot remove the last OWNER"},
    )
    with pytest.raises(PortalOpenApiError) as exc:
        await client.remove_organization_member(organization_id, membership_id)
    assert exc.value.status_code == 400
    assert exc.value.code == "BAD_REQUEST"
    await client.close()


def _single(body: dict[str, list[str]], key: str) -> str:
    values = body.get(key)
    assert values is not None
    assert len(values) == 1
    return values[0]


def _basic_auth(request: httpx.Request) -> str:
    prefix = "Basic "
    header = request.headers.get("authorization", "")
    assert header.startswith(prefix)
    return base64.b64decode(header[len(prefix) :]).decode("utf-8")


def _page() -> dict[str, int]:
    return {"size": 20, "number": 0, "totalElements": 0, "totalPages": 0}


def _grant(grant_type: str) -> dict[str, object]:
    return {
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "type": grant_type,
        "status": "ACTIVE",
        "displayName": None,
        "allowedEmail": None,
        "allowedDomain": None,
        "expiresAt": None,
        "maxUses": None,
        "usedCount": 0,
        "sourceType": "API",
        "createdAt": "2026-07-11T00:00:00Z",
        "updatedAt": "2026-07-11T00:00:00Z",
        "revokedAt": None,
        "revokeReason": None,
    }


def _organization(organization_id: str) -> dict[str, object]:
    return {
        "id": organization_id,
        "name": "Acme",
        "slug": "acme",
        "version": 7,
        "createdAt": "2026-07-12T00:00:00Z",
        "updatedAt": "2026-07-12T00:00:00Z",
    }


def _invitation(invitation_id: str) -> dict[str, object]:
    return {
        "id": invitation_id,
        "email": "member@example.test",
        "role": "ADMIN",
        "status": "PENDING",
        "deliveryStatus": "SENT",
        "expiresAt": "2026-07-19T00:00:00Z",
        "createdAt": "2026-07-12T00:00:00Z",
        "updatedAt": "2026-07-12T00:00:00Z",
    }


def _member(membership_id: str) -> dict[str, object]:
    return {
        "membershipId": membership_id,
        "userId": "423e4567-e89b-42d3-a456-426614174000",
        "email": "member@example.test",
        "displayName": "Member",
        "role": "ADMIN",
        "joinedAt": "2026-07-12T00:00:00Z",
        "updatedAt": "2026-07-12T00:00:00Z",
        "version": 2,
    }


def _snake(camel: str) -> str:
    return "".join(
        f"_{character.lower()}" if character.isupper() else character for character in camel
    ).lstrip("_")


@pytest.mark.asyncio
async def test_authorization_management_exact_scope_contract() -> None:
    server = PortalOpenApiMock()
    role_id = "123e4567-e89b-42d3-a456-426614174000"
    permission_id = "223e4567-e89b-42d3-a456-426614174000"
    user_id = "323e4567-e89b-42d3-a456-426614174000"
    assignment_id = "423e4567-e89b-42d3-a456-426614174000"
    timestamp = "2026-07-15T00:00:00Z"
    page = {"size": 20, "number": 0, "totalElements": 1, "totalPages": 1}
    role: dict[str, object] = {
        "id": role_id,
        "key": "admin",
        "name": "Admin",
        "description": None,
        "system": False,
        "version": 1,
        "createdAt": timestamp,
        "updatedAt": timestamp,
    }
    permission: dict[str, object] = {
        "id": permission_id,
        "resource": "orders",
        "action": "read",
        "key": "orders:read",
        "name": "Read",
        "description": None,
        "source": "MANUAL",
        "version": 1,
        "createdAt": timestamp,
        "updatedAt": timestamp,
    }
    assignment: dict[str, object] = {
        "id": assignment_id,
        "userId": user_id,
        "roleId": role_id,
        "organizationId": None,
        "conditionExpression": None,
        "conditionDescription": None,
        "version": 1,
        "createdAt": timestamp,
        "updatedAt": timestamp,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body: object
        if request.method == "DELETE":
            return httpx.Response(204)
        if path.endswith("/permissions") and f"/roles/{role_id}" in path:
            body = (
                {
                    "content": [
                        {"roleId": role_id, "permissionId": permission_id, "createdAt": timestamp}
                    ],
                    "page": page,
                }
                if request.method == "GET"
                else {"roleId": role_id, "permissionIds": [permission_id], "version": 1}
            )
        elif f"/users/{user_id}/roles" in path:
            body = (
                {"content": [assignment], "page": page} if request.method == "GET" else assignment
            )
        elif path.startswith("/open/v1/permissions"):
            body = (
                {"content": [permission], "page": page}
                if path.endswith("/permissions") and request.method == "GET"
                else permission
            )
        else:
            body = (
                {"content": [role], "page": page}
                if path.endswith("/roles") and request.method == "GET"
                else role
            )
        return httpx.Response(
            201 if request.method == "POST" else 200, json=body, headers={"ETag": '"1"'}
        )

    server.portal_handler = handler
    client = server.client()

    await client.list_roles()
    await client.get_role(role_id)
    await client.create_role(CreateRoleRequest("admin", "Admin"), idempotency_key="role-key")
    await client.update_role(role_id, UpdateRoleRequest(name="Admin 2"), if_match='"1"')
    await client.delete_role(role_id, if_match='"2"')
    await client.list_permissions()
    await client.get_permission(permission_id)
    await client.create_permission(
        CreatePermissionRequest("orders", "read", "Read"), idempotency_key="permission-key"
    )
    await client.update_permission(
        permission_id, UpdatePermissionRequest(name="Read 2"), if_match='"1"'
    )
    await client.delete_permission(permission_id, if_match='"2"')
    await client.list_role_permissions(role_id)
    await client.replace_role_permissions(role_id, (permission_id,), if_match='"1"')
    await client.list_user_roles(user_id)
    await client.create_user_role(
        user_id, CreateUserRoleRequest(role_id), idempotency_key="assignment-key"
    )
    await client.update_user_role(
        user_id, assignment_id, UserRoleCondition("department == 'sales'"), if_match='"1"'
    )
    await client.delete_user_role(user_id, assignment_id, if_match='"2"')
    assert {scope for _, scope, _ in server.token_requests} == {
        ROLES_READ_SCOPE,
        ROLES_WRITE_SCOPE,
        PERMISSIONS_READ_SCOPE,
        PERMISSIONS_WRITE_SCOPE,
        ROLE_PERMISSIONS_READ_SCOPE,
        ROLE_PERMISSIONS_WRITE_SCOPE,
        USER_ROLES_READ_SCOPE,
        USER_ROLES_WRITE_SCOPE,
    }
    assert any(
        request.headers.get("idempotency-key") == "role-key" for request in server.portal_requests
    )
    await client.close()


@pytest.mark.asyncio
async def test_authorization_management_rejects_invalid_grants_pages_and_etags() -> None:
    client = PortalOpenApiMock().client()
    with pytest.raises(PortalOpenApiError, match="Invalid permission grant"):
        await client.create_permission(CreatePermissionRequest("*", "read", "bad"))
    with pytest.raises(PortalOpenApiError, match="size"):
        await client.list_roles(AuthorizationPageOptions(size=101))
    with pytest.raises(PortalOpenApiError, match="ETag"):
        await client.update_role(
            "123e4567-e89b-42d3-a456-426614174000", UpdateRoleRequest(name="x"), if_match='W/"1"'
        )
    await client.close()


@pytest.mark.asyncio
async def test_authorization_management_binds_object_response_to_path_identity() -> None:
    server = PortalOpenApiMock()
    role_id = "123e4567-e89b-42d3-a456-426614174000"
    permission_id = "223e4567-e89b-42d3-a456-426614174000"
    user_id = "323e4567-e89b-42d3-a456-426614174000"
    assignment_id = "423e4567-e89b-42d3-a456-426614174000"
    wrong_id = "523e4567-e89b-42d3-a456-426614174000"
    timestamp = "2026-07-15T00:00:00Z"
    response_body: object = {}

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response_body, headers={"ETag": '"0"'})

    server.portal_handler = handler
    client = server.client()

    async def assert_invalid(call: Callable[[], Awaitable[object]]) -> None:
        with pytest.raises(PortalOpenApiError) as raised:
            await call()
        assert raised.value.code == "invalid_authorization_response"

    role = {
        "id": wrong_id,
        "key": "admin",
        "name": "Admin",
        "description": None,
        "system": False,
        "version": 0,
        "createdAt": timestamp,
        "updatedAt": timestamp,
    }
    permission = {
        "id": wrong_id,
        "resource": "orders",
        "action": "read",
        "key": "orders:read",
        "name": "Read",
        "description": None,
        "source": "MANUAL",
        "version": 0,
        "createdAt": timestamp,
        "updatedAt": timestamp,
    }
    assignment = {
        "id": assignment_id,
        "userId": user_id,
        "roleId": role_id,
        "organizationId": None,
        "conditionExpression": None,
        "conditionDescription": None,
        "version": 0,
        "createdAt": timestamp,
        "updatedAt": timestamp,
    }

    calls: list[Callable[[], Awaitable[object]]] = []
    response_body = role
    calls.extend(
        [
            lambda: client.get_role(role_id),
            lambda: client.update_role(role_id, UpdateRoleRequest(name="x"), if_match='"0"'),
        ]
    )
    for call in calls:
        await assert_invalid(call)
    response_body = permission
    for call in [
        lambda: client.get_permission(permission_id),
        lambda: client.update_permission(
            permission_id, UpdatePermissionRequest(name="x"), if_match='"0"'
        ),
    ]:
        await assert_invalid(call)
    response_body = {"roleId": wrong_id, "permissionIds": [permission_id], "version": 0}
    await assert_invalid(
        lambda: client.replace_role_permissions(role_id, (permission_id,), if_match='"0"')
    )
    for field in ("userId", "roleId"):
        response_body = {**assignment, field: wrong_id}
        await assert_invalid(
            lambda: client.create_user_role(user_id, CreateUserRoleRequest(role_id))
        )
    for field in ("userId", "id"):
        response_body = {**assignment, field: wrong_id}
        await assert_invalid(
            lambda: client.update_user_role(user_id, assignment_id, None, if_match='"0"')
        )
    await client.close()


def test_authorization_response_parsers_fail_closed_with_stable_code() -> None:
    timestamp = "2026-07-15T00:00:00Z"
    role: dict[str, object] = {
        "id": "123e4567-e89b-42d3-a456-426614174000",
        "key": "admin",
        "name": "Admin",
        "description": None,
        "system": False,
        "version": 1,
        "createdAt": timestamp,
        "updatedAt": timestamp,
    }
    permission: dict[str, object] = {
        "id": "223e4567-e89b-42d3-a456-426614174000",
        "resource": "orders",
        "action": "read",
        "key": "orders:read",
        "name": "Read",
        "description": None,
        "source": "MANUAL",
        "version": 1,
        "createdAt": timestamp,
        "updatedAt": timestamp,
    }
    assignment: dict[str, object] = {
        "id": "423e4567-e89b-42d3-a456-426614174000",
        "userId": "323e4567-e89b-42d3-a456-426614174000",
        "roleId": role["id"],
        "organizationId": None,
        "conditionExpression": None,
        "conditionDescription": None,
        "version": 1,
        "createdAt": timestamp,
        "updatedAt": timestamp,
    }
    valid_page: dict[str, object] = {
        "size": 20,
        "number": 0,
        "totalElements": 1,
        "totalPages": 1,
    }
    malformed: list[Callable[[], object]] = [
        lambda: portal_api._role([]),
        lambda: portal_api._role({**role, "id": "not-a-uuid"}),
        lambda: portal_api._role({**role, "createdAt": "yesterday"}),
        lambda: portal_api._role({key: value for key, value in role.items() if key != "system"}),
        lambda: portal_api._role({key: value for key, value in role.items() if key != "version"}),
        lambda: portal_api._role_page({"content": [], "page": {"size": 20}}),
        lambda: portal_api._role_page(
            {"content": [], "page": {"size": 20, "totalElements": 0, "totalPages": 0}}
        ),
        lambda: portal_api._role_page(
            {"content": [], "page": {"size": 20, "number": 0, "totalPages": 0}}
        ),
        lambda: portal_api._role_page(
            {"content": [], "page": {"size": 20, "number": 0, "totalElements": 0}}
        ),
        lambda: portal_api._role_page({"content": [role], "page": dict(valid_page, size=1000)}),
        lambda: portal_api._role_page(
            {
                "content": [role],
                "page": {"size": 1, "number": 0, "totalElements": 0, "totalPages": 0},
            }
        ),
        lambda: portal_api._role_page(
            {
                "content": [role],
                "page": {"size": 1, "number": 1, "totalElements": 1, "totalPages": 1},
            }
        ),
        lambda: portal_api._role_page(
            {
                "content": [role],
                "page": {"size": 2, "number": 0, "totalElements": 2, "totalPages": 1},
            }
        ),
        lambda: portal_api._permission({**permission, "source": "CUSTOM"}),
        lambda: portal_api._permission(
            {key: value for key, value in permission.items() if key != "version"}
        ),
        lambda: portal_api._role_permission_set(
            {
                "roleId": role["id"],
                "permissionIds": [],
            },
            '"0"',
        ),
        lambda: portal_api._role_permission_page(
            {
                "content": [
                    {"roleId": "bad", "permissionId": permission["id"], "createdAt": timestamp}
                ],
                "page": valid_page,
            }
        ),
        lambda: portal_api._user_role_page(
            {"content": [{**assignment, "roleId": "bad"}], "page": valid_page}
        ),
        lambda: portal_api._user_role_page(
            {"content": [{**assignment, "updatedAt": "invalid"}], "page": valid_page}
        ),
        lambda: portal_api._user_role(
            {key: value for key, value in assignment.items() if key != "version"}
        ),
    ]
    for parse in malformed:
        with pytest.raises(PortalOpenApiError) as raised:
            parse()
        assert raised.value.code == "invalid_authorization_response"
    assert portal_api._role({**role, "system": False, "version": 0}).version == 0
    assert portal_api._permission({**permission, "version": 0}).version == 0
    assert (
        portal_api._role_permission_set(
            {"roleId": role["id"], "permissionIds": [permission["id"]], "version": 0},
            '"0"',
        ).version
        == 0
    )
    assert portal_api._user_role({**assignment, "version": 0}).version == 0
    assert (
        portal_api._role_page(
            {"content": [], "page": {"size": 20, "number": 0, "totalElements": 0, "totalPages": 0}}
        ).content
        == ()
    )
