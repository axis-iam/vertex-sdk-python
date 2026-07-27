"""Mock IAM server helpers backed by ``httpx.MockTransport``."""

from __future__ import annotations

import base64
import json
from collections.abc import Sequence
from typing import Any

import httpx

from axis_vertex.client import IamClient
from axis_vertex.config import IamConfig
from axis_vertex.permissions import PermissionDefinition
from axis_vertex.testing.tokens import TokenFactory


class MockIamServer:
    """In-process mock for discovery, JWKS, permissions, profile, and snapshots."""

    def __init__(
        self,
        *,
        url: str = "https://mock-iam.test",
        client_id: str = "mock-client",
        client_secret: str = "mock-secret",
        resource_audience: str = "api://mock-app",
    ) -> None:
        self.url = url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.resource_audience = resource_audience
        self.tokens = TokenFactory(issuer=self.url, audience=resource_audience)
        self.permissions_by_role: dict[str, set[str]] = {}
        self.profiles_by_subject: dict[str, dict[str, Any]] = {}
        self.snapshot_permissions: list[PermissionDefinition] = []
        self.resolve_calls = 0
        self.me_calls = 0
        self.list_calls = 0

    def given_role(self, role: str, *permissions: str) -> MockIamServer:
        """Bind permissions to a role for resolve calls."""

        self.permissions_by_role.setdefault(role, set()).update(permissions)
        return self

    def given_snapshot_permissions(self, *permissions: PermissionDefinition) -> MockIamServer:
        """Set the confidential permission snapshot returned by the mock server."""

        self.snapshot_permissions = list(permissions)
        return self

    def given_profile(self, subject: str, profile: dict[str, Any]) -> MockIamServer:
        """Bind a profile response to a subject."""

        self.profiles_by_subject[subject] = dict(profile)
        return self

    def issue_token(
        self,
        subject: str = "user-1",
        *,
        roles: list[str] | None = None,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Issue a token using the mock server's signing key."""

        return self.tokens.issue_token(subject, roles=roles, extra_claims=extra_claims)

    def expired_token(self, subject: str = "user-1") -> str:
        """Issue an expired token."""

        from datetime import timedelta

        return self.tokens.issue_token(subject, expires_delta=timedelta(seconds=-1))

    def config(self) -> IamConfig:
        """Return SDK config pointing at this mock server."""

        return IamConfig(
            endpoint=self.url,
            client_id=self.client_id,
            client_secret=self.client_secret,
            resource_audience=self.resource_audience,
        )

    def http_client(self) -> httpx.AsyncClient:
        """Return an AsyncClient using this mock server transport."""

        return httpx.AsyncClient(transport=httpx.MockTransport(self._handle))

    def client(self) -> IamClient:
        """Return an IamClient using this mock server."""

        return IamClient(self.config(), http_client=self.http_client())

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            return _json({"issuer": self.url, "jwks_uri": f"{self.url}/oauth2/jwks"})
        if path == "/oauth2/jwks":
            return _json(self.tokens.jwks())
        if path == "/open/v1/permissions:resolve" and request.method == "POST":
            if not self._has_valid_basic_auth(request):
                return _json({"error": "unauthorized"}, 401)
            self.resolve_calls += 1
            body = json.loads(request.content.decode("utf-8"))
            if body.get("clientId") != self.client_id:
                return _json({"error": "cannot_access_another_application"}, 403)
            roles = body.get("roles", [])
            permissions: set[str] = set()
            if isinstance(roles, Sequence) and not isinstance(roles, str):
                for role in roles:
                    if isinstance(role, str):
                        permissions.update(self.permissions_by_role.get(role, set()))
            return _json({"permissions": sorted(permissions)})
        if path == "/api/v1/auth/me/profile" and request.method in {"GET", "PATCH"}:
            self.me_calls += 1
            token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
            subject = _unsafe_subject(token)
            profile = self.profiles_by_subject.get(
                subject,
                {
                    "userId": subject,
                    "applicationId": "app-1",
                    "email": f"{subject}@example.com",
                    "emailVerified": True,
                    "username": subject,
                    "status": "ACTIVE",
                },
            )
            return _json(profile)
        if path == "/api/v1/auth/me/security" and request.method == "GET":
            if not request.headers.get("authorization", "").startswith("Bearer "):
                return _json({"error": "unauthorized"}, 401)
            return _json(
                {
                    "emailVerified": True,
                    "passwordCredentialPresent": True,
                    "mfaEnrolled": False,
                    "totpEnrolled": False,
                    "webAuthnEnrolled": False,
                    "activeSessionCount": 2,
                }
            )
        if path == "/api/v1/auth/email/verification/send" and request.method == "POST":
            return _json(
                {
                    "message": "If eligible, a verification email has been sent.",
                    "retryAfterSeconds": 60,
                }
            )
        if path == "/api/v1/auth/email/verification/verify" and request.method == "POST":
            return _json({"message": "Email verified", "retryAfterSeconds": None})
        if path == "/api/v1/auth/password/change" and request.method == "POST":
            if not request.headers.get("authorization", "").startswith("Bearer "):
                return _json({"error": "unauthorized"}, 401)
            return httpx.Response(204)
        if path == "/api/v1/auth/password/forgot" and request.method == "POST":
            return httpx.Response(204)
        if path == "/api/v1/auth/password/reset" and request.method == "POST":
            return httpx.Response(204)
        if path == "/api/v1/auth/sessions" and request.method == "GET":
            if not request.headers.get("authorization", "").startswith("Bearer "):
                return _json({"error": "unauthorized"}, 401)
            return _json_list(
                [
                    {
                        "sessionId": "sid-current",
                        "ipAddress": "127.0.0.1",
                        "userAgent": "iam-sdk-test",
                        "deviceId": None,
                        "createdAt": "2026-07-07T00:00:00Z",
                        "lastSeenAt": "2026-07-07T01:00:00Z",
                        "current": True,
                    }
                ]
            )
        if path.startswith("/api/v1/auth/sessions/") and request.method == "DELETE":
            if not request.headers.get("authorization", "").startswith("Bearer "):
                return _json({"error": "unauthorized"}, 401)
            return httpx.Response(204)
        if path == "/api/v1/auth/sessions" and request.method == "DELETE":
            if not request.headers.get("authorization", "").startswith("Bearer "):
                return _json({"error": "unauthorized"}, 401)
            return httpx.Response(204)
        if path == "/api/v1/auth/logout" and request.method == "POST":
            if not request.headers.get("authorization", "").startswith("Bearer "):
                return _json({"error": "unauthorized"}, 401)
            return httpx.Response(204)
        if path == "/api/v1/auth/me/organizations" and request.method == "GET":
            if not request.headers.get("authorization", "").startswith("Bearer "):
                return _json({"error": "unauthorized"}, 401)
            return _json_list(
                [
                    {
                        "organizationId": "org-1",
                        "name": "Acme",
                        "slug": "acme",
                        "role": "ADMIN",
                        "joinedAt": "2026-07-06T00:00:00Z",
                        "current": True,
                    }
                ]
            )
        if path == "/api/v1/auth/me/organizations/current" and request.method == "GET":
            if not request.headers.get("authorization", "").startswith("Bearer "):
                return _json({"error": "unauthorized"}, 401)
            return _json(
                {
                    "organizationId": "org-1",
                    "name": "Acme",
                    "slug": "acme",
                    "role": "ADMIN",
                    "joinedAt": "2026-07-06T00:00:00Z",
                    "current": True,
                }
            )
        if path == "/api/v1/auth/me/organizations/current" and request.method == "POST":
            if not request.headers.get("authorization", "").startswith("Bearer "):
                return _json({"error": "unauthorized"}, 401)
            return _json(
                {
                    "organizationId": "org-2",
                    "continuation": "REFRESH_OR_REAUTHENTICATE_WITH_ORGANIZATION",
                    "tokenRefreshRequired": True,
                    "message": "Refresh token to receive the new organization context.",
                },
                202,
            )
        if path == "/api/v1/auth/me/permissions" and request.method == "GET":
            if not request.headers.get("authorization", "").startswith("Bearer "):
                return _json({"error": "unauthorized"}, 401)
            return _json(
                {
                    "applicationId": "app-1",
                    "organizationId": request.url.params.get("organizationId", "org-1"),
                    "roles": ["admin"],
                    "permissions": ["orders:read", "orders:*"],
                }
            )
        if path == "/api/v1/auth/me/permissions:check" and request.method == "POST":
            if not request.headers.get("authorization", "").startswith("Bearer "):
                return _json({"error": "unauthorized"}, 401)
            return _json(
                {
                    "applicationId": "app-1",
                    "organizationId": "org-1",
                    "permission": "orders:write",
                    "allowed": True,
                    "roles": ["admin"],
                }
            )
        if (
            path.startswith("/api/v1/auth/organization-invitations/")
            and path.endswith("/accept")
            and request.method == "POST"
        ):
            return _json(
                {
                    "status": "LOGIN_REQUIRED",
                    "continuation": "LOGIN_OR_REGISTER_THEN_RETRY_ACCEPT",
                    "applicationId": "app-1",
                    "organizationId": "org-1",
                    "organizationName": "Acme",
                    "role": "MEMBER",
                },
                202,
            )
        if path.startswith("/api/v1/auth/organization-invitations/") and request.method == "GET":
            return _json(
                {
                    "applicationId": "app-1",
                    "applicationName": "Demo",
                    "organizationId": "org-1",
                    "organizationName": "Acme",
                    "inviteeEmail": "a***@example.com",
                    "role": "MEMBER",
                    "status": "PENDING",
                    "expiresAt": "2026-07-08T00:00:00Z",
                }
            )
        if path.endswith("/permissions") and path.startswith("/open/v1/apps/"):
            self.list_calls += 1
            client_id = path.removeprefix("/open/v1/apps/").removesuffix("/permissions")
            return _json(
                {
                    "applicationId": "123e4567-e89b-42d3-a456-426614174000",
                    "clientId": client_id,
                    "roles": [
                        {
                            "key": "registered",
                            "name": "Registered",
                            "permissions": [
                                definition.resource + ":" + definition.action
                                for definition in self.snapshot_permissions
                            ],
                        }
                    ],
                }
            )
        return _json({"error": "not_found"}, 404)

    def _has_valid_basic_auth(self, request: httpx.Request) -> bool:
        header = request.headers.get("authorization", "")
        prefix = "Basic "
        if not header.startswith(prefix):
            return False
        raw = base64.b64decode(header[len(prefix) :]).decode("utf-8")
        return raw == f"{self.client_id}:{self.client_secret}"


def _json(body: dict[str, Any], status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, json=body, headers={"content-type": "application/json"})


def _json_list(body: list[dict[str, Any]], status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, json=body, headers={"content-type": "application/json"})


def _unsafe_subject(token: str) -> str:
    import jwt

    try:
        payload = jwt.decode(token, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return "unknown"
    subject = payload.get("sub")
    return subject if isinstance(subject, str) else "unknown"
