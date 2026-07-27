"""Async-first IAM client for token verification and server-side IAM APIs."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from collections.abc import Coroutine, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
import jwt

from .claims import IamClaims
from .config import IamConfig
from .context import IamContext, IamUser
from .errors import IamApiError, UnauthorizedError
from .permissions import PermissionDefinition
from .profile import (
    AccountOrganization,
    AccountPermissionSummary,
    AccountSecuritySummary,
    EmailVerificationResponse,
    OrganizationSwitchResponse,
    PermissionCheckResponse,
    PublicOrganizationInvitationAcceptResponse,
    PublicOrganizationInvitationPreview,
    SessionView,
    UserProfile,
)


@dataclass(slots=True)
class _CacheEntry[T]:
    expires_at: float
    value: T


_CONCRETE_PERMISSION = re.compile(r"^[a-z0-9_-]{1,128}:[a-z0-9_-]{1,128}$")
_CANONICAL_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class IamClient:
    """Server-side IAM SDK client.

    The client verifies Java IAM access tokens, resolves roles to final
    permissions, exposes request context, and provides explicit profile and
    permission registration helpers.
    """

    def __init__(self, config: IamConfig, *, http_client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self._http = http_client or httpx.AsyncClient(timeout=config.http_timeout)
        self._owns_http = http_client is None
        self._jwks_uri: str | None = None
        self._jwks: _CacheEntry[dict[str, dict[str, Any]]] | None = None
        self._jwks_lock = asyncio.Lock()
        self._permission_cache: dict[tuple[str, tuple[str, ...]], _CacheEntry[frozenset[str]]] = {}
        self._profile_cache: dict[str, _CacheEntry[UserProfile]] = {}

    async def verify_token(self, access_token: str) -> IamClaims:
        """Verify a Java IAM access token and return typed claims."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise UnauthorizedError("malformed bearer token") from exc
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise UnauthorizedError("JWT kid header is required")
        key_data = await self._jwk_for_kid(kid)
        try:
            key = jwt.PyJWK.from_dict(key_data).key
            payload = jwt.decode(
                token,
                key=key,
                algorithms=["RS256", "ES256"],
                audience=self.config.resource_audience,
                issuer=self.config.issuer,
            )
        except jwt.ExpiredSignatureError as exc:
            raise UnauthorizedError("bearer token is expired") from exc
        except jwt.InvalidTokenError as exc:
            raise UnauthorizedError("bearer token is invalid") from exc
        return IamClaims.from_mapping(payload)

    async def authenticate(self, access_token: str) -> IamContext:
        """Verify a token, resolve role permissions, and build request context."""

        claims = await self.verify_token(access_token)
        permissions = await self.resolve_permissions(tuple(claims.roles))
        user = IamUser.from_claims(claims, permissions)
        return IamContext(user=user, access_token=_normalize_bearer(access_token))

    async def resolve_permissions(
        self,
        roles: Sequence[str],
        client_id: str | None = None,
    ) -> frozenset[str]:
        """Resolve Java IAM roles to final ``resource:action`` permissions."""

        role_key = tuple(sorted(role for role in roles if role))
        if not role_key:
            return frozenset()
        requested_client_id = client_id or self.config.client_id
        cache_key = (requested_client_id, role_key)
        cached = self._permission_cache.get(cache_key)
        if cached is not None and cached.expires_at > time.monotonic():
            return cached.value

        try:
            response = await self._request_strict_mapping(
                "POST",
                "/open/v1/permissions:resolve",
                json_body={"clientId": requested_client_id, "roles": list(role_key)},
                auth=True,
            )
        except Exception:
            if self.config.fail_open:
                return frozenset()
            raise
        if set(response) != {"permissions"}:
            raise IamApiError(200, "invalid permission resolve response")
        permissions = frozenset(
            _strict_permission_keys(
                response["permissions"], "permission resolve", allow_wildcards=True
            )
        )
        self._permission_cache[cache_key] = _CacheEntry(
            expires_at=time.monotonic() + self.config.permission_cache_ttl,
            value=permissions,
        )
        return permissions

    async def get_me(self, access_token: str, *, bypass_cache: bool = False) -> UserProfile:
        """Return the current user's profile from ``GET /api/v1/auth/me/profile``."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        cache_key = hashlib.sha256(token.encode("utf-8")).hexdigest()
        cached = self._profile_cache.get(cache_key)
        if not bypass_cache and cached is not None and cached.expires_at > time.monotonic():
            return cached.value
        response = await self._request_mapping("GET", "/api/v1/auth/me/profile", bearer=token)
        profile = UserProfile.from_mapping(response)
        self._profile_cache[cache_key] = _CacheEntry(
            expires_at=time.monotonic() + self.config.user_profile_cache_ttl,
            value=profile,
        )
        return profile

    async def update_account_profile(
        self,
        access_token: str,
        *,
        username: str | None = None,
        display_name: str | None = None,
        avatar_url: str | None = None,
    ) -> UserProfile:
        """Update safe scalar profile fields via ``PATCH /api/v1/auth/me/profile``."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        body = {
            key: value
            for key, value in {
                "username": username,
                "displayName": display_name,
                "avatarUrl": avatar_url,
            }.items()
            if value is not None
        }
        response = await self._request_mapping(
            "PATCH",
            "/api/v1/auth/me/profile",
            json_body=body,
            bearer=token,
        )
        self._profile_cache.pop(hashlib.sha256(token.encode("utf-8")).hexdigest(), None)
        return UserProfile.from_mapping(response)

    async def get_account_security_summary(self, access_token: str) -> AccountSecuritySummary:
        """Return the current user's secret-free security summary."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        response = await self._request_mapping("GET", "/api/v1/auth/me/security", bearer=token)
        return AccountSecuritySummary.from_mapping(response)

    async def send_email_verification(self, email: str) -> EmailVerificationResponse:
        """Start the opaque public email verification send flow."""

        email = email.strip()
        if not email:
            raise ValueError("email is required")
        response = await self._request_mapping(
            "POST",
            "/api/v1/auth/email/verification/send",
            json_body={"email": email, "client_id": self.config.client_id},
        )
        return EmailVerificationResponse.from_mapping(response)

    async def verify_email(self, token: str) -> EmailVerificationResponse:
        """Verify a public email-verification token."""

        token = token.strip()
        if not token:
            raise ValueError("token is required")
        response = await self._request_mapping(
            "POST",
            "/api/v1/auth/email/verification/verify",
            json_body={"token": token},
        )
        return EmailVerificationResponse.from_mapping(response)

    async def change_password(
        self, access_token: str, *, current_password: str, new_password: str
    ) -> None:
        """Change the current user's password with bearer auth."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        await self._request(
            "POST",
            "/api/v1/auth/password/change",
            json_body={"currentPassword": current_password, "newPassword": new_password},
            bearer=token,
            expect_json=False,
        )

    async def request_password_reset(self, email: str, *, redirect_uri: str | None = None) -> None:
        """Start the opaque public forgot-password flow."""

        email = email.strip()
        if not email:
            raise ValueError("email is required")
        body = {"email": email, "client_id": self.config.client_id}
        if redirect_uri:
            body["redirect_uri"] = redirect_uri
        await self._request(
            "POST",
            "/api/v1/auth/password/forgot",
            json_body=body,
            expect_json=False,
        )

    async def reset_password(self, token: str, *, new_password: str) -> None:
        """Complete public password reset."""

        token = token.strip()
        if not token:
            raise ValueError("token is required")
        await self._request(
            "POST",
            "/api/v1/auth/password/reset",
            json_body={"token": token, "newPassword": new_password},
            expect_json=False,
        )

    async def list_account_sessions(self, access_token: str) -> list[SessionView]:
        """List the current user's active sessions."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        response = await self._request("GET", "/api/v1/auth/sessions", bearer=token)
        if not isinstance(response, list):
            return []
        return [SessionView.from_mapping(item) for item in response if isinstance(item, Mapping)]

    async def revoke_account_session(self, access_token: str, session_id: str) -> None:
        """Revoke one session owned by the current user."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        session_id = session_id.strip()
        if not session_id:
            raise ValueError("session_id is required")
        await self._request(
            "DELETE",
            f"/api/v1/auth/sessions/{quote(session_id, safe='')}",
            bearer=token,
            expect_json=False,
        )

    async def revoke_other_account_sessions(self, access_token: str) -> None:
        """Revoke all sessions except the current token's sid."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        await self._request("DELETE", "/api/v1/auth/sessions", bearer=token, expect_json=False)

    async def logout_account(self, access_token: str, *, refresh_token: str | None = None) -> None:
        """Log out the current token/session and optionally revoke a refresh token."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        body = {"refresh_token": refresh_token} if refresh_token else None
        await self._request(
            "POST",
            "/api/v1/auth/logout",
            json_body=body,
            bearer=token,
            expect_json=False,
        )

    async def list_account_organizations(self, access_token: str) -> list[AccountOrganization]:
        """List the current user's Application-scoped Organizations."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        response = await self._request("GET", "/api/v1/auth/me/organizations", bearer=token)
        if not isinstance(response, list):
            return []
        return [
            AccountOrganization.from_mapping(item) for item in response if isinstance(item, Mapping)
        ]

    async def get_current_account_organization(
        self, access_token: str
    ) -> AccountOrganization | None:
        """Return the selected Organization context, if any."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        response = await self._request("GET", "/api/v1/auth/me/organizations/current", bearer=token)
        return AccountOrganization.from_mapping(response) if isinstance(response, Mapping) else None

    async def switch_account_organization(
        self, access_token: str, organization_id: str
    ) -> OrganizationSwitchResponse:
        """Request an Organization switch and return IAM's refresh/reauth continuation."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        organization_id = organization_id.strip()
        if not organization_id:
            raise ValueError("organization_id is required")
        response = await self._request_mapping(
            "POST",
            "/api/v1/auth/me/organizations/current",
            json_body={"organizationId": organization_id},
            bearer=token,
        )
        return OrganizationSwitchResponse.from_mapping(response)

    async def has_account_organization_membership(
        self, access_token: str, organization_id: str
    ) -> bool:
        """Return membership by deriving it from the Organization list."""

        organization_id = organization_id.strip()
        if not organization_id:
            raise ValueError("organization_id is required")
        organizations = await self.list_account_organizations(access_token)
        return any(item.organization_id == organization_id for item in organizations)

    async def get_account_permission_summary(
        self, access_token: str, *, organization_id: str | None = None
    ) -> AccountPermissionSummary:
        """Resolve current-user permissions in the active or explicit Organization context."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        path = "/api/v1/auth/me/permissions"
        if organization_id:
            path += f"?organizationId={quote(organization_id, safe='')}"
        response = await self._request_mapping("GET", path, bearer=token)
        return AccountPermissionSummary.from_mapping(response)

    async def check_account_permission(
        self,
        access_token: str,
        permission: str,
        *,
        organization_id: str | None = None,
    ) -> PermissionCheckResponse:
        """Check one permission through IAM. Wildcard semantics are backend-owned."""

        token = _normalize_bearer(access_token)
        if not token:
            raise UnauthorizedError("bearer token is required")
        permission = permission.strip()
        if not permission:
            raise ValueError("permission is required")
        body = {"permission": permission}
        if organization_id:
            body["organizationId"] = organization_id
        response = await self._request_mapping(
            "POST",
            "/api/v1/auth/me/permissions:check",
            json_body=body,
            bearer=token,
        )
        return PermissionCheckResponse.from_mapping(response)

    async def preview_organization_invitation(
        self, invitation_token: str
    ) -> PublicOrganizationInvitationPreview:
        """Preview a public Organization invitation without bearer auth."""

        token = invitation_token.strip()
        if not token:
            raise ValueError("invitation_token is required")
        response = await self._request_mapping(
            "GET",
            f"/api/v1/auth/organization-invitations/{quote(token, safe='')}",
        )
        return PublicOrganizationInvitationPreview.from_mapping(response)

    async def accept_organization_invitation(
        self,
        invitation_token: str,
        *,
        access_token: str | None = None,
    ) -> PublicOrganizationInvitationAcceptResponse:
        """Accept a public invitation or receive IAM's login-required continuation."""

        token = invitation_token.strip()
        if not token:
            raise ValueError("invitation_token is required")
        bearer = _normalize_bearer(access_token) if access_token else None
        response = await self._request_mapping(
            "POST",
            f"/api/v1/auth/organization-invitations/{quote(token, safe='')}/accept",
            json_body={},
            bearer=bearer,
        )
        return PublicOrganizationInvitationAcceptResponse.from_mapping(response)

    async def list_permissions(self, client_id: str | None = None) -> list[PermissionDefinition]:
        """Return a strictly parsed confidential role-permission snapshot."""

        cid = client_id or self.config.client_id
        encoded_client_id = quote(cid, safe="")
        response = await self._request_strict_mapping(
            "GET", f"/open/v1/apps/{encoded_client_id}/permissions", auth=True
        )
        if set(response) != {"applicationId", "clientId", "roles"}:
            raise IamApiError(200, "invalid permission snapshot response")
        if not isinstance(response["applicationId"], str) or not _CANONICAL_UUID.fullmatch(
            response["applicationId"]
        ):
            raise IamApiError(200, "invalid permission snapshot response")
        if response["clientId"] != cid or not isinstance(response["roles"], list):
            raise IamApiError(200, "invalid permission snapshot response")
        role_keys: set[str] = set()
        permission_keys: set[str] = set()
        out: list[PermissionDefinition] = []
        for role_value in response["roles"]:
            if not isinstance(role_value, Mapping) or set(role_value) != {
                "key",
                "name",
                "permissions",
            }:
                raise IamApiError(200, "invalid permission snapshot response")
            key = role_value["key"]
            name = role_value["name"]
            if (
                not isinstance(key, str)
                or not re.fullmatch(r"[a-z0-9_-]{1,128}", key)
                or not isinstance(name, str)
                or not name.strip()
            ):
                raise IamApiError(200, "invalid permission snapshot response")
            if key in role_keys:
                raise IamApiError(200, "invalid permission snapshot response: duplicate role key")
            role_keys.add(key)
            for permission in _strict_permission_keys(
                role_value["permissions"], "permission snapshot", allow_wildcards=True
            ):
                if permission in permission_keys:
                    continue
                permission_keys.add(permission)
                resource, action = permission.split(":", 1)
                out.append(PermissionDefinition(resource=resource, action=action))
        return out

    def authenticate_sync(self, access_token: str) -> IamContext:
        """Synchronous wrapper for Django-style integrations."""

        return _run_sync(self.authenticate(access_token))

    def get_me_sync(self, access_token: str, bypass_cache: bool = False) -> UserProfile:
        """Synchronous profile wrapper for Django-style integrations."""

        return _run_sync(self.get_me(access_token, bypass_cache=bypass_cache))

    def get_account_security_summary_sync(self, access_token: str) -> AccountSecuritySummary:
        """Synchronous security summary wrapper for Django-style integrations."""

        return _run_sync(self.get_account_security_summary(access_token))

    def send_email_verification_sync(self, email: str) -> EmailVerificationResponse:
        """Synchronous email verification send wrapper for Django-style integrations."""

        return _run_sync(self.send_email_verification(email))

    def verify_email_sync(self, token: str) -> EmailVerificationResponse:
        """Synchronous email verification wrapper for Django-style integrations."""

        return _run_sync(self.verify_email(token))

    def change_password_sync(
        self, access_token: str, *, current_password: str, new_password: str
    ) -> None:
        """Synchronous password-change wrapper for Django-style integrations."""

        return _run_sync(
            self.change_password(
                access_token,
                current_password=current_password,
                new_password=new_password,
            )
        )

    def request_password_reset_sync(self, email: str, *, redirect_uri: str | None = None) -> None:
        """Synchronous forgot-password wrapper for Django-style integrations."""

        return _run_sync(self.request_password_reset(email, redirect_uri=redirect_uri))

    def reset_password_sync(self, token: str, *, new_password: str) -> None:
        """Synchronous password reset wrapper for Django-style integrations."""

        return _run_sync(self.reset_password(token, new_password=new_password))

    def list_account_sessions_sync(self, access_token: str) -> list[SessionView]:
        """Synchronous session list wrapper for Django-style integrations."""

        return _run_sync(self.list_account_sessions(access_token))

    def revoke_account_session_sync(self, access_token: str, session_id: str) -> None:
        """Synchronous single-session revoke wrapper for Django-style integrations."""

        return _run_sync(self.revoke_account_session(access_token, session_id))

    def revoke_other_account_sessions_sync(self, access_token: str) -> None:
        """Synchronous other-sessions revoke wrapper for Django-style integrations."""

        return _run_sync(self.revoke_other_account_sessions(access_token))

    def logout_account_sync(self, access_token: str, *, refresh_token: str | None = None) -> None:
        """Synchronous logout wrapper for Django-style integrations."""

        return _run_sync(self.logout_account(access_token, refresh_token=refresh_token))

    def list_account_organizations_sync(self, access_token: str) -> list[AccountOrganization]:
        """Synchronous Organization list wrapper for Django-style integrations."""

        return _run_sync(self.list_account_organizations(access_token))

    def get_current_account_organization_sync(
        self, access_token: str
    ) -> AccountOrganization | None:
        """Synchronous current Organization wrapper for Django-style integrations."""

        return _run_sync(self.get_current_account_organization(access_token))

    def switch_account_organization_sync(
        self, access_token: str, organization_id: str
    ) -> OrganizationSwitchResponse:
        """Synchronous Organization switch wrapper for Django-style integrations."""

        return _run_sync(self.switch_account_organization(access_token, organization_id))

    def has_account_organization_membership_sync(
        self, access_token: str, organization_id: str
    ) -> bool:
        """Synchronous membership check wrapper for Django-style integrations."""

        return _run_sync(self.has_account_organization_membership(access_token, organization_id))

    def get_account_permission_summary_sync(
        self, access_token: str, organization_id: str | None = None
    ) -> AccountPermissionSummary:
        """Synchronous permission summary wrapper for Django-style integrations."""

        return _run_sync(
            self.get_account_permission_summary(access_token, organization_id=organization_id)
        )

    def check_account_permission_sync(
        self, access_token: str, permission: str, organization_id: str | None = None
    ) -> PermissionCheckResponse:
        """Synchronous permission check wrapper for Django-style integrations."""

        return _run_sync(
            self.check_account_permission(
                access_token,
                permission,
                organization_id=organization_id,
            )
        )

    def preview_organization_invitation_sync(
        self, invitation_token: str
    ) -> PublicOrganizationInvitationPreview:
        """Synchronous invitation preview wrapper for Django-style integrations."""

        return _run_sync(self.preview_organization_invitation(invitation_token))

    def accept_organization_invitation_sync(
        self, invitation_token: str, access_token: str | None = None
    ) -> PublicOrganizationInvitationAcceptResponse:
        """Synchronous invitation accept wrapper for Django-style integrations."""

        return _run_sync(
            self.accept_organization_invitation(invitation_token, access_token=access_token)
        )

    async def close(self) -> None:
        """Close the underlying HTTP client when owned by this SDK."""

        if self._owns_http:
            await self._http.aclose()

    async def _jwk_for_kid(self, kid: str) -> dict[str, Any]:
        keys = await self._jwks_keys()
        key = keys.get(kid)
        if key is not None:
            return key
        keys = await self._jwks_keys(force=True)
        key = keys.get(kid)
        if key is None:
            raise UnauthorizedError(f"JWT signing key not found: {kid}")
        return key

    async def _jwks_keys(self, *, force: bool = False) -> dict[str, dict[str, Any]]:
        cached = self._jwks
        if not force and cached is not None and cached.expires_at > time.monotonic():
            return cached.value
        async with self._jwks_lock:
            cached = self._jwks
            if not force and cached is not None and cached.expires_at > time.monotonic():
                return cached.value
            jwks_uri = await self._discover_jwks_uri()
            response = await self._http.get(jwks_uri)
            if response.status_code >= 400:
                raise IamApiError(response.status_code, response.text)
            body = response.json()
            values = body.get("keys", [])
            keys: dict[str, dict[str, Any]] = {}
            if isinstance(values, list):
                for item in values:
                    if isinstance(item, dict) and isinstance(item.get("kid"), str):
                        keys[item["kid"]] = item
            self._jwks = _CacheEntry(
                expires_at=time.monotonic() + self.config.jwks_cache_ttl,
                value=keys,
            )
            return keys

    async def _discover_jwks_uri(self) -> str:
        if self._jwks_uri is not None:
            return self._jwks_uri
        response = await self._http.get(f"{self.config.endpoint}/.well-known/openid-configuration")
        if response.status_code >= 400:
            raise IamApiError(response.status_code, response.text)
        body = response.json()
        jwks_uri = body.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri:
            raise IamApiError(response.status_code, "OIDC discovery missing jwks_uri")
        self._jwks_uri = jwks_uri
        return jwks_uri

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        auth: bool = False,
        bearer: str | None = None,
        expect_json: bool = True,
    ) -> Any:
        headers = {"Accept": "application/json"}
        if auth:
            headers["X-IAM-Client-Id"] = self.config.client_id
        if bearer is not None:
            headers["Authorization"] = f"Bearer {bearer}"
        request_auth = (self.config.client_id, self.config.client_secret) if auth else None
        response = await self._http.request(
            method,
            f"{self.config.endpoint}{path}",
            json=json_body,
            headers=headers,
            auth=request_auth,
        )
        if response.status_code >= 400:
            raise IamApiError(response.status_code, response.text)
        if not expect_json or response.status_code == 204 or not response.content:
            return {}
        return response.json()

    async def _request_mapping(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        auth: bool = False,
        bearer: str | None = None,
    ) -> Mapping[str, Any]:
        data = await self._request(
            method,
            path,
            json_body=json_body,
            auth=auth,
            bearer=bearer,
        )
        return data if isinstance(data, Mapping) else {}

    async def _request_strict_mapping(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        auth: bool = False,
    ) -> Mapping[str, Any]:
        headers = {"Accept": "application/json"}
        request_auth = None
        if auth:
            headers["X-IAM-Client-Id"] = self.config.client_id
            request_auth = (self.config.client_id, self.config.client_secret)
        response = await self._http.request(
            method,
            f"{self.config.endpoint}{path}",
            json=json_body,
            headers=headers,
            auth=request_auth,
        )
        if response.status_code >= 400:
            raise IamApiError(response.status_code, response.text)
        try:
            data = json.loads(response.text, object_pairs_hook=_reject_duplicate_json_members)
        except (TypeError, ValueError) as error:
            raise IamApiError(response.status_code, "invalid JSON response") from error
        if not isinstance(data, Mapping):
            raise IamApiError(response.status_code, "invalid object response")
        return data


def _normalize_bearer(value: str | None) -> str:
    token = (value or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _reject_duplicate_json_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key}")
        result[key] = value
    return result


def _strict_permission_keys(
    value: object, operation: str, *, allow_wildcards: bool = False
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise IamApiError(200, f"invalid {operation} response")
    seen: set[str] = set()
    out: list[str] = []
    for item in value:
        valid = isinstance(item, str) and (
            _CONCRETE_PERMISSION.fullmatch(item) is not None
            or (
                allow_wildcards
                and (
                    item == "*:*"
                    or (
                        item.endswith(":*")
                        and _CONCRETE_PERMISSION.fullmatch(item[:-1] + "read") is not None
                    )
                )
            )
        )
        if not valid:
            raise IamApiError(200, f"invalid {operation} response")
        if not isinstance(item, str):
            raise IamApiError(200, f"invalid {operation} response")
        if item in seen:
            raise IamApiError(200, f"invalid {operation} response: duplicate permission")
        seen.add(item)
        out.append(item)
    return tuple(out)


def _run_sync[T](awaitable: Coroutine[Any, Any, T]) -> T:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)
    raise RuntimeError("sync IAM SDK wrapper cannot run inside an active event loop")
