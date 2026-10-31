"""Server-side client for iam-portal ``/open/v1/**`` M2M APIs."""

from __future__ import annotations

import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, cast
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from .config import normalize_endpoint
from .errors import (
    PortalOpenApiConfigError,
    PortalOpenApiError,
    PortalOpenApiTokenError,
    PortalOpenApiTransportError,
)

PORTAL_OPEN_API_READ_SCOPE = "portal:openapi:read"
PORTAL_OPEN_API_WRITE_SCOPE = "portal:openapi:write"
REGISTRATION_GRANTS_READ_SCOPE = "registration_grants:read"
REGISTRATION_GRANTS_WRITE_SCOPE = "registration_grants:write"
REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE = "registration_grants:redemptions:read"
ORGANIZATIONS_READ_SCOPE = "organizations:read"
ORGANIZATIONS_WRITE_SCOPE = "organizations:write"
ORGANIZATION_INVITATIONS_READ_SCOPE = "organization_invitations:read"
ORGANIZATION_INVITATIONS_WRITE_SCOPE = "organization_invitations:write"
ORGANIZATION_MEMBERS_READ_SCOPE = "organization_members:read"
ORGANIZATION_MEMBERS_WRITE_SCOPE = "organization_members:write"
ROLES_READ_SCOPE = "roles:read"
ROLES_WRITE_SCOPE = "roles:write"
PERMISSIONS_READ_SCOPE = "permissions:read"
PERMISSIONS_WRITE_SCOPE = "permissions:write"
ROLE_PERMISSIONS_READ_SCOPE = "role_permissions:read"
ROLE_PERMISSIONS_WRITE_SCOPE = "role_permissions:write"
USER_ROLES_READ_SCOPE = "user_roles:read"
USER_ROLES_WRITE_SCOPE = "user_roles:write"

PortalOpenApiScope = Literal[
    "portal:openapi:read",
    "portal:openapi:write",
    "registration_grants:read",
    "registration_grants:write",
    "registration_grants:redemptions:read",
    "organizations:read",
    "organizations:write",
    "organization_invitations:read",
    "organization_invitations:write",
    "organization_members:read",
    "organization_members:write",
    "roles:read",
    "roles:write",
    "permissions:read",
    "permissions:write",
    "role_permissions:read",
    "role_permissions:write",
    "user_roles:read",
    "user_roles:write",
]
PortalOpenApiMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
Jsonish = dict[str, Any] | list[Any] | str | int | float | bool | None

_SUPPORTED_SCOPES = {
    PORTAL_OPEN_API_READ_SCOPE,
    PORTAL_OPEN_API_WRITE_SCOPE,
    REGISTRATION_GRANTS_READ_SCOPE,
    REGISTRATION_GRANTS_WRITE_SCOPE,
    REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE,
    ORGANIZATIONS_READ_SCOPE,
    ORGANIZATIONS_WRITE_SCOPE,
    ORGANIZATION_INVITATIONS_READ_SCOPE,
    ORGANIZATION_INVITATIONS_WRITE_SCOPE,
    ORGANIZATION_MEMBERS_READ_SCOPE,
    ORGANIZATION_MEMBERS_WRITE_SCOPE,
    ROLES_READ_SCOPE,
    ROLES_WRITE_SCOPE,
    PERMISSIONS_READ_SCOPE,
    PERMISSIONS_WRITE_SCOPE,
    ROLE_PERMISSIONS_READ_SCOPE,
    ROLE_PERMISSIONS_WRITE_SCOPE,
    USER_ROLES_READ_SCOPE,
    USER_ROLES_WRITE_SCOPE,
}
_SUPPORTED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_PORTAL_ERROR_CODES = {
    "OPEN_API_SCOPE_INSUFFICIENT",
    "OPEN_API_MACHINE_TOKEN_REQUIRED",
    "OPEN_API_INVALID_AUDIENCE",
}
_FORBIDDEN_PORTAL_HEADERS = {
    "authorization",
    "x-iam-client-id",
    "x-application-id",
    "x-app-key",
}


@dataclass(frozen=True, slots=True)
class PortalOpenApiConfig:
    """Configuration for :class:`axis_vertex.PortalOpenApiClient`.

    ``client_id`` and ``client_secret`` must be an M2M confidential
    ApplicationClient allowed to receive explicit Portal Open API scopes.
    """

    issuer: str
    portal_endpoint: str
    client_id: str
    client_secret: str
    timeout: float = 5.0
    token_skew_seconds: float = 30.0

    def __post_init__(self) -> None:
        issuer = normalize_endpoint(self.issuer)
        portal_endpoint = normalize_endpoint(self.portal_endpoint)
        client_id = self.client_id.strip()
        client_secret = self.client_secret.strip()
        if not client_id or not client_secret:
            raise PortalOpenApiConfigError(
                "PortalOpenApiClient requires M2M client_id and client_secret"
            )
        if self.timeout <= 0:
            raise PortalOpenApiConfigError("timeout must be positive")
        if self.token_skew_seconds < 0:
            raise PortalOpenApiConfigError("token_skew_seconds must be non-negative")
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "portal_endpoint", portal_endpoint)
        object.__setattr__(self, "client_id", client_id)
        object.__setattr__(self, "client_secret", client_secret)


@dataclass(frozen=True, slots=True)
class PortalOpenApiMachineToken:
    """Cached M2M token returned by :meth:`PortalOpenApiClient.get_machine_token`."""

    access_token: str
    scope: PortalOpenApiScope
    expires_at: float


RegistrationGrantType = Literal["EMAIL_LINK", "ACCESS_CODE", "ORG_INVITATION"]
CreateRegistrationGrantType = Literal["EMAIL_LINK", "ACCESS_CODE"]
RegistrationGrantStatus = Literal["ACTIVE", "PAUSED", "REDEEMED", "EXPIRED", "REVOKED"]


@dataclass(frozen=True, slots=True)
class RegistrationGrant:
    """Safe registration-grant detail. Raw proofs are never included."""

    id: str
    version: int
    type: RegistrationGrantType
    status: RegistrationGrantStatus
    display_name: str | None
    allowed_email: str | None
    allowed_domain: str | None
    expires_at: str | None
    max_uses: int | None
    used_count: int
    source_type: str
    created_at: str
    updated_at: str
    revoked_at: str | None
    revoke_reason: str | None


@dataclass(frozen=True, slots=True)
class CreateRegistrationGrantRequest:
    """Manual EMAIL_LINK or ACCESS_CODE registration-grant create payload."""

    type: CreateRegistrationGrantType
    display_name: str | None = None
    allowed_email: str | None = None
    allowed_domain: str | None = None
    expires_at: str | None = None
    max_uses: int | None = None

    def to_json(self) -> dict[str, object]:
        result: dict[str, object] = {"type": self.type}
        for key, value in (
            ("displayName", self.display_name),
            ("allowedEmail", self.allowed_email),
            ("allowedDomain", self.allowed_domain),
            ("expiresAt", self.expires_at),
            ("maxUses", self.max_uses),
        ):
            if value is not None:
                result[key] = value
        return result


@dataclass(frozen=True, slots=True)
class CreatedRegistrationGrant:
    """One-time create/rotate material, or a replay without reissued secrets."""

    grant: RegistrationGrant
    registration_grant_token: str | None
    registration_access_code: str | None
    registration_invitation_url: str | None
    secret_already_issued: bool


@dataclass(frozen=True, slots=True)
class RegistrationGrantDeliveryRequest:
    recipient: str
    variant: Literal["LINK", "CODE"]
    locale: str | None = None

    def to_json(self) -> dict[str, object]:
        if not self.recipient.strip() or self.variant not in {"LINK", "CODE"}:
            raise ValueError("Recipient and delivery variant are required")
        return {"recipient": self.recipient, "variant": self.variant, "locale": self.locale}


@dataclass(frozen=True, slots=True)
class RegistrationGrantDelivery:
    id: str
    grant_id: str
    recipient: str
    variant: Literal["LINK", "CODE"]
    status: Literal["QUEUED", "SENDING", "DELIVERED", "FAILED", "UNKNOWN"]
    failure_code: str | None
    attempt_count: int
    max_attempts: int | None
    next_attempt_at: str | None
    retryable: bool
    expires_at: str
    created_at: str


@dataclass(frozen=True, slots=True)
class RegistrationGrantListOptions:
    """Optional API filtering and pagination for registration grants."""

    type: RegistrationGrantType | None = None
    status: RegistrationGrantStatus | None = None
    search: str | None = None
    page: int | None = None
    size: int | None = None


@dataclass(frozen=True, slots=True)
class RegistrationGrantPageMetadata:
    """Nested Spring PagedModel metadata."""

    size: int
    number: int
    total_elements: int
    total_pages: int


@dataclass(frozen=True, slots=True)
class RegistrationGrantPage:
    """A page of safe registration-grant details."""

    content: tuple[RegistrationGrant, ...]
    page: RegistrationGrantPageMetadata


@dataclass(frozen=True, slots=True)
class RegistrationGrantRedemption:
    """Safe masked registration-grant redemption entry."""

    id: str
    result: str
    email: str | None
    auth_method: str | None
    idp_id: str | None
    client_id: str | None
    redeemed_at: str
    failure_reason: str | None


@dataclass(frozen=True, slots=True)
class RegistrationGrantRedemptionPage:
    """A page of safe masked registration-grant redemptions."""

    content: tuple[RegistrationGrantRedemption, ...]
    page: RegistrationGrantPageMetadata


OrganizationMemberRole = Literal["OWNER", "ADMIN", "MEMBER"]
OrganizationInvitationStatus = Literal["PENDING", "ACCEPTED", "CANCELLED", "EXPIRED"]
OrganizationInvitationDeliveryStatus = Literal["NOT_REQUESTED", "SENT", "FAILED"]
OrganizationSortDirection = Literal["ASC", "DESC"]


@dataclass(frozen=True, slots=True)
class Organization:
    """Application-bound Organization detail with the ETag from create/get/update."""

    id: str
    name: str
    slug: str
    version: int
    created_at: str
    updated_at: str
    etag: str | None = None


@dataclass(frozen=True, slots=True)
class CreateOrganizationRequest:
    """Strict Organization create payload."""

    name: str
    slug: str

    def to_json(self) -> dict[str, str]:
        return {"name": self.name, "slug": self.slug}


@dataclass(frozen=True, slots=True)
class UpdateOrganizationRequest:
    """Strict Organization PATCH payload; at least one non-null field is required."""

    name: str | None = None
    slug: str | None = None

    def to_json(self) -> dict[str, str]:
        result: dict[str, str] = {}
        if self.name is not None:
            result["name"] = self.name
        if self.slug is not None:
            result["slug"] = self.slug
        return result


@dataclass(frozen=True, slots=True)
class OrganizationListOptions:
    """Optional Organization search, paging, and sorting parameters."""

    search: str | None = None
    page: int | None = None
    size: int | None = None
    sort: tuple[str, ...] = ()
    direction: tuple[OrganizationSortDirection, ...] = ()


@dataclass(frozen=True, slots=True)
class OrganizationPageMetadata:
    """Nested Spring PagedModel metadata for Organization management lists."""

    size: int
    number: int
    total_elements: int
    total_pages: int


@dataclass(frozen=True, slots=True)
class OrganizationPage:
    """Page of Application-bound Organizations."""

    content: tuple[Organization, ...]
    page: OrganizationPageMetadata


@dataclass(frozen=True, slots=True)
class OrganizationInvitation:
    """Safe invitation detail; no raw invitation proof is exposed."""

    id: str
    email: str
    role: OrganizationMemberRole
    status: OrganizationInvitationStatus
    delivery_status: OrganizationInvitationDeliveryStatus
    expires_at: str
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class CreateOrganizationInvitationRequest:
    """Strict Organization invitation create payload."""

    email: str
    role: OrganizationMemberRole | None = None
    send_email: bool | None = None

    def to_json(self) -> dict[str, object]:
        result: dict[str, object] = {"email": self.email}
        if self.role is not None:
            result["role"] = self.role
        if self.send_email is not None:
            result["sendEmail"] = self.send_email
        return result


@dataclass(frozen=True, slots=True)
class OrganizationInvitationListOptions:
    """Optional invitation terminal-state filter and paging parameters."""

    status: OrganizationInvitationStatus | None = None
    page: int | None = None
    size: int | None = None


@dataclass(frozen=True, slots=True)
class OrganizationInvitationPage:
    """Page of Organization invitation lifecycle and delivery details."""

    content: tuple[OrganizationInvitation, ...]
    page: OrganizationPageMetadata


@dataclass(frozen=True, slots=True)
class OrganizationMember:
    """Organization membership detail, including optimistic-lock version."""

    membership_id: str
    user_id: str
    email: str
    display_name: str
    role: OrganizationMemberRole
    joined_at: str
    updated_at: str
    version: int


@dataclass(frozen=True, slots=True)
class OrganizationMemberListOptions:
    """Optional Organization member search and paging parameters."""

    search: str | None = None
    page: int | None = None
    size: int | None = None


@dataclass(frozen=True, slots=True)
class OrganizationMemberPage:
    """Page of Organization memberships."""

    content: tuple[OrganizationMember, ...]
    page: OrganizationPageMetadata


@dataclass(frozen=True, slots=True)
class AuthorizationPageOptions:
    page: int = 0
    size: int = 20


@dataclass(frozen=True, slots=True)
class AuthorizationPageMetadata:
    size: int
    number: int
    total_elements: int
    total_pages: int


@dataclass(frozen=True, slots=True)
class Role:
    id: str
    key: str
    name: str
    description: str | None
    system: bool
    version: int
    created_at: str
    updated_at: str
    etag: str = ""


@dataclass(frozen=True, slots=True)
class RolePage:
    content: tuple[Role, ...]
    page: AuthorizationPageMetadata


@dataclass(frozen=True, slots=True)
class CreateRoleRequest:
    key: str
    name: str
    description: str | None = None

    def to_json(self) -> dict[str, object]:
        return {"key": self.key, "name": self.name, "description": self.description}


@dataclass(frozen=True, slots=True)
class UpdateRoleRequest:
    key: str | None = None
    name: str | None = None
    description: str | None = None

    def to_json(self) -> dict[str, object]:
        return {
            k: v
            for k, v in {
                "key": self.key,
                "name": self.name,
                "description": self.description,
            }.items()
            if v is not None
        }


@dataclass(frozen=True, slots=True)
class Permission:
    id: str
    resource: str
    action: str
    key: str
    name: str
    description: str | None
    source: Literal["CODE", "MANUAL"]
    version: int
    created_at: str
    updated_at: str
    etag: str = ""


@dataclass(frozen=True, slots=True)
class PermissionPage:
    content: tuple[Permission, ...]
    page: AuthorizationPageMetadata


@dataclass(frozen=True, slots=True)
class CreatePermissionRequest:
    resource: str
    action: str
    name: str
    description: str | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "resource": self.resource,
            "action": self.action,
            "name": self.name,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class UpdatePermissionRequest:
    name: str | None = None
    description: str | None = None

    def to_json(self) -> dict[str, object]:
        return {
            k: v
            for k, v in {"name": self.name, "description": self.description}.items()
            if v is not None
        }


@dataclass(frozen=True, slots=True)
class RolePermissionBinding:
    role_id: str
    permission_id: str
    created_at: str


@dataclass(frozen=True, slots=True)
class RolePermissionBindingPage:
    content: tuple[RolePermissionBinding, ...]
    page: AuthorizationPageMetadata
    etag: str


@dataclass(frozen=True, slots=True)
class RolePermissionSet:
    role_id: str
    permission_ids: tuple[str, ...]
    version: int
    etag: str


@dataclass(frozen=True, slots=True)
class UserRoleCondition:
    expression: str | None = None
    description: str | None = None

    def to_json(self) -> dict[str, object]:
        return {"expression": self.expression, "description": self.description}


@dataclass(frozen=True, slots=True)
class UserRoleAssignment:
    id: str
    user_id: str
    role_id: str
    organization_id: str | None
    condition_expression: str | None
    condition_description: str | None
    version: int
    created_at: str
    updated_at: str
    etag: str = ""


@dataclass(frozen=True, slots=True)
class UserRoleAssignmentPage:
    content: tuple[UserRoleAssignment, ...]
    page: AuthorizationPageMetadata


@dataclass(frozen=True, slots=True)
class CreateUserRoleRequest:
    role_id: str
    condition: UserRoleCondition | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "roleId": self.role_id,
            "condition": None if self.condition is None else self.condition.to_json(),
        }


@dataclass(frozen=True, slots=True)
class _PortalOpenApiResponse:
    body: Jsonish
    etag: str | None


class PortalOpenApiClient:
    """Server-side M2M client for iam-portal ``/open/v1/**``.

    The client requests ``client_credentials`` machine tokens from iam-server
    with explicit ``portal:openapi:read`` or ``portal:openapi:write`` scope,
    caches read/write tokens separately, and sends only bearer auth to Portal.
    """

    def __init__(
        self,
        config: PortalOpenApiConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        self._http = http_client or httpx.AsyncClient(timeout=config.timeout)
        self._owns_http = http_client is None
        self._token_cache: dict[PortalOpenApiScope, PortalOpenApiMachineToken] = {}

    async def request_json(
        self,
        method: str,
        path: str,
        *,
        json: object = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any] | list[Any] | str | int | float | bool | None:
        """Call a Portal ``/open/v1/**`` endpoint with a bearer machine token."""

        return await self._request_json_with_scope(
            method,
            path,
            _scope_for_method(self._normalize_method(method)),
            json=json,
            headers=headers,
        )

    async def list_registration_grants(
        self, options: RegistrationGrantListOptions | None = None
    ) -> RegistrationGrantPage:
        effective_options = options or RegistrationGrantListOptions()
        body = await self._request_json_with_scope(
            "GET",
            "/open/v1/registration-grants" + _registration_grant_query(effective_options),
            cast(PortalOpenApiScope, REGISTRATION_GRANTS_READ_SCOPE),
        )
        return _registration_grant_page(body)

    async def create_registration_grant(
        self, request: CreateRegistrationGrantRequest, *, idempotency_key: str
    ) -> CreatedRegistrationGrant:
        body = await self._request_json_with_scope(
            "POST",
            "/open/v1/registration-grants",
            cast(PortalOpenApiScope, REGISTRATION_GRANTS_WRITE_SCOPE),
            json=request.to_json(),
            headers=_registration_command_headers(idempotency_key),
        )
        return _created_registration_grant(body)

    async def rotate_registration_grant(
        self, grant_id: str, expected_version: int, *, idempotency_key: str
    ) -> CreatedRegistrationGrant:
        if isinstance(expected_version, bool) or expected_version < 0:
            raise ValueError("Expected version must be non-negative")
        body = await self._request_json_with_scope(
            "POST",
            _registration_grant_path(grant_id) + "/rotate",
            cast(PortalOpenApiScope, REGISTRATION_GRANTS_WRITE_SCOPE),
            json={"expectedVersion": expected_version},
            headers=_registration_command_headers(idempotency_key),
        )
        result = _created_registration_grant(body)
        if result.grant.id != grant_id:
            raise _invalid_registration_grant_response()
        return result

    async def deliver_registration_grant(
        self, grant_id: str, request: RegistrationGrantDeliveryRequest, *, idempotency_key: str
    ) -> RegistrationGrantDelivery:
        body = await self._request_json_with_scope(
            "POST",
            _registration_grant_path(grant_id) + "/deliveries",
            cast(PortalOpenApiScope, REGISTRATION_GRANTS_WRITE_SCOPE),
            json=request.to_json(),
            headers=_registration_command_headers(idempotency_key),
        )
        result = _registration_grant_delivery(body)
        if result.grant_id != grant_id or result.variant != request.variant:
            raise _invalid_registration_grant_response()
        return result

    async def get_registration_grant_delivery(
        self, grant_id: str, delivery_id: str
    ) -> RegistrationGrantDelivery:
        _registration_grant_path(delivery_id)
        body = await self._request_json_with_scope(
            "GET",
            _registration_grant_path(grant_id) + "/deliveries/" + delivery_id,
            cast(PortalOpenApiScope, REGISTRATION_GRANTS_READ_SCOPE),
        )
        result = _registration_grant_delivery(body)
        if result.grant_id != grant_id or result.id != delivery_id:
            raise _invalid_registration_grant_response()
        return result

    async def get_registration_grant(self, grant_id: str) -> RegistrationGrant:
        body = await self._request_json_with_scope(
            "GET",
            _registration_grant_path(grant_id),
            cast(PortalOpenApiScope, REGISTRATION_GRANTS_READ_SCOPE),
        )
        return _registration_grant(body)

    async def pause_registration_grant(self, grant_id: str) -> RegistrationGrant:
        return await self._registration_grant_lifecycle(grant_id, "pause")

    async def resume_registration_grant(self, grant_id: str) -> RegistrationGrant:
        return await self._registration_grant_lifecycle(grant_id, "resume")

    async def revoke_registration_grant(
        self, grant_id: str, reason: str | None = None
    ) -> RegistrationGrant:
        body = await self._request_json_with_scope(
            "POST",
            _registration_grant_path(grant_id) + "/revoke",
            cast(PortalOpenApiScope, REGISTRATION_GRANTS_WRITE_SCOPE),
            json=None if reason is None else {"reason": reason},
        )
        return _registration_grant(body)

    async def list_registration_grant_redemptions(
        self, grant_id: str, *, page: int | None = None, size: int | None = None
    ) -> RegistrationGrantRedemptionPage:
        body = await self._request_json_with_scope(
            "GET",
            _registration_grant_path(grant_id) + "/redemptions" + _page_query(page, size),
            cast(PortalOpenApiScope, REGISTRATION_GRANTS_REDEMPTIONS_READ_SCOPE),
        )
        return _registration_grant_redemption_page(body)

    async def list_organizations(
        self, options: OrganizationListOptions | None = None
    ) -> OrganizationPage:
        body = await self._request_json_with_scope(
            "GET",
            "/open/v1/organizations" + _organization_query(options or OrganizationListOptions()),
            cast(PortalOpenApiScope, ORGANIZATIONS_READ_SCOPE),
        )
        return _organization_page(body)

    async def create_organization(
        self,
        request: CreateOrganizationRequest,
        *,
        idempotency_key: str | None = None,
    ) -> Organization:
        response = await self._request_json_with_scope_response(
            "POST",
            "/open/v1/organizations",
            cast(PortalOpenApiScope, ORGANIZATIONS_WRITE_SCOPE),
            json=request.to_json(),
            headers=_idempotency_headers(idempotency_key),
        )
        return _organization(response.body, etag=response.etag)

    async def get_organization(self, organization_id: str) -> Organization:
        response = await self._request_json_with_scope_response(
            "GET",
            _organization_path(organization_id),
            cast(PortalOpenApiScope, ORGANIZATIONS_READ_SCOPE),
        )
        return _organization(response.body, etag=response.etag)

    async def update_organization(
        self,
        organization_id: str,
        request: UpdateOrganizationRequest,
        *,
        if_match: str | None = None,
    ) -> Organization:
        response = await self._request_json_with_scope_response(
            "PATCH",
            _organization_path(organization_id),
            cast(PortalOpenApiScope, ORGANIZATIONS_WRITE_SCOPE),
            json=request.to_json(),
            headers=_if_match_headers(if_match),
        )
        return _organization(response.body, etag=response.etag)

    async def delete_organization(
        self, organization_id: str, *, if_match: str | None = None
    ) -> None:
        await self._request_json_with_scope(
            "DELETE",
            _organization_path(organization_id),
            cast(PortalOpenApiScope, ORGANIZATIONS_WRITE_SCOPE),
            headers=_if_match_headers(if_match),
        )

    async def list_organization_invitations(
        self, organization_id: str, options: OrganizationInvitationListOptions | None = None
    ) -> OrganizationInvitationPage:
        body = await self._request_json_with_scope(
            "GET",
            _organization_path(organization_id)
            + "/invitations"
            + _organization_invitation_query(options or OrganizationInvitationListOptions()),
            cast(PortalOpenApiScope, ORGANIZATION_INVITATIONS_READ_SCOPE),
        )
        return _organization_invitation_page(body)

    async def create_organization_invitation(
        self,
        organization_id: str,
        request: CreateOrganizationInvitationRequest,
        *,
        idempotency_key: str | None = None,
    ) -> OrganizationInvitation:
        body = await self._request_json_with_scope(
            "POST",
            _organization_path(organization_id) + "/invitations",
            cast(PortalOpenApiScope, ORGANIZATION_INVITATIONS_WRITE_SCOPE),
            json=request.to_json(),
            headers=_idempotency_headers(idempotency_key),
        )
        return _organization_invitation(body)

    async def get_organization_invitation(
        self, organization_id: str, invitation_id: str
    ) -> OrganizationInvitation:
        body = await self._request_json_with_scope(
            "GET",
            _organization_invitation_path(organization_id, invitation_id),
            cast(PortalOpenApiScope, ORGANIZATION_INVITATIONS_READ_SCOPE),
        )
        return _organization_invitation(body)

    async def resend_organization_invitation(
        self, organization_id: str, invitation_id: str
    ) -> OrganizationInvitation:
        body = await self._request_json_with_scope(
            "POST",
            _organization_invitation_path(organization_id, invitation_id) + "/resend",
            cast(PortalOpenApiScope, ORGANIZATION_INVITATIONS_WRITE_SCOPE),
        )
        return _organization_invitation(body)

    async def cancel_organization_invitation(
        self, organization_id: str, invitation_id: str
    ) -> None:
        await self._request_json_with_scope(
            "DELETE",
            _organization_invitation_path(organization_id, invitation_id),
            cast(PortalOpenApiScope, ORGANIZATION_INVITATIONS_WRITE_SCOPE),
        )

    async def list_organization_members(
        self, organization_id: str, options: OrganizationMemberListOptions | None = None
    ) -> OrganizationMemberPage:
        body = await self._request_json_with_scope(
            "GET",
            _organization_path(organization_id)
            + "/members"
            + _organization_member_query(options or OrganizationMemberListOptions()),
            cast(PortalOpenApiScope, ORGANIZATION_MEMBERS_READ_SCOPE),
        )
        return _organization_member_page(body)

    async def get_organization_member(
        self, organization_id: str, membership_id: str
    ) -> OrganizationMember:
        body = await self._request_json_with_scope(
            "GET",
            _organization_member_path(organization_id, membership_id),
            cast(PortalOpenApiScope, ORGANIZATION_MEMBERS_READ_SCOPE),
        )
        return _organization_member(body)

    async def update_organization_member_role(
        self,
        organization_id: str,
        membership_id: str,
        role: OrganizationMemberRole,
        *,
        if_match: str | None = None,
    ) -> OrganizationMember:
        body = await self._request_json_with_scope(
            "PATCH",
            _organization_member_path(organization_id, membership_id),
            cast(PortalOpenApiScope, ORGANIZATION_MEMBERS_WRITE_SCOPE),
            json={"role": role},
            headers=_if_match_headers(if_match),
        )
        return _organization_member(body)

    async def remove_organization_member(self, organization_id: str, membership_id: str) -> None:
        await self._request_json_with_scope(
            "DELETE",
            _organization_member_path(organization_id, membership_id),
            cast(PortalOpenApiScope, ORGANIZATION_MEMBERS_WRITE_SCOPE),
        )

    async def list_roles(self, options: AuthorizationPageOptions | None = None) -> RolePage:
        body = await self._request_json_with_scope(
            "GET",
            "/open/v1/roles" + _authorization_page_query(options or AuthorizationPageOptions()),
            cast(PortalOpenApiScope, ROLES_READ_SCOPE),
        )
        return _role_page(body)

    async def get_role(self, role_id: str) -> Role:
        response = await self._request_json_with_scope_response(
            "GET",
            _authorization_path("roles", role_id, "role"),
            cast(PortalOpenApiScope, ROLES_READ_SCOPE),
        )
        role = _role(response.body, _strong_etag(response.etag))
        return _require_authorization_identity(role, role.id, role_id)

    async def create_role(
        self, request: CreateRoleRequest, *, idempotency_key: str | None = None
    ) -> Role:
        response = await self._request_json_with_scope_response(
            "POST",
            "/open/v1/roles",
            cast(PortalOpenApiScope, ROLES_WRITE_SCOPE),
            json=request.to_json(),
            headers=_idempotency_headers(idempotency_key),
        )
        return _role(response.body, _strong_etag(response.etag))

    async def update_role(self, role_id: str, request: UpdateRoleRequest, *, if_match: str) -> Role:
        response = await self._request_json_with_scope_response(
            "PATCH",
            _authorization_path("roles", role_id, "role"),
            cast(PortalOpenApiScope, ROLES_WRITE_SCOPE),
            json=request.to_json(),
            headers=_required_if_match_headers(if_match),
        )
        role = _role(response.body, _strong_etag(response.etag))
        return _require_authorization_identity(role, role.id, role_id)

    async def delete_role(self, role_id: str, *, if_match: str) -> None:
        await self._request_json_with_scope(
            "DELETE",
            _authorization_path("roles", role_id, "role"),
            cast(PortalOpenApiScope, ROLES_WRITE_SCOPE),
            headers=_required_if_match_headers(if_match),
        )

    async def list_permissions(
        self, options: AuthorizationPageOptions | None = None
    ) -> PermissionPage:
        body = await self._request_json_with_scope(
            "GET",
            "/open/v1/permissions"
            + _authorization_page_query(options or AuthorizationPageOptions()),
            cast(PortalOpenApiScope, PERMISSIONS_READ_SCOPE),
        )
        return _permission_page(body)

    async def get_permission(self, permission_id: str) -> Permission:
        response = await self._request_json_with_scope_response(
            "GET",
            _authorization_path("permissions", permission_id, "permission"),
            cast(PortalOpenApiScope, PERMISSIONS_READ_SCOPE),
        )
        permission = _permission(response.body, _strong_etag(response.etag))
        return _require_authorization_identity(permission, permission.id, permission_id)

    async def create_permission(
        self, request: CreatePermissionRequest, *, idempotency_key: str | None = None
    ) -> Permission:
        _validate_permission_grant(request.resource, request.action)
        response = await self._request_json_with_scope_response(
            "POST",
            "/open/v1/permissions",
            cast(PortalOpenApiScope, PERMISSIONS_WRITE_SCOPE),
            json=request.to_json(),
            headers=_idempotency_headers(idempotency_key),
        )
        return _permission(response.body, _strong_etag(response.etag))

    async def update_permission(
        self, permission_id: str, request: UpdatePermissionRequest, *, if_match: str
    ) -> Permission:
        response = await self._request_json_with_scope_response(
            "PATCH",
            _authorization_path("permissions", permission_id, "permission"),
            cast(PortalOpenApiScope, PERMISSIONS_WRITE_SCOPE),
            json=request.to_json(),
            headers=_required_if_match_headers(if_match),
        )
        permission = _permission(response.body, _strong_etag(response.etag))
        return _require_authorization_identity(permission, permission.id, permission_id)

    async def delete_permission(self, permission_id: str, *, if_match: str) -> None:
        await self._request_json_with_scope(
            "DELETE",
            _authorization_path("permissions", permission_id, "permission"),
            cast(PortalOpenApiScope, PERMISSIONS_WRITE_SCOPE),
            headers=_required_if_match_headers(if_match),
        )

    async def list_role_permissions(
        self, role_id: str, options: AuthorizationPageOptions | None = None
    ) -> RolePermissionBindingPage:
        response = await self._request_json_with_scope_response(
            "GET",
            _authorization_path("roles", role_id, "role")
            + "/permissions"
            + _authorization_page_query(options or AuthorizationPageOptions()),
            cast(PortalOpenApiScope, ROLE_PERMISSIONS_READ_SCOPE),
        )
        page = _role_permission_page(response.body)
        if any(binding.role_id != role_id for binding in page.content):
            raise _invalid_authorization_response()
        return RolePermissionBindingPage(page.content, page.page, _strong_etag(response.etag))

    async def replace_role_permissions(
        self, role_id: str, permission_ids: tuple[str, ...], *, if_match: str
    ) -> RolePermissionSet:
        for permission_id in permission_ids:
            _authorization_id(permission_id, "permission")
        response = await self._request_json_with_scope_response(
            "PUT",
            _authorization_path("roles", role_id, "role") + "/permissions",
            cast(PortalOpenApiScope, ROLE_PERMISSIONS_WRITE_SCOPE),
            json={"permissionIds": list(permission_ids)},
            headers=_required_if_match_headers(if_match),
        )
        result = _role_permission_set(response.body, _strong_etag(response.etag))
        return _require_authorization_identity(result, result.role_id, role_id)

    async def list_user_roles(
        self, user_id: str, options: AuthorizationPageOptions | None = None
    ) -> UserRoleAssignmentPage:
        body = await self._request_json_with_scope(
            "GET",
            _user_role_path(user_id)
            + _authorization_page_query(options or AuthorizationPageOptions()),
            cast(PortalOpenApiScope, USER_ROLES_READ_SCOPE),
        )
        page = _user_role_page(body)
        if any(assignment.user_id != user_id for assignment in page.content):
            raise _invalid_authorization_response()
        return page

    async def create_user_role(
        self, user_id: str, request: CreateUserRoleRequest, *, idempotency_key: str | None = None
    ) -> UserRoleAssignment:
        _authorization_id(request.role_id, "role")
        response = await self._request_json_with_scope_response(
            "POST",
            _user_role_path(user_id),
            cast(PortalOpenApiScope, USER_ROLES_WRITE_SCOPE),
            json=request.to_json(),
            headers=_idempotency_headers(idempotency_key),
        )
        assignment = _user_role(response.body, _strong_etag(response.etag))
        if assignment.user_id != user_id or assignment.role_id != request.role_id:
            raise _invalid_authorization_response()
        return assignment

    async def update_user_role(
        self,
        user_id: str,
        assignment_id: str,
        condition: UserRoleCondition | None,
        *,
        if_match: str,
    ) -> UserRoleAssignment:
        response = await self._request_json_with_scope_response(
            "PATCH",
            _user_role_path(user_id) + "/" + _authorization_id(assignment_id, "assignment"),
            cast(PortalOpenApiScope, USER_ROLES_WRITE_SCOPE),
            json={"condition": None if condition is None else condition.to_json()},
            headers=_required_if_match_headers(if_match),
        )
        assignment = _user_role(response.body, _strong_etag(response.etag))
        if assignment.user_id != user_id or assignment.id != assignment_id:
            raise _invalid_authorization_response()
        return assignment

    async def delete_user_role(self, user_id: str, assignment_id: str, *, if_match: str) -> None:
        await self._request_json_with_scope(
            "DELETE",
            _user_role_path(user_id) + "/" + _authorization_id(assignment_id, "assignment"),
            cast(PortalOpenApiScope, USER_ROLES_WRITE_SCOPE),
            headers=_required_if_match_headers(if_match),
        )

    async def _registration_grant_lifecycle(self, grant_id: str, action: str) -> RegistrationGrant:
        body = await self._request_json_with_scope(
            "POST",
            _registration_grant_path(grant_id) + "/" + action,
            cast(PortalOpenApiScope, REGISTRATION_GRANTS_WRITE_SCOPE),
        )
        return _registration_grant(body)

    async def _request_json_with_scope(
        self,
        method: str,
        path: str,
        scope: PortalOpenApiScope,
        *,
        json: object = None,
        headers: Mapping[str, str] | None = None,
    ) -> Jsonish:
        return (
            await self._request_json_with_scope_response(
                method, path, scope, json=json, headers=headers
            )
        ).body

    async def _request_json_with_scope_response(
        self,
        method: str,
        path: str,
        scope: PortalOpenApiScope,
        *,
        json: object = None,
        headers: Mapping[str, str] | None = None,
    ) -> _PortalOpenApiResponse:
        normalized_method = self._normalize_method(method)
        self._normalize_scope(scope)
        url = self._portal_url(path)
        request_headers = self._portal_headers(headers)
        token = await self.get_machine_token(scope)
        request_headers["Authorization"] = f"Bearer {token.access_token}"
        if json is not None:
            request_headers["Content-Type"] = "application/json"
        try:
            response = await self._http.request(
                normalized_method,
                url,
                json=json,
                headers=request_headers,
            )
        except httpx.HTTPError as exc:
            raise PortalOpenApiTransportError(str(exc)) from exc
        if response.status_code >= 400:
            raise self._portal_error(response)
        if response.status_code == 204 or not response.content:
            return _PortalOpenApiResponse(None, response.headers.get("etag"))
        return _PortalOpenApiResponse(_parse_body(response), response.headers.get("etag"))

    async def get_machine_token(self, scope: str) -> PortalOpenApiMachineToken:
        """Return a cached or freshly requested machine token for an explicit scope."""

        typed_scope = self._normalize_scope(scope)
        cached = self._token_cache.get(typed_scope)
        if cached is not None and cached.expires_at > time.monotonic():
            return cached
        token = await self._request_machine_token(typed_scope)
        self._token_cache[typed_scope] = token
        return token

    def clear_token_cache(self, scope: str | None = None) -> None:
        """Clear cached read/write tokens, or only one scope when provided."""

        if scope is None:
            self._token_cache.clear()
            return
        self._token_cache.pop(self._normalize_scope(scope), None)

    async def close(self) -> None:
        """Close the underlying HTTP client when owned by this SDK."""

        if self._owns_http:
            await self._http.aclose()

    async def _request_machine_token(self, scope: PortalOpenApiScope) -> PortalOpenApiMachineToken:
        try:
            response = await self._http.post(
                f"{self.config.issuer}/oauth2/token",
                data={"grant_type": "client_credentials", "scope": scope},
                headers={"Accept": "application/json"},
                auth=(self.config.client_id, self.config.client_secret),
            )
        except httpx.HTTPError as exc:
            raise PortalOpenApiTransportError(str(exc)) from exc
        body = _parse_body(response)
        if response.status_code >= 400:
            raise PortalOpenApiTokenError(
                _extract_message(body)
                or _extract_code(body)
                or f"Token request failed with HTTP {response.status_code}",
                _extract_code(body) or "token_request_failed",
                status_code=response.status_code,
                body=body,
            )
        if not isinstance(body, dict):
            raise PortalOpenApiTokenError(
                "Token response is not a JSON object",
                "invalid_token_response",
                status_code=response.status_code,
                body=body,
            )
        access_token = body.get("access_token")
        token_type = body.get("token_type")
        expires_in = body.get("expires_in")
        if not isinstance(access_token, str) or not access_token.strip():
            raise PortalOpenApiTokenError(
                "Token response is missing access_token",
                "missing_bearer_token",
                status_code=response.status_code,
                body=body,
            )
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise PortalOpenApiTokenError(
                "Token response is missing bearer token_type",
                "missing_bearer_token",
                status_code=response.status_code,
                body=body,
            )
        if not isinstance(expires_in, int | float) or expires_in <= 0:
            raise PortalOpenApiTokenError(
                "Token response is missing positive expires_in",
                "invalid_token_response",
                status_code=response.status_code,
                body=body,
            )
        response_scope = body.get("scope")
        response_scopes = (
            {item for item in response_scope.split() if item}
            if isinstance(response_scope, str)
            else {scope}
        )
        if scope not in response_scopes:
            raise PortalOpenApiTokenError(
                f"Token response does not include requested scope {scope}",
                "invalid_scope",
                status_code=response.status_code,
                body=body,
            )
        ttl = max(float(expires_in) - self.config.token_skew_seconds, 0.0)
        return PortalOpenApiMachineToken(
            access_token=access_token,
            scope=scope,
            expires_at=time.monotonic() + ttl,
        )

    def _portal_headers(self, headers: Mapping[str, str] | None) -> dict[str, str]:
        request_headers = {"Accept": "application/json"}
        if headers is None:
            return request_headers
        for key, value in headers.items():
            lowered = key.lower()
            if lowered in _FORBIDDEN_PORTAL_HEADERS:
                raise PortalOpenApiError(
                    f"Portal Open API header is managed by the SDK: {key}",
                    0,
                    "invalid_portal_header",
                    body={"header": key},
                )
            request_headers[key] = value
        return request_headers

    def _portal_url(self, path: str) -> str:
        if not path.startswith("/open/v1/"):
            raise PortalOpenApiError(
                "Portal Open API path must start with /open/v1/",
                0,
                "invalid_portal_path",
                body={"path": path},
            )
        return f"{self.config.portal_endpoint}{path}"

    def _normalize_method(self, method: str) -> PortalOpenApiMethod:
        value = method.upper()
        if value not in _SUPPORTED_METHODS:
            raise PortalOpenApiError(
                f"Unsupported Portal Open API method: {method}",
                0,
                "invalid_portal_method",
                body={"method": method},
            )
        return value  # type: ignore[return-value]

    def _normalize_scope(self, scope: str) -> PortalOpenApiScope:
        if not scope:
            raise PortalOpenApiTokenError(
                "Portal Open API token requests require an explicit scope",
                "invalid_scope",
            )
        if scope not in _SUPPORTED_SCOPES:
            raise PortalOpenApiTokenError(
                f"Unsupported Portal Open API scope: {scope}",
                "invalid_scope",
            )
        return scope  # type: ignore[return-value]

    def _portal_error(self, response: httpx.Response) -> PortalOpenApiError:
        body = _parse_body(response)
        code = _extract_code(body) or f"HTTP_{response.status_code}"
        message = (
            code
            if code in _PORTAL_ERROR_CODES
            else _extract_message(body)
            or f"Portal Open API request failed with HTTP {response.status_code}"
        )
        return PortalOpenApiError(
            message,
            response.status_code,
            code,
            body=body,
            retry_after=response.headers.get("retry-after"),
        )


def _scope_for_method(method: PortalOpenApiMethod) -> PortalOpenApiScope:
    if method == "GET":
        return cast(PortalOpenApiScope, PORTAL_OPEN_API_READ_SCOPE)
    return cast(PortalOpenApiScope, PORTAL_OPEN_API_WRITE_SCOPE)


def _registration_grant_path(grant_id: str) -> str:
    try:
        parsed = UUID(grant_id)
        if str(parsed) != grant_id:
            raise ValueError("Registration grant id must be canonical")
        return f"/open/v1/registration-grants/{parsed}"
    except (TypeError, ValueError) as exc:
        raise PortalOpenApiError(
            "Registration grant id must be a UUID", 0, "invalid_registration_grant_id"
        ) from exc


def _organization_path(organization_id: str) -> str:
    return f"/open/v1/organizations/{_organization_id_segment(organization_id, 'organization')}"


def _organization_invitation_path(organization_id: str, invitation_id: str) -> str:
    return (
        _organization_path(organization_id)
        + f"/invitations/{_organization_id_segment(invitation_id, 'invitation')}"
    )


def _organization_member_path(organization_id: str, membership_id: str) -> str:
    return (
        _organization_path(organization_id)
        + f"/members/{_organization_id_segment(membership_id, 'membership')}"
    )


def _organization_id_segment(value: str, resource: str) -> str:
    try:
        parsed = UUID(value)
        if str(parsed) != value:
            raise ValueError(f"{resource} id must be canonical")
        return str(parsed)
    except (TypeError, ValueError) as exc:
        raise PortalOpenApiError(
            f"{resource.capitalize()} id must be a UUID", 0, f"invalid_{resource}_id"
        ) from exc


def _registration_grant_query(options: RegistrationGrantListOptions) -> str:
    values: list[tuple[str, str | int | float | bool | None]] = []
    for key, value in (
        ("type", options.type),
        ("status", options.status),
        ("search", options.search),
        ("page", options.page),
        ("size", options.size),
    ):
        if value is not None:
            values.append((key, str(value)))
    return "?" + str(httpx.QueryParams(values)) if values else ""


def _page_query(page: int | None, size: int | None) -> str:
    values: list[tuple[str, str | int | float | bool | None]] = [
        (key, str(value)) for key, value in (("page", page), ("size", size)) if value is not None
    ]
    return "?" + str(httpx.QueryParams(values)) if values else ""


def _organization_query(options: OrganizationListOptions) -> str:
    values: list[tuple[str, str | int | float | bool | None]] = []
    for key, value in (("search", options.search), ("page", options.page), ("size", options.size)):
        if value is not None:
            values.append((key, str(value)))
    values.extend(("sort", value) for value in options.sort)
    values.extend(("direction", value) for value in options.direction)
    return "?" + str(httpx.QueryParams(values)) if values else ""


def _organization_invitation_query(options: OrganizationInvitationListOptions) -> str:
    values: list[tuple[str, str | int | float | bool | None]] = []
    for key, value in (("status", options.status), ("page", options.page), ("size", options.size)):
        if value is not None:
            values.append((key, str(value)))
    return "?" + str(httpx.QueryParams(values)) if values else ""


def _organization_member_query(options: OrganizationMemberListOptions) -> str:
    values: list[tuple[str, str | int | float | bool | None]] = []
    for key, value in (("search", options.search), ("page", options.page), ("size", options.size)):
        if value is not None:
            values.append((key, str(value)))
    return "?" + str(httpx.QueryParams(values)) if values else ""


def _idempotency_headers(idempotency_key: str | None) -> Mapping[str, str] | None:
    return None if idempotency_key is None else {"Idempotency-Key": idempotency_key}


def _if_match_headers(if_match: str | None) -> Mapping[str, str] | None:
    return None if if_match is None else {"If-Match": if_match}


def _mapping(body: object) -> Mapping[str, object]:
    if not isinstance(body, Mapping):
        raise _invalid_registration_grant_response()
    return cast(Mapping[str, object], body)


def _required_string(payload: Mapping[str, object], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise _invalid_registration_grant_response()
    return value


def _optional_string(payload: Mapping[str, object], field: str) -> str | None:
    value = payload.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise _invalid_registration_grant_response()
    return value


def _registration_grant(body: object) -> RegistrationGrant:
    payload = _mapping(body)
    grant_type = _required_string(payload, "type")
    status = _required_string(payload, "status")
    if grant_type not in ("EMAIL_LINK", "ACCESS_CODE", "ORG_INVITATION") or status not in (
        "ACTIVE",
        "PAUSED",
        "REDEEMED",
        "EXPIRED",
        "REVOKED",
    ):
        raise _invalid_registration_grant_response()
    max_uses = payload.get("maxUses")
    if max_uses is not None and (not isinstance(max_uses, int) or isinstance(max_uses, bool)):
        raise _invalid_registration_grant_response()
    used_count = payload.get("usedCount")
    if not isinstance(used_count, int) or isinstance(used_count, bool):
        raise _invalid_registration_grant_response()
    version = payload.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 0:
        raise _invalid_registration_grant_response()
    return RegistrationGrant(
        id=_required_string(payload, "id"),
        version=version,
        type=cast(RegistrationGrantType, grant_type),
        status=cast(RegistrationGrantStatus, status),
        display_name=_optional_string(payload, "displayName"),
        allowed_email=_optional_string(payload, "allowedEmail"),
        allowed_domain=_optional_string(payload, "allowedDomain"),
        expires_at=_optional_string(payload, "expiresAt"),
        max_uses=max_uses,
        used_count=used_count,
        source_type=_required_string(payload, "sourceType"),
        created_at=_required_string(payload, "createdAt"),
        updated_at=_required_string(payload, "updatedAt"),
        revoked_at=_optional_string(payload, "revokedAt"),
        revoke_reason=_optional_string(payload, "revokeReason"),
    )


def _created_registration_grant(body: object) -> CreatedRegistrationGrant:
    payload = _mapping(body)
    grant = _registration_grant(payload.get("grant"))
    token = _optional_string(payload, "registrationGrantToken")
    code = _optional_string(payload, "registrationAccessCode")
    url = _optional_string(payload, "registrationInvitationUrl")
    issued = payload.get("secretAlreadyIssued")
    if (
        not isinstance(issued, bool)
        or grant.type not in ("EMAIL_LINK", "ACCESS_CODE")
        or (issued and (token is not None or code is not None or url is not None))
        or (
            not issued and grant.type == "EMAIL_LINK" and (not token or not url or code is not None)
        )
        or (
            not issued
            and grant.type == "ACCESS_CODE"
            and (not code or token is not None or url is not None)
        )
    ):
        raise _invalid_registration_grant_response()
    if url is not None:
        try:
            parsed = urlsplit(url)
        except ValueError:
            raise _invalid_registration_grant_response() from None
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.fragment
        ):
            raise _invalid_registration_grant_response()
    return CreatedRegistrationGrant(grant, token, code, url, issued)


def _registration_command_headers(key: str) -> Mapping[str, str]:
    if not key.strip() or len(key) > 200 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in key):
        raise ValueError("Idempotency-Key must contain 1 to 200 printable characters")
    return {"Idempotency-Key": key}


def _registration_grant_delivery(body: object) -> RegistrationGrantDelivery:
    p = _mapping(body)
    variant, status = p.get("variant"), p.get("status")
    count, maximum, retryable = p.get("attemptCount"), p.get("maxAttempts"), p.get("retryable")
    if (
        not isinstance(variant, str)
        or variant not in {"LINK", "CODE"}
        or not isinstance(status, str)
        or status not in {"QUEUED", "SENDING", "DELIVERED", "FAILED", "UNKNOWN"}
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count < 0
        or (
            maximum is not None
            and (not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1)
        )
        or not isinstance(retryable, bool)
    ):
        raise _invalid_registration_grant_response()
    return RegistrationGrantDelivery(
        id=_required_string(p, "id"),
        grant_id=_required_string(p, "grantId"),
        recipient=_required_string(p, "recipient"),
        variant=cast(Literal["LINK", "CODE"], variant),
        status=cast(Literal["QUEUED", "SENDING", "DELIVERED", "FAILED", "UNKNOWN"], status),
        failure_code=_optional_string(p, "failureCode"),
        attempt_count=count,
        max_attempts=maximum,
        next_attempt_at=_optional_string(p, "nextAttemptAt"),
        retryable=retryable,
        expires_at=_required_string(p, "expiresAt"),
        created_at=_required_string(p, "createdAt"),
    )


def _page_metadata(body: object) -> RegistrationGrantPageMetadata:
    payload = _mapping(body)
    values = [payload.get(key) for key in ("size", "number", "totalElements", "totalPages")]
    if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
        raise _invalid_registration_grant_response()
    return RegistrationGrantPageMetadata(*cast(tuple[int, int, int, int], tuple(values)))


def _registration_grant_page(body: object) -> RegistrationGrantPage:
    payload = _mapping(body)
    content = payload.get("content")
    if not isinstance(content, list):
        raise _invalid_registration_grant_response()
    return RegistrationGrantPage(
        tuple(_registration_grant(item) for item in content),
        _page_metadata(payload.get("page")),
    )


def _registration_grant_redemption(body: object) -> RegistrationGrantRedemption:
    payload = _mapping(body)
    return RegistrationGrantRedemption(
        id=_required_string(payload, "id"),
        result=_required_string(payload, "result"),
        email=_optional_string(payload, "email"),
        auth_method=_optional_string(payload, "authMethod"),
        idp_id=_optional_string(payload, "idpId"),
        client_id=_optional_string(payload, "clientId"),
        redeemed_at=_required_string(payload, "redeemedAt"),
        failure_reason=_optional_string(payload, "failureReason"),
    )


def _registration_grant_redemption_page(body: object) -> RegistrationGrantRedemptionPage:
    payload = _mapping(body)
    content = payload.get("content")
    if not isinstance(content, list):
        raise _invalid_registration_grant_response()
    return RegistrationGrantRedemptionPage(
        tuple(_registration_grant_redemption(item) for item in content),
        _page_metadata(payload.get("page")),
    )


def _invalid_registration_grant_response() -> PortalOpenApiError:
    return PortalOpenApiError(
        "Invalid registration grant response", 0, "invalid_registration_grant_response"
    )


def _organization_mapping(body: object) -> Mapping[str, object]:
    if not isinstance(body, Mapping):
        raise _invalid_organization_response()
    return cast(Mapping[str, object], body)


def _organization_required_string(payload: Mapping[str, object], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise _invalid_organization_response()
    return value


def _organization_required_int(payload: Mapping[str, object], field: str) -> int:
    value = payload.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise _invalid_organization_response()
    return value


def _organization_page_metadata(body: object) -> OrganizationPageMetadata:
    payload = _organization_mapping(body)
    return OrganizationPageMetadata(
        _organization_required_int(payload, "size"),
        _organization_required_int(payload, "number"),
        _organization_required_int(payload, "totalElements"),
        _organization_required_int(payload, "totalPages"),
    )


def _organization(body: object, *, etag: str | None = None) -> Organization:
    payload = _organization_mapping(body)
    return Organization(
        id=_organization_required_string(payload, "id"),
        name=_organization_required_string(payload, "name"),
        slug=_organization_required_string(payload, "slug"),
        version=_organization_required_int(payload, "version"),
        created_at=_organization_required_string(payload, "createdAt"),
        updated_at=_organization_required_string(payload, "updatedAt"),
        etag=etag,
    )


def _organization_page(body: object) -> OrganizationPage:
    payload = _organization_mapping(body)
    content = payload.get("content")
    if not isinstance(content, list):
        raise _invalid_organization_response()
    return OrganizationPage(
        tuple(_organization(item) for item in content),
        _organization_page_metadata(payload.get("page")),
    )


def _organization_invitation(body: object) -> OrganizationInvitation:
    payload = _organization_mapping(body)
    role = _organization_required_string(payload, "role")
    status = _organization_required_string(payload, "status")
    delivery_status = _organization_required_string(payload, "deliveryStatus")
    if (
        role not in ("OWNER", "ADMIN", "MEMBER")
        or status
        not in (
            "PENDING",
            "ACCEPTED",
            "CANCELLED",
            "EXPIRED",
        )
        or delivery_status not in ("NOT_REQUESTED", "SENT", "FAILED")
    ):
        raise _invalid_organization_response()
    return OrganizationInvitation(
        id=_organization_required_string(payload, "id"),
        email=_organization_required_string(payload, "email"),
        role=cast(OrganizationMemberRole, role),
        status=cast(OrganizationInvitationStatus, status),
        delivery_status=cast(OrganizationInvitationDeliveryStatus, delivery_status),
        expires_at=_organization_required_string(payload, "expiresAt"),
        created_at=_organization_required_string(payload, "createdAt"),
        updated_at=_organization_required_string(payload, "updatedAt"),
    )


def _organization_invitation_page(body: object) -> OrganizationInvitationPage:
    payload = _organization_mapping(body)
    content = payload.get("content")
    if not isinstance(content, list):
        raise _invalid_organization_response()
    return OrganizationInvitationPage(
        tuple(_organization_invitation(item) for item in content),
        _organization_page_metadata(payload.get("page")),
    )


def _organization_member(body: object) -> OrganizationMember:
    payload = _organization_mapping(body)
    role = _organization_required_string(payload, "role")
    if role not in ("OWNER", "ADMIN", "MEMBER"):
        raise _invalid_organization_response()
    return OrganizationMember(
        membership_id=_organization_required_string(payload, "membershipId"),
        user_id=_organization_required_string(payload, "userId"),
        email=_organization_required_string(payload, "email"),
        display_name=_organization_required_string(payload, "displayName"),
        role=cast(OrganizationMemberRole, role),
        joined_at=_organization_required_string(payload, "joinedAt"),
        updated_at=_organization_required_string(payload, "updatedAt"),
        version=_organization_required_int(payload, "version"),
    )


def _organization_member_page(body: object) -> OrganizationMemberPage:
    payload = _organization_mapping(body)
    content = payload.get("content")
    if not isinstance(content, list):
        raise _invalid_organization_response()
    return OrganizationMemberPage(
        tuple(_organization_member(item) for item in content),
        _organization_page_metadata(payload.get("page")),
    )


def _invalid_organization_response() -> PortalOpenApiError:
    return PortalOpenApiError(
        "Invalid organization management response", 0, "invalid_organization_response"
    )


def _invalid_authorization_response(
    message: str = "Invalid authorization management response",
) -> PortalOpenApiError:
    return PortalOpenApiError(message, 0, "invalid_authorization_response")


def _authorization_page_query(options: AuthorizationPageOptions) -> str:
    if options.page < 0 or options.size < 1 or options.size > 100:
        raise _invalid_authorization_response(
            "page must be non-negative and size must be between 1 and 100"
        )
    return f"?page={options.page}&size={options.size}"


def _authorization_id(value: str, resource: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise PortalOpenApiError(
            f"{resource} id must be a UUID", 0, f"invalid_{resource}_id"
        ) from exc
    if str(parsed) != value:
        raise PortalOpenApiError(f"{resource} id must be a UUID", 0, f"invalid_{resource}_id")
    return value


def _authorization_path(collection: str, value: str, resource: str) -> str:
    return f"/open/v1/{collection}/{_authorization_id(value, resource)}"


def _user_role_path(user_id: str) -> str:
    return f"/open/v1/users/{_authorization_id(user_id, 'user')}/roles"


def _strong_etag(value: str | None) -> str:
    if value is None or re.fullmatch(r'"[0-9]+"', value) is None:
        raise _invalid_authorization_response("Missing or malformed strong ETag")
    return value


def _required_if_match_headers(value: str) -> Mapping[str, str]:
    return {"If-Match": _strong_etag(value)}


def _authorization_int(payload: Mapping[str, object], field: str) -> int:
    value = payload.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _invalid_authorization_response()
    return value


def _authorization_string(payload: Mapping[str, object], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise _invalid_authorization_response()
    return value


def _authorization_nullable_string(payload: Mapping[str, object], field: str) -> str | None:
    value = payload.get(field)
    if value is not None and not isinstance(value, str):
        raise _invalid_authorization_response()
    return value


def _authorization_mapping(body: object) -> Mapping[str, object]:
    if not isinstance(body, Mapping):
        raise _invalid_authorization_response()
    return cast(Mapping[str, object], body)


def _require_authorization_identity[T](value: T, actual: str, expected: str) -> T:
    if actual != expected:
        raise _invalid_authorization_response()
    return value


def _is_canonical_authorization_uuid(value: str) -> bool:
    if (
        re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            value,
        )
        is None
    ):
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def _authorization_uuid(payload: Mapping[str, object], field: str) -> str:
    value = _authorization_string(payload, field)
    if not _is_canonical_authorization_uuid(value):
        raise _invalid_authorization_response()
    return value


def _authorization_timestamp(payload: Mapping[str, object], field: str) -> str:
    value = _authorization_string(payload, field)
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", value) is None:
        raise _invalid_authorization_response()
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _invalid_authorization_response() from exc
    return value


def _authorization_page_metadata(body: object, content_length: int) -> AuthorizationPageMetadata:
    payload = _authorization_mapping(body)
    page = AuthorizationPageMetadata(
        _authorization_int(payload, "size"),
        _authorization_int(payload, "number"),
        _authorization_int(payload, "totalElements"),
        _authorization_int(payload, "totalPages"),
    )
    expected_pages = (page.total_elements + page.size - 1) // page.size if page.size else -1
    expected_content = (
        0
        if page.total_elements == 0
        else min(page.size, page.total_elements - page.number * page.size)
    )
    if (
        page.size < 1
        or page.size > 100
        or content_length > page.size
        or content_length > page.total_elements
        or page.total_pages != expected_pages
        or (page.number != 0 if page.total_elements == 0 else page.number >= page.total_pages)
        or content_length != expected_content
    ):
        raise _invalid_authorization_response()
    return page


def _role(body: object, etag: str = "") -> Role:
    p = _authorization_mapping(body)
    system = p.get("system")
    if not isinstance(system, bool):
        raise _invalid_authorization_response()
    return Role(
        _authorization_uuid(p, "id"),
        _authorization_string(p, "key"),
        _authorization_string(p, "name"),
        _authorization_nullable_string(p, "description"),
        system,
        _authorization_int(p, "version"),
        _authorization_timestamp(p, "createdAt"),
        _authorization_timestamp(p, "updatedAt"),
        etag,
    )


def _role_page(body: object) -> RolePage:
    p = _authorization_mapping(body)
    content = p.get("content")
    if not isinstance(content, list):
        raise _invalid_authorization_response()
    return RolePage(
        tuple(_role(item) for item in content),
        _authorization_page_metadata(p.get("page"), len(content)),
    )


def _validate_permission_grant(resource: str, action: str) -> None:
    segment = re.compile(r"^(?:\*|[a-z0-9_-]{1,128})$")
    if (
        segment.fullmatch(resource) is None
        or segment.fullmatch(action) is None
        or (resource == "*" and action != "*")
    ):
        raise PortalOpenApiError("Invalid permission grant", 0, "invalid_permission_key")


def _permission(body: object, etag: str = "") -> Permission:
    p = _authorization_mapping(body)
    resource = _authorization_string(p, "resource")
    action = _authorization_string(p, "action")
    try:
        _validate_permission_grant(resource, action)
    except PortalOpenApiError as exc:
        raise _invalid_authorization_response() from exc
    key = _authorization_string(p, "key")
    if key != f"{resource}:{action}":
        raise _invalid_authorization_response()
    source = _authorization_string(p, "source")
    if source not in {"CODE", "MANUAL"}:
        raise _invalid_authorization_response()
    return Permission(
        _authorization_uuid(p, "id"),
        resource,
        action,
        key,
        _authorization_string(p, "name"),
        _authorization_nullable_string(p, "description"),
        cast(Literal["CODE", "MANUAL"], source),
        _authorization_int(p, "version"),
        _authorization_timestamp(p, "createdAt"),
        _authorization_timestamp(p, "updatedAt"),
        etag,
    )


def _permission_page(body: object) -> PermissionPage:
    p = _authorization_mapping(body)
    content = p.get("content")
    if not isinstance(content, list):
        raise _invalid_authorization_response()
    return PermissionPage(
        tuple(_permission(item) for item in content),
        _authorization_page_metadata(p.get("page"), len(content)),
    )


def _role_permission_page(body: object) -> RolePermissionBindingPage:
    p = _authorization_mapping(body)
    content = p.get("content")
    if not isinstance(content, list):
        raise _invalid_authorization_response()
    items = []
    for item in content:
        row = _authorization_mapping(item)
        items.append(
            RolePermissionBinding(
                _authorization_uuid(row, "roleId"),
                _authorization_uuid(row, "permissionId"),
                _authorization_timestamp(row, "createdAt"),
            )
        )
    return RolePermissionBindingPage(
        tuple(items), _authorization_page_metadata(p.get("page"), len(content)), ""
    )


def _role_permission_set(body: object, etag: str) -> RolePermissionSet:
    p = _authorization_mapping(body)
    ids = p.get("permissionIds")
    if not isinstance(ids, list) or any(not isinstance(item, str) for item in ids):
        raise _invalid_authorization_response()
    typed_ids = tuple(cast(list[str], ids))
    if any(not _is_canonical_authorization_uuid(item) for item in typed_ids):
        raise _invalid_authorization_response()
    return RolePermissionSet(
        _authorization_uuid(p, "roleId"),
        typed_ids,
        _authorization_int(p, "version"),
        etag,
    )


def _user_role(body: object, etag: str = "") -> UserRoleAssignment:
    p = _authorization_mapping(body)
    organization_id = _authorization_nullable_string(p, "organizationId")
    if organization_id is not None and not _is_canonical_authorization_uuid(organization_id):
        raise _invalid_authorization_response()
    return UserRoleAssignment(
        _authorization_uuid(p, "id"),
        _authorization_uuid(p, "userId"),
        _authorization_uuid(p, "roleId"),
        organization_id,
        _authorization_nullable_string(p, "conditionExpression"),
        _authorization_nullable_string(p, "conditionDescription"),
        _authorization_int(p, "version"),
        _authorization_timestamp(p, "createdAt"),
        _authorization_timestamp(p, "updatedAt"),
        etag,
    )


def _user_role_page(body: object) -> UserRoleAssignmentPage:
    p = _authorization_mapping(body)
    content = p.get("content")
    if not isinstance(content, list):
        raise _invalid_authorization_response()
    return UserRoleAssignmentPage(
        tuple(_user_role(item) for item in content),
        _authorization_page_metadata(p.get("page"), len(content)),
    )


def _parse_body(response: httpx.Response) -> Jsonish:
    if not response.content:
        return None
    try:
        parsed = response.json()
        if isinstance(parsed, dict | list | str | int | float | bool) or parsed is None:
            return parsed
        return None
    except ValueError:
        pass
    return response.text


def _extract_code(body: object) -> str | None:
    if not isinstance(body, dict):
        return None
    for key in ("code", "error", "errorCode"):
        value = body.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _extract_message(body: object) -> str | None:
    if isinstance(body, str) and body:
        return body
    if not isinstance(body, dict):
        return None
    for key in ("message", "error_description", "error"):
        value = body.get(key)
        if isinstance(value, str) and value:
            return value
    return None
