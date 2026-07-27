"""Profile and account-center DTOs for explicit current-user IAM calls."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


@dataclass(frozen=True, slots=True)
class AccountOrganization:
    """Current user's Application-scoped Organization membership."""

    organization_id: str
    name: str
    slug: str | None
    role: str | None
    joined_at: str | None
    current: bool

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> AccountOrganization:
        """Parse an Organization membership response."""

        return cls(
            organization_id=_string(data.get("organizationId")) or "",
            name=_string(data.get("name")) or "",
            slug=_string(data.get("slug")),
            role=_string(data.get("role")),
            joined_at=_string(data.get("joinedAt")),
            current=bool(data.get("current")),
        )


@dataclass(frozen=True, slots=True)
class UserProfile:
    """Current-user profile returned by IAM.

    ``metadata`` is profile metadata for display/profile reads. It is not App
    User authorization attributes and must not be used as an authorization
    source.
    """

    user_id: str
    application_id: str | None
    global_identity_id: str | None
    id: str
    email: str | None
    email_verified: bool
    username: str | None
    display_name: str | None
    avatar_url: str | None
    status: str | None
    created_at: str | None
    updated_at: str | None
    current_organization: AccountOrganization | None
    roles: tuple[str, ...]
    metadata: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> UserProfile:
        """Parse a profile response."""

        roles = data.get("roles")
        metadata = data.get("metadata")
        current_organization = data.get("currentOrganization")
        user_id = _string(data.get("userId")) or _string(data.get("id")) or ""
        return cls(
            user_id=user_id,
            application_id=_string(data.get("applicationId")),
            global_identity_id=_string(data.get("globalIdentityId")),
            id=user_id,
            email=_string(data.get("email")),
            email_verified=bool(data.get("emailVerified")),
            username=_string(data.get("username")),
            display_name=_string(data.get("displayName")),
            avatar_url=_string(data.get("avatarUrl")),
            status=_string(data.get("status")),
            created_at=_string(data.get("createdAt")),
            updated_at=_string(data.get("updatedAt")),
            current_organization=AccountOrganization.from_mapping(current_organization)
            if isinstance(current_organization, Mapping)
            else None,
            roles=tuple(item for item in roles if isinstance(item, str))
            if isinstance(roles, list | tuple)
            else (),
            metadata=MappingProxyType(dict(metadata))
            if isinstance(metadata, Mapping)
            else MappingProxyType({}),
        )


@dataclass(frozen=True, slots=True)
class AccountSecuritySummary:
    """Secret-free current-user security summary."""

    email_verified: bool
    password_credential_present: bool
    mfa_enrolled: bool
    totp_enrolled: bool
    web_authn_enrolled: bool
    active_session_count: int

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> AccountSecuritySummary:
        """Parse a security summary response."""

        count = data.get("activeSessionCount")
        return cls(
            email_verified=bool(data.get("emailVerified")),
            password_credential_present=bool(data.get("passwordCredentialPresent")),
            mfa_enrolled=bool(data.get("mfaEnrolled")),
            totp_enrolled=bool(data.get("totpEnrolled")),
            web_authn_enrolled=bool(data.get("webAuthnEnrolled")),
            active_session_count=count if isinstance(count, int) else 0,
        )


@dataclass(frozen=True, slots=True)
class EmailVerificationResponse:
    """Public email verification send/verify response."""

    message: str
    retry_after_seconds: int | None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> EmailVerificationResponse:
        """Parse an email verification response."""

        retry_after = data.get("retryAfterSeconds")
        return cls(
            message=_string(data.get("message")) or "",
            retry_after_seconds=retry_after if isinstance(retry_after, int) else None,
        )


@dataclass(frozen=True, slots=True)
class SessionView:
    """Current-user session/device view."""

    session_id: str
    ip_address: str | None
    user_agent: str | None
    device_id: str | None
    created_at: str | None
    last_seen_at: str | None
    current: bool

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> SessionView:
        """Parse a session view response."""

        return cls(
            session_id=_string(data.get("sessionId")) or "",
            ip_address=_string(data.get("ipAddress")),
            user_agent=_string(data.get("userAgent")),
            device_id=_string(data.get("deviceId")),
            created_at=_string(data.get("createdAt")),
            last_seen_at=_string(data.get("lastSeenAt")),
            current=bool(data.get("current")),
        )


@dataclass(frozen=True, slots=True)
class AccountPermissionSummary:
    """Current-user permission summary resolved by IAM."""

    application_id: str
    organization_id: str | None
    roles: tuple[str, ...]
    permissions: tuple[str, ...]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> AccountPermissionSummary:
        """Parse a permission summary response."""

        roles = data.get("roles")
        permissions = data.get("permissions")
        return cls(
            application_id=_string(data.get("applicationId")) or "",
            organization_id=_string(data.get("organizationId")),
            roles=tuple(item for item in roles if isinstance(item, str))
            if isinstance(roles, list | tuple)
            else (),
            permissions=tuple(item for item in permissions if isinstance(item, str))
            if isinstance(permissions, list | tuple)
            else (),
        )


@dataclass(frozen=True, slots=True)
class PermissionCheckResponse:
    """Current-user permission check result returned by IAM."""

    application_id: str
    organization_id: str | None
    permission: str
    allowed: bool
    roles: tuple[str, ...]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> PermissionCheckResponse:
        """Parse a permission check response."""

        roles = data.get("roles")
        return cls(
            application_id=_string(data.get("applicationId")) or "",
            organization_id=_string(data.get("organizationId")),
            permission=_string(data.get("permission")) or "",
            allowed=bool(data.get("allowed")),
            roles=tuple(item for item in roles if isinstance(item, str))
            if isinstance(roles, list | tuple)
            else (),
        )


@dataclass(frozen=True, slots=True)
class OrganizationSwitchResponse:
    """Current Organization switch continuation response."""

    organization_id: str
    continuation: str | None
    token_refresh_required: bool
    message: str | None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> OrganizationSwitchResponse:
        """Parse an Organization switch response."""

        return cls(
            organization_id=_string(data.get("organizationId")) or "",
            continuation=_string(data.get("continuation")),
            token_refresh_required=bool(data.get("tokenRefreshRequired")),
            message=_string(data.get("message")),
        )


@dataclass(frozen=True, slots=True)
class PublicOrganizationInvitationPreview:
    """Safe public Organization invitation preview."""

    application_id: str
    application_name: str | None
    organization_id: str
    organization_name: str
    invitee_email: str | None
    role: str | None
    status: str | None
    expires_at: str | None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> PublicOrganizationInvitationPreview:
        """Parse an invitation preview response."""

        return cls(
            application_id=_string(data.get("applicationId")) or "",
            application_name=_string(data.get("applicationName")),
            organization_id=_string(data.get("organizationId")) or "",
            organization_name=_string(data.get("organizationName")) or "",
            invitee_email=_string(data.get("inviteeEmail")),
            role=_string(data.get("role")),
            status=_string(data.get("status")),
            expires_at=_string(data.get("expiresAt")),
        )


@dataclass(frozen=True, slots=True)
class PublicOrganizationInvitationAcceptResponse:
    """Organization invitation accept result or login-required continuation."""

    status: str
    continuation: str | None
    application_id: str
    organization_id: str
    organization_name: str
    role: str | None
    accepted_at: str | None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> PublicOrganizationInvitationAcceptResponse:
        """Parse an invitation accept response."""

        return cls(
            status=_string(data.get("status")) or "",
            continuation=_string(data.get("continuation")),
            application_id=_string(data.get("applicationId")) or "",
            organization_id=_string(data.get("organizationId")) or "",
            organization_name=_string(data.get("organizationName")) or "",
            role=_string(data.get("role")),
            accepted_at=_string(data.get("acceptedAt")),
        )


def _string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None
