"""Request-local IAM user context."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .claims import Actor, IamClaims
from .permissions import PermissionKey, has_permission


@dataclass(frozen=True, slots=True)
class IamUser:
    """Authenticated user derived from verified JWT claims and resolved permissions."""

    user_id: str
    application_id: str | None
    email: str | None
    email_verified: bool
    username: str | None
    organization_id: str | None
    organization_slug: str | None
    organization_role: str | None
    workspace_id: str | None
    session_id: str | None
    roles: frozenset[str]
    permissions: frozenset[str]
    authentication_methods: tuple[str, ...]
    authentication_context_class: str | None
    actor: Actor | None
    claims: Mapping[str, Any]

    @classmethod
    def from_claims(cls, claims: IamClaims, permissions: frozenset[str]) -> IamUser:
        """Build a user value object from claims and resolved permissions."""

        return cls(
            user_id=claims.subject,
            application_id=claims.application_id,
            email=claims.email,
            email_verified=claims.email_verified,
            username=claims.username,
            organization_id=claims.organization_id,
            organization_slug=claims.organization_slug,
            organization_role=claims.organization_role,
            workspace_id=claims.workspace_id,
            session_id=claims.session_id,
            roles=claims.roles,
            permissions=permissions,
            authentication_methods=claims.authentication_methods,
            authentication_context_class=claims.authentication_context_class,
            actor=claims.actor,
            claims=MappingProxyType(dict(claims.claims)),
        )

    def has_permission(self, resource: str, action: str) -> bool:
        """Return whether the user has ``resource:action``."""

        return has_permission(PermissionKey(resource, action), self.permissions)

    def has_mfa(self) -> bool:
        """Return whether the authentication methods include an MFA factor."""

        return any(
            method in {"mfa", "totp", "webauthn", "pwd+mfa"}
            for method in self.authentication_methods
        )

    def is_impersonating(self) -> bool:
        """Return whether this token carries a delegating actor."""

        return self.actor is not None and bool(self.actor.subject.strip())


@dataclass(frozen=True, slots=True)
class IamContext:
    """Request-local IAM context exposed to framework integrations."""

    user: IamUser
    access_token: str | None = None

    @property
    def user_id(self) -> str:
        return self.user.user_id

    @property
    def application_id(self) -> str | None:
        return self.user.application_id

    @property
    def email(self) -> str | None:
        return self.user.email

    @property
    def email_verified(self) -> bool:
        return self.user.email_verified

    @property
    def username(self) -> str | None:
        return self.user.username

    @property
    def organization_id(self) -> str | None:
        return self.user.organization_id

    @property
    def organization_slug(self) -> str | None:
        return self.user.organization_slug

    @property
    def organization_role(self) -> str | None:
        return self.user.organization_role

    @property
    def workspace_id(self) -> str | None:
        return self.user.workspace_id

    @property
    def session_id(self) -> str | None:
        return self.user.session_id

    @property
    def roles(self) -> frozenset[str]:
        return self.user.roles

    @property
    def permissions(self) -> frozenset[str]:
        return self.user.permissions

    @property
    def authentication_methods(self) -> tuple[str, ...]:
        return self.user.authentication_methods

    @property
    def authentication_context_class(self) -> str | None:
        return self.user.authentication_context_class

    @property
    def actor(self) -> Actor | None:
        return self.user.actor

    @property
    def claims(self) -> Mapping[str, Any]:
        return self.user.claims

    def has_permission(self, resource: str, action: str) -> bool:
        """Return whether the current user has ``resource:action``."""

        return self.user.has_permission(resource, action)

    def has_mfa(self) -> bool:
        """Return whether the current user authenticated with MFA."""

        return self.user.has_mfa()

    def is_impersonating(self) -> bool:
        """Return whether this request is an impersonated session."""

        return self.user.is_impersonating()
