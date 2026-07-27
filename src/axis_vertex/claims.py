"""Typed Java IAM JWT claims."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


@dataclass(frozen=True, slots=True)
class Actor:
    """Delegating actor carried by the JWT ``act`` claim during impersonation."""

    subject: str


@dataclass(frozen=True, slots=True)
class IamClaims:
    """Verified IAM access-token claims."""

    subject: str
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
    authentication_methods: tuple[str, ...]
    authentication_context_class: str | None
    actor: Actor | None
    claims: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, claims: Mapping[str, Any]) -> IamClaims:
        """Build typed claims from a verified JWT payload."""

        return cls(
            subject=_string(claims.get("sub")) or "",
            application_id=_application_id(claims),
            email=_string(claims.get("email")),
            email_verified=bool(claims.get("email_verified")),
            username=_string(claims.get("username")),
            organization_id=_string(claims.get("org_id")),
            organization_slug=_string(claims.get("org_slug")),
            organization_role=_string(claims.get("org_role")),
            workspace_id=_string(claims.get("workspace_id")),
            session_id=_string(claims.get("sid")),
            roles=frozenset(_strings(claims.get("roles"))),
            authentication_methods=tuple(_strings(claims.get("amr"))),
            authentication_context_class=_string(claims.get("acr")),
            actor=_actor(claims.get("act")),
            claims=MappingProxyType(dict(claims)),
        )


def _string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _strings(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list | tuple | set | frozenset):
        return [item for item in value if isinstance(item, str) and item.strip()]
    return []


def _application_id(claims: Mapping[str, Any]) -> str | None:
    return _string(claims.get("app_id"))


def _actor(value: object) -> Actor | None:
    if isinstance(value, Mapping):
        subject = _string(value.get("sub"))
        if subject is not None:
            return Actor(subject=subject)
    return None
