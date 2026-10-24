"""Safe current-user API context, independent of Access Token representation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise ValueError("Invalid current-user view")
    return {k: v for k, v in value.items()}


def _text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Missing current-user binding")
    return value


def _nullable(value: object) -> str | None:
    return None if value is None else _text(value)


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError("Invalid current-user flag")
    return value


@dataclass(frozen=True, slots=True)
class ImpersonationContext:
    actor_id: str
    impersonation_id: str


@dataclass(frozen=True, slots=True)
class AuthenticationContext:
    subject_type: str
    application_id: str
    client_id: str
    session_id: str
    workspace_id: str | None
    workspace_selection_required: bool
    organization_id: str | None
    organization_slug: str | None
    organization_role: str | None
    auth_time: datetime | None
    authentication_methods: tuple[str, ...]
    assurance_level: str | None
    impersonation: ImpersonationContext | None


@dataclass(frozen=True, slots=True)
class CurrentUser:
    id: str
    email: str | None
    username: str | None
    status: str
    email_verified: bool
    authentication_context: AuthenticationContext
    metadata: Mapping[str, object]

    @classmethod
    def from_mapping(cls, value: object) -> CurrentUser:
        """Require complete bindings, including explicitly nullable context fields."""
        v = _object(value)
        try:
            c = _object(v["authenticationContext"])
            if c["subjectType"] != "USER":
                raise ValueError("Invalid current-user subject type")
            methods = c["authenticationMethods"]
            if not isinstance(methods, list):
                raise ValueError("Invalid authentication methods")
            time = _nullable(c["authTime"])
            auth_time = None if time is None else datetime.fromisoformat(time)
            if time is not None and (
                "T" not in time or auth_time is None or auth_time.tzinfo is None
            ):
                raise ValueError("Invalid authentication time")
            i = None if c["impersonation"] is None else _object(c["impersonation"])
            context = AuthenticationContext(
                subject_type="USER",
                application_id=_text(c["applicationId"]),
                client_id=_text(c["clientId"]),
                session_id=_text(c["sessionId"]),
                workspace_id=_nullable(c["workspaceId"]),
                workspace_selection_required=_boolean(c["workspaceSelectionRequired"]),
                organization_id=_nullable(c["organizationId"]),
                organization_slug=_nullable(c["organizationSlug"]),
                organization_role=_nullable(c["organizationRole"]),
                auth_time=auth_time,
                authentication_methods=tuple(_text(m) for m in methods),
                assurance_level=_nullable(c["assuranceLevel"]),
                impersonation=None
                if i is None
                else ImpersonationContext(
                    actor_id=_text(i["actorId"]), impersonation_id=_text(i["impersonationId"])
                ),
            )
            if (context.workspace_selection_required and context.workspace_id is not None) or (
                context.organization_id is None
                and (context.organization_slug is not None or context.organization_role is not None)
            ):
                raise ValueError("Inconsistent current-user context")
            return cls(
                id=_text(v["id"]),
                email=_nullable(v["email"]),
                username=_nullable(v["username"]),
                status=_text(v["status"]),
                email_verified=_boolean(v["emailVerified"]),
                authentication_context=context,
                metadata=MappingProxyType(_object(v["metadata"])),
            )
        except KeyError:
            raise ValueError("Incomplete current-user view") from None
