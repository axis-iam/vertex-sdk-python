"""Typed server-session configuration and strictly validated public views (C0 1.0.1)."""

from __future__ import annotations

import math
import re
import secrets
from collections.abc import Set
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from axis_vertex.current_user import CurrentUser
from axis_vertex.errors import IamConfigError, IamSdkError

JsonObject = dict[str, object]
StoreOutcome = Literal["ABSENT", "CONFLICT", "CAPACITY", "UNAVAILABLE", "CLOSED"]


class SessionError(IamSdkError):
    """A sanitized host error; never contains an upstream body or credential."""

    def __init__(
        self, code: str, status: int = 400, *, details: JsonObject | None = None,
        retry_after: int | None = None,
    ):
        self.code, self.status, self.details = code, status, details
        self.retry_after = retry_after
        super().__init__(code)

    def envelope(self) -> JsonObject:
        result: JsonObject = {
            "status": self.status,
            "error": self.code,
            "message": self.code,
            "timestamp": timestamp(datetime.now(UTC).timestamp()),
        }
        if self.details is not None:
            result["details"] = self.details
        return result


class StoreError(SessionError):
    def __init__(self, outcome: StoreOutcome):
        self.outcome = outcome
        super().__init__(
            {
                "ABSENT": "SESSION_INVALIDATED",
                "CONFLICT": "SESSION_ACTION_PENDING",
                "CAPACITY": "SESSION_STORE_CAPACITY",
                "UNAVAILABLE": "SESSION_STORE_UNAVAILABLE",
                "CLOSED": "SESSION_STORE_UNAVAILABLE",
            }[outcome],
            {"ABSENT": 401, "CONFLICT": 409}.get(outcome, 503),
        )


def random_id() -> str:
    return secrets.token_urlsafe(32)


def obj(value: object) -> JsonObject:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise SessionError("VALIDATION_ERROR")
    return {k: v for k, v in value.items()}


def text(value: object, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise SessionError("VALIDATION_ERROR")
    return value


def integer(value: object, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value > 9007199254740991:
        raise SessionError("VALIDATION_ERROR")
    return value


def strings(value: object) -> list[str]:
    if not isinstance(value, list):
        raise SessionError("VALIDATION_ERROR")
    return [text(v) for v in value]


def uuid_text(value: object) -> str:
    v = text(value)
    try:
        UUID(v)
    except ValueError:
        raise SessionError("VALIDATION_ERROR") from None
    return v


def epoch(value: object) -> float:
    try:
        v = text(value)
        d = datetime.fromisoformat(v)
        if "T" not in v or d.tzinfo is None:
            raise ValueError
        return d.timestamp()
    except ValueError:
        raise SessionError("VALIDATION_ERROR") from None


def timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, UTC).isoformat().replace("+00:00", "Z")


def exact(value: JsonObject, required: Set[str], optional: Set[str] = frozenset()) -> None:
    if not required <= value.keys() or value.keys() - required - optional:
        raise SessionError("VALIDATION_ERROR")


def parse_view(value: object) -> JsonObject:
    """Validate the browser-safe C0 shape, including proof-complete vs signed in."""
    v = obj(value)
    exact(
        v,
        {"state", "expiresAt", "csrfToken"},
        {
            "owner",
            "version",
            "profile",
            "permissions",
            "nextAction",
            "challengeExpiresAt",
            "cooldownSeconds",
            "authorizationUrl",
        },
    )
    state = text(v["state"])
    if state not in {
        "PRELOGIN",
        "AUTHENTICATING",
        "AWAITING_PROVIDER",
        "MFA_REQUIRED",
        "AUTHENTICATED",
        "COMPLETED",
        "CANCELLED",
        "EXPIRED",
        "REJECTED",
    }:
        raise SessionError("VALIDATION_ERROR")
    epoch(v["expiresAt"])
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", text(v["csrfToken"])):
        raise SessionError("VALIDATION_ERROR")
    if any(k in v for k in ("owner", "version", "profile", "permissions")):
        if (
            state != "AUTHENTICATED"
            or not {"owner", "version", "profile", "permissions"} <= v.keys()
        ):
            raise SessionError("VALIDATION_ERROR")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", text(v["owner"])):
            raise SessionError("VALIDATION_ERROR")
        integer(v["version"])
        p = obj(v["profile"])
        try:
            user = CurrentUser.from_mapping(p)
        except ValueError:
            raise SessionError("VALIDATION_ERROR") from None
        uuid_text(user.id)
        uuid_text(user.authentication_context.application_id)
        permissions = obj(v["permissions"])
        exact(permissions, {"roles", "permissions"}, {"applicationId", "organizationId"})
        strings(permissions["roles"])
        strings(permissions["permissions"])
        c = user.authentication_context
        for binding in (c.workspace_id, c.organization_id):
            if binding is not None:
                uuid_text(binding)
        if (
            "applicationId" in permissions and permissions["applicationId"] != c.application_id
        ) or (
            "organizationId" in permissions and permissions["organizationId"] != c.organization_id
        ):
            raise SessionError("VALIDATION_ERROR")
    elif state == "AUTHENTICATED" and v.get("nextAction") != "complete":
        raise SessionError("VALIDATION_ERROR")
    if "nextAction" in v and v["nextAction"] not in {
        "authenticate",
        "authorize",
        "mfa",
        "complete",
        "none",
    }:
        raise SessionError("VALIDATION_ERROR")
    if "challengeExpiresAt" in v:
        epoch(v["challengeExpiresAt"])
    if "cooldownSeconds" in v:
        integer(v["cooldownSeconds"])
    if "authorizationUrl" in v:
        text(v["authorizationUrl"])
    return v


@dataclass(frozen=True, slots=True)
class SessionConfig:
    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    resource_audience: str
    origin: str
    callback_uri: str
    return_paths: tuple[str, ...] = ("/",)
    scopes: tuple[str, ...] = ("openid",)
    cookie_name: str = "__Host-axis-session"
    allow_loopback_http: bool = False
    absolute_ttl: float = 3600
    idle_ttl: float = 3600
    prelogin_ttl: float = 600
    refresh_skew: float = 30
    lease: float = 15
    upstream_timeout: float = 5
    auth_budget: float = 10
    replicas: int = 1
    password_reset_redirect: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "absolute_ttl",
            "idle_ttl",
            "prelogin_ttl",
            "lease",
            "upstream_timeout",
            "auth_budget",
        ):
            n = getattr(self, name)
            if isinstance(n, bool) or not math.isfinite(n) or n <= 0:
                raise IamConfigError(f"{name} must be positive and finite")
        if not math.isfinite(self.refresh_skew) or self.refresh_skew < 0:
            raise IamConfigError("refresh_skew must be finite and nonnegative")
        if type(self.replicas) is not int or self.replicas < 1:
            raise IamConfigError("replicas must be positive")
        for name in ("client_id", "client_secret", "resource_audience"):
            if not getattr(self, name).strip():
                raise IamConfigError(f"{name} is required")
        if "openid" not in self.scopes or not all(
            s and not any(c.isspace() for c in s) for s in self.scopes
        ):
            raise IamConfigError("explicit OpenID scopes are required")
        for name in ("issuer", "origin", "callback_uri"):
            raw = getattr(self, name)
            u = urlsplit(raw)
            loopback = u.hostname in {"localhost", "127.0.0.1", "::1"}
            if (
                u.scheme != "https"
                and not (self.allow_loopback_http and loopback and u.scheme == "http")
            ) or (
                not raw.startswith(u.scheme + "://") or not u.netloc or
                u.username or u.password or u.query or u.fragment
            ):
                raise IamConfigError(f"{name} must be an explicit secure URL")
        origin = urlsplit(self.origin)
        if origin.path or self.issuer.endswith("/"):
            raise IamConfigError("origin has no path and issuer has no trailing slash")
        if not self.callback_uri.startswith(self.origin + "/"):
            raise IamConfigError("callback must belong to canonical origin")
        if not self.return_paths or any(
            not p.startswith("/")
            or p.startswith("//")
            or "\\" in p
            or "#" in p
            or "?" in p
            or any(ord(c) < 32 for c in p)
            or "%" in p
            for p in self.return_paths
        ):
            raise IamConfigError("return paths must be exact local paths")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", self.cookie_name):
            raise IamConfigError("invalid cookie name")
        if self.origin.startswith("http:") and self.cookie_name.startswith("__Host-"):
            raise IamConfigError("HTTP development requires a non-__Host cookie name")
        if self.password_reset_redirect is not None and self.password_reset_redirect not in (
            self.origin + p for p in self.return_paths
        ):
            raise IamConfigError("password reset landing must be explicitly allowlisted")


@dataclass(slots=True, repr=False)
class Record:
    """Provider snapshot. Sensitive fields deliberately excluded from repr."""

    key: str
    kind: Literal["prelogin", "session", "terminal"]
    created_at: float
    absolute_expires_at: float
    idle_expires_at: float
    csrf: str = field(default_factory=random_id)
    owner: str = field(default_factory=random_id)
    version: int = 0
    schema_version: int = 1
    data: JsonObject = field(default_factory=dict)
    operation: str | None = None
    intent: bool = False
    lease_until: float = 0


@dataclass(slots=True, repr=False)
class SessionResult:
    body: JsonObject
    cookie: str | None = None
    clear_cookie: bool = False
    status: int = 200
    location: str | None = None
    retry_after: int | None = None
