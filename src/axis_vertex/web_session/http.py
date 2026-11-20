"""Finite host routes shared by ASGI and WSGI adapters."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field

from .client import ServerSession
from .models import JsonObject, SessionError, SessionResult, exact, obj, text


def unique_pairs(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for k, v in pairs:
        if k in result:
            raise SessionError("VALIDATION_ERROR")
        result[k] = v
    return result


def parse_body(raw: bytes, content_type: str) -> JsonObject:
    if len(raw) > 65536 or content_type.split(";")[0].lower() != "application/json":
        raise SessionError("VALIDATION_ERROR")
    try:
        return obj(
            json.loads(
                raw,
                object_pairs_hook=unique_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            )
        )
    except (ValueError, UnicodeError):
        raise SessionError("VALIDATION_ERROR") from None


@dataclass(slots=True, repr=False)
class HostRequest:
    method: str
    path: str
    cookie: str | None
    origin: str | None = None
    csrf: str | None = None
    authorization: str | None = None
    query: JsonObject = field(default_factory=dict)
    body: JsonObject = field(default_factory=dict)


async def dispatch(session: ServerSession, request: HostRequest) -> SessionResult:
    r = request
    try:
        # Explicit credential failure never falls back to the ambient Cookie.
        if r.authorization is not None:
            raise SessionError("SESSION_INVALIDATED", 401)
        if r.method == "POST" and r.origin != session.config.origin:
            raise SessionError("SESSION_CSRF_INVALID", 403)
        async with asyncio.timeout(session.config.auth_budget):
            if r.method == "GET":
                if r.path == "/callback":
                    return await session.callback(r.cookie, r.query)
                if r.path == "/login":
                    exact(r.query, set(), {"returnTo"})
                    return await session.hosted_login(r.cookie, text(r.query.get("returnTo", "/")))
                exact(r.query, set())
                if r.path == "/session/bootstrap":
                    return await session.bootstrap(r.cookie)
                if r.path == "/session":
                    return await session.session(r.cookie)
                if r.path in {"/auth-methods", "/auth-policy"}:
                    return await session.capabilities(r.path == "/auth-policy")
                if r.path.startswith("/registration/"):
                    ref = r.path.removeprefix("/registration/")
                    if "/" not in ref:
                        return await session.registration(
                            r.cookie, "get", {}, r.origin, r.csrf, ref
                        )
            elif r.method == "POST":
                exact(r.query, set())
                if r.path == "/session/logout":
                    exact(r.body, set())
                    result = await session.logout(r.cookie, r.origin, r.csrf)
                    if result.status == 503:
                        result.body = SessionError(
                            "LOGOUT_UNCONFIRMED", 503, details=result.body
                        ).envelope()
                    return result
                if r.path == "/session/login" or r.path.startswith("/session/login/"):
                    action = (
                        "start"
                        if r.path == "/session/login"
                        else r.path.removeprefix("/session/login/")
                    )
                    return await session.login_action(r.cookie, action, r.body, r.origin, r.csrf)
                if r.path == "/registration":
                    return await session.registration(r.cookie, "start", r.body, r.origin, r.csrf)
                if r.path.startswith("/registration/"):
                    parts = r.path.removeprefix("/registration/").split("/")
                    if len(parts) == 2:
                        return await session.registration(
                            r.cookie, parts[1], r.body, r.origin, r.csrf, parts[0]
                        )
                if r.path in {"/password-reset/request", "/password-reset/complete"}:
                    return await session.password_reset(
                        r.cookie, r.path.endswith("/complete"), r.body, r.origin, r.csrf
                    )
            raise SessionError("NOT_FOUND", 404)
    except SessionError as exc:
        logout_fault = r.path == "/session/logout" and exc.status >= 500
        if logout_fault:
            exc = SessionError(
                "LOGOUT_UNCONFIRMED",
                503,
                details={
                    "local": "UNCONFIRMED",
                    "cookie": "CLEARED",
                    "remote": "NOT_ATTEMPTED",
                    "sso": "NOT_REQUESTED",
                },
            )
        return SessionResult(
            exc.envelope(), status=exc.status, clear_cookie=exc.status == 401 or logout_fault,
            retry_after=exc.retry_after,
        )
    except TimeoutError:
        return SessionResult(SessionError("IAM_UNAVAILABLE", 503).envelope(), status=503)
