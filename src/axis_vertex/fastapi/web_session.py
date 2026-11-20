"""Explicit FastAPI BFF routes and request-local session dependencies."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from axis_vertex.web_session import ServerSession, SessionError, SyncServerSession
from axis_vertex.web_session.http import HostRequest, dispatch, parse_body, unique_pairs
from axis_vertex.web_session.models import JsonObject


def _cookie(request: Request, name: str) -> str | None:
    if any(len(request.headers.getlist(key)) > 1 for key in (
        "cookie", "origin", "x-csrf-token", "authorization"
    )):
        raise SessionError("VALIDATION_ERROR")
    matches = [
        part.split("=", 1)[0].strip() for part in request.headers.get("cookie", "").split(";")
    ]
    if matches.count(name) > 1:
        raise SessionError("VALIDATION_ERROR")
    return request.cookies.get(name)


async def _check_write(session: ServerSession, request: Request) -> None:
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        record = await session._load(_cookie(request, session.config.cookie_name), "session")
        session.csrf(record, request.headers.get("origin"), request.headers.get("x-csrf-token"))


def session_router(session: ServerSession, *, prefix: str = "/auth") -> APIRouter:
    """Mount explicitly with ``app.include_router(session_router(session))``."""
    if isinstance(session, SyncServerSession):
        raise ValueError("FastAPI requires the asynchronous ServerSession channel")
    if not prefix.startswith("/") or prefix.endswith("/"):
        raise ValueError("prefix must be an absolute path without a trailing slash")
    router = APIRouter(prefix=prefix)

    async def endpoint(request: Request) -> Response:
        try:
            query = unique_pairs(list(request.query_params.multi_items()))
            body: JsonObject = {}
            if request.method == "POST":
                raw = bytearray()
                async for chunk in request.stream():
                    raw.extend(chunk)
                    if len(raw) > 65536:
                        raise SessionError("VALIDATION_ERROR")
                body = parse_body(bytes(raw), request.headers.get("content-type", ""))
            result = await dispatch(
                session,
                HostRequest(
                    request.method,
                    request.url.path.removeprefix(prefix),
                    _cookie(request, session.config.cookie_name),
                    request.headers.get("origin"),
                    request.headers.get("x-csrf-token"),
                    request.headers.get("authorization"),
                    query,
                    body,
                ),
            )
        except SessionError as exc:
            return JSONResponse(
                exc.envelope(),
                status_code=exc.status,
                headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
            )
        response: Response
        if result.location is not None:
            response = RedirectResponse(result.location, status_code=result.status)
        elif result.status == 204:
            response = Response(status_code=204)
        else:
            response = JSONResponse(result.body, status_code=result.status)
        response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
        if result.retry_after is not None:
            response.headers["Retry-After"] = str(result.retry_after)
        if result.clear_cookie or result.cookie is not None:
            response.set_cookie(
                session.config.cookie_name,
                result.cookie or "",
                max_age=0 if result.clear_cookie else None,
                path="/",
                secure=session.config.origin.startswith("https:"),
                httponly=True,
                samesite="lax",
            )
        return response

    # Finite routes avoid exposing a generic IAM or application proxy.
    for path in (
        "/session/bootstrap",
        "/session",
        "/login",
        "/callback",
        "/auth-methods",
        "/auth-policy",
        "/registration/{ref}",
    ):
        router.add_api_route(path, endpoint, methods=["GET"], include_in_schema=False)
    for path in (
        "/session/login",
        "/session/login/{action}",
        "/session/logout",
        "/registration",
        "/registration/{ref}/{action}",
        "/password-reset/request",
        "/password-reset/complete",
    ):
        router.add_api_route(path, endpoint, methods=["POST"], include_in_schema=False)
    return router


def require_web_session(
    session: ServerSession, permission: str | None = None
) -> Callable[[Request], object]:
    """Explicitly validate once per request; getters only read request.state."""
    if isinstance(session, SyncServerSession):
        raise ValueError("FastAPI requires asynchronous ServerSession")

    async def dependency(request: Request) -> JsonObject:
        existing = getattr(request.state, "axis_web_session", None)
        try:
            if request.headers.get("authorization") is not None:
                raise SessionError("SESSION_INVALIDATED", 401)
            await _check_write(session, request)
            if existing is None:
                existing = await session.require_session(
                    _cookie(request, session.config.cookie_name)
                )
                request.state.axis_web_session = existing
            session.check_permission(existing, permission)
            return existing
        except SessionError as exc:
            raise HTTPException(
                exc.status, detail=exc.envelope(), headers={"Cache-Control": "no-store"}
            ) from None

    return dependency


def web_session_from_request(request: Request) -> JsonObject | None:
    """Read only; application must mount require_web_session explicitly."""
    value = getattr(request.state, "axis_web_session", None)
    return value if isinstance(value, dict) else None


class WebSessionMiddleware(BaseHTTPMiddleware):
    """Validate explicitly listed business paths before application dispatch."""

    def __init__(
        self, app: ASGIApp, session: ServerSession, *, paths: tuple[str, ...],
    ) -> None:
        if isinstance(session, SyncServerSession):
            raise ValueError("ASGI middleware requires the asynchronous session channel")
        super().__init__(app)
        self.session, self.paths = session, paths

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.url.path in self.paths:
            try:
                if request.headers.get("authorization") is not None:
                    raise SessionError("SESSION_INVALIDATED", 401)
                await _check_write(self.session, request)
                request.state.axis_web_session = await self.session.require_session(
                    _cookie(request, self.session.config.cookie_name)
                )
            except SessionError as exc:
                return JSONResponse(exc.envelope(), status_code=exc.status,
                                    headers={"Cache-Control": "no-store"})
        return await call_next(request)
