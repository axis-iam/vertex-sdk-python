"""Explicit Django sync/async URL and business-view wiring.

SDK Cookie ownership is separate from Django SessionMiddleware; credentials are
never put in request.session, so its automatic save cannot resurrect authentication.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from functools import wraps
from typing import TYPE_CHECKING

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.urls import URLPattern, re_path
from django.views.decorators.csrf import csrf_exempt

from axis_vertex.web_session import ServerSession, SessionError, SyncServerSession
from axis_vertex.web_session.http import HostRequest, dispatch, parse_body, unique_pairs
from axis_vertex.web_session.models import JsonObject, SessionResult

if TYPE_CHECKING:
    from collections.abc import Awaitable


def _cookie(request: HttpRequest, name: str) -> str | None:
    names = [p.split("=", 1)[0].strip() for p in request.META.get("HTTP_COOKIE", "").split(";")]
    if names.count(name) > 1:
        raise SessionError("VALIDATION_ERROR")
    value = request.COOKIES.get(name)
    return value if isinstance(value, str) else None


def _request(session: ServerSession, request: HttpRequest, prefix: str) -> HostRequest:
    query = unique_pairs([(k, v) for k, values in request.GET.lists() for v in values])
    if request.method == "POST" and int(request.META.get("CONTENT_LENGTH") or 0) > 65536:
        raise SessionError("VALIDATION_ERROR")
    body = parse_body(request.body, request.content_type or "") if request.method == "POST" else {}
    return HostRequest(
        request.method or "",
        request.path.removeprefix(prefix),
        _cookie(request, session.config.cookie_name),
        request.headers.get("Origin"),
        request.headers.get("X-CSRF-Token"),
        request.headers.get("Authorization"),
        query,
        body,
    )


def _response(session: ServerSession, result: SessionResult) -> HttpResponse:
    response = (
        HttpResponse(status=result.status)
        if result.status == 204
        else JsonResponse(result.body, status=result.status)
    )
    if result.location is not None:
        response = HttpResponse(status=result.status, headers={"Location": result.location})
    response["Cache-Control"] = "no-store"
    response["Referrer-Policy"] = "no-referrer"
    if result.retry_after is not None:
        response["Retry-After"] = str(result.retry_after)
    if result.clear_cookie or result.cookie is not None:
        response.set_cookie(
            session.config.cookie_name,
            result.cookie or "",
            max_age=0 if result.clear_cookie else None,
            path="/",
            secure=session.config.origin.startswith("https:"),
            httponly=True,
            samesite="Lax",
        )
    return response


def session_urls(session: ServerSession, *, prefix: str = "/auth") -> list[URLPattern]:
    """Include returned patterns in urlpatterns, once, with explicit channel."""
    if not prefix.startswith("/") or prefix.endswith("/"):
        raise ValueError("prefix must be absolute without a trailing slash")
    if session.config.cookie_name == settings.SESSION_COOKIE_NAME:
        raise ValueError("SDK and native Django sessions require distinct Cookie owners")

    # csrf_exempt bypasses Django's unrelated token format; C0 Origin+CSRF are
    # enforced centrally on every POST. This also works with CsrfViewMiddleware.
    def sync_view(request: HttpRequest, **kwargs: str) -> HttpResponse:
        assert isinstance(session, SyncServerSession)
        try:
            result = session.run(dispatch(session, _request(session, request, prefix)))
        except SessionError as exc:
            result = SessionResult(exc.envelope(), status=exc.status)
        return _response(session, result)

    async def async_view(request: HttpRequest, **kwargs: str) -> HttpResponse:
        try:
            result = await dispatch(session, _request(session, request, prefix))
        except SessionError as exc:
            result = SessionResult(exc.envelope(), status=exc.status)
        return _response(session, result)

    view = csrf_exempt(sync_view if isinstance(session, SyncServerSession) else async_view)
    root = re.escape(prefix.lstrip("/"))
    routes = (
        r"(?:session(?:/bootstrap|/logout|/login(?:/[a-z-]+)?)?|login|callback|"
        r"auth-methods|auth-policy|registration(?:/[A-Za-z0-9_-]+(?:/[a-z]+)?)?|"
        r"password-reset/(?:request|complete))"
    )
    return [re_path("^" + root + "/" + routes + "$", view)]


def require_web_session(
    session: SyncServerSession, permission: str | None = None
) -> Callable[[Callable[[HttpRequest], HttpResponse]], Callable[[HttpRequest], HttpResponse]]:
    def decorator(
        view: Callable[[HttpRequest], HttpResponse],
    ) -> Callable[[HttpRequest], HttpResponse]:
        @wraps(view)
        def wrapped(request: HttpRequest) -> HttpResponse:
            try:
                if request.headers.get("Authorization") is not None:
                    raise SessionError("SESSION_INVALIDATED", 401)
                if request.method not in {"GET", "HEAD", "OPTIONS"}:
                    record = session.run(
                        session._load(_cookie(request, session.config.cookie_name), "session")
                    )
                    session.csrf(
                        record, request.headers.get("Origin"), request.headers.get("X-CSRF-Token")
                    )
                value = getattr(request, "axis_web_session", None)
                if value is None:
                    value = session.run(
                        session.require_session(_cookie(request, session.config.cookie_name))
                    )
                    request.axis_web_session = value
                session.check_permission(value, permission)
                return view(request)
            except SessionError as exc:
                return _response(session, SessionResult(exc.envelope(), status=exc.status))

        return wrapped

    return decorator


def require_async_web_session(
    session: ServerSession, permission: str | None = None
) -> Callable[
    [Callable[[HttpRequest], Awaitable[HttpResponse]]],
    Callable[[HttpRequest], Awaitable[HttpResponse]],
]:
    if isinstance(session, SyncServerSession):
        raise ValueError("async Django views require the async channel")

    def decorator(
        view: Callable[[HttpRequest], Awaitable[HttpResponse]],
    ) -> Callable[[HttpRequest], Awaitable[HttpResponse]]:
        @wraps(view)
        async def wrapped(request: HttpRequest) -> HttpResponse:
            try:
                if request.headers.get("Authorization") is not None:
                    raise SessionError("SESSION_INVALIDATED", 401)
                if request.method not in {"GET", "HEAD", "OPTIONS"}:
                    record = await session._load(
                        _cookie(request, session.config.cookie_name), "session"
                    )
                    session.csrf(
                        record, request.headers.get("Origin"), request.headers.get("X-CSRF-Token")
                    )
                value = getattr(request, "axis_web_session", None)
                if value is None:
                    value = await session.require_session(
                        _cookie(request, session.config.cookie_name)
                    )
                    request.axis_web_session = value
                session.check_permission(value, permission)
                return await view(request)
            except SessionError as exc:
                return _response(session, SessionResult(exc.envelope(), status=exc.status))

        return wrapped

    return decorator


def web_session_from_request(request: HttpRequest) -> JsonObject | None:
    value = getattr(request, "axis_web_session", None)
    return value if isinstance(value, dict) else None


class WebSessionMiddleware:
    """Explicit sync middleware factory target for named protected paths."""

    def __init__(
        self, get_response: Callable[[HttpRequest], HttpResponse],
        session: SyncServerSession, *, paths: tuple[str, ...],
    ) -> None:
        self.get_response = get_response
        self.protected_response = require_web_session(session)(get_response)
        self.paths = paths

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.path in self.paths:
            return self.protected_response(request)
        return self.get_response(request)


class AsyncWebSessionMiddleware:
    """Explicit native async middleware; no sync provider or runner inside ASGI."""

    sync_capable = False
    async_capable = True

    def __init__(
        self, get_response: Callable[[HttpRequest], Awaitable[HttpResponse]],
        session: ServerSession, *, paths: tuple[str, ...],
    ) -> None:
        from asgiref.sync import markcoroutinefunction
        self.get_response = get_response
        self.protected_response = require_async_web_session(session)(get_response)
        self.paths = paths
        markcoroutinefunction(self)

    async def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.path in self.paths:
            return await self.protected_response(request)
        return await self.get_response(request)


def async_session_middleware(
    session: ServerSession, *, paths: tuple[str, ...],
) -> Callable[
    [Callable[[HttpRequest], Awaitable[HttpResponse]]], AsyncWebSessionMiddleware
]:
    """Return a Django ASGI middleware factory with explicit async capability."""
    from django.utils.decorators import async_only_middleware

    def factory(
        get_response: Callable[[HttpRequest], Awaitable[HttpResponse]],
    ) -> AsyncWebSessionMiddleware:
        return AsyncWebSessionMiddleware(get_response, session, paths=paths)

    async_only_middleware(factory)
    return factory
