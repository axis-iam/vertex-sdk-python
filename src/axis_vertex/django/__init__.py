"""Django integration for the IAM SDK."""

from __future__ import annotations

from .decorators import (
    require_all_permissions,
    require_any_permission,
    require_no_impersonation,
    require_permission,
    require_step_up,
)
from .middleware import IamAuthenticationMiddleware
from .web_session import (
    AsyncWebSessionMiddleware,
    WebSessionMiddleware,
    async_session_middleware,
    require_async_web_session,
    require_web_session,
    session_urls,
    web_session_from_request,
)

__all__ = [
    "IamAuthenticationMiddleware",
    "require_all_permissions",
    "require_any_permission",
    "require_no_impersonation",
    "require_permission",
    "require_step_up",
    "require_async_web_session",
    "require_web_session",
    "session_urls",
    "web_session_from_request",
    "WebSessionMiddleware",
    "AsyncWebSessionMiddleware",
    "async_session_middleware",
]
