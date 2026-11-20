"""FastAPI integration for the IAM SDK."""

from __future__ import annotations

from .dependencies import (
    get_iam_context,
    require_all_permissions,
    require_any_permission,
    require_no_impersonation,
    require_permission,
    require_step_up,
)
from .middleware import IamAuthenticationMiddleware
from .web_session import (
    WebSessionMiddleware,
    require_web_session,
    session_router,
    web_session_from_request,
)

__all__ = [
    "IamAuthenticationMiddleware",
    "get_iam_context",
    "require_all_permissions",
    "require_any_permission",
    "require_no_impersonation",
    "require_permission",
    "require_step_up",
    "require_web_session",
    "session_router",
    "web_session_from_request",
    "WebSessionMiddleware",
]
