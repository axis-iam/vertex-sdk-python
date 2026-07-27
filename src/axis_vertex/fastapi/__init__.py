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

__all__ = [
    "IamAuthenticationMiddleware",
    "get_iam_context",
    "require_all_permissions",
    "require_any_permission",
    "require_no_impersonation",
    "require_permission",
    "require_step_up",
]
