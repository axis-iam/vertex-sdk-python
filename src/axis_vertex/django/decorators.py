"""Django view decorators for IAM authorization."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Concatenate, ParamSpec, cast

from django.http import HttpRequest, HttpResponse, JsonResponse

from axis_vertex.context import IamContext
from axis_vertex.permissions import PermissionKey, has_all_permissions, has_any_permission

P = ParamSpec("P")
ViewFunc = Callable[Concatenate[HttpRequest, P], HttpResponse]


def require_permission(
    resource: str,
    action: str,
) -> Callable[[ViewFunc[P]], ViewFunc[P]]:
    """Require one permission on a Django view."""

    def decorator(view: ViewFunc[P]) -> ViewFunc[P]:
        @wraps(view)
        def wrapped(request: HttpRequest, *args: P.args, **kwargs: P.kwargs) -> HttpResponse:
            context = _require_context(request)
            if context is None:
                return _json_error(401, "UNAUTHORIZED", "not authenticated")
            if not context.has_permission(resource, action):
                return _json_error(
                    403,
                    "FORBIDDEN",
                    f"missing permission: {resource}:{action}",
                )
            return view(request, *args, **kwargs)

        return cast("ViewFunc[P]", wrapped)

    return decorator


def require_any_permission(
    *permissions: tuple[str, str],
) -> Callable[[ViewFunc[P]], ViewFunc[P]]:
    """Require any one of the provided permissions."""

    keys = tuple(PermissionKey(resource, action) for resource, action in permissions)

    def decorator(view: ViewFunc[P]) -> ViewFunc[P]:
        @wraps(view)
        def wrapped(request: HttpRequest, *args: P.args, **kwargs: P.kwargs) -> HttpResponse:
            context = _require_context(request)
            if context is None:
                return _json_error(401, "UNAUTHORIZED", "not authenticated")
            if not has_any_permission(keys, context.permissions):
                return _json_error(
                    403,
                    "FORBIDDEN",
                    "missing any of required permissions",
                )
            return view(request, *args, **kwargs)

        return cast("ViewFunc[P]", wrapped)

    return decorator


def require_all_permissions(
    *permissions: tuple[str, str],
) -> Callable[[ViewFunc[P]], ViewFunc[P]]:
    """Require every provided permission."""

    keys = tuple(PermissionKey(resource, action) for resource, action in permissions)

    def decorator(view: ViewFunc[P]) -> ViewFunc[P]:
        @wraps(view)
        def wrapped(request: HttpRequest, *args: P.args, **kwargs: P.kwargs) -> HttpResponse:
            context = _require_context(request)
            if context is None:
                return _json_error(401, "UNAUTHORIZED", "not authenticated")
            if not has_all_permissions(keys, context.permissions):
                return _json_error(
                    403,
                    "FORBIDDEN",
                    "missing required permissions",
                )
            return view(request, *args, **kwargs)

        return cast("ViewFunc[P]", wrapped)

    return decorator


def require_step_up(
    acr: str = "urn:iam:acr:mfa",
) -> Callable[[ViewFunc[P]], ViewFunc[P]]:
    """Require the JWT ``acr`` claim to match ``acr``."""

    def decorator(view: ViewFunc[P]) -> ViewFunc[P]:
        @wraps(view)
        def wrapped(request: HttpRequest, *args: P.args, **kwargs: P.kwargs) -> HttpResponse:
            context = _require_context(request)
            if context is None:
                return _json_error(401, "UNAUTHORIZED", "not authenticated")
            if context.authentication_context_class != acr:
                return _json_error(403, "STEP_UP_REQUIRED", f"acr {acr} required")
            return view(request, *args, **kwargs)

        return cast("ViewFunc[P]", wrapped)

    return decorator


def require_no_impersonation() -> Callable[
    [ViewFunc[P]],
    ViewFunc[P],
]:
    """Block requests carrying an impersonation actor."""

    def decorator(view: ViewFunc[P]) -> ViewFunc[P]:
        @wraps(view)
        def wrapped(request: HttpRequest, *args: P.args, **kwargs: P.kwargs) -> HttpResponse:
            context = _require_context(request)
            if context is None:
                return _json_error(401, "UNAUTHORIZED", "not authenticated")
            if context.is_impersonating():
                return _json_error(
                    403,
                    "FORBIDDEN",
                    "impersonated sessions may not perform this action",
                )
            return view(request, *args, **kwargs)

        return cast("ViewFunc[P]", wrapped)

    return decorator


def _require_context(request: HttpRequest) -> IamContext | None:
    value = getattr(request, "iam_context", None)
    return value if isinstance(value, IamContext) else None


def _json_error(status_code: int, code: str, message: str) -> JsonResponse:
    return JsonResponse({"code": code, "message": message}, status=status_code)
