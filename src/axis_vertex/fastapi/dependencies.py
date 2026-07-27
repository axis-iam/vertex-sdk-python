"""FastAPI dependency helpers for IAM authentication and authorization."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import HTTPException, Request, status

from axis_vertex.client import IamClient
from axis_vertex.context import IamContext
from axis_vertex.errors import UnauthorizedError
from axis_vertex.permissions import PermissionKey, has_all_permissions, has_any_permission


async def _context_from_request(iam: IamClient, request: Request) -> IamContext:
    existing = getattr(request.state, "iam_context", None)
    if isinstance(existing, IamContext):
        return existing
    token = _bearer_token(request)
    if not token:
        raise _http_error(status.HTTP_401_UNAUTHORIZED, "UNAUTHORIZED", "missing bearer token")
    try:
        context = await iam.authenticate(token)
    except UnauthorizedError as exc:
        raise _http_error(status.HTTP_401_UNAUTHORIZED, "UNAUTHORIZED", str(exc)) from exc
    request.state.iam_context = context
    return context


def get_iam_context(iam: IamClient) -> Callable[[Request], object]:
    """Return a FastAPI dependency that authenticates the current request."""

    async def dependency(request: Request) -> IamContext:
        return await _context_from_request(iam, request)

    return dependency


def require_permission(
    iam: IamClient, resource: str | PermissionKey, action: str | None = None
) -> Callable[[Request], object]:
    """Return a dependency requiring one permission."""

    key = resource if isinstance(resource, PermissionKey) else PermissionKey(resource, action or "")
    if not key.resource or not key.action:
        raise ValueError("require_permission needs a PermissionKey or resource and action")

    async def dependency(request: Request) -> IamContext:
        context = await _context_from_request(iam, request)
        if not context.has_permission(key.resource, key.action):
            raise _http_error(
                status.HTTP_403_FORBIDDEN,
                "FORBIDDEN",
                f"missing permission: {key.authority()}",
            )
        return context

    return dependency


def require_any_permission(
    iam: IamClient,
    *permissions: tuple[str, str],
) -> Callable[[Request], object]:
    """Return a dependency accepting any one of the provided permissions."""

    keys = tuple(PermissionKey(resource, action) for resource, action in permissions)

    async def dependency(request: Request) -> IamContext:
        context = await _context_from_request(iam, request)
        if not has_any_permission(keys, context.permissions):
            raise _http_error(
                status.HTTP_403_FORBIDDEN,
                "FORBIDDEN",
                "missing any of required permissions",
            )
        return context

    return dependency


def require_all_permissions(
    iam: IamClient,
    *permissions: tuple[str, str],
) -> Callable[[Request], object]:
    """Return a dependency requiring every provided permission."""

    keys = tuple(PermissionKey(resource, action) for resource, action in permissions)

    async def dependency(request: Request) -> IamContext:
        context = await _context_from_request(iam, request)
        if not has_all_permissions(keys, context.permissions):
            raise _http_error(
                status.HTTP_403_FORBIDDEN,
                "FORBIDDEN",
                "missing required permissions",
            )
        return context

    return dependency


def require_step_up(iam: IamClient, acr: str = "urn:iam:acr:mfa") -> Callable[[Request], object]:
    """Return a dependency requiring the JWT ``acr`` claim to match ``acr``."""

    async def dependency(request: Request) -> IamContext:
        context = await _context_from_request(iam, request)
        if context.authentication_context_class != acr:
            raise _http_error(status.HTTP_403_FORBIDDEN, "STEP_UP_REQUIRED", f"acr {acr} required")
        return context

    return dependency


def require_no_impersonation(iam: IamClient) -> Callable[[Request], object]:
    """Return a dependency blocking impersonated sessions."""

    async def dependency(request: Request) -> IamContext:
        context = await _context_from_request(iam, request)
        if context.is_impersonating():
            raise _http_error(
                status.HTTP_403_FORBIDDEN,
                "FORBIDDEN",
                "impersonated sessions may not perform this action",
            )
        return context

    return dependency


def _bearer_token(request: Request) -> str:
    value = request.headers.get("authorization", "").strip()
    if not value.lower().startswith("bearer "):
        return ""
    return value[7:].strip()


def _http_error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


IamContextDependency = Annotated[IamContext, "IAM context dependency"]
