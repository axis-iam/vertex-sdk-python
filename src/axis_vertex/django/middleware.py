"""Django middleware for IAM authentication."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse

from axis_vertex.client import IamClient
from axis_vertex.config import IamConfig
from axis_vertex.errors import UnauthorizedError


def get_default_client() -> IamClient:
    """Return the configured Django IAM client."""

    cfg = getattr(settings, "IAM_SDK", None)
    if not isinstance(cfg, dict):
        raise RuntimeError("Django setting IAM_SDK is required")
    injected = cfg.get("CLIENT")
    if isinstance(injected, IamClient):
        return injected
    return IamClient(
        IamConfig(
            endpoint=str(cfg["ENDPOINT"]),
            client_id=str(cfg["CLIENT_ID"]),
            client_secret=str(cfg["CLIENT_SECRET"]),
            resource_audience=str(cfg["RESOURCE_AUDIENCE"]),
            audience=str(cfg["AUDIENCE"]) if cfg.get("AUDIENCE") else None,
            issuer=str(cfg["ISSUER"]) if cfg.get("ISSUER") else None,
        )
    )


class IamAuthenticationMiddleware:
    """Attach ``request.iam_context`` when a bearer token is present."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        self.iam = get_default_client()

    def __call__(self, request: HttpRequest) -> HttpResponse:
        value = request.META.get("HTTP_AUTHORIZATION", "").strip()
        if value:
            if not value.lower().startswith("bearer "):
                return _json_error(401, "UNAUTHORIZED", "invalid authorization header")
            try:
                request.iam_context = self.iam.authenticate_sync(value[7:].strip())
            except UnauthorizedError as exc:
                return _json_error(401, "UNAUTHORIZED", str(exc))
        return self.get_response(request)


def _json_error(status_code: int, code: str, message: str) -> JsonResponse:
    return JsonResponse({"code": code, "message": message}, status=status_code)


def iam_context_from_request(request: HttpRequest) -> Any:
    """Return ``request.iam_context`` if middleware populated it."""

    return getattr(request, "iam_context", None)
