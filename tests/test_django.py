from __future__ import annotations

import asyncio
import json

import django
from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.test import RequestFactory, override_settings

if not settings.configured:
    settings.configure(
        DEFAULT_CHARSET="utf-8",
        SECRET_KEY="test",
        ROOT_URLCONF=__name__,
        ALLOWED_HOSTS=["*"],
        INSTALLED_APPS=[],
    )
    django.setup()

from axis_vertex.django import (  # noqa: E402
    IamAuthenticationMiddleware,
    require_no_impersonation,
    require_permission,
    require_step_up,
)
from axis_vertex.testing import MockIamServer  # noqa: E402


def test_django_constructs_client_with_canonical_resource_audience() -> None:
    from axis_vertex.django.middleware import get_default_client

    with override_settings(
        IAM_SDK={
            "ENDPOINT": "https://iam.example.test",
            "CLIENT_ID": "confidential-client",
            "CLIENT_SECRET": "fixture-secret",
            "RESOURCE_AUDIENCE": "api://orders",
        }
    ):
        client = get_default_client()
    try:
        assert client.config.resource_audience == "api://orders"
        assert client.config.client_id == "confidential-client"
        assert not hasattr(client.config, "audience")
    finally:
        asyncio.run(client.close())


def test_django_middleware_and_permission_decorator() -> None:
    server = MockIamServer().given_role("admin", "orders:read")
    iam = server.client()
    token = server.issue_token("u1", roles=["admin"])
    factory = RequestFactory()

    @require_permission("orders", "read")
    def view(request: HttpRequest) -> JsonResponse:
        return JsonResponse({"user": request.iam_context.user_id})

    with override_settings(IAM_SDK={"CLIENT": iam}):
        middleware = IamAuthenticationMiddleware(view)
        request = factory.get("/orders", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = middleware(request)

    assert response.status_code == 200
    assert json.loads(response.content) == {"user": "u1"}


def test_django_decorators_deny_missing_permission_and_step_up() -> None:
    server = MockIamServer().given_role("viewer", "orders:read")
    iam = server.client()
    token = server.issue_token("u1", roles=["viewer"])
    factory = RequestFactory()

    @require_permission("orders", "create")
    def create_view(request: HttpRequest) -> JsonResponse:
        return JsonResponse({"ok": True})

    @require_step_up("urn:iam:acr:mfa")
    def transfer_view(request: HttpRequest) -> JsonResponse:
        return JsonResponse({"ok": True})

    with override_settings(IAM_SDK={"CLIENT": iam}):
        auth_create = IamAuthenticationMiddleware(create_view)
        auth_transfer = IamAuthenticationMiddleware(transfer_view)
        create_response = auth_create(factory.post("/orders", HTTP_AUTHORIZATION=f"Bearer {token}"))
        transfer_response = auth_transfer(
            factory.post("/transfer", HTTP_AUTHORIZATION=f"Bearer {token}")
        )

    assert create_response.status_code == 403
    assert transfer_response.status_code == 403
    assert json.loads(transfer_response.content)["code"] == "STEP_UP_REQUIRED"


def test_django_no_impersonation_guard() -> None:
    server = MockIamServer().given_role("admin", "orders:*")
    iam = server.client()
    token = server.issue_token(
        "u1",
        roles=["admin"],
        extra_claims={"act": {"sub": "admin-actor"}},
    )
    factory = RequestFactory()

    @require_no_impersonation()
    def view(request: HttpRequest) -> JsonResponse:
        return JsonResponse({"ok": True})

    with override_settings(IAM_SDK={"CLIENT": iam}):
        middleware = IamAuthenticationMiddleware(view)
        response = middleware(factory.post("/danger", HTTP_AUTHORIZATION=f"Bearer {token}"))

    assert response.status_code == 403
    assert json.loads(response.content)["code"] == "FORBIDDEN"
