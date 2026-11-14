from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from contextlib import contextmanager

import django
import httpx
import pytest
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

from axis_vertex import IamClient  # noqa: E402
from axis_vertex.django import (  # noqa: E402
    IamAuthenticationMiddleware,
    require_no_impersonation,
    require_permission,
    require_step_up,
)
from axis_vertex.testing import MockIamServer  # noqa: E402


@contextmanager
def django_client(server: MockIamServer) -> Iterator[IamClient]:
    """Keep Django's synchronous pool separate from the caller-owned async pool."""
    async_http = server.http_client()
    sync_clients: list[httpx.AsyncClient] = []
    async_requests: list[str] = []

    async def record_async_request(request: httpx.Request) -> None:
        async_requests.append(request.url.path)

    async_http.event_hooks["request"].append(record_async_request)

    def sync_factory() -> httpx.AsyncClient:
        sync_http = server.http_client()
        assert sync_http is not async_http
        sync_clients.append(sync_http)
        return sync_http

    iam = IamClient(
        server.config(),
        http_client=async_http,
        sync_http_client_factory=sync_factory,
    )
    try:
        yield iam
    finally:
        try:
            iam.close_sync()
            assert len(sync_clients) <= 1
            assert all(client.is_closed for client in sync_clients)
            assert not async_http.is_closed
            assert async_requests == []
        finally:
            asyncio.run(async_http.aclose())
        assert async_http.is_closed


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
    token = server.issue_token("u1", roles=["admin"])
    factory = RequestFactory()

    @require_permission("orders", "read")
    def view(request: HttpRequest) -> JsonResponse:
        return JsonResponse({"user": request.iam_context.user_id})

    with django_client(server) as iam, override_settings(IAM_SDK={"CLIENT": iam}):
        middleware = IamAuthenticationMiddleware(view)
        request = factory.get("/orders", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = middleware(request)

    assert response.status_code == 200
    assert json.loads(response.content) == {"user": "u1"}


def test_django_decorators_deny_missing_permission_and_step_up() -> None:
    server = MockIamServer().given_role("viewer", "orders:read")
    token = server.issue_token("u1", roles=["viewer"])
    factory = RequestFactory()

    @require_permission("orders", "create")
    def create_view(request: HttpRequest) -> JsonResponse:
        return JsonResponse({"ok": True})

    @require_step_up("urn:iam:acr:mfa")
    def transfer_view(request: HttpRequest) -> JsonResponse:
        return JsonResponse({"ok": True})

    with django_client(server) as iam, override_settings(IAM_SDK={"CLIENT": iam}):
        auth_create = IamAuthenticationMiddleware(create_view)
        auth_transfer = IamAuthenticationMiddleware(transfer_view)
        create_response = auth_create(factory.post("/orders", HTTP_AUTHORIZATION=f"Bearer {token}"))
        transfer_response = auth_transfer(
            factory.post("/transfer", HTTP_AUTHORIZATION=f"Bearer {token}")
        )

    assert create_response.status_code == 403
    assert json.loads(create_response.content)["code"] == "FORBIDDEN"
    assert transfer_response.status_code == 403
    assert json.loads(transfer_response.content)["code"] == "STEP_UP_REQUIRED"


def test_django_no_impersonation_guard() -> None:
    server = MockIamServer().given_role("admin", "orders:*")
    token = server.issue_token(
        "u1",
        roles=["admin"],
        extra_claims={"act": {"sub": "admin-actor"}},
    )
    factory = RequestFactory()

    @require_no_impersonation()
    def view(request: HttpRequest) -> JsonResponse:
        return JsonResponse({"ok": True})

    with django_client(server) as iam, override_settings(IAM_SDK={"CLIENT": iam}):
        middleware = IamAuthenticationMiddleware(view)
        response = middleware(factory.post("/danger", HTTP_AUTHORIZATION=f"Bearer {token}"))

    assert response.status_code == 403
    assert json.loads(response.content)["code"] == "FORBIDDEN"


@pytest.mark.parametrize("rejection", ["missing", "wrong_scheme", "malformed", "expired"])
def test_django_rejects_auth_without_leaking_adjacent_request_identity(rejection: str) -> None:
    server = MockIamServer().given_role("reader", "orders:read")
    token_u1 = server.issue_token("u1", roles=["reader"])
    token_u2 = server.issue_token("u2", roles=["reader"])
    token_denied = server.issue_token("u3", roles=[])
    authorization = {
        "missing": "",
        "wrong_scheme": "Basic invalid",
        "malformed": "Bearer not-a-jwt",
        "expired": f"Bearer {server.expired_token('expired-user')}",
    }[rejection]
    factory = RequestFactory()
    called_users: list[str] = []

    @require_permission("orders", "read")
    def view(request: HttpRequest) -> JsonResponse:
        called_users.append(request.iam_context.user_id)
        return JsonResponse({"user": request.iam_context.user_id})

    with django_client(server) as iam, override_settings(IAM_SDK={"CLIENT": iam}):
        middleware = IamAuthenticationMiddleware(view)
        first = factory.get("/orders", HTTP_AUTHORIZATION=f"Bearer {token_u1}")
        assert json.loads(middleware(first).content) == {"user": "u1"}

        rejected = factory.get("/orders", HTTP_AUTHORIZATION=authorization)
        rejection_response = middleware(rejected)
        assert rejection_response.status_code == 401
        assert json.loads(rejection_response.content)["code"] == "UNAUTHORIZED"
        assert not hasattr(rejected, "iam_context")
        assert called_users == ["u1"]

        denied = factory.get("/orders", HTTP_AUTHORIZATION=f"Bearer {token_denied}")
        denied_response = middleware(denied)
        assert denied_response.status_code == 403
        assert json.loads(denied_response.content)["code"] == "FORBIDDEN"
        assert denied.iam_context.user_id == "u3"
        assert not denied.iam_context.has_permission("orders", "read")
        assert called_users == ["u1"]

        second = factory.get("/orders", HTTP_AUTHORIZATION=f"Bearer {token_u2}")
        second_response = middleware(second)
        assert second_response.status_code == 200
        assert json.loads(second_response.content) == {"user": "u2"}
        assert first.iam_context.user_id == "u1"
        assert called_users == ["u1", "u2"]


def test_django_sync_transport_is_lazy_reused_and_closed_with_separate_async_ownership() -> None:
    server = MockIamServer().given_role("reader", "orders:read")
    async_http = server.http_client()
    sync_clients: list[httpx.AsyncClient] = []

    def sync_factory() -> httpx.AsyncClient:
        client = server.http_client()
        sync_clients.append(client)
        return client

    iam = IamClient(
        server.config(), http_client=async_http, sync_http_client_factory=sync_factory
    )
    token = server.issue_token("u1", roles=["reader"])
    factory = RequestFactory()

    @require_permission("orders", "read")
    def view(request: HttpRequest) -> JsonResponse:
        return JsonResponse({"user": request.iam_context.user_id})

    try:
        with override_settings(IAM_SDK={"CLIENT": iam}):
            middleware = IamAuthenticationMiddleware(view)
            assert sync_clients == []
            for _ in range(2):
                response = middleware(factory.get("/orders", HTTP_AUTHORIZATION=f"Bearer {token}"))
                assert response.status_code == 200
                assert json.loads(response.content) == {"user": "u1"}
            assert len(sync_clients) == 1
            assert sync_clients[0] is not async_http
            assert not sync_clients[0].is_closed
            assert not async_http.is_closed
    finally:
        try:
            iam.close_sync()
            assert all(client.is_closed for client in sync_clients)
            assert not async_http.is_closed
        finally:
            asyncio.run(async_http.aclose())
    assert async_http.is_closed
    with pytest.raises(RuntimeError, match="Synchronous IAM client is closed"):
        iam.authenticate_sync(token)
