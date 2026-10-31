from __future__ import annotations

from dataclasses import fields
from inspect import signature

import pytest

from axis_vertex import IamConfig, IamConfigError, UnauthorizedError
from axis_vertex.testing import MockIamServer


def test_resource_audience_is_the_only_public_configuration_field() -> None:
    config = IamConfig(
        endpoint=" https://iam.example.test/ ",
        client_id=" confidential-client ",
        client_secret=" fixture-secret ",
        resource_audience=" api://orders ",
    )
    assert config.resource_audience == "api://orders"
    assert config.client_id == "confidential-client"
    assert config.endpoint == "https://iam.example.test"
    assert "audience" not in signature(IamConfig).parameters
    assert "audience" not in {field.name for field in fields(IamConfig)}
    assert not hasattr(config, "audience")


@pytest.mark.parametrize("resource_audience", ["", "api://orders"])
def test_retired_audience_keyword_is_rejected(resource_audience: str) -> None:
    with pytest.raises(TypeError, match="unexpected keyword argument 'audience'"):
        IamConfig(  # type: ignore[call-arg]
            endpoint="https://iam.example.test",
            client_id="confidential-client",
            client_secret="fixture-secret",
            resource_audience=resource_audience,
            audience="api://orders",
        )


@pytest.mark.parametrize("resource_audience", ["", "   "])
def test_missing_resource_audience_fails_without_client_id_fallback(resource_audience: str) -> None:
    with pytest.raises(IamConfigError, match="resource_audience is required"):
        IamConfig(
            endpoint="https://iam.example.test",
            client_id="confidential-client",
            client_secret="fixture-secret",
            resource_audience=resource_audience,
        )


@pytest.mark.asyncio
async def test_canonical_resource_audience_verifies_jwt_and_permissions() -> None:
    server = MockIamServer(resource_audience="api://orders").given_role("reader", "orders:read")
    client = server.client()
    try:
        token = server.issue_token("user-1", roles=["reader"], extra_claims={"app_id": "app-1"})
        claims = await client.verify_token(token)
        assert claims.subject == "user-1"
        assert claims.application_id == "app-1"
        context = await client.authenticate(token)
        assert context.has_permission("orders", "read")
        assert not context.has_permission("orders", "write")
        assert server.resolve_calls == 1
        for audience in [server.client_id, "api://other-application"]:
            wrong = server.issue_token("user-1", extra_claims={"app_id": "app-1", "aud": audience})
            with pytest.raises(UnauthorizedError):
                await client.verify_token(wrong)
        assert server.resolve_calls == 1
    finally:
        await client.close()
