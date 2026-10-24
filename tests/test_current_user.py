from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from axis_vertex import CurrentUser, IamApiError, IamClient, IamConfig


def fixture() -> dict[str, object]:
    return json.loads((Path(__file__).parent / "fixtures/current-user.json").read_text())


def test_current_user_nullable_context_and_impersonation() -> None:
    view = CurrentUser.from_mapping(fixture())
    assert view.email is None
    assert view.authentication_context.workspace_selection_required
    assert view.authentication_context.workspace_id is None
    assert view.authentication_context.auth_time.isoformat() == "2026-10-20T01:02:03+00:00"
    assert not hasattr(view, "roles")
    data = fixture()
    data["authenticationContext"]["impersonation"] = {
        "actorId": "actor",
        "impersonationId": "imp-session",
    }
    assert (
        CurrentUser.from_mapping(data).authentication_context.impersonation.impersonation_id
        == "imp-session"
    )


@pytest.mark.parametrize(
    "key",
    [
        "applicationId",
        "clientId",
        "sessionId",
        "subjectType",
        "workspaceId",
        "authTime",
        "impersonation",
        "authenticationMethods",
    ],
)
def test_current_user_missing_binding_rejected(key: str) -> None:
    data = fixture()
    del data["authenticationContext"][key]
    with pytest.raises(ValueError):
        CurrentUser.from_mapping(data)


@pytest.mark.parametrize(
    "patch",
    [
        {"authTime": "yesterday"},
        {"authTime": "2026-10-20T00:00:00"},
        {"impersonation": {"actorId": "actor"}},
        {"workspaceId": "ws"},
        {"organizationSlug": "unbound"},
        {"subjectType": "MACHINE"},
    ],
)
def test_current_user_invalid_context_rejected(patch: dict[str, object]) -> None:
    data = fixture()
    data["authenticationContext"].update(patch)
    with pytest.raises(ValueError):
        CurrentUser.from_mapping(data)


@pytest.mark.asyncio
async def test_current_user_http_bearer_and_failure_status() -> None:
    status = 200

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/auth/me"
        assert request.headers["authorization"] == "Bearer contract-fixture"
        assert "X-IAM-Client-Id" not in request.headers
        return httpx.Response(status, json=fixture() if status == 200 else {"message": "private"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = IamClient(
            IamConfig(
                endpoint="https://iam.invalid",
                client_id="test-client",
                client_secret="fixture",
                resource_audience="api://fixture",
            ),
            http_client=http,
        )
        assert (await client.get_current_user("contract-fixture")).email is None
        for status in (302, 401, 403, 503):
            with pytest.raises(IamApiError) as raised:
                await client.get_current_user("contract-fixture")
            assert raised.value.status_code == status
            assert "private" not in str(raised.value)
