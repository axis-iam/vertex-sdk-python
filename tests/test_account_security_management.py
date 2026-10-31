"""P-001/P-002 public SDK wire proof, not real-Backend policy evaluation."""

import json
from pathlib import Path
from typing import cast

import httpx
import pytest

from axis_vertex import (
    AccountSecurityProtocolError,
    IamClient,
    IamConfig,
    IdentifierAction,
    IdentifierDenial,
    IdentifierKind,
    IdentifierRequirement,
    ProviderExchange,
)

ID = "00000000-0000-0000-0000-000000000001"
DATA = cast(
    dict[str, object],
    json.loads((Path(__file__).parent / "fixtures/account-security-management.json").read_text()),
)


def vectors(key: str) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], DATA[key])


def fixture_client(wire: dict[str, object]) -> tuple[IamClient, httpx.AsyncClient]:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer current-user"
        return httpx.Response(200, json=wire)

    http = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    return IamClient(
        IamConfig(
            "https://iam.example.test",
            "client",
            "fixture-secret",
            resource_audience="api://fixture",
        ),
        http_client=http,
    ), http


@pytest.mark.asyncio
@pytest.mark.parametrize("wire", vectors("validOperations"))
async def test_provider_target_nullable_and_additive_wire(wire: dict[str, object]) -> None:
    sdk, http = fixture_client(wire)
    try:
        operation = await sdk.get_identity_operation("current-user", ID)
        expected = cast(dict[str, object] | None, wire.get("providerTarget"))
        if expected is None:
            assert operation.provider_target is None
        else:
            target = operation.provider_target
            assert target is not None
            assert target.provider_id == expected["providerId"]
            assert target.reference == expected["reference"]
            assert target.masked_display_name == expected.get("maskedDisplayName")
            assert target.masked_email == expected.get("maskedEmail")
            assert not hasattr(target, "future")
    finally:
        await http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("wire", vectors("invalidOperations"))
async def test_provider_target_invalid_known_fields(wire: dict[str, object]) -> None:
    sdk, http = fixture_client(wire)
    try:
        with pytest.raises(AccountSecurityProtocolError):
            await sdk.get_identity_operation("current-user", ID)
    finally:
        await http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("wire", vectors("validSnapshots"))
async def test_authenticated_management_snapshot(wire: dict[str, object]) -> None:
    sdk, http = fixture_client(wire)
    try:
        snapshot = await sdk.list_account_identifiers("current-user")
        if wire.get("management") is None:
            assert snapshot.management is None
            assert all(item.capabilities is None for item in snapshot.items)
            return
        assert snapshot.management is not None
        assert set(snapshot.management.add) == set(IdentifierKind)
        assert len(snapshot.management.proof_options) == 4
        email = snapshot.management.add[IdentifierKind.EMAIL]
        assert email.allowed
        assert IdentifierRequirement.TARGET_EMAIL_OTP in email.requirements
        capabilities = snapshot.items[0].capabilities
        assert capabilities is not None
        assert set(capabilities) == set(IdentifierAction)
        assert capabilities[IdentifierAction.REMOVE].replacement_primary_ids == (
            "00000000-0000-0000-0000-000000000002",
        )
        transfer = capabilities[IdentifierAction.TRANSFER]
        assert not transfer.allowed
        assert transfer.unavailable_reasons == (IdentifierDenial.IDENTIFIER_RANGE_REJECTED,)
        assert capabilities[IdentifierAction.REMOVE].allowed  # existing range is grandfathered
        assert not hasattr(email, "future")
    finally:
        await http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("wire", vectors("invalidSnapshots"))
async def test_management_missing_malformed_known_fields(wire: dict[str, object]) -> None:
    sdk, http = fixture_client(wire)
    try:
        with pytest.raises(AccountSecurityProtocolError):
            await sdk.list_account_identifiers("current-user")
    finally:
        await http.aclose()


@pytest.mark.asyncio
async def test_adapter_target_callback_replay_and_committed_status() -> None:
    calls: list[str] = []
    ready, committed = vectors("validOperations")[:2]

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        assert request.headers["Authorization"] == "Bearer current-user"
        if request.method == "POST":
            assert request.url.path.endswith("/provider-callback")
            assert json.loads(request.content) == {"authorizationId": ID, "codeVerifier": "v" * 43}
        return httpx.Response(200, json=ready if len(calls) < 3 else committed)

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as http:
        sdk = IamClient(
            IamConfig(
                "https://iam.example.test",
                "client",
                "fixture-secret",
                resource_audience="api://fixture",
            ),
            http_client=http,
        )
        first = await sdk.complete_identity_provider_authorization(
            "current-user", ID, ProviderExchange(ID, "v" * 43)
        )
        replay = await sdk.get_identity_operation("current-user", ID)
        terminal = await sdk.get_identity_operation("current-user", ID)
        assert first.provider_target == replay.provider_target == terminal.provider_target
        assert len(calls) == 3  # no catalog, linked-identity lookup or browser orchestration


@pytest.mark.asyncio
@pytest.mark.parametrize("wire", vectors("invalidMfaStatus"))
async def test_status_never_redelivers_reserved_sensitive_fields(wire: dict[str, object]) -> None:
    sdk, http = fixture_client(wire)
    try:
        with pytest.raises(AccountSecurityProtocolError):
            await sdk.get_mfa_operation("current-user", ID)
    finally:
        await http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("wire", vectors("validExtendedMfa"))
async def test_mfa_future_fields_remain_compatible(wire: dict[str, object]) -> None:
    sdk, http = fixture_client(wire)
    try:
        assert (await sdk.get_mfa_capabilities("current-user")).login_method_version == 4
    finally:
        await http.aclose()
