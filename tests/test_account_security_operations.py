from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Coroutine
from pathlib import Path
from typing import cast

import httpx
import pytest

from axis_vertex import (
    AccountSecurityError,
    AccountSecurityProtocolError,
    AccountSecurityTransportError,
    AddIdentity,
    AuthorizationPurpose,
    EmailOtpReauthentication,
    IamClient,
    IamConfig,
    IdentifierKind,
    IdentityOperationComplete,
    IdentityOperationCreate,
    IdentityProviderAuthorize,
    LoginIdentifier,
    MfaOperationCreate,
    MfaOperationState,
    MfaOperationType,
    MfaProviderAuthorize,
    OperationStepUpVerify,
    OperationWebAuthnVerify,
    PasswordReauthentication,
    ProviderExchange,
    SensitiveDelivery,
    SessionImpact,
    TargetProofMethod,
    TransferDecision,
    UnauthorizedError,
)

ID = "00000000-0000-0000-0000-000000000001"
FIXTURE = cast(
    dict[str, object],
    json.loads((Path(__file__).parent / "fixtures/account-security-contract.json").read_text()),
)
SAMPLES = cast(dict[str, dict[str, object]], FIXTURE["samples"])
CASES = cast(list[dict[str, object]], FIXTURE["cases"])


def client(
    handler: Callable[[httpx.Request], httpx.Response]
    | Callable[[httpx.Request], Coroutine[None, None, httpx.Response]],
) -> IamClient:
    return IamClient(
        IamConfig(
            "https://iam.example.test",
            "configured-client",
            "configured-secret",
            resource_audience="api://fixture",
        ),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


CALLS: list[Callable[[IamClient], Awaitable[object]]] = [
    lambda sdk: sdk.list_account_identifiers("Bearer current-user"),
    lambda sdk: sdk.list_account_login_methods("Bearer current-user"),
    lambda sdk: sdk.list_linkable_identity_providers("Bearer current-user"),
    lambda sdk: sdk.create_identity_operation(
        "Bearer current-user",
        IdentityOperationCreate(
            4, AddIdentity(LoginIdentifier(IdentifierKind.EMAIL, "new@example.test"))
        ),
        "retained-key",
    ),
    lambda sdk: sdk.get_identity_operation("Bearer current-user", ID),
    lambda sdk: sdk.list_identity_transfers("Bearer current-user"),
    lambda sdk: sdk.reauthenticate_identity_operation(
        "Bearer current-user", ID, PasswordReauthentication("fixture-password")
    ),
    lambda sdk: sdk.challenge_identity_operation(
        "Bearer current-user", ID, TargetProofMethod.EMAIL_OTP
    ),
    lambda sdk: sdk.challenge_identity_current_account("Bearer current-user", ID, ID),
    lambda sdk: sdk.complete_identity_operation(
        "Bearer current-user", ID, IdentityOperationComplete(())
    ),
    lambda sdk: sdk.cancel_identity_operation("Bearer current-user", ID),
    lambda sdk: sdk.confirm_identity_transfer("Bearer current-user", ID, TransferDecision.ACCEPT),
    lambda sdk: sdk.authorize_identity_operation(
        "Bearer current-user",
        ID,
        IdentityProviderAuthorize(
            AuthorizationPurpose.CURRENT_ACCOUNT,
            "https://app.example.test/callback",
            "ccccccccccccccccccccccccccccccccccccccccccc",
            "S256",
            "identity:linked",
        ),
    ),
    lambda sdk: sdk.complete_identity_provider_authorization(
        "Bearer current-user",
        ID,
        ProviderExchange(ID, "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"),
    ),
    lambda sdk: sdk.get_mfa_capabilities("Bearer current-user"),
    lambda sdk: sdk.create_mfa_operation(
        "Bearer current-user", MfaOperationCreate(MfaOperationType.TOTP_ENROLL, 4), "retained-key"
    ),
    lambda sdk: sdk.get_mfa_operation("Bearer current-user", ID),
    lambda sdk: sdk.reauthenticate_mfa_operation(
        "Bearer current-user", ID, PasswordReauthentication("fixture-password")
    ),
    lambda sdk: sdk.challenge_mfa_operation("Bearer current-user", ID, ID),
    lambda sdk: sdk.authorize_mfa_operation(
        "Bearer current-user",
        ID,
        MfaProviderAuthorize(
            "identity:linked",
            "https://app.example.test/callback",
            "ccccccccccccccccccccccccccccccccccccccccccc",
            "S256",
        ),
    ),
    lambda sdk: sdk.complete_mfa_provider_authorization(
        "Bearer current-user",
        ID,
        ProviderExchange(ID, "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"),
    ),
    lambda sdk: sdk.begin_totp_enrollment_operation("Bearer current-user", ID),
    lambda sdk: sdk.complete_mfa_operation("Bearer current-user", ID, None),
    lambda sdk: sdk.cancel_mfa_operation("Bearer current-user", ID),
    lambda sdk: sdk.start_identity_operation_step_up("Bearer current-user", ID),
    lambda sdk: sdk.verify_identity_operation_step_up(
        "Bearer current-user", ID, OperationStepUpVerify("scoped-challenge", "123456")
    ),
    lambda sdk: sdk.start_identity_operation_webauthn(
        "Bearer current-user", ID, "scoped-challenge"
    ),
    lambda sdk: sdk.verify_identity_operation_webauthn(
        "Bearer current-user",
        ID,
        OperationWebAuthnVerify("scoped-challenge", "scoped-request", "fixture-credential"),
    ),
    lambda sdk: sdk.start_mfa_operation_step_up("Bearer current-user", ID),
    lambda sdk: sdk.verify_mfa_operation_step_up(
        "Bearer current-user", ID, OperationStepUpVerify("scoped-challenge", "123456")
    ),
    lambda sdk: sdk.start_mfa_operation_webauthn("Bearer current-user", ID, "scoped-challenge"),
    lambda sdk: sdk.verify_mfa_operation_webauthn(
        "Bearer current-user",
        ID,
        OperationWebAuthnVerify("scoped-challenge", "scoped-request", "fixture-credential"),
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("index", range(len(CALLS)))
async def test_public_operation_matrix(index: int) -> None:
    expected = CASES[index]
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.method == expected["method"]
        assert request.url.path == expected["path"]
        assert request.headers["Authorization"] == "Bearer current-user"
        assert "configured-secret" not in str(request.headers)
        assert "X-IAM-Client-Secret" not in request.headers
        if expected["body"] is not None:
            assert json.loads(request.content) == expected["body"]
        else:
            assert not request.content
        if str(expected["name"]).startswith("create_"):
            assert request.headers["Idempotency-Key"] == "retained-key"
        return httpx.Response(200, json=expected["response"])

    sdk = client(handler)
    try:
        assert await CALLS[index](sdk) is not None
        assert calls == 1
    finally:
        await sdk._http.aclose()


@pytest.mark.asyncio
async def test_lifecycle_sensitive_delivery_and_session_recovery() -> None:
    pending = dict(SAMPLES["MfaOperation"])
    committed = dict(
        pending,
        type="RECOVERY_CODES_GENERATE",
        state="COMMITTED",
        result=dict(
            SAMPLES["MfaOperationResult"],
            sessionImpact="UNCHANGED",
            recoveryCount=1,
            recoveryBatchId=ID,
        ),
    )
    bodies = [
        dict(operation=pending, delivery="AVAILABLE", material=SAMPLES["TotpMaterial"]),
        dict(operation=pending, delivery="ALREADY_DELIVERED", material=None),
        dict(operation=committed, delivery="AVAILABLE", recoveryCodes=SAMPLES["RecoveryCodes"]),
        dict(operation=committed, delivery="ALREADY_DELIVERED", recoveryCodes=None),
        committed,
        dict(pending, state="CANCELLED"),
    ]
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=bodies.pop(0))

    sdk = client(handler)
    first = await sdk.begin_totp_enrollment_operation("current-user", ID)
    repeated = await sdk.begin_totp_enrollment_operation("current-user", ID)
    assert first.material is not None and first.material.secret == "fixture-material"
    assert repeated.material is None and repeated.delivery is SensitiveDelivery.ALREADY_DELIVERED
    assert "fixture-material" not in repr(first)
    completed = await sdk.complete_mfa_operation("current-user", ID)
    replay = await sdk.complete_mfa_operation("current-user", ID)
    assert completed.recovery_codes is not None and completed.recovery_codes.codes == (
        "fixture-code",
    )
    assert replay.recovery_codes is None and "fixture-code" not in repr(completed)
    recovered = await sdk.get_mfa_operation("new-session-same-owner", ID)
    assert (
        recovered.result is not None and recovered.result.session_impact is SessionImpact.UNCHANGED
    )
    assert (await sdk.cancel_mfa_operation("current-user", ID)).state is MfaOperationState.CANCELLED
    assert len(seen) == 6 and not bodies
    await sdk._http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code,status,retry,delay",
    [
        ("OPERATION_PROOF_INVALID", 400, None, None),
        ("OPERATION_PROOF_RATE_LIMITED", 429, "60", 60),
        ("OPERATION_CANCELLED", 410, "-1", None),
        ("OPERATION_RESULT_EXPIRED", 410, "99999999999999", None),
        ("STALE_LOGIN_METHOD_VERSION", 409, "1.2", None),
        ("REAUTH_REQUIRED", 403, None, None),
        ("NOT_FOUND", 404, None, None),
        ("SESSION_REVOKED", 401, None, None),
    ],
)
async def test_typed_error_no_retry(
    code: str, status: int, retry: str | None, delay: int | None
) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            status,
            json={"status": status, "error": code, "message": "provider-secret-never-surface"},
            headers={} if retry is None else {"Retry-After": retry},
        )

    sdk = client(handler)
    with pytest.raises(AccountSecurityError) as caught:
        await sdk.complete_mfa_operation("current-user", ID)
    assert caught.value.code == code and caught.value.status_code == status
    assert caught.value.retry_after_seconds == delay
    assert "provider-secret" not in str(caught.value) and calls == 1
    await sdk._http.aclose()


@pytest.mark.asyncio
async def test_unknown_mutation_result_has_no_automatic_replay() -> None:
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.method)
        if req.method == "POST":
            raise httpx.ReadError("transport diagnostic must not escape")
        return httpx.Response(200, json=SAMPLES["MfaOperation"])

    sdk = client(handler)
    with pytest.raises(AccountSecurityTransportError) as caught:
        await sdk.complete_mfa_operation("current-user", ID)
    assert caught.value.outcome_unknown and "diagnostic" not in str(caught.value)
    assert (await sdk.get_mfa_operation("current-user", ID)).id == ID
    assert calls == ["POST", "GET"]
    await sdk._http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "wire",
    [
        {},
        {"loginMethodVersion": 4},
        {"loginMethodVersion": True},
        dict(SAMPLES["MfaCapabilities"], totpEnroll=None),
        dict(
            SAMPLES["MfaCapabilities"],
            totpEnroll={"allowed": True, "proofRequirement": "STEP_UP", "proofOptions": []},
        ),
    ],
)
async def test_strict_capability_response(wire: dict[str, object]) -> None:
    sdk = client(lambda _: httpx.Response(200, json=wire))
    with pytest.raises(AccountSecurityProtocolError):
        await sdk.get_mfa_capabilities("current-user")
    await sdk._http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", [b'{"id":1,"id":2}', b"{} {}", b"null", b"[]"])
async def test_malformed_json_response(raw: bytes) -> None:
    sdk = client(lambda _: httpx.Response(200, content=raw))
    with pytest.raises(AccountSecurityProtocolError):
        await sdk.get_mfa_operation("current-user", ID)
    await sdk._http.aclose()


@pytest.mark.asyncio
async def test_strict_request_null_omission_and_auth_negatives() -> None:
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return httpx.Response(
            403, json={"status": 403, "error": "FORBIDDEN", "message": "no current user"}
        )

    sdk = client(handler)
    with pytest.raises(UnauthorizedError):
        await sdk.get_mfa_capabilities("")
    with pytest.raises(ValueError):
        await sdk.get_mfa_operation("current-user", "../escape")
    with pytest.raises(ValueError):
        await sdk.create_mfa_operation(
            "current-user", MfaOperationCreate(MfaOperationType.TOTP_ENROLL, -1), "key"
        )
    with pytest.raises(ValueError):
        await sdk.create_mfa_operation(
            "current-user", MfaOperationCreate(MfaOperationType.TOTP_ENROLL, 4), ""
        )
    with pytest.raises(ValueError):
        await sdk.complete_mfa_operation("current-user", ID, "")
    assert not calls
    with pytest.raises(AccountSecurityError):
        await sdk.reauthenticate_mfa_operation(
            "machine-token", ID, EmailOtpReauthentication(ID, "123456")
        )
    assert json.loads(calls[-1].content) == {
        "method": "EMAIL_OTP",
        "challengeId": ID,
        "code": "123456",
    }
    assert calls[-1].headers["Authorization"] == "Bearer machine-token"
    await sdk._http.aclose()


@pytest.mark.asyncio
async def test_cancellation_propagates_and_sync_rejects_active_loop() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        raise asyncio.CancelledError

    sdk = client(handler)
    with pytest.raises(asyncio.CancelledError):
        await sdk.get_mfa_capabilities("current-user")
    with pytest.raises(RuntimeError):
        sdk.get_mfa_capabilities_sync("current-user")
    await sdk._http.aclose()


def test_sync_public_entry() -> None:
    sdk = IamClient(
        IamConfig(
            "https://iam.example.test",
            "client",
            "fixture-secret",
            resource_audience="api://fixture",
        ),
        sync_http_client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(200, json=SAMPLES["MfaCapabilities"])
            )
        ),
    )
    assert sdk.get_mfa_capabilities_sync("current-user").login_method_version == 4
    sdk.close_sync()
    asyncio.run(sdk.close())


@pytest.mark.asyncio
async def test_identity_payload_variants_and_same_key_recovery() -> None:
    from axis_vertex import (
        IdentityPayload,
        LinkIdentity,
        RemoveIdentity,
        ReplaceIdentity,
        SetPrimaryIdentity,
        TransferIdentity,
        UnlinkIdentity,
        VerifyIdentity,
    )

    payloads: list[tuple[IdentityPayload, str, dict[str, object]]] = [
        (
            AddIdentity(LoginIdentifier(IdentifierKind.EMAIL, "new@example.test")),
            "ADD",
            {"identifier": {"kind": "EMAIL", "value": "new@example.test"}},
        ),
        (VerifyIdentity(ID), "VERIFY", {"identifierId": ID}),
        (SetPrimaryIdentity(ID), "SET_PRIMARY", {"identifierId": ID}),
        (RemoveIdentity(ID), "REMOVE", {"identifierId": ID}),
        (
            ReplaceIdentity(ID, LoginIdentifier(IdentifierKind.USERNAME, "new-name"), False),
            "REPLACE",
            {
                "identifierId": ID,
                "replacement": {"kind": "USERNAME", "value": "new-name"},
                "removeOld": False,
            },
        ),
        (LinkIdentity(ID), "LINK", {"providerId": ID}),
        (UnlinkIdentity("identity:linked"), "UNLINK", {"methodId": "identity:linked"}),
        (TransferIdentity(ID, ID), "TRANSFER", {"identifierId": ID, "targetUserId": ID}),
    ]
    bodies: list[dict[str, object]] = []
    keys: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        bodies.append(cast(dict[str, object], json.loads(req.content)))
        keys.append(req.headers["Idempotency-Key"])
        return httpx.Response(200, json=SAMPLES["IdentityOperation"])

    sdk = client(handler)
    for payload, kind, body in payloads:
        first = await sdk.create_identity_operation(
            "current-user", IdentityOperationCreate(4, payload), "same-request-key"
        )
        recovered = await sdk.create_identity_operation(
            "current-user", IdentityOperationCreate(4, payload), "same-request-key"
        )
        assert first.id == recovered.id == ID
        assert bodies[-1] == {"type": kind, "expectedLoginMethodVersion": 4, "payload": body}
    assert keys == ["same-request-key"] * 16
    await sdk._http.aclose()


@pytest.mark.asyncio
async def test_transfer_counterpart_nullable_completion_and_status_no_material() -> None:
    body = dict(
        SAMPLES["IdentityOperation"],
        type="TRANSFER",
        state="COMMITTED",
        result=None,
        completion=None,
    )
    sdk = client(lambda _: httpx.Response(200, json=body))
    assert (await sdk.get_identity_operation("counterpart-user", ID)).completion is None
    await sdk._http.aclose()
    leaked = dict(SAMPLES["MfaOperation"], material=SAMPLES["TotpMaterial"])
    sdk = client(lambda _: httpx.Response(200, json=leaked))
    with pytest.raises(AccountSecurityProtocolError):
        await sdk.get_mfa_operation("current-user", ID)
    await sdk._http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "proof",
    [
        {"method": "PASSWORD"},
        {"method": "EMAIL_OTP", "identifierId": ID, "maskedIdentifier": "m***@example.test"},
        {"method": "PROVIDER", "methodId": "idp:linked", "displayName": "Example"},
        {"method": "STEP_UP_PROOF", "availableMethods": ["TOTP", "WEBAUTHN"]},
    ],
)
async def test_executable_proof_option_shapes(proof: dict[str, object]) -> None:
    body = dict(SAMPLES["MfaCapabilities"])
    body["totpEnroll"] = {
        "allowed": True,
        "reasonCode": None,
        "proofRequirement": "REAUTHENTICATION",
        "proofOptions": [proof],
    }
    sdk = client(lambda _: httpx.Response(200, json=body))
    assert len((await sdk.get_mfa_capabilities("current-user")).totp_enroll.proof_options) == 1
    await sdk._http.aclose()
    body["totpEnroll"] = {
        "allowed": True,
        "reasonCode": None,
        "proofRequirement": "REAUTHENTICATION",
        "proofOptions": [dict(proof, invalidReference="not-allowed")],
    }
    sdk = client(lambda _: httpx.Response(200, json=body))
    assert len((await sdk.get_mfa_capabilities("current-user")).totp_enroll.proof_options) == 1
    await sdk._http.aclose()
    forbidden = "identifierId" if proof["method"] == "PROVIDER" else "methodId"
    body["totpEnroll"] = {
        "allowed": True,
        "reasonCode": None,
        "proofRequirement": "REAUTHENTICATION",
        "proofOptions": [dict(proof, **{forbidden: ID})],
    }
    sdk = client(lambda _: httpx.Response(200, json=body))
    with pytest.raises(AccountSecurityProtocolError):
        await sdk.get_mfa_capabilities("current-user")
    await sdk._http.aclose()
