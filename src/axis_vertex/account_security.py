"""Typed current-user security operations. No implicit retries or credential persistence."""

from __future__ import annotations

import json
import re
import types
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from enum import StrEnum
from typing import TypeAliasType, cast, get_args, get_origin, get_type_hints
from uuid import UUID

from .errors import IamSdkError


class AccountSecurityProtocolError(IamSdkError):
    """The producer returned a malformed or unsupported security contract."""


class AccountSecurityError(IamSdkError):
    """Stable producer code, HTTP status and validated retry delay; no raw body."""

    def __init__(self, status_code: int, code: str, retry_after_seconds: int | None) -> None:
        self.status_code = status_code
        self.code = code
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"Account security request rejected: HTTP {status_code} {code}")


class AccountSecurityTransportError(IamSdkError):
    """No response; mutations may have committed. Query the saved operation identity."""

    def __init__(self, *, outcome_unknown: bool) -> None:
        self.outcome_unknown = outcome_unknown
        super().__init__("Account security transport failed; no automatic replay")


class MfaOperationType(StrEnum):
    TOTP_ENROLL = "TOTP_ENROLL"
    TOTP_DISABLE = "TOTP_DISABLE"
    RECOVERY_CODES_GENERATE = "RECOVERY_CODES_GENERATE"


class MfaOperationState(StrEnum):
    AWAITING_REAUTH = "AWAITING_REAUTH"
    READY = "READY"
    AWAITING_CONFIRMATION = "AWAITING_CONFIRMATION"
    COMMITTED = "COMMITTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


class ProofRequirement(StrEnum):
    SESSION = "SESSION"
    REAUTHENTICATION = "REAUTHENTICATION"
    STEP_UP = "STEP_UP"


class ProofMethod(StrEnum):
    PASSWORD = "PASSWORD"
    EMAIL_OTP = "EMAIL_OTP"
    PROVIDER = "PROVIDER"
    STEP_UP_PROOF = "STEP_UP_PROOF"


class SessionImpact(StrEnum):
    UNCHANGED = "UNCHANGED"
    CURRENT_SESSION_RETAINED = "CURRENT_SESSION_RETAINED"
    REAUTHENTICATE = "REAUTHENTICATE"


class SensitiveDelivery(StrEnum):
    AVAILABLE = "AVAILABLE"
    ALREADY_DELIVERED = "ALREADY_DELIVERED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class IdentityOperationType(StrEnum):
    ADD = "ADD"
    VERIFY = "VERIFY"
    SET_PRIMARY = "SET_PRIMARY"
    REMOVE = "REMOVE"
    REPLACE = "REPLACE"
    LINK = "LINK"
    UNLINK = "UNLINK"
    TRANSFER = "TRANSFER"
    ACCOUNT_DELETE = "ACCOUNT_DELETE"


class IdentityOperationState(StrEnum):
    AWAITING_REAUTH = "AWAITING_REAUTH"
    AWAITING_PROOF = "AWAITING_PROOF"
    READY = "READY"
    COMMITTED = "COMMITTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"


class IdentifierKind(StrEnum):
    USERNAME = "USERNAME"
    EMAIL = "EMAIL"
    PHONE = "PHONE"


class IdentifierAction(StrEnum):
    VERIFY = "VERIFY"
    SET_PRIMARY = "SET_PRIMARY"
    REMOVE = "REMOVE"
    REPLACE = "REPLACE"
    TRANSFER = "TRANSFER"


class IdentifierDenial(StrEnum):
    ACCOUNT_INACTIVE = "ACCOUNT_INACTIVE"
    MANAGED_IDENTIFIER = "MANAGED_IDENTIFIER"
    METHOD_UNAVAILABLE = "METHOD_UNAVAILABLE"
    REAUTH_METHOD_UNAVAILABLE = "REAUTH_METHOD_UNAVAILABLE"
    TARGET_PROOF_UNAVAILABLE = "TARGET_PROOF_UNAVAILABLE"
    IDENTIFIER_ALREADY_EXISTS = "IDENTIFIER_ALREADY_EXISTS"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ALREADY_VERIFIED = "ALREADY_VERIFIED"
    ALREADY_PRIMARY = "ALREADY_PRIMARY"
    IDENTIFIER_UNVERIFIED = "IDENTIFIER_UNVERIFIED"
    IDENTIFIER_RANGE_REJECTED = "IDENTIFIER_RANGE_REJECTED"
    LAST_LOGIN_METHOD = "LAST_LOGIN_METHOD"
    PRIMARY_REPLACEMENT_UNAVAILABLE = "PRIMARY_REPLACEMENT_UNAVAILABLE"


class IdentifierRequirement(StrEnum):
    CURRENT_ACCOUNT_PROOF = "CURRENT_ACCOUNT_PROOF"
    NEW_IDENTIFIER = "NEW_IDENTIFIER"
    TARGET_EMAIL_OTP = "TARGET_EMAIL_OTP"
    TARGET_PHONE_OTP = "TARGET_PHONE_OTP"
    REPLACEMENT_PRIMARY = "REPLACEMENT_PRIMARY"
    REMOVE_OLD = "REMOVE_OLD"
    COUNTERPART_CONFIRMATION = "COUNTERPART_CONFIRMATION"
    REMAINING_LOGIN_PATH = "REMAINING_LOGIN_PATH"


class TargetProofMethod(StrEnum):
    EMAIL_OTP = "EMAIL_OTP"
    PHONE_OTP = "PHONE_OTP"


class AuthorizationPurpose(StrEnum):
    CURRENT_ACCOUNT = "CURRENT_ACCOUNT"
    TARGET_OWNERSHIP = "TARGET_OWNERSHIP"
    TRANSFER_COUNTERPART = "TRANSFER_COUNTERPART"


class TransferDecision(StrEnum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"


@dataclass(frozen=True, slots=True)
class OperationProofOption:
    method: ProofMethod
    identifier_id: str | None = None
    masked_identifier: str | None = None
    method_id: str | None = None
    display_name: str | None = None
    available_methods: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class OperationCompletion:
    completed_at: str
    final_login_method_version: int
    session_impact: SessionImpact


@dataclass(frozen=True, slots=True)
class MfaOperationResult:
    completed_at: str
    final_login_method_version: int
    session_impact: SessionImpact
    recovery_batch_id: str | None = None
    recovery_count: int | None = None


@dataclass(frozen=True, slots=True)
class MfaAction:
    allowed: bool
    proof_requirement: ProofRequirement
    proof_options: tuple[OperationProofOption, ...]
    reason_code: str | None = None


@dataclass(frozen=True, slots=True)
class MfaCapabilities:
    login_method_version: int
    totp_enroll: MfaAction
    totp_disable: MfaAction
    recovery_codes_generate: MfaAction


@dataclass(frozen=True, slots=True)
class MfaOperation:
    id: str
    type: MfaOperationType
    state: MfaOperationState
    created_at: str
    expires_at: str
    expected_login_method_version: int
    proof_requirement: ProofRequirement
    proof_options: tuple[OperationProofOption, ...]
    proof_satisfied: bool
    next_challenge_at: str | None = None
    reason_code: str | None = None
    result: MfaOperationResult | None = None


@dataclass(frozen=True, slots=True, repr=False)
class TotpMaterial:
    secret: str
    qr_code_uri: str
    issuer: str

    def __repr__(self) -> str:
        return "TotpMaterial[redacted]"


@dataclass(frozen=True, slots=True, repr=False)
class TotpBeginResult:
    operation: MfaOperation
    delivery: SensitiveDelivery
    material: TotpMaterial | None = None

    def __repr__(self) -> str:
        return "TotpBeginResult[redacted]"


@dataclass(frozen=True, slots=True)
class RecoveryCodesRemaining:
    remaining: int


@dataclass(frozen=True, slots=True, repr=False)
class RecoveryCodes:
    codes: tuple[str, ...]
    count: int

    def __repr__(self) -> str:
        return "RecoveryCodes[redacted]"


@dataclass(frozen=True, slots=True, repr=False)
class MfaCompletionResult:
    operation: MfaOperation
    delivery: SensitiveDelivery
    recovery_codes: RecoveryCodes | None = None

    def __repr__(self) -> str:
        return "MfaCompletionResult[redacted]"


@dataclass(frozen=True, slots=True)
class MfaChallengeResult:
    operation: MfaOperation
    challenge_id: str
    next_challenge_at: str


@dataclass(frozen=True, slots=True)
class IdentityRequiredProof:
    purpose: str
    methods: tuple[str, ...]
    strength: str
    satisfied: bool


@dataclass(frozen=True, slots=True)
class ProviderTarget:
    provider_id: str
    reference: str
    masked_display_name: str | None = None
    masked_email: str | None = None


@dataclass(frozen=True, slots=True)
class IdentityOperation:
    id: str
    type: IdentityOperationType
    state: IdentityOperationState
    expires_at: str
    required_proofs: tuple[IdentityRequiredProof, ...]
    proof_options: tuple[OperationProofOption, ...]
    result: dict[str, str] | None = None
    masked_identifier: str | None = None
    next_challenge_at: str | None = None
    completion: OperationCompletion | None = None
    provider_target: ProviderTarget | None = None


@dataclass(frozen=True, slots=True)
class IdentityChallengeResult:
    operation: IdentityOperation
    challenge_id: str
    next_challenge_at: str


@dataclass(frozen=True, slots=True)
class ProviderAuthorization:
    authorization_id: str
    authorization_url: str
    expires_at: str


@dataclass(frozen=True, slots=True)
class OperationStepUpChallenge:
    challenge_id: str
    available_methods: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OperationWebAuthnStart:
    request_id: str
    public_key: str


@dataclass(frozen=True, slots=True)
class IdentifierCapability:
    allowed: bool
    unavailable_reasons: tuple[IdentifierDenial, ...]
    requirements: tuple[IdentifierRequirement, ...]
    replacement_primary_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IdentifierManagement:
    add: dict[IdentifierKind, IdentifierCapability]
    proof_options: tuple[OperationProofOption, ...]


@dataclass(frozen=True, slots=True)
class AccountIdentifier:
    id: str
    kind: IdentifierKind
    display_value: str
    status: str
    verification_state: str
    is_primary: bool
    verified_at: str | None = None
    verification_source: str | None = None
    managed_by: str | None = None
    capabilities: dict[IdentifierAction, IdentifierCapability] | None = None


@dataclass(frozen=True, slots=True)
class AccountIdentifiers:
    login_method_version: int
    items: tuple[AccountIdentifier, ...]
    management: IdentifierManagement | None = None


@dataclass(frozen=True, slots=True)
class AccountLoginMethod:
    method_id: str
    kind: str
    roles: tuple[str, ...]
    status: str
    capabilities: dict[str, bool]
    unavailable_reasons: tuple[str, ...]
    identifier_id: str | None = None
    credential_id: str | None = None
    identity_id: str | None = None
    provider_id: str | None = None


@dataclass(frozen=True, slots=True)
class AccountLoginMethods:
    login_method_version: int
    methods: tuple[AccountLoginMethod, ...]


@dataclass(frozen=True, slots=True)
class LinkableIdentityProvider:
    id: str
    provider_type: str
    protocol: str
    display_name: str
    enabled: bool
    linked: bool
    supports_account_linking: bool
    can_link: bool
    can_reauthenticate: bool
    unavailable_reasons: tuple[str, ...]
    linked_at: str | None = None


@dataclass(frozen=True, slots=True)
class MfaOperationCreate:
    type: MfaOperationType
    expected_login_method_version: int


@dataclass(frozen=True, slots=True)
class LoginIdentifier:
    kind: IdentifierKind
    value: str
    region: str | None = None


@dataclass(frozen=True, slots=True)
class AddIdentity:
    identifier: LoginIdentifier


@dataclass(frozen=True, slots=True)
class VerifyIdentity:
    identifier_id: str


@dataclass(frozen=True, slots=True)
class SetPrimaryIdentity:
    identifier_id: str


@dataclass(frozen=True, slots=True)
class RemoveIdentity:
    identifier_id: str
    replacement_primary_id: str | None = None


@dataclass(frozen=True, slots=True)
class ReplaceIdentity:
    identifier_id: str
    replacement: LoginIdentifier
    remove_old: bool
    replacement_primary_id: str | None = None


@dataclass(frozen=True, slots=True)
class LinkIdentity:
    provider_id: str


@dataclass(frozen=True, slots=True)
class UnlinkIdentity:
    method_id: str


@dataclass(frozen=True, slots=True)
class TransferIdentity:
    identifier_id: str
    target_user_id: str
    source_replacement_primary_id: str | None = None


@dataclass(frozen=True, slots=True, repr=False)
class PasswordReauthentication:
    password: str

    def __repr__(self) -> str:
        return "PasswordReauthentication[redacted]"


@dataclass(frozen=True, slots=True, repr=False)
class EmailOtpReauthentication:
    challenge_id: str
    code: str

    def __repr__(self) -> str:
        return "EmailOtpReauthentication[redacted]"


@dataclass(frozen=True, slots=True, repr=False)
class OperationStepUpVerify:
    challenge_id: str
    code: str

    def __repr__(self) -> str:
        return "OperationStepUpVerify[redacted]"


@dataclass(frozen=True, slots=True, repr=False)
class OperationWebAuthnVerify:
    challenge_id: str
    request_id: str
    credential: str

    def __repr__(self) -> str:
        return "OperationWebAuthnVerify[redacted]"


@dataclass(frozen=True, slots=True, repr=False)
class ProviderExchange:
    authorization_id: str
    code_verifier: str

    def __repr__(self) -> str:
        return "ProviderExchange[redacted]"


@dataclass(frozen=True, slots=True)
class MfaProviderAuthorize:
    method_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str


@dataclass(frozen=True, slots=True)
class IdentityProviderAuthorize:
    purpose: AuthorizationPurpose
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    method_id: str | None = None


@dataclass(frozen=True, slots=True, repr=False)
class IdentityTargetProof:
    method: TargetProofMethod
    code: str

    def __repr__(self) -> str:
        return "IdentityTargetProof[redacted]"


@dataclass(frozen=True, slots=True, repr=False)
class IdentityOperationComplete:
    proofs: tuple[IdentityTargetProof, ...]

    def __repr__(self) -> str:
        return "IdentityOperationComplete[redacted]"


type IdentityPayload = (
    AddIdentity
    | VerifyIdentity
    | SetPrimaryIdentity
    | RemoveIdentity
    | ReplaceIdentity
    | LinkIdentity
    | UnlinkIdentity
    | TransferIdentity
)
type Reauthentication = PasswordReauthentication | EmailOtpReauthentication


@dataclass(frozen=True, slots=True)
class IdentityOperationCreate:
    expected_login_method_version: int
    payload: IdentityPayload


_PAYLOAD_TYPES = {
    AddIdentity: "ADD",
    VerifyIdentity: "VERIFY",
    SetPrimaryIdentity: "SET_PRIMARY",
    RemoveIdentity: "REMOVE",
    ReplaceIdentity: "REPLACE",
    LinkIdentity: "LINK",
    UnlinkIdentity: "UNLINK",
    TransferIdentity: "TRANSFER",
}


def _camel(value: str) -> str:
    first, *rest = value.split("_")
    return first + "".join(part.title() for part in rest)


def _decode(tp: object, value: object) -> object:
    args = get_args(tp)
    origin = get_origin(tp)
    if origin is types.UnionType and type(None) in args:
        return (
            None if value is None else _decode(next(t for t in args if t is not type(None)), value)
        )
    if origin is tuple:
        if not isinstance(value, list):
            raise AccountSecurityProtocolError("Expected a security response array")
        return tuple(_decode(args[0], item) for item in value)
    if origin is dict:
        if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
            raise AccountSecurityProtocolError("Expected a security response object")
        return {_decode(args[0], k): _decode(args[1], v) for k, v in value.items()}
    if isinstance(tp, type) and issubclass(tp, StrEnum):
        if not isinstance(value, str):
            raise AccountSecurityProtocolError("Invalid security enum")
        try:
            return tp(value)
        except ValueError:
            raise AccountSecurityProtocolError("Unsupported security enum") from None
    if isinstance(tp, type) and is_dataclass(tp):
        if not isinstance(value, dict):
            raise AccountSecurityProtocolError("Expected a security response object")
        hints = get_type_hints(tp)
        kwargs: dict[str, object] = {}
        if tp is RecoveryCodesRemaining and any(
            value.get(key) is not None for key in ("codes", "recoveryCodes", "material")
        ):
            raise AccountSecurityProtocolError(
                "Remaining count cannot contain plaintext recovery material"
            )
        if tp is MfaOperation and any(
            value.get(key) is not None for key in ("material", "recoveryCodes")
        ):
            raise AccountSecurityProtocolError("Status cannot redeliver one-time material")
        for f in fields(tp):
            key = _camel(f.name)
            hint = hints[f.name]
            if key not in value and type(None) not in get_args(hint):
                raise AccountSecurityProtocolError("Missing required security response field")
            kwargs[f.name] = _decode(hint, value.get(key))
        result = tp(**kwargs)
        _validate_response(result)
        return result
    if tp in (str, int, bool) and type(value) is tp:
        return value
    raise AccountSecurityProtocolError("Invalid security response field type")


def decode[T](tp: type[T], value: object) -> T:
    return cast(T, _decode(tp, value))


def _validate_response(value: object) -> None:
    if (
        isinstance(value, RecoveryCodesRemaining)
        and not 0 <= value.remaining <= 9223372036854775807
    ):
        raise AccountSecurityProtocolError("Invalid recovery code remainder")
    if isinstance(value, ProviderTarget):
        try:
            _uuid(value.provider_id)
        except ValueError:
            raise AccountSecurityProtocolError("Invalid provider target identifier") from None
        if re.fullmatch(r"[0-9a-f]{64}", value.reference) is None:
            raise AccountSecurityProtocolError("Invalid opaque provider reference")
    if (
        isinstance(value, IdentityOperation)
        and value.provider_target is not None
        and (
            value.type is not IdentityOperationType.LINK
            or value.state
            in (
                IdentityOperationState.CANCELLED,
                IdentityOperationState.EXPIRED,
                IdentityOperationState.REJECTED,
            )
        )
    ):
        raise AccountSecurityProtocolError("Unexpected provider target state")
    if isinstance(value, IdentifierCapability):
        if value.allowed != (not value.unavailable_reasons):
            raise AccountSecurityProtocolError("Contradictory identifier capability")
        for identifier_id in value.replacement_primary_ids:
            try:
                _uuid(identifier_id)
            except ValueError:
                raise AccountSecurityProtocolError(
                    "Invalid replacement primary identifier"
                ) from None
    if isinstance(value, MfaOperation) and (
        (value.state is MfaOperationState.COMMITTED) != (value.result is not None)
    ):
        raise AccountSecurityProtocolError("Missing or unexpected operation result")
    if (
        isinstance(value, MfaAction)
        and value.allowed
        and (value.proof_requirement is not ProofRequirement.SESSION and not value.proof_options)
    ):
        raise AccountSecurityProtocolError("Allowed action has no executable proof")
    if isinstance(value, OperationProofOption):
        required = {
            ProofMethod.PASSWORD: (),
            ProofMethod.EMAIL_OTP: (value.identifier_id, value.masked_identifier),
            ProofMethod.PROVIDER: (value.method_id, value.display_name),
            ProofMethod.STEP_UP_PROOF: (value.available_methods,),
        }[value.method]
        if any(not part for part in required):
            raise AccountSecurityProtocolError("Incomplete operation proof option")
        actual = {
            key
            for key, part in {
                "identifierId": value.identifier_id,
                "maskedIdentifier": value.masked_identifier,
                "methodId": value.method_id,
                "displayName": value.display_name,
                "availableMethods": value.available_methods,
            }.items()
            if part is not None
        }
        expected = {
            ProofMethod.PASSWORD: set(),
            ProofMethod.EMAIL_OTP: {"identifierId", "maskedIdentifier"},
            ProofMethod.PROVIDER: {"methodId", "displayName"},
            ProofMethod.STEP_UP_PROOF: {"availableMethods"},
        }[value.method]
        if actual != expected:
            raise AccountSecurityProtocolError("Mismatched operation proof option")
        if value.available_methods is not None and any(
            method not in ("TOTP", "WEBAUTHN") for method in value.available_methods
        ):
            raise AccountSecurityProtocolError("Unsupported operation step-up method")
    if isinstance(value, TotpBeginResult):
        if (value.delivery is SensitiveDelivery.AVAILABLE) != (value.material is not None):
            raise AccountSecurityProtocolError("Invalid one-time TOTP delivery")
        if value.delivery is SensitiveDelivery.NOT_APPLICABLE:
            raise AccountSecurityProtocolError("Invalid TOTP delivery state")
    if isinstance(value, MfaCompletionResult) and (
        (value.delivery is SensitiveDelivery.AVAILABLE) != (value.recovery_codes is not None)
    ):
        raise AccountSecurityProtocolError("Invalid one-time recovery delivery")
    if isinstance(value, RecoveryCodes) and value.count != len(value.codes):
        raise AccountSecurityProtocolError("Invalid recovery code count")


def _uuid(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("A canonical operation/identifier UUID is required")
    try:
        parsed = UUID(value)
    except ValueError:
        raise ValueError("A canonical operation/identifier UUID is required") from None
    if str(parsed) != value:
        raise ValueError("A canonical operation/identifier UUID is required")
    return value


def _text(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("A nonblank security field is required")
    return value


def _code(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{6}", value) is None:
        raise ValueError("A six-digit ASCII code is required")
    return value


def _key(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 256
        or any(ord(c) < 32 or ord(c) > 126 for c in value)
    ):
        raise ValueError("A valid, caller-retained Idempotency-Key is required")
    return value


def _encode(value: object) -> object:
    if isinstance(value, StrEnum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        out = {
            _camel(f.name): _encode(getattr(value, f.name))
            for f in fields(value)
            if getattr(value, f.name) is not None
        }
        if isinstance(value, IdentityOperationCreate):
            if type(value.payload) not in _PAYLOAD_TYPES:
                raise ValueError("Unsupported identity payload")
            out["type"] = _PAYLOAD_TYPES[type(value.payload)]
        if isinstance(value, PasswordReauthentication):
            out["method"] = "PASSWORD"
        if isinstance(value, EmailOtpReauthentication):
            out["method"] = "EMAIL_OTP"
        if isinstance(value, IdentityTargetProof):
            out["purpose"] = "TARGET_OWNERSHIP"
        _validate_request(value)
        return out
    if isinstance(value, tuple):
        return [_encode(v) for v in value]
    if type(value) in (str, int, bool) or value is None:
        return value
    raise ValueError("Unsupported security request type")


def _validate_request(value: object) -> None:
    if not is_dataclass(value) or isinstance(value, type):
        raise ValueError("A typed security request is required")
    hints = get_type_hints(type(value))
    for f in fields(value):
        v = getattr(value, f.name)
        if v is None:
            if type(None) in get_args(hints[f.name]):
                continue
            raise ValueError("A required security request field is missing")
        tp = hints[f.name]
        if isinstance(tp, TypeAliasType):
            tp = tp.__value__
        if type(None) in get_args(tp):
            tp = next(t for t in get_args(tp) if t is not type(None))
        if isinstance(tp, type) and issubclass(tp, StrEnum) and not isinstance(v, tp):
            raise ValueError("A typed security enum is required")
        if tp in (str, int, bool) and type(v) is not tp:
            raise ValueError("Invalid security request field type")
        if isinstance(tp, type) and is_dataclass(tp) and not isinstance(v, tp):
            raise ValueError("Invalid nested security request type")
        if get_origin(tp) is tuple and (
            not isinstance(v, tuple) or any(not isinstance(item, get_args(tp)[0]) for item in v)
        ):
            raise ValueError("Invalid typed security request collection")
        if isinstance(v, str):
            _text(v)
        if (
            f.name.endswith("_id")
            and f.name not in ("method_id", "request_id")
            and (f.name != "challenge_id" or isinstance(value, EmailOtpReauthentication))
        ):
            _uuid(v)
        if f.name == "code":
            _code(v)
        if f.name == "expected_login_method_version" and (type(v) is not int or v < 0):
            raise ValueError("A nonnegative login method version is required")
    if isinstance(value, PasswordReauthentication) and len(value.password) > 128:
        raise ValueError("Password exceeds the protocol limit")
    if (
        isinstance(value, ProviderExchange)
        and re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", value.code_verifier) is None
    ):
        raise ValueError("Invalid PKCE verifier")
    if isinstance(value, MfaProviderAuthorize | IdentityProviderAuthorize) and (
        value.code_challenge_method != "S256"
        or re.fullmatch(r"[A-Za-z0-9_-]{43}", value.code_challenge) is None
    ):
        raise ValueError("An S256 PKCE challenge is required")
    if isinstance(value, IdentityOperationComplete) and (
        not isinstance(value.proofs, tuple)
        or len(value.proofs) > 1
        or any(not isinstance(proof, IdentityTargetProof) for proof in value.proofs)
    ):
        raise ValueError("Zero or one typed target proof is required")


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AccountSecurityProtocolError("Duplicate security response field")
        result[key] = value
    return result


def _json(content: bytes) -> object:
    try:
        return json.loads(content, object_pairs_hook=_object_pairs)
    except (ValueError, UnicodeDecodeError):
        raise AccountSecurityProtocolError("Invalid security JSON response") from None


def _api_error(status: int, content: bytes, retry: str | None) -> AccountSecurityError:
    wire = _json(content)
    if not isinstance(wire, Mapping) or not isinstance(wire.get("error"), str):
        raise AccountSecurityProtocolError("Invalid security error response")
    code = wire["error"]
    if (
        re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", code) is None
        or type(wire.get("status")) is not int
        or wire.get("status") != status
    ):
        raise AccountSecurityProtocolError("Invalid security error code/status")
    delay = None
    if retry is not None and re.fullmatch(r"[0-9]{1,10}", retry):
        parsed = int(retry)
        if parsed <= 2147483647:
            delay = parsed
    return AccountSecurityError(status, code, delay)
