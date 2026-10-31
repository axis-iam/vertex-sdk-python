"""Explicit current-user HTTP operations, composed into the public IamClient."""

from __future__ import annotations

import asyncio
from typing import cast

import httpx

from . import account_security as security
from ._sync_runtime import SyncRuntime
from .config import IamConfig
from .errors import UnauthorizedError


class AccountSecurityOperations:
    _http: httpx.AsyncClient
    _sync_runtime: SyncRuntime
    config: IamConfig

    def _http_for_call(self) -> httpx.AsyncClient:
        return self._sync_runtime.select_http(self._http)

    async def _security_request(
        self,
        access_token: str,
        method: str,
        path: str,
        body: object = None,
        idempotency_key: str | None = None,
    ) -> object:
        if not isinstance(access_token, str):
            raise UnauthorizedError("An explicit current-user bearer token is required")
        token = access_token.removeprefix("Bearer ")
        if not token or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in token):
            raise UnauthorizedError("An explicit current-user bearer token is required")
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if idempotency_key is not None:
            headers["Idempotency-Key"] = security._key(idempotency_key)
        try:
            response = await self._http_for_call().request(
                method,
                self.config.endpoint + path,
                headers=headers,
                json=body,
                follow_redirects=False,
            )
        except httpx.RequestError:
            raise security.AccountSecurityTransportError(outcome_unknown=method != "GET") from None
        if len(response.content) > 1048576:
            raise security.AccountSecurityProtocolError("Security response exceeds size limit")
        if not 200 <= response.status_code < 300:
            raise security._api_error(
                response.status_code, response.content, response.headers.get("Retry-After")
            )
        return security._json(response.content)

    async def list_account_identifiers(self, access_token: str) -> security.AccountIdentifiers:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token, "GET", "/api/v1/auth/me/identifiers", None
        )
        return security.decode(security.AccountIdentifiers, wire)

    def list_account_identifiers_sync(self, access_token: str) -> security.AccountIdentifiers:
        _assert_sync_context()
        return self._sync_runtime.run(self.list_account_identifiers(access_token))

    async def list_account_login_methods(self, access_token: str) -> security.AccountLoginMethods:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token, "GET", "/api/v1/auth/me/login-methods", None
        )
        return security.decode(security.AccountLoginMethods, wire)

    def list_account_login_methods_sync(self, access_token: str) -> security.AccountLoginMethods:
        _assert_sync_context()
        return self._sync_runtime.run(self.list_account_login_methods(access_token))

    async def list_linkable_identity_providers(
        self, access_token: str
    ) -> tuple[security.LinkableIdentityProvider, ...]:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token, "GET", "/api/v1/auth/me/linkable-identity-providers", None
        )
        return cast(
            tuple[security.LinkableIdentityProvider, ...],
            security._decode(tuple[security.LinkableIdentityProvider, ...], wire),
        )

    def list_linkable_identity_providers_sync(
        self, access_token: str
    ) -> tuple[security.LinkableIdentityProvider, ...]:
        _assert_sync_context()
        return self._sync_runtime.run(self.list_linkable_identity_providers(access_token))

    async def create_identity_operation(
        self, access_token: str, request: security.IdentityOperationCreate, idempotency_key: str
    ) -> security.IdentityOperation:
        """Execute the account security operation."""
        if not isinstance(request, security.IdentityOperationCreate):
            raise ValueError("A typed security request is required")
        wire = await self._security_request(
            access_token,
            "POST",
            "/api/v1/auth/me/identity-operations",
            security._encode(request),
            idempotency_key,
        )
        return security.decode(security.IdentityOperation, wire)

    def create_identity_operation_sync(
        self, access_token: str, request: security.IdentityOperationCreate, idempotency_key: str
    ) -> security.IdentityOperation:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.create_identity_operation(access_token, request, idempotency_key)
        )

    async def get_identity_operation(
        self, access_token: str, operation_id: str
    ) -> security.IdentityOperation:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token,
            "GET",
            f"/api/v1/auth/me/identity-operations/{security._uuid(operation_id)}",
            None,
        )
        return security.decode(security.IdentityOperation, wire)

    def get_identity_operation_sync(
        self, access_token: str, operation_id: str
    ) -> security.IdentityOperation:
        _assert_sync_context()
        return self._sync_runtime.run(self.get_identity_operation(access_token, operation_id))

    async def list_identity_transfers(
        self, access_token: str
    ) -> tuple[security.IdentityOperation, ...]:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token, "GET", "/api/v1/auth/me/identity-operations/transfers", None
        )
        return cast(
            tuple[security.IdentityOperation, ...],
            security._decode(tuple[security.IdentityOperation, ...], wire),
        )

    def list_identity_transfers_sync(
        self, access_token: str
    ) -> tuple[security.IdentityOperation, ...]:
        _assert_sync_context()
        return self._sync_runtime.run(self.list_identity_transfers(access_token))

    async def reauthenticate_identity_operation(
        self, access_token: str, operation_id: str, request: security.Reauthentication
    ) -> security.IdentityOperation:
        """Execute the account security operation."""
        if not isinstance(
            request, security.PasswordReauthentication | security.EmailOtpReauthentication
        ):
            raise ValueError("A typed security request is required")
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/me/identity-operations/{security._uuid(operation_id)}/reauthenticate",
            security._encode(request),
        )
        return security.decode(security.IdentityOperation, wire)

    def reauthenticate_identity_operation_sync(
        self, access_token: str, operation_id: str, request: security.Reauthentication
    ) -> security.IdentityOperation:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.reauthenticate_identity_operation(access_token, operation_id, request)
        )

    async def challenge_identity_operation(
        self, access_token: str, operation_id: str, target_proof_method: security.TargetProofMethod
    ) -> security.IdentityOperation:
        """Execute the account security operation."""
        if not isinstance(target_proof_method, security.TargetProofMethod):
            raise ValueError("A typed security enum is required")
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/me/identity-operations/{security._uuid(operation_id)}/challenges",
            {"targetProofMethod": target_proof_method.value},
        )
        return security.decode(security.IdentityOperation, wire)

    def challenge_identity_operation_sync(
        self, access_token: str, operation_id: str, target_proof_method: security.TargetProofMethod
    ) -> security.IdentityOperation:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.challenge_identity_operation(access_token, operation_id, target_proof_method)
        )

    async def challenge_identity_current_account(
        self, access_token: str, operation_id: str, identifier_id: str
    ) -> security.IdentityChallengeResult:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/me/identity-operations/{security._uuid(operation_id)}/current-account/challenges",
            {"identifierId": security._uuid(identifier_id)},
        )
        return security.decode(security.IdentityChallengeResult, wire)

    def challenge_identity_current_account_sync(
        self, access_token: str, operation_id: str, identifier_id: str
    ) -> security.IdentityChallengeResult:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.challenge_identity_current_account(access_token, operation_id, identifier_id)
        )

    async def complete_identity_operation(
        self, access_token: str, operation_id: str, request: security.IdentityOperationComplete
    ) -> security.IdentityOperation:
        """Execute the account security operation."""
        if not isinstance(request, security.IdentityOperationComplete):
            raise ValueError("A typed security request is required")
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/me/identity-operations/{security._uuid(operation_id)}/complete",
            security._encode(request),
        )
        return security.decode(security.IdentityOperation, wire)

    def complete_identity_operation_sync(
        self, access_token: str, operation_id: str, request: security.IdentityOperationComplete
    ) -> security.IdentityOperation:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.complete_identity_operation(access_token, operation_id, request)
        )

    async def cancel_identity_operation(
        self, access_token: str, operation_id: str
    ) -> security.IdentityOperation:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/me/identity-operations/{security._uuid(operation_id)}/cancel",
            {},
        )
        return security.decode(security.IdentityOperation, wire)

    def cancel_identity_operation_sync(
        self, access_token: str, operation_id: str
    ) -> security.IdentityOperation:
        _assert_sync_context()
        return self._sync_runtime.run(self.cancel_identity_operation(access_token, operation_id))

    async def confirm_identity_transfer(
        self, access_token: str, operation_id: str, decision: security.TransferDecision
    ) -> security.IdentityOperation:
        """Execute the account security operation."""
        if not isinstance(decision, security.TransferDecision):
            raise ValueError("A typed security enum is required")
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/me/identity-operations/{security._uuid(operation_id)}/confirm-transfer",
            {"decision": decision.value},
        )
        return security.decode(security.IdentityOperation, wire)

    def confirm_identity_transfer_sync(
        self, access_token: str, operation_id: str, decision: security.TransferDecision
    ) -> security.IdentityOperation:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.confirm_identity_transfer(access_token, operation_id, decision)
        )

    async def authorize_identity_operation(
        self, access_token: str, operation_id: str, request: security.IdentityProviderAuthorize
    ) -> security.ProviderAuthorization:
        """Execute the account security operation."""
        if not isinstance(request, security.IdentityProviderAuthorize):
            raise ValueError("A typed security request is required")
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/me/identity-operations/{security._uuid(operation_id)}/authorize",
            security._encode(request),
        )
        return security.decode(security.ProviderAuthorization, wire)

    def authorize_identity_operation_sync(
        self, access_token: str, operation_id: str, request: security.IdentityProviderAuthorize
    ) -> security.ProviderAuthorization:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.authorize_identity_operation(access_token, operation_id, request)
        )

    async def complete_identity_provider_authorization(
        self, access_token: str, operation_id: str, request: security.ProviderExchange
    ) -> security.IdentityOperation:
        """Execute the account security operation."""
        if not isinstance(request, security.ProviderExchange):
            raise ValueError("A typed security request is required")
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/me/identity-operations/{security._uuid(operation_id)}/provider-callback",
            security._encode(request),
        )
        return security.decode(security.IdentityOperation, wire)

    def complete_identity_provider_authorization_sync(
        self, access_token: str, operation_id: str, request: security.ProviderExchange
    ) -> security.IdentityOperation:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.complete_identity_provider_authorization(access_token, operation_id, request)
        )

    async def get_recovery_codes_remaining(
        self, access_token: str
    ) -> security.RecoveryCodesRemaining:
        """Read the current unused count, never generation-time counts or plaintext codes."""
        wire = await self._security_request(
            access_token, "GET", "/api/v1/auth/mfa/recovery-codes/remaining"
        )
        return security.decode(security.RecoveryCodesRemaining, wire)

    def get_recovery_codes_remaining_sync(
        self, access_token: str
    ) -> security.RecoveryCodesRemaining:
        _assert_sync_context()
        return self._sync_runtime.run(self.get_recovery_codes_remaining(access_token))

    async def get_mfa_capabilities(self, access_token: str) -> security.MfaCapabilities:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token, "GET", "/api/v1/auth/mfa/capabilities", None
        )
        return security.decode(security.MfaCapabilities, wire)

    def get_mfa_capabilities_sync(self, access_token: str) -> security.MfaCapabilities:
        _assert_sync_context()
        return self._sync_runtime.run(self.get_mfa_capabilities(access_token))

    async def create_mfa_operation(
        self, access_token: str, request: security.MfaOperationCreate, idempotency_key: str
    ) -> security.MfaOperation:
        """Execute the account security operation."""
        if not isinstance(request, security.MfaOperationCreate):
            raise ValueError("A typed security request is required")
        wire = await self._security_request(
            access_token,
            "POST",
            "/api/v1/auth/mfa/operations",
            security._encode(request),
            idempotency_key,
        )
        return security.decode(security.MfaOperation, wire)

    def create_mfa_operation_sync(
        self, access_token: str, request: security.MfaOperationCreate, idempotency_key: str
    ) -> security.MfaOperation:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.create_mfa_operation(access_token, request, idempotency_key)
        )

    async def get_mfa_operation(
        self, access_token: str, operation_id: str
    ) -> security.MfaOperation:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token, "GET", f"/api/v1/auth/mfa/operations/{security._uuid(operation_id)}", None
        )
        return security.decode(security.MfaOperation, wire)

    def get_mfa_operation_sync(self, access_token: str, operation_id: str) -> security.MfaOperation:
        _assert_sync_context()
        return self._sync_runtime.run(self.get_mfa_operation(access_token, operation_id))

    async def reauthenticate_mfa_operation(
        self, access_token: str, operation_id: str, request: security.Reauthentication
    ) -> security.MfaOperation:
        """Execute the account security operation."""
        if not isinstance(
            request, security.PasswordReauthentication | security.EmailOtpReauthentication
        ):
            raise ValueError("A typed security request is required")
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/mfa/operations/{security._uuid(operation_id)}/reauthenticate",
            security._encode(request),
        )
        return security.decode(security.MfaOperation, wire)

    def reauthenticate_mfa_operation_sync(
        self, access_token: str, operation_id: str, request: security.Reauthentication
    ) -> security.MfaOperation:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.reauthenticate_mfa_operation(access_token, operation_id, request)
        )

    async def challenge_mfa_operation(
        self, access_token: str, operation_id: str, identifier_id: str
    ) -> security.MfaChallengeResult:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/mfa/operations/{security._uuid(operation_id)}/challenges",
            {"method": "EMAIL_OTP", "identifierId": security._uuid(identifier_id)},
        )
        return security.decode(security.MfaChallengeResult, wire)

    def challenge_mfa_operation_sync(
        self, access_token: str, operation_id: str, identifier_id: str
    ) -> security.MfaChallengeResult:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.challenge_mfa_operation(access_token, operation_id, identifier_id)
        )

    async def authorize_mfa_operation(
        self, access_token: str, operation_id: str, request: security.MfaProviderAuthorize
    ) -> security.ProviderAuthorization:
        """Execute the account security operation."""
        if not isinstance(request, security.MfaProviderAuthorize):
            raise ValueError("A typed security request is required")
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/mfa/operations/{security._uuid(operation_id)}/authorize",
            security._encode(request),
        )
        return security.decode(security.ProviderAuthorization, wire)

    def authorize_mfa_operation_sync(
        self, access_token: str, operation_id: str, request: security.MfaProviderAuthorize
    ) -> security.ProviderAuthorization:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.authorize_mfa_operation(access_token, operation_id, request)
        )

    async def complete_mfa_provider_authorization(
        self, access_token: str, operation_id: str, request: security.ProviderExchange
    ) -> security.MfaOperation:
        """Execute the account security operation."""
        if not isinstance(request, security.ProviderExchange):
            raise ValueError("A typed security request is required")
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/mfa/operations/{security._uuid(operation_id)}/provider-callback",
            security._encode(request),
        )
        return security.decode(security.MfaOperation, wire)

    def complete_mfa_provider_authorization_sync(
        self, access_token: str, operation_id: str, request: security.ProviderExchange
    ) -> security.MfaOperation:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.complete_mfa_provider_authorization(access_token, operation_id, request)
        )

    async def begin_totp_enrollment_operation(
        self, access_token: str, operation_id: str
    ) -> security.TotpBeginResult:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/mfa/operations/{security._uuid(operation_id)}/begin",
            {},
        )
        return security.decode(security.TotpBeginResult, wire)

    def begin_totp_enrollment_operation_sync(
        self, access_token: str, operation_id: str
    ) -> security.TotpBeginResult:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.begin_totp_enrollment_operation(access_token, operation_id)
        )

    async def complete_mfa_operation(
        self, access_token: str, operation_id: str, code: str | None = None
    ) -> security.MfaCompletionResult:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/mfa/operations/{security._uuid(operation_id)}/complete",
            {} if code is None else {"code": security._code(code)},
        )
        return security.decode(security.MfaCompletionResult, wire)

    def complete_mfa_operation_sync(
        self, access_token: str, operation_id: str, code: str | None = None
    ) -> security.MfaCompletionResult:
        _assert_sync_context()
        return self._sync_runtime.run(self.complete_mfa_operation(access_token, operation_id, code))

    async def cancel_mfa_operation(
        self, access_token: str, operation_id: str
    ) -> security.MfaOperation:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/mfa/operations/{security._uuid(operation_id)}/cancel",
            {},
        )
        return security.decode(security.MfaOperation, wire)

    def cancel_mfa_operation_sync(
        self, access_token: str, operation_id: str
    ) -> security.MfaOperation:
        _assert_sync_context()
        return self._sync_runtime.run(self.cancel_mfa_operation(access_token, operation_id))

    async def start_identity_operation_step_up(
        self, access_token: str, operation_id: str
    ) -> security.OperationStepUpChallenge:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/me/identity-operations/{security._uuid(operation_id)}/step-up/start",
            {},
        )
        return security.decode(security.OperationStepUpChallenge, wire)

    def start_identity_operation_step_up_sync(
        self, access_token: str, operation_id: str
    ) -> security.OperationStepUpChallenge:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.start_identity_operation_step_up(access_token, operation_id)
        )

    async def verify_identity_operation_step_up(
        self, access_token: str, operation_id: str, request: security.OperationStepUpVerify
    ) -> security.IdentityOperation:
        """Execute the account security operation."""
        if not isinstance(request, security.OperationStepUpVerify):
            raise ValueError("A typed security request is required")
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/me/identity-operations/{security._uuid(operation_id)}/step-up/verify",
            security._encode(request),
        )
        return security.decode(security.IdentityOperation, wire)

    def verify_identity_operation_step_up_sync(
        self, access_token: str, operation_id: str, request: security.OperationStepUpVerify
    ) -> security.IdentityOperation:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.verify_identity_operation_step_up(access_token, operation_id, request)
        )

    async def start_identity_operation_webauthn(
        self, access_token: str, operation_id: str, challenge_id: str
    ) -> security.OperationWebAuthnStart:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/me/identity-operations/{security._uuid(operation_id)}/step-up/webauthn/start",
            {"challengeId": security._text(challenge_id)},
        )
        return security.decode(security.OperationWebAuthnStart, wire)

    def start_identity_operation_webauthn_sync(
        self, access_token: str, operation_id: str, challenge_id: str
    ) -> security.OperationWebAuthnStart:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.start_identity_operation_webauthn(access_token, operation_id, challenge_id)
        )

    async def verify_identity_operation_webauthn(
        self, access_token: str, operation_id: str, request: security.OperationWebAuthnVerify
    ) -> security.IdentityOperation:
        """Execute the account security operation."""
        if not isinstance(request, security.OperationWebAuthnVerify):
            raise ValueError("A typed security request is required")
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/me/identity-operations/{security._uuid(operation_id)}/step-up/webauthn/verify",
            security._encode(request),
        )
        return security.decode(security.IdentityOperation, wire)

    def verify_identity_operation_webauthn_sync(
        self, access_token: str, operation_id: str, request: security.OperationWebAuthnVerify
    ) -> security.IdentityOperation:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.verify_identity_operation_webauthn(access_token, operation_id, request)
        )

    async def start_mfa_operation_step_up(
        self, access_token: str, operation_id: str
    ) -> security.OperationStepUpChallenge:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/mfa/operations/{security._uuid(operation_id)}/step-up/start",
            {},
        )
        return security.decode(security.OperationStepUpChallenge, wire)

    def start_mfa_operation_step_up_sync(
        self, access_token: str, operation_id: str
    ) -> security.OperationStepUpChallenge:
        _assert_sync_context()
        return self._sync_runtime.run(self.start_mfa_operation_step_up(access_token, operation_id))

    async def verify_mfa_operation_step_up(
        self, access_token: str, operation_id: str, request: security.OperationStepUpVerify
    ) -> security.MfaOperation:
        """Execute the account security operation."""
        if not isinstance(request, security.OperationStepUpVerify):
            raise ValueError("A typed security request is required")
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/mfa/operations/{security._uuid(operation_id)}/step-up/verify",
            security._encode(request),
        )
        return security.decode(security.MfaOperation, wire)

    def verify_mfa_operation_step_up_sync(
        self, access_token: str, operation_id: str, request: security.OperationStepUpVerify
    ) -> security.MfaOperation:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.verify_mfa_operation_step_up(access_token, operation_id, request)
        )

    async def start_mfa_operation_webauthn(
        self, access_token: str, operation_id: str, challenge_id: str
    ) -> security.OperationWebAuthnStart:
        """Execute the account security operation."""
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/mfa/operations/{security._uuid(operation_id)}/step-up/webauthn/start",
            {"challengeId": security._text(challenge_id)},
        )
        return security.decode(security.OperationWebAuthnStart, wire)

    def start_mfa_operation_webauthn_sync(
        self, access_token: str, operation_id: str, challenge_id: str
    ) -> security.OperationWebAuthnStart:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.start_mfa_operation_webauthn(access_token, operation_id, challenge_id)
        )

    async def verify_mfa_operation_webauthn(
        self, access_token: str, operation_id: str, request: security.OperationWebAuthnVerify
    ) -> security.MfaOperation:
        """Execute the account security operation."""
        if not isinstance(request, security.OperationWebAuthnVerify):
            raise ValueError("A typed security request is required")
        wire = await self._security_request(
            access_token,
            "POST",
            f"/api/v1/auth/mfa/operations/{security._uuid(operation_id)}/step-up/webauthn/verify",
            security._encode(request),
        )
        return security.decode(security.MfaOperation, wire)

    def verify_mfa_operation_webauthn_sync(
        self, access_token: str, operation_id: str, request: security.OperationWebAuthnVerify
    ) -> security.MfaOperation:
        _assert_sync_context()
        return self._sync_runtime.run(
            self.verify_mfa_operation_webauthn(access_token, operation_id, request)
        )


def _assert_sync_context() -> None:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise RuntimeError("sync security operations cannot run inside an active event loop")
