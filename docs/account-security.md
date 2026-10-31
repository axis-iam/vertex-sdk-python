# Headless Account Security

These APIs operate on the explicitly supplied **current-user access token**. The configured
confidential client's secret is never substituted for user authorization. The server enforces
Application/user/client/session ownership, proof expiry and login-method versions. A machine
token cannot become a self-service principal. No method opens a browser, refreshes a session,
starts another operation, caches secrets or automatically retries an unknown mutation.

Save the operation ID and a caller-generated non-secret idempotency key before starting. Reuse
the same key and identical typed create request to recover a lost creation response; do not
silently generate a new key. After an uncertain begin/complete/provider exchange, query the
saved operation ID. A new authenticated session of the same owner/client can read terminal
results, but cannot take over pending mutations. A transfer counterpart may receive nullable
`result`/`completion` because the producer deliberately redacts the initiator's metadata.

`AVAILABLE` delivers TOTP material or recovery codes once. `ALREADY_DELIVERED` has no secret;
status queries never redeliver it. If enrollment material was lost, explicitly cancel or let
it expire before creating a new operation. If generated recovery codes were lost, only an
explicitly authorized new generation replaces them. Do not log request bodies, passwords,
OTPs, provider exchange verifiers, material or codes. Their diagnostic representations are
redacted, but intentional serialization/access still reveals them.

Honor typed `sessionImpact`: `CURRENT_SESSION_RETAINED` refreshes application security facts;
`REAUTHENTICATE` requires your application to clear its own user session and initiate legitimate
reauthentication; `UNCHANGED` does not imply an extra logout. The SDK performs none of these
application/session transitions implicitly. Server proof options, not anonymous login metadata,
determine executable PASSWORD/EMAIL_OTP/PROVIDER/scoped TOTP/WebAuthn actions.

Requests are closed typed payloads. Optional fields are omitted rather than serialized as null;
complete uses an omitted code for non-enrollment operations. Missing required response
fields, unsupported enum values, duplicate JSON members and malformed one-time delivery are protocol errors,
not empty success. Stable HTTP error codes and strictly parsed nonnegative integer Retry-After
seconds remain available without raw provider diagnostics. Invalid/overflow retry values produce
no delay, not a retry or a successful result. Cancellation/interruption propagates through the
language's existing context/timeout boundary. No unsafe mutation is replayed automatically.

## Public Calls

Entry: `axis_vertex.IamClient`, with DTOs/enums/errors exported from `axis_vertex`. Every listed
async method also has an explicit `_sync` counterpart; sync calls reject an active event loop.
FastAPI/Django consumers use the same client with their request-local authenticated access token.
Errors: `AccountSecurityError` (`status_code`, `code`, `retry_after_seconds`),
`AccountSecurityProtocolError`, `AccountSecurityTransportError` (`outcome_unknown`).
`complete_mfa_operation(..., code=None)` omits code; an empty string is invalid.

| Method | Producer route |
| --- | --- |
| `get_recovery_codes_remaining` | GET `/api/v1/auth/mfa/recovery-codes/remaining` |
| `list_account_identifiers` | GET `/api/v1/auth/me/identifiers` |
| `list_account_login_methods` | GET `/api/v1/auth/me/login-methods` |
| `list_linkable_identity_providers` | GET `/api/v1/auth/me/linkable-identity-providers` |
| `create_identity_operation` | POST `/api/v1/auth/me/identity-operations` |
| `get_identity_operation` | GET `/api/v1/auth/me/identity-operations/{id}` |
| `list_identity_transfers` | GET `/api/v1/auth/me/identity-operations/transfers` |
| `reauthenticate_identity_operation` | POST `/api/v1/auth/me/identity-operations/{id}/reauthenticate` |
| `challenge_identity_operation` | POST `/api/v1/auth/me/identity-operations/{id}/challenges` |
| `challenge_identity_current_account` | POST `/api/v1/auth/me/identity-operations/{id}/current-account/challenges` |
| `complete_identity_operation` | POST `/api/v1/auth/me/identity-operations/{id}/complete` |
| `cancel_identity_operation` | POST `/api/v1/auth/me/identity-operations/{id}/cancel` |
| `confirm_identity_transfer` | POST `/api/v1/auth/me/identity-operations/{id}/confirm-transfer` |
| `authorize_identity_operation` | POST `/api/v1/auth/me/identity-operations/{id}/authorize` |
| `complete_identity_provider_authorization` | POST `/api/v1/auth/me/identity-operations/{id}/provider-callback` |
| `get_mfa_capabilities` | GET `/api/v1/auth/mfa/capabilities` |
| `create_mfa_operation` | POST `/api/v1/auth/mfa/operations` |
| `get_mfa_operation` | GET `/api/v1/auth/mfa/operations/{id}` |
| `reauthenticate_mfa_operation` | POST `/api/v1/auth/mfa/operations/{id}/reauthenticate` |
| `challenge_mfa_operation` | POST `/api/v1/auth/mfa/operations/{id}/challenges` |
| `authorize_mfa_operation` | POST `/api/v1/auth/mfa/operations/{id}/authorize` |
| `complete_mfa_provider_authorization` | POST `/api/v1/auth/mfa/operations/{id}/provider-callback` |
| `begin_totp_enrollment_operation` | POST `/api/v1/auth/mfa/operations/{id}/begin` |
| `complete_mfa_operation` | POST `/api/v1/auth/mfa/operations/{id}/complete` |
| `cancel_mfa_operation` | POST `/api/v1/auth/mfa/operations/{id}/cancel` |
| `start_identity_operation_step_up` | POST `/api/v1/auth/me/identity-operations/{id}/step-up/start` |
| `verify_identity_operation_step_up` | POST `/api/v1/auth/me/identity-operations/{id}/step-up/verify` |
| `start_identity_operation_webauthn` | POST `/api/v1/auth/me/identity-operations/{id}/step-up/webauthn/start` |
| `verify_identity_operation_webauthn` | POST `/api/v1/auth/me/identity-operations/{id}/step-up/webauthn/verify` |
| `start_mfa_operation_step_up` | POST `/api/v1/auth/mfa/operations/{id}/step-up/start` |
| `verify_mfa_operation_step_up` | POST `/api/v1/auth/mfa/operations/{id}/step-up/verify` |
| `start_mfa_operation_webauthn` | POST `/api/v1/auth/mfa/operations/{id}/step-up/webauthn/start` |
| `verify_mfa_operation_webauthn` | POST `/api/v1/auth/mfa/operations/{id}/step-up/webauthn/verify` |

## Recovery Example

```python
from axis_vertex import IamClient, MfaOperationCreate, MfaOperationType

async def start_enrollment(client: IamClient, user_token: str, retained_key: str) -> str:
    capabilities = await client.get_mfa_capabilities(user_token)
    operation = await client.create_mfa_operation(
        user_token,
        MfaOperationCreate(MfaOperationType.TOTP_ENROLL, capabilities.login_method_version),
        retained_key,
    )
    # Retain only this non-secret identity. Execute the actual returned proof options explicitly.
    await client.get_mfa_operation(user_token, operation.id)
    return operation.id
```


## Authenticated Identifier Management and LINK Target

`listAccountIdentifiers` (language-equivalent name) returns server facts plus nullable `management`.
`management.add` is keyed by USERNAME/EMAIL/PHONE; each identifier's nullable `capabilities`
is keyed by VERIFY/SET_PRIMARY/REMOVE/REPLACE/TRANSFER. Each capability carries `allowed`,
`unavailableReasons`, `requirements`, and the exact eligible `replacementPrimaryIds`.
`management.proofOptions` lists the actual current-account proof channels. These are authenticated
advisory snapshots, not grants: do not derive management permission from anonymous login metadata,
identifier status, a catalog entry, or a configured client secret. Missing/null snapshots remain
absent; the SDK never manufactures an allowed action or substitutes a denial.

Denials are typed: ACCOUNT_INACTIVE, MANAGED_IDENTIFIER, METHOD_UNAVAILABLE,
REAUTH_METHOD_UNAVAILABLE, TARGET_PROOF_UNAVAILABLE, IDENTIFIER_ALREADY_EXISTS, NOT_APPLICABLE,
ALREADY_VERIFIED, ALREADY_PRIMARY, IDENTIFIER_UNVERIFIED, IDENTIFIER_RANGE_REJECTED,
LAST_LOGIN_METHOD and PRIMARY_REPLACEMENT_UNAVAILABLE. Requirements are typed:
CURRENT_ACCOUNT_PROOF, NEW_IDENTIFIER, TARGET_EMAIL_OTP, TARGET_PHONE_OTP, REPLACEMENT_PRIMARY,
REMOVE_OLD, COUNTERPART_CONFIRMATION and REMAINING_LOGIN_PATH. Present replacement choices to the
caller; never silently pick the first ID. Preserve the snapshot's login-method version when
creating a selected operation, and honor its actual required proofs. Mutations still revalidate
ownership, current policy/range, security version, and the last usable login path. Grandfathered
existing identifiers may remain verifiable/promotable/removable even when new ADD/REPLACE/TRANSFER
values are outside the current binding range; do not override the server's per-action decision.

An identity operation's nullable `providerTarget` comes from the **actual verified LINK adapter
result**: `providerId`, nullable/omittable `maskedDisplayName` and `maskedEmail`, and opaque
64-lowercase-hex `reference`. Display only these returned masks. Do not use Provider catalog names
or an already-linked identity as the new target, invent a fallback identity, interpret the reference
as a subject, or store raw provider claims. The target may be absent before proof; cancelled,
expired, rejected and counterpart views do not supply it. Successful LINK status/replay/committed
reads may retain the same target. The SDK does not synthesize transitions, enforce another user's
ownership locally, authorize an action from the presentation, or open a browser.

Known required fields/types/enums and malformed references remain strict protocol errors;
additive unknown response fields (including nested fields) are ignored and not retained. Duplicate
JSON members and trailing JSON remain invalid. Reserved `material`/`recoveryCodes` members on an
MFA status are not treated as future extensions: non-null redelivery is a protocol error. Optional request fields are still omitted rather
than sent as null; no new request keys or endpoint were invented for these response additions.

```python
from axis_vertex import IdentifierKind

snapshot = await client.list_account_identifiers(user_token)
if snapshot.management is not None:
    add_email = snapshot.management.add.get(IdentifierKind.EMAIL)
    if add_email is not None and add_email.allowed:
        requirements = add_email.requirements
        proof_options = snapshot.management.proof_options
        # Present these to the caller; a later create uses snapshot.login_method_version.
operation = await client.get_identity_operation(user_token, retained_operation_id)
if operation.provider_target is not None:
    target = operation.provider_target
    # Present target.masked_display_name / masked_email, not catalog/linked identity data.
```

## Live Recovery-Code Remainder

Use the explicit current-user `getRecoveryCodesRemaining` equivalent (method table below) to read
`GET /api/v1/auth/mfa/recovery-codes/remaining`. The typed `RecoveryCodesRemaining` response has
only `remaining`, a nonnegative integer count of currently unused codes. This read is uncached and
never returns old plaintext recovery codes. Its bearer identifies the current owner; the configured
client secret is not substituted and there is no arbitrary userId or Application override argument.
The producer remains authoritative for authenticated user/Application ownership.

Read again after generation or consumption: `operation.result.recoveryCount` records how many
codes were generated at completion, NOT the live remainder. Do not use it, a local decrement, or
a cached generation response instead of this endpoint. Errors retain the usual sanitized typed
HTTP/code/Retry-After contract; malformed/missing/negative/overflow counts fail as protocol errors.
Additive unknown response fields stay compatible, but reserved plaintext `codes`/`recoveryCodes`/
`material` on this count response are rejected. No code-generation, verification, refresh, browser
flow or retry of an uncertain mutation is triggered by the read.

Public methods: `IamClient.get_recovery_codes_remaining(access_token)` and explicit
`get_recovery_codes_remaining_sync(access_token)`; `RecoveryCodesRemaining` is a root export.

```python
live = await client.get_recovery_codes_remaining(user_token)
currently_unused = live.remaining
```

## Explicit Synchronous Lifecycle

All `IamClient` sync wrappers share an instance-owned persistent asyncio Runner and a separate
pooled AsyncClient; the loop and keep-alive connections live until `close_sync()` or async `close()`.
They do not reuse the asynchronous channel's connections, recreate a client for each call, disable
keep-alive, or replay mutations. Calls on the same sync channel are serialized. Normal async calls
keep their own async transport and run on the caller's event loop. Every sync wrapper and
`close_sync()` rejects an already running event loop before performing network work; use `await`
inside async handlers.

```python
client = IamClient(config)
try:
    before = client.get_recovery_codes_remaining_sync(user_token)
    capabilities = client.get_mfa_capabilities_sync(user_token)
    after = client.get_recovery_codes_remaining_sync(user_token)
finally:
    client.close_sync()  # Closes this channel's pool AND loop, including after errors.
```

`close_sync()` is idempotent and closes the sync channel only; a closed sync channel cannot be
silently reopened. Hybrid callers should `await client.close()` in the asynchronous channel's
owning loop; it closes SDK-owned async HTTP resources and offloads sync cleanup without blocking
the handler's event loop. No background service/thread is retained for ordinary sync requests.
The existing injected `http_client` remains async-only and caller-owned. For custom synchronous
transport, explicitly pass `sync_http_client_factory=lambda: httpx.AsyncClient(...)`; the factory
must produce a fresh client distinct from the async one and the SDK owns its sync lifecycle.
An injected async transport without a sync factory fails explicitly instead of being silently
ignored or reused across event loops. Never share an externally loop-bound AsyncClient through
that factory.
