# Connected application BFF contract

Contract version: `connected-app-bff-c0/1.0.1`. Source baseline:
`e1aac5502e906aac8605c654dcb8984862a5202b`. Machine-readable companion:
`iam-server/src/test/resources/connected-app-bff/c0-v1.json`.
`SHA256SUMS.json` fingerprints this guide and the vector file; it is not a signature.

This is a shared implementation contract for TASK-20261119-001 through 005.
`SOURCE_CONFIRMED` means derived from the named production source; `SDK_REQUIRED`
means a requirement for the four SDK tasks, not functionality installed in IAM.
Runtime results are recorded separately in the task execution evidence. C0 does
not certify a SDK package, external Provider, message delivery, or deployment.

## Ownership and configuration

IAM owns authentication, authorization codes, tokens, policy and durable revocation.
The SDK runs inside the integrating application's backend. Its authentication core
owns protocol validation and lifecycle transitions; its framework adapter owns
routes, CSRF and the single Cookie lifecycle; its session provider supplies atomic
storage semantics. Business endpoints and permission decisions belong to the app.
No third-party BFF route or session store is installed in IAM Server.

Use an active registered WEB client with CLIENT_SECRET authentication and S256 PKCE.
Explicitly configure issuer, resource audience, client ID/secret, exact registered
callback, canonical app origin, allowed local return destinations and session
provider. Resource audience is resolved by IAM registration, not an arbitrary
`audience` request parameter. ID Token audience is the client ID. No internal
Application UUID, second SPA/M2M client, Console library or workspace ID is required.
Organization is optional Application-local authorization context.

`oauth_tokens` remains the existing default mode. `server_session` is explicit.
Credentials, PKCE verifier, transaction control secret, nonce and refresh intent
remain on the app backend. Browser views contain none of these. Context getters
read request-local verified state without network calls. Business URLs are not
automatically proxied.

## IAM HTTP contract — SOURCE_CONFIRMED

Paths below are relative to the configured IAM issuer/service origin. JSON success
bodies are direct DTOs. JSON request bodies are strict (unknown fields rejected).
OAuth form fields use snake_case; transaction requests deliberately mix the exact
annotated snake_case fields with camelCase. UTC timestamps are ISO-8601 strings,
UUIDs are strings. Nullable fields in the safe user view must be explicitly
normalized to JSON null for the existing JS parser; an absent required field is
not an empty string or empty permission list.

| Method and path | Binding/request | Success |
| --- | --- | --- |
| GET `/.well-known/openid-configuration` | Explicit issuer | Discovery; use exact issuer/JWKS, supported signing algorithms |
| GET `/oauth2/authorize` | `response_type=code,client_id,redirect_uri,scope,state,code_challenge,code_challenge_method=S256,nonce` | Browser Hosted navigation; exact callback `?code=…&state=…`, or OAuth error |
| POST `/oauth2/token` | Form, Basic WEB client authentication; authorization_code: `grant_type,code,redirect_uri,code_verifier`; refresh: `grant_type=refresh_token,refresh_token` | OAuth token response below |
| POST `/oauth2/revoke` | Form `token,token_type_hint=refresh_token`; Basic same WEB client | 200 empty; unknown/already revoked token may also return 200 |
| GET `/api/v1/auth/me` | Valid Bearer user AT | `UserInfoResponse` below |
| GET `/api/v1/auth/me/permissions` | Valid Bearer; optional UUID `organizationId` | Permission summary below |
| GET `/api/v1/auth/session/validity` | Valid Bearer with current user/session binding | Validity below; `Cache-Control: no-store` |
| POST `/api/v1/auth/logout` | Valid, unexpired Bearer; absent body, `{}`, or `{"refresh_token":null}`; optional nonblank owned `refresh_token` | 204; current AT/session revoked, supplied owned RT authorization removed |
| GET `/api/v1/apps/{clientId}/auth-methods` | Configured public client ID | Current concrete method capabilities |
| GET `/api/v1/apps/{clientId}/auth-policy` | Same client | Resolved public policy; unknown client 404 may have no body |

Sources: `api/controller/{AuthPermissionsController,ConsoleSessionValidityController,
SessionController,AuthMethodsPublicController,AuthPolicyPublicController}`,
`account/AccountController`, `config/ServerSecurityConfig`,
`config/AuthorizationServerConfig`, `auth/refresh/PublicRefreshOAuth2AuthorizationService`.
The class named ConsoleSessionValidityController is wired into the general Bearer
chain; it is not restricted to Console clients.

OAuth token success requires nonempty `access_token`, `token_type=Bearer`, positive
integer `expires_in`; `scope` is a space-separated string when returned. `id_token`
is required for a requested OpenID flow; validate signature, allowed algorithm,
exact issuer, client audience/azp, time and the stored nonce using discovery/JWKS.
The AT is an opaque credential to this BFF: do not derive profile or permissions
by decoding it. `refresh_token` is optional. It is issued only if the registered
grant and authorized `offline_access` permit it; absence is a supported outcome,
not permission to fabricate one or retry with broader scopes. Without RT, AT
expiry leads to a new authorization. Refresh rotates the RT; never replay an old
generation, even after a local lock timeout.

UserInfoResponse fields: `id:UUID`, `email:string|null`,
`username:string|null`, `status:string`, `emailVerified:boolean`,
`metadata:object`, `authenticationContext:object`. Context requires
`subjectType:"USER",applicationId:UUID,clientId:string,sessionId:string,
workspaceId:UUID|null,workspaceSelectionRequired:boolean,organizationId:UUID|null,
organizationSlug:string|null,organizationRole:string|null,authTime:timestamp|null,
authenticationMethods:string[],assuranceLevel:string|null,
impersonation:{actorId:string,impersonationId:string}|null`.
Workspace selection required implies null workspaceId; null organizationId implies
null organizationSlug/Role. Identity status is not a permission.

Permission summary: `applicationId:UUID,organizationId:UUID|null,roles:string[],
permissions:string[]`. Require its Application/Organization to match the profile.
Never substitute `[]` after failed fetch. Exact `resource:action`, `resource:*`,
and `*:*` match; malformed/absent permissions deny. A forbidden business action is
403 and does not destroy an otherwise valid session.

Validity requires all six nonnull fields:
`sessionId:string,clientId:string,applicationId:UUID,expiresAt:timestamp,
idleExpiresAt:timestamp,accessExpiresAt:timestamp`. Match all identity bindings.
`expiresAt` is IAM's absolute bound, `idleExpiresAt` its idle bound,
`accessExpiresAt` the current credential bound. The SDK clamps to these and its
original local absolute deadline. Refresh/touch never reset that original deadline.
Dependency failure is not proof of a revoked session.

## Custom transaction wire — SOURCE_CONFIRMED

Base `/api/v1/auth/transactions`, source `auth/transaction/
AuthenticationTransaction{Controller,Requests,Service}` and
`idp/AuthenticationTransactionProviderFlow`.

| Action | Method/suffix and exact JSON body | Response |
| --- | --- | --- |
| create | POST base: `client_id:string<=128,entryMode:CUSTOM,redirect_uri:string<=2048,scope:nonblank<=2048,state:nonblank<=512,code_challenge:base64url43,code_challenge_method:S256,nonce?:string<=512` | 201 `{transactionId,controlSecret,expiresAt,nextAction}` |
| get | GET `/{id}` | 200 View |
| password | POST `/{id}/authenticate`: `{method:"PASSWORD",identifier,password:nonblank<=1024}` | 200 View |
| primary proof | POST same: `{method:"EMAIL_OTP"|"SMS_OTP"|"EMAIL_MAGIC_LINK",identifier,proof:nonblank<=128}` | 200 View |
| challenge | POST `/{id}/challenges`: `{method:"EMAIL_OTP"|"SMS_OTP"|"EMAIL_MAGIC_LINK",identifier}` | 200 `{transactionId,expiresAt,challengeExpiresAt,cooldownSeconds,nextAction}` |
| Provider | POST `/{id}/authorize`: `{providerId:UUID,registrationGrantToken?:nonempty<=2048,registrationAccessCode?:nonempty<=128}`; at most one registration proof | 200 `{authorizationUrl,expiresAt}` |
| MFA | POST `/{id}/mfa`: `{method:"TOTP"|"RECOVERY_CODE",code:nonblank<=128}` | 200 View |
| complete | POST `/{id}/complete`: `{}` | 200 `{kind:"authorization_code",code,state,expiresIn:integer>=0}` |
| cancel | POST `/{id}/cancel`: `{}` | 200 View |

Every suffix requires `Authentication-Transaction: <controlSecret>` from the
backend record. The transaction ID alone has no authority. MFA/complete require
`Idempotency-Key`; authenticate/cancel accept the same header. SDK generates a
stable high entropy key per logical action, never per retry of that action.
This business completion idempotency does not make `/oauth2/token` replay safe.
All transaction responses use no-store.

Identifier is `{kind:"EMAIL"|"USERNAME"|"PHONE",value:nonblank,region?:string|null}`.
PHONE normalization uses the supported region/capability contract. Do not guess
identifier type from punctuation. Policy and concrete availability decide methods.
View is `{transactionId:UUID,state,expiresAt:timestamp,nextAction}`. States/actions:
AUTHENTICATING/authenticate, AWAITING_PROVIDER/authorize, MFA_REQUIRED/mfa,
AUTHENTICATED/complete, COMPLETED|CANCELLED|EXPIRED|REJECTED/none.
AUTHENTICATED here means proofs collected; only the completed code exchange and
safe user/permission/validity acquisition produce an authenticated app session.
Initial login lifetime is at most ten minutes, MFA at most five minutes bounded
by the parent, code at most sixty seconds bounded by the transaction.

The browser never receives the Created DTO, transaction control, verifier, or
Completed DTO. SDK maps these to the host view below. It may expose a transaction
reference only where needed for the existing magic fragment binding.

Callback branches:

* Hosted or successful custom Provider: exact registered GET callback `code,state`.
  Validate local prelogin Cookie/state, consume once, then exchange in the backend.
  A Provider code navigates to the BFF; it is not returned to application JS.
* Provider requiring MFA: `kind=AUTH_CONTINUATION,auth_transaction_id,state`.
  Check against the existing local transaction; read its controlled state and
  continue MFA. Missing code is not success. HOSTED MFA stays on IAM `/login`.
* Provider denied/cancelled: `error=access_denied,state`; validate binding and
  terminate that attempt. Do not create an anonymous "successful" session.
* Email link: registered browser landing route with fragment
  `kind=AUTH_PROOF&method=EMAIL_MAGIC_LINK&auth_transaction_id=…&state=…&proof=…`.
  Fragments do not reach HTTP servers. Minimal JS validates exact origin/path,
  unique allowed keys, no query/userinfo, EMAIL identifier and local generation,
  removes fragment with history.replaceState, and posts only
  `{transactionId,state,proof}` to the CSRF-protected host magic action.
  BFF matches its stored transaction/identifier/state and calls IAM authenticate.
  This one-time proof is neither a Token nor the transaction control secret.
* Duplicate parameters, mixed code/continuation/error shapes, wrong state,
  expired/missing prelogin binding, cancelled attempts and consumed callbacks
  reject without a second token request.

## Registration and recovery wire — SOURCE_CONFIRMED

These are distinct purposes, never a substitute for ordinary login proof.
Sources: `api/controller/{AuthController,PasswordController}`,
`preregistration/{PreRegistrationSignupController,dto/*}`,
`api/dto/{authentication/SignupRequest,password/*}`,
`security/registration/RegistrationFlowService`.

| IAM action | Request | Response |
| --- | --- | --- |
| POST `/api/v1/auth/signup` | Idempotency-Key; `{client_id,identifier,password<=128,uiLocales?,registrationGrantToken?,registrationAccessCode?,organizationInvitationToken?}` | 202 PENDING_VERIFICATION or 201 final Result |
| GET `/api/v1/auth/signup/operations/{id}` | Registration-Client and Registration-Control headers | 200 Result |
| POST same `/challenges` or `/cancel` | Registration-Client; `{controlSecret}` | 200 Result |
| POST same `/complete` | Registration-Client; `{controlSecret,code:string length 6}` | 200 Result |
| POST `/api/v1/auth/password/forgot` | `{email,client_id,redirect_uri?:string<=2048}` | 204 enumeration-safe; does not promise delivery |
| POST `/api/v1/auth/password/reset` | Password-Reset-Client bound by BFF; `{token,newPassword}` | 204; no login credentials issued |

Result fields: `registrationId:UUID,status:string,expiresAt:timestamp,
nextAction:string,controlSecret:string|null,nextChallengeAt:timestamp|null`.
Creation/control material stays backend. Registration grant/access/invitation
proofs are purpose-bound; capability and policy determine whether registration
is available. Completion starts a normal login if desired; it does not itself
yield authenticated host state. Password recovery supports the current EMAIL
route only, not a newly invented username/SMS recovery flow. Reset proof landing
and delivery require configured allowed redirect and actual delivery evidence.
Authenticated identifier change, step-up and MFA enrollment APIs are not
implicitly exposed by this BFF contract; existing Console capabilities remain.

Capability responses are the current DTOs `AuthMethodsPublicResponse` and
`AuthPolicyPublicResponse`. Forward only the configured client and their public
fields, never a generic URL. The companion `wire-records.json` lists their exact
record components (including nested capability/policy types) for consumer snapshots.
No unavailable method may be inferred solely from an enabled boolean; require its
concrete availableForLogin/Signup and typed identifier capability.

## Host HTTP contract — SDK_REQUIRED

All paths in this section run at the integrating application. Default base `/auth`
is configurable. Console's existing `/console` default and semantics stay intact.
No general `/api/{arbitrary-path}` or arbitrary-header proxy is added.

| Host method/path | Browser body/query | Result |
| --- | --- | --- |
| GET `/session/bootstrap` | none | 200 safe View, sets/reads prelogin binding when anonymous |
| GET `/session` | none | 200 safe View; authenticated path protected online |
| GET `/login` | existing bootstrap prelogin Cookie; allowlisted local return target only | 302 Hosted authorize; bind this attempt to prelogin, never overwrite authenticated identity |
| GET `/callback` | one exact callback branch above | safe fixed app redirect; no code/token in final URL |
| POST `/session/login` | `{}` | 200 authenticating View; create CUSTOM transaction backend |
| POST `/session/login/authenticate` | exact IAM authenticate body | 200 safe View |
| POST `/session/login/challenges` | exact IAM challenge body | 200 safe View plus challenge fields |
| POST `/session/login/authorize` | exact IAM authorize body | 200 safe View plus authorizationUrl |
| POST `/session/login/mfa` | exact IAM MFA body | 200 safe View |
| POST `/session/login/complete` | `{}` | 200 authenticated View after exchange and identity/validity loading |
| POST `/session/login/cancel` | `{}` | 200 CANCELLED View; invalidate prelogin |
| POST `/session/login/magic` | `{transactionId:UUID,state,proof}` | 200 safe View |
| GET `/auth-methods`, `/auth-policy` | none | 200 configured client public capability/policy DTO |
| POST `/registration` | SignupRequest without client_id | 202/201 safe registration Result |
| GET `/registration/{ref}` | opaque local ref | 200 safe registration Result |
| POST `/registration/{ref}/challenges`, `/complete`, `/cancel` | `{}`, `{code}`, `{}` respectively | 200 safe registration Result |
| POST `/password-reset/request` | `{email}` | 204; backend supplies client/allowed redirect |
| POST `/password-reset/complete` | `{token,newPassword}` | 204 |
| POST `/session/logout` | `{}` | 200 explicit LogoutResult; partial failure uses 503 and same result fields in error details |

Safe registration Result is `{registrationId,status,expiresAt,nextAction,
nextChallengeAt}`; registrationId is a local opaque ref and controlSecret is
omitted. SDK binds that ref to client/control/purpose server-side. All POST
actions require exact canonical Origin and bound `X-CSRF-Token`, including
anonymous signup/recovery. Unknown JSON fields reject. First obtain bootstrap from
the app to establish its protected prelogin Cookie. GET Hosted login/callback
are top-level navigations without a custom header; missing/expired bootstrap
binding rejects login before IAM navigation. Prelogin binding, state,
PKCE, nonce and single consumption provide their binding. Callback need not have
same-origin Origin. No form_post callback or credentialed cross-site iframe
support is implied.

Safe View always has `state,expiresAt,csrfToken`. `csrfToken` and authenticated
`owner` are independent base64url43 random values. `version` is a nonnegative safe
integer. Authenticated View adds exactly `owner,version,profile,permissions`;
profile is CurrentUser above; permissions is `{roles:string[],permissions:string[]}`
or the matching-context IAM envelope. Other allowed fields are `nextAction`,
`challengeExpiresAt`, nonnegative integer `cooldownSeconds`, `authorizationUrl`.
No token/secret/code/redirect-binding field is permitted. Anonymous bootstrap is
`state:PRELOGIN`; login states follow the transaction state/action matrix.
State AUTHENTICATED with nextAction complete and no profile is a proof-complete
login view, not a signed-in user. Existing JS `parseServerSession` and
`parseCurrentUser` are the strict reference consumers; vectors include both
accepted shapes and malformed/context-mismatch denials.

LogoutResult is
`{local:"INVALIDATED"|"NOT_FOUND"|"UNCONFIRMED",cookie:"CLEARED",
remote:"SESSION_REVOKED"|"REFRESH_FAMILY_REVOKED"|"UNCONFIRMED"|"NOT_ATTEMPTED",
sso:"NOT_REQUESTED"}`. SSO end-session is explicit separately configured
navigation, never an automatic logout side effect. Revocation 200 for an unknown
RT is a completed protocol request, not proof that an arbitrary IAM session was
deleted. No Token is present in a logout response.

Use no-store on all host auth JSON/navigation responses and no-referrer on callback
landing. Production Cookie: random 32-byte identifier, HttpOnly, Secure,
SameSite=Lax, host-only, Path=/ by default; `__Host-axis-session` is the standalone
adapter default. Framework bridges retain their configured single owner/name.
Development HTTP requires explicit loopback-only opt-in and a non-__Host name.
Cookie ports do not isolate apps. Proxy trust and canonical origin are explicit.
Rotate ID and CSRF at successful login; clear with the same name/path/domain.
No browser token endpoint exists.

## Session provider and failure semantics — SDK_REQUIRED

Provider operations must distinguish FOUND, ABSENT/EXPIRED, CONFLICT,
CAPACITY, UNAVAILABLE and CLOSED; absent is not a catch-all for read failure.
Records carry schemaVersion=1, version, immutable createdAt/absoluteExpiresAt,
idleExpiresAt, binding owner/generation and a lifecycle state. Snapshot reads
return isolated copies. Providers implement create-if-absent, controlled read,
single prelogin consume, exclusive operation acquisition, conditional commit
and terminal invalidate. Exact method names are language-owned.

Prelogin consumption atomically validates version, state, Cookie binding,
expiry and selected callback branch. The winner alone may exchange. A second
callback never recovers tokens from state/transaction ID. Pending response
recovery requires the original bound operation and its short-lived terminal
result, not another token exchange.

Refresh acquisition precedes HTTP send across every instance using the record.
Persist/send intent is monotonic: READY → OWNED → SEND_INTENT → COMMITTED or
INVALIDATED. Before sending, persist an operation/fence and intent with a
conditional update. An operation that expires after intent is conservatively
uncertain; a new lease holder invalidates/requires new authorization and never
resends the RT. A known pre-send transport failure may release ownership without
destroying the session. A sent timeout/disconnect, crash after intent, successful
refresh followed by failed storage commit, or lost fence cannot continue with
the previous token snapshot. No background replay queue or token-endpoint retry.

Commit binds expected version, fence, owner, user, client and nonterminal state.
Logout first invalidates authentication and outstanding operation authority,
then clears Cookie and attempts bounded IAM revocation using a captured credential.
Late refresh/callback/framework automatic save/touch cannot recreate it. Framework
bridges must preserve unrelated session fields while refusing stale authentication
snapshots. Capability declarations alone do not prove shared coordination.

Protected-request order: load provider → check immutable local deadlines →
refresh if AT expired and RT exists (single owner) → online IAM validity →
provide request-local identity → app business authorization. With usable AT,
perform online validity directly. No extra network from getters. Default refresh
skew 30 seconds clamped by absolute bound. Default upstream timeout 5 seconds,
request auth budget 10 seconds (including refresh then validity), zero automatic
token retries; cancellation propagates. A replay-safe read may be retried only by
explicit bounded policy, not as a hidden reauthorization.

SDK finite defaults: prelogin TTL 600s, terminal callback-result TTL 60s,
memory session absolute/idle cap 3600s each clamped to IAM, refresh ownership
lease 15s, cleanup interval 60s, maximum sessions 10000, prelogins 1000,
maximum serialized record 65536 bytes. Positive finite configuration required;
shorter IAM limits win. Expired records are purged on access and periodically.
Capacity first purges expired records, then returns typed 503
SESSION_STORE_CAPACITY; never evict a live identity silently. Closing stops
timers, clears sensitive records and makes further operations fail CLOSED.

Storage configuration is mandatory. Explicit memory means backend-process RAM,
one shared provider instance for that process; thread/coroutine-safe, volatile on
restart, no HA or multiprocess coordination. Reject declared replicas/workers >1
with memory; do not claim automatic topology detection. A framework bridge or
custom provider must pass the same atomic/lifecycle scenarios for its stated
scope. No mandatory DB driver, schema migration or encryption key is introduced
for RAM. Persistent providers follow their credential protection contract;
clientSecret must not double as a storage key.

## Errors and revocation boundaries

IAM business errors use `{status:number,error:string,message:string,
timestamp:timestamp,details?:object}`. For example a strict-body failure is
400 VALIDATION_ERROR. OAuth endpoints instead use `{error:"invalid_client"|
"invalid_grant"|"invalid_request"|…,error_description?:string,error_uri?:string}`;
do not parse a success token response from an error or login HTML.
Transaction symbolic reasons may occur in the sanitized message; do not invent
that all are top-level error codes. Preserve stable code/status, not provider
payloads, SQL, token values or secret-bearing messages.

Host errors use the business envelope. 400 VALIDATION_ERROR for malformed
input, 401 SESSION_REQUIRED/SESSION_INVALIDATED for established invalidity,
403 SESSION_CSRF_INVALID or business authorization refusal, 409
SESSION_ACTION_PENDING for a currently owned action, 429 RATE_LIMITED with
validated Retry-After, 503 SESSION_STORE_UNAVAILABLE/SESSION_STORE_CAPACITY/
IAM_UNAVAILABLE for temporary dependency failure, and 401
AUTH_EXCHANGE_UNCERTAIN or REFRESH_UNCERTAIN after a send with unknown result.
Uncertain results terminate that authentication; temporary read/dependency
failure returns 503 and never masquerades as anonymous success or empty permissions.
Error details never return token/control material.

| Available credentials | IAM operation | Confirmed scope |
| --- | --- | --- |
| Valid AT, owned RT | POST logout with RT | Current AT and session; remove that authorization/refresh family |
| Valid AT, no RT | POST logout `{}` | Current AT/session; no fabricated RT; other sessions unaffected |
| Expired AT, RT | POST revoke with WEB Basic | Refresh family revoked; **does not revoke/delete the bound IAM session or all ATs** |
| Expired AT, no RT | No usable current-session public revocation credential | Local invalidate, remote NOT_ATTEMPTED/UNCONFIRMED; no implicit refresh |
| Already revoked/unknown RT | POST revoke | Protocol idempotent 200; does not establish new session-revocation facts |
| Different client RT | POST revoke with caller Basic | Caller cannot mutate another client's family |
| Other user/session RT with valid AT | POST logout | Ownership refusal before requested logout mutations |
| Remote unavailable | Bounded attempted operation | Local cleanup independent; remote UNCONFIRMED |
| Local invalidation unavailable | Clear Cookie and bounded remote attempt | local UNCONFIRMED, never claim full logout; stale writes must remain fenced |

AT expiry forbids using `/api/v1/auth/logout` as a successful logout route.
Do not refresh solely to make logout possible. `/oauth2/revoke` of RT invalidates
the refresh family through authorization persistence; it is not equivalent to
session revocation. Tests must preserve this distinction. Independent browser
contexts isolate A/B users; same-site tabs share Cookie and do not promise
simultaneous different identities.

## Support and evidence boundary

Hosted code+PKCE/client authentication/rotation have existing ordinary WEB
selectors in OAuthPersistenceProtocolIT. C0 adds consumer and lifecycle vectors,
with focused third-party WEB proof recorded in execution evidence.
CUSTOM PASSWORD and supported OTP/magic/MFA reuse existing transactions;
Provider transport and email/SMS delivery must be classified independently as
controlled fixture, actual external delivery, or not run. External input missing
blocks that proof only. No new grant, issuer, migration, opaque token engine,
sealed-cookie product or internal Console dependency is required.

Consumers copy the guide/vector/record snapshots and record SHA-256/version.
They execute vectors against their own packaged SDK, plus their declared
frameworks and real IAM browser paths. The backend's JSON vectors alone cannot
prove a SDK implementation or framework's automatic-save behavior.
