# Server sessions for FastAPI and Django

Install `axis-iam-vertex[fastapi]` or `axis-iam-vertex[django]` on Python 3.12+.
The optional `axis_vertex.web_session` module implements C0
`connected-app-bff-c0/1.0.1`. Existing Bearer and `oauth_tokens` integrations keep
their existing defaults. Browser UI belongs to the shared JS SDK; Python keeps
OAuth tokens, transaction control and PKCE material in the application backend.

## Configure and mount

Register a confidential WEB client with S256 PKCE and the exact callback below.
Load its secret from application configuration. Resource audience is the registered
Application audience; ID Token verification uses the WEB client ID instead.

```python
from axis_vertex.web_session import MemorySessionStore, ServerSession, SessionConfig

config = SessionConfig(
    issuer=issuer, client_id=client_id, client_secret=client_secret,
    resource_audience=resource_audience,
    origin="https://app.example.com",
    callback_uri="https://app.example.com/auth/callback",
    scopes=("openid", "profile", "offline_access"),
    return_paths=("/", "/documents"),
    replicas=1,
)
store = MemorySessionStore()  # explicit, one shared instance in this process
session = ServerSession(config, store)
```

Use the runnable factory in `examples/bff_fastapi.py`, or mount
`app.include_router(session_router(session))` from `axis_vertex.fastapi`.
Protect a business route with `Depends(require_web_session(session, "documents:read"))`.
`web_session_from_request(request)` reads only the value set by that dependency.
No business URL is automatically proxied. Explicit Authorization headers on these
Cookie routes are refused; use the existing Bearer dependencies for Bearer routes.
An invalid explicit credential never falls back to a Cookie.

For a group of explicitly named paths, install FastAPI `WebSessionMiddleware`
with `session=session, paths=("/documents",)`. Dependencies reuse its validated
request value and still enforce each route's permission. Django sync hosts can
expose an application middleware factory returning
`WebSessionMiddleware(get_response, core, paths=("/documents",))`.
Django ASGI hosts export `async_session_middleware(session, paths=(...))` as their
middleware factory; it declares the async capability Django needs before creating
the middleware. Both middleware forms are optional, explicitly configured and
share the same core as the dependencies/decorators.

For Django sync views, construct `SyncServerSession(config, store)` once and include
`session_urls(core)` from `axis_vertex.django` in root `urlpatterns`. Use
`@require_web_session(core, "documents:read")`; `examples/bff_django.py` shows both.
`SyncServerSession.run(core.bootstrap(None))` is the explicit sync programmatic
entry. It owns one persistent runner/HTTP pool, refuses an active event loop, and
closes with `core.close()`. It does not create a loop per request.
Django async views use `ServerSession`, `session_urls(session)` and
`@require_async_web_session(session, permission)`. Close owned async HTTP with
`await session.aclose()` and the application-owned store separately.

The Django routes enforce the C0 Origin/CSRF format themselves, including when
`CsrfViewMiddleware` is installed. The SDK owns a dedicated random HttpOnly Cookie;
Django `request.session` and Starlette native session fields are never copied into
its authentication record. Native framework Cookies must have a distinct name.
This is explicit standalone Cookie wiring, not certification of Django database,
cache, file, or signed-cookie session backends as atomic credential providers.
Unrelated host session fields remain under their host lifecycle.

## Browser flow

First GET `/auth/session/bootstrap` with same-origin credentials. It returns
`{state:"PRELOGIN",expiresAt,csrfToken}` and binds a random HttpOnly Cookie.
Hosted navigation then goes to `/auth/login?returnTo=/documents`; a direct login
GET without bootstrap is rejected. The callback consumes its bound code/state
once, exchanges on the backend, validates OIDC and loads profile, permissions and
online validity. It rotates Cookie and CSRF, then redirects to the exact allowed
local path without the code.

Every POST requires the exact configured `Origin` and the current `X-CSRF-Token`.
CUSTOM login uses `/auth/session/login` and its finite `/authenticate`, `/challenges`,
`/authorize`, `/mfa`, `/complete`, `/cancel` and `/magic` actions. The state
AUTHENTICATED with nextAction complete means proofs collected; signed-in views
require owner, version, profile and permissions after confidential code exchange.
Provider code is consumed by the BFF callback. AUTH_CONTINUATION resumes the
bound transaction's MFA. Duplicate/mixed callback shapes and replays reject.

Email fragments do not reach Python HTTP requests. The shared JS browser bridge
must validate origin/path/unique fragment fields and EMAIL/local-generation
binding, clear the fragment with history.replaceState, then POST only
`{transactionId,state,proof}` to `/auth/session/login/magic`. No Python endpoint
reads browser fragments or exposes tokens. Shared JS artifact/browser integration
is a separate combined validation prerequisite; protocol fixture tests do not
establish real external email, SMS, Provider delivery or combined browser proof.

Registration (`/registration`, `/{ref}`, `/{ref}/challenges|complete|cancel`) uses
opaque local refs bound to backend registration controls. It never signs a user
in. EMAIL password recovery uses `/password-reset/request` and `/complete`.
The backend supplies the configured client and optional explicitly allowlisted
`password_reset_redirect`. Capability/policy GET routes are fixed to that client.
No arbitrary URL/header proxy exists. Password/identifier/provider fields use
exact C0 wire names; unknown fields and duplicate JSON keys reject.

## Provider and deployment contract

Storage is mandatory. Memory defaults: 10,000 sessions, 1,000 prelogins, 65,536
serialized bytes per record, 60s cleanup, 600s prelogin maximum, 15s operation
lease; local authenticated absolute/idle caps default to 3600s and clamp to IAM.
Expired records purge on access and periodically; full capacity refuses new
records with 503 rather than evicting live identities. Reads are isolated copies.
Close clears sensitive records, joins cleanup and makes subsequent access CLOSED.
The SDK never serializes token records into a browser Cookie or logs their repr.

Memory is volatile backend RAM and supports one process only. Declare actual
workers/replicas with `replicas`; values >1 reject this provider. Multiple
uvicorn/gunicorn workers, sticky routing and a machine-local lock do not share
RAM. Restart loses local login and requires authorization again; this does not
claim IAM/SSO revocation. No DB, migrations or encryption key are required.

Custom providers implement `AsyncSessionStore` or `SyncSessionStore` and declare
`StoreCapabilities`. Async methods must perform native async IO. The explicit
sync port runs on the sync caller's persistent runner. Missing atomic/server-side
capabilities reject; multiple replicas require actual shared coordination.
Namespace only SDK data, e.g. `axis_vertex.server_session.v1`, preserve unrelated
host data, and protect persisted credentials under the application's policy.
A capability flag alone does not prove a backend. Run the store/lifecycle contract
scenarios for each claimed deployment. No production persistent backend is
certified by this package's controlled fixture evidence.

`create` is create-if-absent. `read` distinguishes absence/expiry from unavailability.
`compare_exchange(key, version, replacement)` atomically requires a live record,
expected version, immutable owner/deadlines (except the one prelogin-to-session
rotation), and replacement.version == version+1. Rotating key consumes the old
record and creates the new one atomically. A live send intent and lease authorize
that rotation; expired intent must invalidate. `invalidate` fences all late
updates. ABSENT, CONFLICT, CAPACITY, UNAVAILABLE and CLOSED are distinct outcomes.
Custom stores must not implement conditional update as unconditional get/set.

Refresh claims ownership before sending, persists send intent, and commits with
CAS. A sent timeout, lost fence, expired intent or failed commit ends authentication;
old RT is never replayed. A known failure before send may release the claim and
return 503. No RT is supported: its absence never broadens scopes and AT expiry
requires authorization. Each protected request checks online IAM validity within
10s total auth budget/5s upstream timeout; getters do no extra network. Network or
store outage returns a service error, not an anonymous success or empty permissions.
Absolute deadline does not slide on refresh/touch. Permission denial is 403 and
preserves valid authentication.

Logout invalidates local state first, clears the same Cookie, then attempts bounded
remote revocation. The result separates local, Cookie, remote and SSO facts.
Unexpired AT can revoke the current session; expired AT with RT only confirms the
refresh-family revocation endpoint, never session/all-AT deletion. Expired AT
without RT has no usable remote credential. Logout never refreshes to acquire one.
Storage/remote failure returns 503 and explicit details. SSO is NOT_REQUESTED;
no automatic end-session navigation is performed. Late framework saves of
unrelated session data cannot create credentials or recreate a consumed record.

Production Cookie defaults to `__Host-axis-session`, Secure, HttpOnly, host-only,
Path=/, SameSite=Lax. HTTP development requires explicit loopback URLs,
`allow_loopback_http=True` and a non-__Host Cookie name. Cookie ports do not isolate
apps: use distinct names for multiple local apps. Configure proxy/origin trust in
the host; incoming Host never determines issuer or redirects.

## Protected business writes

SDK guards require exact canonical Origin and the current Cookie record's
X-CSRF-Token on business methods other than GET, HEAD and OPTIONS, including when
middleware has already populated a request identity. Read the current token from
/auth/session/bootstrap or /auth/session after login, which rotates it. Send the
token in the X-CSRF-Token header with same-origin credentials; browsers supply
Origin, while server HTTP clients must set it to the configured origin explicitly.
Missing or mismatched Origin/CSRF returns 403 SESSION_CSRF_INVALID before business
code. The FastAPI factory includes POST /documents; the Django URL example has
POST /documents/create. Both require documents:write.

Keep native Django CsrfViewMiddleware enabled. Where installed, its separate
Cookie and X-CSRFToken header are required in addition to the SDK's X-CSRF-Token.
The SDK does not disable native protection for business routes. A middleware plus
dependency/decorator combination safely rechecks writes against the current
record; it does not accept cached identity as a substitute for Cookie binding.
