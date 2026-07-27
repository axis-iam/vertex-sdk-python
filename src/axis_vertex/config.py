"""Configuration for the server-side IAM SDK."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import IamConfigError


def normalize_endpoint(endpoint: str) -> str:
    """Return endpoint without trailing slashes."""

    value = endpoint.strip().rstrip("/")
    if not value:
        raise IamConfigError("endpoint is required")
    return value


@dataclass(frozen=True, slots=True)
class IamConfig:
    """Runtime configuration for :class:`axis_vertex.IamClient`.

    ``client_id`` is ``ApplicationClient.clientId`` for a WEB/M2M confidential
    ApplicationClient. ``resource_audience`` is ``Application.resourceAudience``
    and is used to verify access-token ``aud``. ``client_secret`` is required
    because this SDK resolves permissions and optionally registers permission
    definitions server-side.
    """

    endpoint: str
    client_id: str
    client_secret: str
    resource_audience: str = ""
    # Deprecated alias for resource_audience. Do not pass client_id here.
    audience: str | None = None
    issuer: str | None = None
    http_timeout: float = 5.0
    jwks_cache_ttl: float = 300.0
    permission_cache_ttl: float = 300.0
    user_profile_cache_ttl: float = 60.0
    fail_open: bool = False

    def __post_init__(self) -> None:
        endpoint = normalize_endpoint(self.endpoint)
        client_id = self.client_id.strip()
        client_secret = self.client_secret.strip()
        resource_audience = (self.resource_audience or "").strip()
        deprecated_audience = (self.audience or "").strip()
        if not client_id:
            raise IamConfigError("client_id is required")
        if not client_secret:
            raise IamConfigError(
                "client_secret is required for WEB/M2M confidential ApplicationClient"
            )
        if resource_audience and deprecated_audience and resource_audience != deprecated_audience:
            raise IamConfigError("audience deprecated alias must match resource_audience")
        resource_audience = resource_audience or deprecated_audience
        if not resource_audience:
            raise IamConfigError("resource_audience is required")
        object.__setattr__(self, "endpoint", endpoint)
        object.__setattr__(self, "client_id", client_id)
        object.__setattr__(self, "client_secret", client_secret)
        object.__setattr__(self, "resource_audience", resource_audience)
        object.__setattr__(self, "audience", resource_audience)
        object.__setattr__(self, "issuer", normalize_endpoint(self.issuer or endpoint))

        if self.http_timeout <= 0:
            raise IamConfigError("http_timeout must be positive")
        if self.jwks_cache_ttl <= 0:
            raise IamConfigError("jwks_cache_ttl must be positive")
        if self.permission_cache_ttl <= 0:
            raise IamConfigError("permission_cache_ttl must be positive")
        if self.user_profile_cache_ttl <= 0:
            raise IamConfigError("user_profile_cache_ttl must be positive")
