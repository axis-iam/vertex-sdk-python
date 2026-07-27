"""Exception types raised by the IAM SDK."""

from __future__ import annotations


class IamSdkError(Exception):
    """Base class for SDK errors."""


class IamConfigError(IamSdkError, ValueError):
    """Raised when SDK configuration is invalid."""


class UnauthorizedError(IamSdkError):
    """Raised when a bearer token is missing, malformed, expired, or invalid."""


class ForbiddenError(IamSdkError):
    """Raised when an authenticated caller is not allowed to perform an action."""


class PermissionDeniedError(ForbiddenError):
    """Raised when a caller lacks a required permission."""


class StepUpRequiredError(ForbiddenError):
    """Raised when a route requires a stronger authentication context."""


class IamApiError(IamSdkError):
    """Raised when the IAM server returns an unsuccessful response."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(f"IAM API request failed: {status_code} {body}")


class PortalOpenApiConfigError(IamConfigError):
    """Raised when Portal Open API client configuration is invalid."""


class PortalOpenApiTransportError(IamSdkError):
    """Raised when a token or Portal Open API request cannot be transported."""


class PortalOpenApiTokenError(IamSdkError):
    """Raised when the M2M machine token request fails or returns an invalid body."""

    def __init__(
        self,
        message: str,
        code: str,
        *,
        status_code: int | None = None,
        body: object = None,
    ) -> None:
        self.code = code
        self.status_code = status_code
        self.body = body
        super().__init__(message)


class PortalOpenApiError(IamSdkError):
    """Raised when a Portal Open API request fails."""

    def __init__(
        self,
        message: str,
        status_code: int,
        code: str,
        *,
        body: object = None,
        retry_after: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.body = body
        self.retry_after = retry_after
        super().__init__(message)
