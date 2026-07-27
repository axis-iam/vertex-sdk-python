"""FastAPI/Starlette middleware for optional IAM context injection."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from axis_vertex.client import IamClient
from axis_vertex.errors import UnauthorizedError


class IamAuthenticationMiddleware(BaseHTTPMiddleware):
    """Authenticate bearer tokens when present and attach ``request.state.iam_context``."""

    def __init__(self, app: object, iam: IamClient) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._iam = iam

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        value = request.headers.get("authorization", "").strip()
        if value:
            if not value.lower().startswith("bearer "):
                return Response(status_code=status.HTTP_401_UNAUTHORIZED)
            try:
                request.state.iam_context = await self._iam.authenticate(value[7:].strip())
            except UnauthorizedError:
                return Response(status_code=status.HTTP_401_UNAUTHORIZED)
        return await call_next(request)
