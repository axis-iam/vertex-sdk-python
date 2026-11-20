"""Install axis-iam-vertex[fastapi]; create one app/store instance per process."""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request

from axis_vertex.fastapi import require_web_session, session_router, web_session_from_request
from axis_vertex.web_session import MemorySessionStore, ServerSession, SessionConfig


def create_app(config: SessionConfig) -> FastAPI:
    store = MemorySessionStore()
    session = ServerSession(config, store)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await session.aclose()
            await store.aclose()

    app = FastAPI(lifespan=lifespan)
    app.include_router(session_router(session))

    @app.get('/documents', dependencies=[Depends(require_web_session(session, 'documents:read'))])
    async def documents(request: Request) -> dict[str, object]:
        view = web_session_from_request(request)
        assert view is not None
        return {'profile': view['profile']}

    @app.post('/documents', dependencies=[Depends(require_web_session(session, 'documents:write'))])
    async def create_document() -> dict[str, bool]:
        # Send canonical Origin and the current /auth/session CSRF token.
        return {'created': True}

    return app
