"""Instance-local synchronous loop and HTTP pool, separate from the async channel."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from contextvars import ContextVar, copy_context
from threading import Lock

import httpx


class SyncRuntime:
    def __init__(
        self,
        factory: Callable[[], httpx.AsyncClient] | None,
        async_transport: httpx.AsyncClient,
    ) -> None:
        self._factory = factory
        self._async_transport = async_transport
        self._active: ContextVar[bool] = ContextVar("iam_sync_transport", default=False)
        self._runner: asyncio.Runner | None = None
        self._http: httpx.AsyncClient | None = None
        self._lock = Lock()
        self._closed = False
        self.jwks_lock = asyncio.Lock()

    @property
    def active(self) -> bool:
        return self._active.get()

    def select_http(self, async_transport: httpx.AsyncClient) -> httpx.AsyncClient:
        if not self.active:
            return async_transport
        if self._http is None:
            raise RuntimeError("Synchronous IAM transport has not been initialized")
        return self._http

    @staticmethod
    def _assert_sync() -> None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        raise RuntimeError("sync IAM SDK wrapper cannot run inside an active event loop")

    def run[T](self, awaitable: Coroutine[None, None, T]) -> T:
        try:
            self._assert_sync()
            with self._lock:
                if self._closed:
                    raise RuntimeError("Synchronous IAM client is closed")
                if self._factory is None:
                    raise ValueError(
                        "Injected async HTTP clients require a sync_http_client_factory"
                    )
                if self._runner is None:
                    self._runner = asyncio.Runner()
                context = copy_context()
                context.run(self._active.set, True)
                return self._runner.run(self._invoke(awaitable), context=context)
        finally:
            awaitable.close()

    async def _invoke[T](self, awaitable: Coroutine[None, None, T]) -> T:
        if self._http is None:
            if self._factory is None:
                raise RuntimeError("Synchronous IAM transport factory is missing")
            client = self._factory()
            if client is self._async_transport:
                raise ValueError("Sync and async HTTP transports must be distinct")
            self._http = client
        return await awaitable

    def close(self) -> None:
        self._assert_sync()
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._runner is not None:
                try:
                    if self._http is not None:
                        self._runner.run(self._http.aclose())
                finally:
                    self._runner.close()
                    self._runner = None
