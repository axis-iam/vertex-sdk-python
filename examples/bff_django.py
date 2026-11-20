"""Install axis-iam-vertex[django]. Include build_urls(core) at the URL root.

Create one SyncServerSession(config, MemorySessionStore()) during application
startup, retain both objects and close core then store at application shutdown.
Django ASGI may instead use ServerSession and require_async_web_session.
"""
from __future__ import annotations

from django.http import HttpRequest, JsonResponse
from django.urls import URLPattern, path

from axis_vertex.django import require_web_session, session_urls, web_session_from_request
from axis_vertex.web_session import SyncServerSession


def build_urls(core: SyncServerSession) -> list[URLPattern]:
    @require_web_session(core, 'documents:read')
    def documents(request: HttpRequest) -> JsonResponse:
        view = web_session_from_request(request)
        assert view is not None
        return JsonResponse({'profile': view['profile']})

    @require_web_session(core, 'documents:write')
    def create_document(request: HttpRequest) -> JsonResponse:
        # SDK guard checks Origin/CSRF; keep native Django CSRF middleware enabled.
        if request.method != 'POST':
            return JsonResponse({'error': 'METHOD_NOT_ALLOWED'}, status=405)
        return JsonResponse({'created': True})

    return [*session_urls(core), path('documents', documents),
            path('documents/create', create_document)]
