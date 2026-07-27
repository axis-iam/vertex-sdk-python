from __future__ import annotations

from django.http import HttpRequest, JsonResponse

from axis_vertex.django import require_no_impersonation, require_permission, require_step_up


@require_permission("orders", "read")
def list_orders(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"user": request.iam_context.user_id})


@require_step_up("urn:iam:acr:mfa")
@require_no_impersonation()
def transfer(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})
