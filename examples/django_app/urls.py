from __future__ import annotations

from django.urls import path

from .views import list_orders, transfer

urlpatterns = [
    path("orders", list_orders),
    path("transfer", transfer),
]
