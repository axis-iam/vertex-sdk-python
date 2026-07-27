from __future__ import annotations

import os

SECRET_KEY = "dev-only"
ROOT_URLCONF = "examples.django_app.urls"
ALLOWED_HOSTS = ["*"]
INSTALLED_APPS: list[str] = []
MIDDLEWARE = ["axis_vertex.django.IamAuthenticationMiddleware"]
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

IAM_SDK = {
    "ENDPOINT": os.environ["IAM_ENDPOINT"],
    "CLIENT_ID": os.environ["IAM_CLIENT_ID"],
    "CLIENT_SECRET": os.environ["IAM_CLIENT_SECRET"],
    "RESOURCE_AUDIENCE": os.environ["IAM_RESOURCE_AUDIENCE"],
}
