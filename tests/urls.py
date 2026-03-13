"""Minimal URL config for middleware tests."""

from django.http import HttpResponse, JsonResponse
from django.urls import path


def ok_view(request):
    return HttpResponse("ok")


def error_view(request):
    raise ValueError("test error")


def json_view(request):
    return JsonResponse({"status": "ok"})


urlpatterns = [
    path("ok/", ok_view),
    path("error/", error_view),
    path("json/", json_view),
]
