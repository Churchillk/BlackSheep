from django.urls import path
from .views import DecodeInput

urlpatterns = [
    path("decode/", DecodeInput.as_view(), name="decoder"),
]
