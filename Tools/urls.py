from django.urls import path
from .views import DecodeInput, EncodeInput

urlpatterns = [
    path("decode/", DecodeInput.as_view(), name="decoder"),
    path("encode/", EncodeInput.as_view(), name="encoder"),
]
