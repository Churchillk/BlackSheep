from django.urls import path
from .views import DecodeInput, EncodeInput, RequestMakerView

urlpatterns = [
    path("decode/", DecodeInput.as_view(), name="decoder"),
    path("encode/", EncodeInput.as_view(), name="encoder"),

    # request maker
    path("request/", RequestMakerView.as_view(), name="request_maker"),
]
