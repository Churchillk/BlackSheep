from django.urls import path
from . import views as HomeViews

urlpatterns = [
    path("", HomeViews.Dashboard.as_view(), name="dashboard"),
]
