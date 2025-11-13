# urls.py (app-level)
from django.urls import path
from . import views

xxsPatterns = [
    path('xxe-scan/', views.XXEScannerView.as_view(), name='scan'),
    path('history/', views.ScanHistoryView.as_view(), name='history'),
    path('scan/<int:scan_id>/', views.ScanDetailView.as_view(), name='scan_detail'),
    path('api/scan/', views.APIScanView.as_view(), name='api_scan'),
]