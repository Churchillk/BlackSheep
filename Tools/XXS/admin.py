# admin.py
from django.contrib import admin
from .models import XXEScan, ScanResult

@admin.register(XXEScan)
class XXEScanAdmin(admin.ModelAdmin):
    list_display = ['target_url', 'endpoint', 'method', 'file_to_read', 'status', 'created_at']
    list_filter = ['status', 'method', 'created_at']
    search_fields = ['target_url', 'endpoint']

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ['scan', 'status_code', 'success', 'created_at']
    list_filter = ['success', 'status_code', 'created_at']
    search_fields = ['scan__target_url', 'response_body']