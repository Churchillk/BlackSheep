from django.db import models
import json

class XXEScan(models.Model):
    HEADER_CHOICES = [
        ('default', 'Default Headers'),
        ('custom', 'Custom Headers')
    ]

    target_url = models.URLField()
    endpoint = models.CharField(max_length=200, default='/data')
    method = models.CharField(max_length=10, default='POST')
    file_to_read = models.CharField(max_length=500, default='/etc/passwd')
    timeout = models.IntegerField(default=10)
    header_choice = models.CharField(max_length=10, choices=HEADER_CHOICES, default='default')
    custom_headers = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def get_headers(self):
        if self.header_choice == 'custom' and self.custom_headers:
            try:
                return json.loads(self.custom_headers)
            except json.JSONDecodeError:
                pass
        # Default headers
        return {
            'Content-Type': 'application/xml',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

    def __str__(self):
        return f"XXE Scan - {self.target_url} - {self.created_at}"

class ScanResult(models.Model):
    scan = models.ForeignKey(XXEScan, on_delete=models.CASCADE, related_name='results')
    payload_used = models.TextField()
    status_code = models.IntegerField()
    response_body = models.TextField()
    success = models.BooleanField(default=False)
    error_message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Result - Scan {self.scan.id} - Success: {self.success}"