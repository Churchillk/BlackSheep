from django.shortcuts import render
import base64, binascii, urllib.parse, html
from django.views.generic import FormView
from .forms import EncodedInputForm, EncodeForm
from django.utils.html import escape


# decoding encoded data
class DecodeInput(FormView):
    form_class = EncodedInputForm
    template_name = "URLS/decoding_forms.html"
    success_url = '.'  # Stay on the same page after form submission
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add any additional context you might need
        return context
    
    def form_valid(self, form):
        encoded_value = form.cleaned_data['encoded_value']
        encoding_type_selected = form.cleaned_data['encoding_type']
        decoded_value = None
        detected_type = "Unknown"
        
        # If auto detect is selected, try all methods
        if encoding_type_selected == 'auto':
            decoded_value, detected_type = self.auto_detect_decode(encoded_value)
        else:
            # Use the selected encoding type
            decoded_value, detected_type = self.decode_with_type(encoded_value, encoding_type_selected)
        
        # Add context with results
        context = self.get_context_data(
            form=form, 
            decoded_value=decoded_value, 
            encoding_type=detected_type,
            original_value=encoded_value
        )
        return self.render_to_response(context)
    
    def auto_detect_decode(self, encoded_value):
        """Try to automatically detect the encoding type and decode"""
        decoding_functions = [
            ('Base64', self.try_base64),
            ('Hex', self.try_hex),
            ('URL', self.try_url),
            ('HTML', self.try_html),
        ]
        
        for encoding_name, decoding_func in decoding_functions:
            result = decoding_func(encoded_value)
            if result is not None:
                return result, encoding_name
        
        return "Could not automatically detect encoding type. Please select manually.", "Unknown"
    
    def decode_with_type(self, encoded_value, encoding_type):
        """Decode with a specific encoding type"""
        if encoding_type == 'base64':
            return self.try_base64(encoded_value), 'Base64'
        elif encoding_type == 'hex':
            return self.try_hex(encoded_value), 'Hex'
        elif encoding_type == 'url':
            return self.try_url(encoded_value), 'URL'
        elif encoding_type == 'html':
            return self.try_html(encoded_value), 'HTML'
        else:
            return "Unsupported encoding type selected", "Unknown"
    
    def try_base64(self, encoded_value):
        """Try Base64 decoding"""
        try:
            # Handle both standard and URL-safe base64
            for altchars in (None, b'-_'):
                try:
                    decoded_bytes = base64.b64decode(encoded_value, altchars=altchars)
                    return decoded_bytes.decode('utf-8')
                except (binascii.Error, UnicodeDecodeError):
                    continue
            return None
        except Exception:
            return None
    
    def try_hex(self, encoded_value):
        """Try Hex decoding"""
        try:
            # Remove any spaces or non-hex characters
            hex_string = ''.join(c for c in encoded_value if c in '0123456789ABCDEFabcdef')
            if len(hex_string) % 2 != 0:
                hex_string = '0' + hex_string  # Pad with leading zero if odd length
            decoded_bytes = bytes.fromhex(hex_string)
            return decoded_bytes.decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            return None
    
    def try_url(self, encoded_value):
        """Try URL decoding"""
        try:
            decoded = urllib.parse.unquote(encoded_value)
            # If the result is different from input, assume it was URL encoded
            if decoded != encoded_value:
                return decoded
            return None
        except Exception:
            return None
    
    def try_html(self, encoded_value):
        """Try HTML entities decoding"""
        try:
            decoded = html.unescape(encoded_value)
            # If the result is different from input, assume it was HTML encoded
            if decoded != encoded_value:
                return decoded
            return None
        except Exception:
            return None
        
        
# encoding raw data
class EncodeInput(FormView):
    template_name = 'URLS/encode.html'
    form_class = EncodeForm

    def form_valid(self, form):
        # Get the input value from the form
        raw_value = form.cleaned_data['raw_value']
        encoding_type = form.cleaned_data['encoding_type']

        # Encode the raw value
        encoded_value = self.encode_with_type(raw_value, encoding_type)

        # Add context with results
        context = self.get_context_data(
            form=form,
            encoded_value=encoded_value,
            encoding_type=encoding_type
        )
        return self.render_to_response(context)

    def encode_with_type(self, raw_value, encoding_type):
        """Encode with a specific encoding type"""
        if encoding_type == 'base64':
            return self.try_base64_encode(raw_value)
        elif encoding_type == 'hex':
            return self.try_hex_encode(raw_value)
        elif encoding_type == 'url':
            return self.try_url_encode(raw_value)
        elif encoding_type == 'html':
            return self.try_html_encode(raw_value)
        else:
            return "Unsupported encoding type selected"

    def try_base64_encode(self, raw_value):
        """Try Base64 encoding"""
        try:
            encoded_bytes = base64.b64encode(raw_value.encode('utf-8'))
            return encoded_bytes.decode('utf-8')
        except Exception:
            return None

    def try_hex_encode(self, raw_value):
        """Try Hex encoding"""
        try:
            encoded_bytes = raw_value.encode('utf-8').hex()
            return encoded_bytes
        except Exception:
            return None

    def try_url_encode(self, raw_value):
        """Try URL encoding"""
        try:
            encoded = urllib.parse.quote(raw_value)
            return encoded
        except Exception:
            return None

    def try_html_encode(self, raw_value):
        """Try HTML entities encoding"""
        try:
            encoded = html.escape(raw_value)
            return encoded
        except Exception:
            return None
        
# -------------------------------------------
#              REQUESTS SITE                #
# -------------------------------------------
import requests
import json
from django.shortcuts import render
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

from django.shortcuts import render
from django.views import View
import requests
import json

class RequestMakerView(View):
    def get(self, request):
        return render(request, 'Requests/request_maker.html')
    
    def post(self, request):
        url = request.POST.get('url', '')
        method = request.POST.get('method', 'GET')
        timeout = int(request.POST.get('timeout', 10))
        data = request.POST.get('data', '')
        
        # Prepare headers
        headers = {}
        header_names = request.POST.getlist('header_name[]')
        header_values = request.POST.getlist('header_value[]')
        for i in range(len(header_names)):
            if header_names[i] and header_values[i]:
                headers[header_names[i]] = header_values[i]
        
        # ✅ Add default User-Agent if not provided
        if "User-Agent" not in headers:
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
        
        # Prepare cookies
        cookies = {}
        cookie_names = request.POST.getlist('cookie_name[]')
        cookie_values = request.POST.getlist('cookie_value[]')
        for i in range(len(cookie_names)):
            if cookie_names[i] and cookie_values[i]:
                cookies[cookie_names[i]] = cookie_values[i]
        
        # Prepare request data
        request_data = None
        if data and method in ['POST', 'PUT', 'PATCH']:
            try:
                # Try to parse as JSON
                request_data = json.loads(data)
                headers['Content-Type'] = headers.get('Content-Type', 'application/json')
            except json.JSONDecodeError:
                # If not JSON, use as form data
                request_data = data
                if 'Content-Type' not in headers:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
        
        try:
            # Make the request
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                cookies=cookies,
                json=request_data if isinstance(request_data, dict) else None,
                data=request_data if not isinstance(request_data, dict) else None,
                timeout=timeout,
                allow_redirects=True
            )
            
            # Get the response content
            content = response.text
            
            # Rewrite relative URLs to absolute URLs for HTML content
            if url.startswith('http') and 'text/html' in response.headers.get('Content-Type', ''):
                from urllib.parse import urlparse
                parsed_url = urlparse(url)
                base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
                
                # Replace relative URLs with absolute URLs
                content = content.replace('src="/', f'src="{base_domain}/')
                content = content.replace('href="/', f'href="{base_domain}/')
                content = content.replace('url("/', f'url("{base_domain}/')
                content = content.replace("url('/", f"url('{base_domain}/")
                content = content.replace('url("/', f'url("{base_domain}/')
            
            # Prepare pretty content (try to parse as JSON first)
            try:
                pretty_content = json.dumps(response.json(), indent=2)
            except:
                pretty_content = content  # Use the modified content
            
            # Determine status category for styling
            status_category = 'other'
            if 200 <= response.status_code < 300:
                status_category = '2xx'
            elif 300 <= response.status_code < 400:
                status_category = '3xx'
            elif 400 <= response.status_code < 500:
                status_category = '4xx'
            elif 500 <= response.status_code < 600:
                status_category = '5xx'
            
            response_data = {
                'status_code': response.status_code,
                'reason': response.reason,
                'headers': dict(response.headers),
                'cookies': dict(response.cookies),
                'content': content,  # Use the modified content
                'pretty_content': pretty_content,
                'elapsed': int(response.elapsed.total_seconds() * 1000),
                'status_category': status_category
            }
            
            return render(request, 'Requests/request_maker.html', {
                'response_data': response_data,
                'cookies': [{'name': k, 'value': v} for k, v in cookies.items()]
            })
            
        except requests.exceptions.RequestException as e:
            return render(request, 'Requests/request_maker.html', {
                'error': str(e),
                'cookies': [{'name': k, 'value': v} for k, v in cookies.items()]
            })
