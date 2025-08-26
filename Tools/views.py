from django.shortcuts import render
import base64, binascii, urllib.parse, html
from django.views.generic import FormView
from .forms import EncodedInputForm
from django.utils.html import escape

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