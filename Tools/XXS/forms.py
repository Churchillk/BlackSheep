from django import forms
import json

class XXEScanForm(forms.Form):
    target_url = forms.URLField(
        label='Target URL',
        widget=forms.URLInput(attrs={
            'class': 'form-control',
            'placeholder': 'https://example.com'
        })
    )

    endpoint = forms.CharField(
        max_length=200,
        initial='/data',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '/data'
        })
    )

    method = forms.ChoiceField(
        choices=[('POST', 'POST'), ('GET', 'GET')],
        initial='POST',
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    file_to_read = forms.CharField(
        max_length=500,
        initial='/etc/passwd',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '/etc/passwd'
        })
    )

    timeout = forms.IntegerField(
        min_value=1,
        max_value=60,
        initial=10,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': '1',
            'max': '60'
        })
    )

    header_choice = forms.ChoiceField(
        choices=[
            ('default', 'Default Headers'),
            ('custom', 'Custom Headers')
        ],
        initial='default',
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    custom_headers = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'placeholder': '{"Content-Type": "application/xml", "User-Agent": "Mozilla/5.0..."}',
            'rows': 4
        }),
        initial='{"Content-Type": "application/xml"}'
    )

    def clean_custom_headers(self):
        custom_headers = self.cleaned_data.get('custom_headers')
        if custom_headers:
            try:
                json.loads(custom_headers)
            except json.JSONDecodeError:
                raise forms.ValidationError("Please enter valid JSON format")
        return custom_headers