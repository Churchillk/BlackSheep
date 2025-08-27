from django import forms

ENCODING_CHOICES = [
    ('auto', 'Auto Detect'),
    ('base64', 'Base64'),
    ('hex', 'Hexadecimal'),
    ('url', 'URL Encoding'),
    ('html', 'HTML Entities'),
]

class EncodedInputForm(forms.Form):
    encoded_value = forms.CharField(
        label="Encoded Value",
        widget=forms.Textarea(attrs={
            "placeholder": "Paste your encoded string here...",
            "class": "form-control",
            "rows": 5,
        }),
        required=True
    )
    
    encoding_type = forms.ChoiceField(
        choices=ENCODING_CHOICES,
        widget=forms.Select(attrs={
            "class": "form-select"
        }),
        label="Encoding Type",
        initial='auto',
        help_text="Select 'Auto Detect' to automatically determine the encoding type"
    )
    

class EncodeForm(forms.Form):
    raw_value = forms.CharField(
        label="Raw Value",
        widget=forms.Textarea(attrs={
            "placeholder": "Enter the string you want to encode...",
            "class": "form-control",
            "rows": 5,
        }),
        required=True
    )
    
    encoding_type = forms.ChoiceField(
        choices=ENCODING_CHOICES[1:],  # Exclude 'auto' for encoding
        widget=forms.Select(attrs={
            "class": "form-select"
        }),
        label="Encoding Type",
        initial='base64',
        help_text="Select the encoding type you want to use"
    )