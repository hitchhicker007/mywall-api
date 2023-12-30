from django import forms


class PasswordResetForm(forms.Form):
    attrs = {
        "type": "password"
    }
    password = forms.CharField(required=True, widget=forms.TextInput(attrs=attrs), min_length=6, label="Password")
    password2 = forms.CharField(required=True, widget=forms.TextInput(attrs=attrs), min_length=6, label="Confirm Password")
