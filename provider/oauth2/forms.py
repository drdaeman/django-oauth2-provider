try:
    from django.utils import timezone
except ImportError:
    from datetime import datetime as timezone
from django import forms
from django.contrib.auth import authenticate
from django.utils.encoding import smart_unicode
from django.utils.translation import ugettext as _
from provider import constants
from provider.constants import RESPONSE_TYPE_CHOICES
from provider.forms import OAuthForm, OAuthValidationError
from provider.oauth2.models import Client, Grant, RefreshToken, Scope
from django.core.exceptions import ValidationError

class ClientForm(forms.ModelForm):
    """
    Form to create new consumers.
    """
    class Meta:
        model = Client
        fields = ('name', 'url', 'redirect_uri', 'client_type')
    
    def save(self, user=None, **kwargs):
        self.instance.user = user
        return super(ClientForm, self).save(**kwargs)

class ClientAuthForm(forms.Form):
    """
    Client authentication form. Required to make sure that we're dealing with a
    real client. Form is used in :attr:`provider.oauth2.backends` to validate
    the client.
    """
    client_id = forms.CharField()
    client_secret = forms.CharField()
    
    def clean(self):
        data = self.cleaned_data
        try:
            client = Client.objects.get(client_id=data.get('client_id'),
                client_secret=data.get('client_secret'))
        except Client.DoesNotExist:
            raise forms.ValidationError(_("Client could not be validated with key pair."))

        data['client'] = client
        return data

class ScopeChoiceField(forms.ModelMultipleChoiceField):
    """ 
    Custom form field that seperates values on space as defined in :draft:`3.3`.
    """
    default_error_messages = {
        'list': _('Enter a list of values.'),
        'invalid_choice': _("'%s' is not one of the available scopes."),
        'invalid_pk_value': _("'%s' is not a valid scope.")
    }

    def to_python(self, value):
        if isinstance(value, basestring):
            value = smart_unicode(val).split(u" ")

        if not isinstance(value, (list, tuple)):
            raise OAuthValidationError({'error': 'invalid_request'})

        return super(ScopeChoiceField, self).to_python(value)

    def clean(self, value):
        try:
            return super(ScopeChoiceField, self).clean(value)
        except ValidationError, e:
            raise OAuthValidationError({'error': 'invalid_scope',
                                        'error_description': '; '.join(e.messages)})

class AuthorizationRequestForm(OAuthForm):
    """
    This form is used to validate the request data that the authorization 
    endpoint receives from clients.
    
    Included data is specified in :draft:`4.1.1`.
    """
    # Setting all required fields to false to explicitly check by hand
    # and use custom error messages that can be reused in the OAuth2
    # protocol
    response_type = forms.CharField(required=False)
    """
    ``"code"`` or ``"token"`` depending on the grant type.
    """
    
    redirect_uri = forms.URLField(required=False)
    """
    Where the client would like to redirect the user
    back to. This has to match whatever value was saved while creating
    the client.
    """
    
    state = forms.CharField(required=False)
    """
    Opaque - just pass back to the client for validation.
    """
    
    scope = ScopeChoiceField(queryset=Scope.objects.all(), required=False)
    """
    The scope that the authorization should include.
    """
    
    def clean_response_type(self):
        """
        :draft:`3.1.1` Lists of values are space delimited.
        """
        response_type = self.cleaned_data.get('response_type')
        
        if not response_type:
            raise OAuthValidationError({'error': 'invalid_request',
                'error_description': "No 'response_type' supplied."})

        types = response_type.split(" ")
        
        for type in types:
            if type not in RESPONSE_TYPE_CHOICES:
                raise OAuthValidationError({'error': 'unsupported_response_type',
                    'error_description': u"'%s' is not a supported response type." % type})
        
        return response_type

    def clean_redirect_uri(self):
        """
        :draft:`3.1.2` The redirect value has to match what was saved on the 
            authorization server.
        """
        redirect_uri = self.cleaned_data.get('redirect_uri')

        if redirect_uri:
            if not redirect_uri == self.client.redirect_uri:
                raise OAuthValidationError({'error': 'invalid_request',
                    'error_description': _("The requested redirect didn't match the client settings.")})
        
        return redirect_uri        
        
class AuthorizationForm(OAuthForm):
    """
    A form used to ask the resource owner for authorization of a given client.
    """
    authorize = forms.BooleanField(required=False)
    scope = ScopeChoiceField(queryset=Scope.objects.all(), required=False)    

    def save(self, **kwargs):
        authorize = self.cleaned_data.get('authorize')

        if not authorize:
            return None
        
        grant = Grant()
        return grant

class RefreshTokenGrantForm(OAuthForm):
    """
    Checks and returns a refresh token.
    """
    refresh_token = forms.CharField(required=False)
    scope = ScopeChoiceField(queryset=Scope.objects.all(), required=False)
    
    def clean_refresh_token(self):
        token = self.cleaned_data.get('refresh_token')

        if not token:
            raise OAuthValidationError({'error': 'invalid_request'})
        
        try:
            token = RefreshToken.objects.get(token=token,
                expired=False, client=self.client)
        except RefreshToken.DoesNotExist:
            raise OAuthValidationError({'error': 'invalid_grant'})
        
        return token
    
    def clean(self):
        """
        Make sure that the scope is less or equal to the previous scope!
        """
        data = self.cleaned_data
        
        if 'scope' in data:
            if set(data.get('scope')) > set(data.get('refresh_token').access_token.scopes.all()):
                raise OAuthValidationError({'error': 'invalid_scope'})
        
        return data
    
class AuthorizationCodeGrantForm(OAuthForm):
    """
    Check and return an authorization grant.
    """
    code = forms.CharField(required=False)
    scope = ScopeChoiceField(queryset=Scope.objects.all(), required=False)
    
    def clean_code(self):
        code = self.cleaned_data.get('code')
        
        if not code:
            raise OAuthValidationError({'error': 'invalid_request'})
        
        try:
            self.cleaned_data['grant'] = Grant.objects.get(
                code=code, client=self.client, expires__gt=timezone.now())
        except Grant.DoesNotExist:
            raise OAuthValidationError({'error': 'invalid_grant'})
        
        return code
    
    def clean(self):
        """
        Make sure that the scope is less or equal to the scope allowed on the
        grant! 
        """
        data = self.cleaned_data
        # Only check if we've actually got a scope in the data
        # (read: All fields have been cleaned)
        if 'scope' in data:
            if set(data.get('scope')) > set(data.get('grant').scopes.all()):
                raise OAuthValidationError({'error': 'invalid_scope'})
        
        return data

class PasswordGrantForm(OAuthForm):
    """
    Validate the password of a user on a password grant request.
    """
    username = forms.CharField(required=False)
    password = forms.CharField(required=False)
    scope = ScopeChoiceField(queryset=Scope.objects.all(), required=False)
        
    def clean_username(self):
        username = self.cleaned_data.get('username')

        if not username:
            raise OAuthValidationError({'error': 'invalid_request'})
        
        return username
    
    def clean_password(self):
        password = self.cleaned_data.get('password')
        
        if not password:
            raise OAuthValidationError({'error': 'invalid_request'})
        
        return password
    
    def clean(self):
        data = self.cleaned_data
        
        user = authenticate(username=data.get('username'),
            password=data.get('password'))
        
        if user is None:
            raise OAuthValidationError({'error': 'invalid_grant'})
        
        data['user'] = user
        return data
        
        
