from datetime import datetime
from django.conf import settings
from provider.constants import EXPIRE_DELTA, EXPIRE_CODE_DELTA
try:
    from django.utils.encoding import smart_bytes, smart_text
except ImportError:
    from django.utils.encoding import smart_str as smart_bytes, smart_unicode as smart_text
import hashlib
import shortuuid
import base64


def short_token():
    """
    Generate a hash that can be used as an application identifier
    """
    hash = hashlib.sha1(smart_bytes(shortuuid.uuid(), encoding="ascii"))
    hash.update(smart_bytes(settings.SECRET_KEY))
    return hash.hexdigest()[::2]

def long_token():
    """
    Generate a hash that can be used as an application secret
    """
    hash = hashlib.sha1(smart_bytes(shortuuid.uuid(), encoding="ascii"))
    hash.update(smart_bytes(settings.SECRET_KEY))
    return hash.hexdigest()
    
def get_token_expiry():
    """
    Return a datetime object indicating when an access token should expire. 
    Can be customized by setting :attr:`settings.OAUTH_EXPIRE_DELTA` to a 
    :attr:`datetime.timedelta` object.
    """
    return datetime.now() + EXPIRE_DELTA

def get_code_expiry():
    """
    Return a datetime object indicating when an authorization code should 
    expire.
    Can be customized by setting :attr:`settings.OAUTH_EXPIRE_CODE_DELTA` to a 
    :attr:`datetime.timedelta` object.
    """
    return datetime.now() + EXPIRE_CODE_DELTA

def base64_encode(text):
    """
    Encode text to base64-encoded string.
    """
    return smart_text(base64.standard_b64encode(smart_bytes(text)), encoding="ascii")

def base64_decode(text):
    """
    Decode base64-encoded text.
    """
    return smart_text(base64.standard_b64decode(smart_bytes(text, encoding="ascii")))
