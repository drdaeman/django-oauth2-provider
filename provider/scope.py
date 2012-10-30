"""
Default scope implementation relying on bit shifting. See 
:attr:`provider.constants.SCOPES` for the list of available scopes.

Scopes can be combined, such as ``"read write"``. Note that a single ``"write"``
scope is *not* the same as ``"read write"``.

See :class:`provider.scope.to_int` on how scopes are combined.
"""

from provider.constants import SCOPES
from django.core.exceptions import ImproperlyConfigured


SCOPE_NAME_DICT = {}
SCOPE_INT_CHOICES = []
SCOPE_NAME_CHOICES = []

for t in SCOPES:
    if len(t) not in (2, 3):
        raise ImproperlyConfigured("OAUTH_SCOPES must be an iterable of 2- or 3-tuples.")
    SCOPE_INT_CHOICES.append((t[0], t[2] if len(t) > 2 else t[1]))
    SCOPE_NAME_CHOICES.append((t[1], t[2] if len(t) > 2 else t[1]))
    SCOPE_NAME_DICT[t[1]] = t[0]
del t

SCOPE_INT_CHOICES = tuple(SCOPE_INT_CHOICES)
SCOPE_NAME_CHOICES = tuple(SCOPE_NAME_CHOICES)


def check(wants, has):
    """
    Check if a desired scope ``wants`` is part of an available scope ``has``.
    
    Returns ``False`` if not, return ``True`` if yes.
    
    :example:
        
    If a list of scopes such as
    
    ::
    
        READ = 1 << 1
        WRITE = 1 << 2
        READ_WRITE = READ | WRITE
    
        SCOPES = (
            (READ, 'read'),
            (WRITE, 'write'),
            (READ_WRITE, 'read+write'),
        )
    
    is defined, we can check if a given scope is part of another:
    
    ::
    
        >>> from provider import scope
        >>> scope.check(READ, READ)
        True
        >>> scope.check(WRITE, READ)
        False
        >>> scope.check(WRITE, WRITE)
        True
        >>> scope.check(READ, WRITE)
        False
        >>> scope.check(READ, READ_WRITE)
        True
        >>> scope.check(WRITE, READ_WRITE)
        True        
    
    """
    if wants & has == 0:
        return False
    if wants & has < wants:
        return False
    return True

def to_names(scope):
    """
    Returns a list of scope names as defined in :attr:`provider.constants.SCOPES` 
    for a given scope integer.
    
        >>> assert ['read', 'write'] == provider.scope.names(provider.constants.READ_WRITE)
        
    """
    return [
        name 
        for (name, value) in SCOPE_NAME_DICT.iteritems()
        if check(value, scope)
    ]
# Keep it compatible
names = to_names

def to_choices(scope):
    """
    Return a list of human-friendly scope descriptions (or names, if there're none)
    as defined in :attr:`provider.constants.SCOPES` for a given scope integer.

        >>> assert [('read', 'Read your data'), ('write', 'Write your data')] \
            == provider.scope.to_choices(provider.constants.READ_WRITE)
    """
    return [
        (name, description)
        for (value, name, description) in SCOPES
        if check(value, scope)
    ]

def to_int(*names, **kwargs):
    """
    Turns a list of scope names into an integer value.
    
    ::
    
        >>> scope.to_int('read')
        2
        >>> scope.to_int('write')
        6
        >>> scope.to_int('read', 'write')
        6
        >>> scope.to_int('invalid')
        0
        >>> scope.to_int('invalid', default = 1)
        1
        
    """
    
    return reduce(lambda prev, next: (prev | SCOPE_NAME_DICT.get(next, 0)), names, kwargs.pop('default', 0))
