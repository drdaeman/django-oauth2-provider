from django import template

register = template.Library()

@register.filter
def scopes(scopes):
    """ 
    Wrapper around :attr:`provider.scope.names` to turn an Scope list into a list
    of scope names in templates.

    Deprecated.
    """
    return [s.name for s in scopes]
