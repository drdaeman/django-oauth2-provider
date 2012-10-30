from django import template
from provider import scope

register = template.Library()

@register.filter
def scopes(scope_int):
    """ 
    Wrapper around :attr:`provider.scope.names` to turn an int into a list
    of scope names in templates.
    """
    return scope.to_names(scope_int)

@register.filter
def scopes_choice(scope_int):
    """
    Wrapper around :attr:`provider.scope.to_choices` to turn an int into a list
    of pairs ofg scope values and human-friendly descriptions (or names).
    """
    return scope.to_choices(scope_int)
