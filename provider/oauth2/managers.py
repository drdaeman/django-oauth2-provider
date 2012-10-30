try:
    from django.utils import timezone
except ImportError:
    from datetime import datetime as timezone
from django.db import models

class AccessTokenManager(models.Manager):
    def get_token(self, token):
        return self.get(token=token, expires__gt=timezone.now())
