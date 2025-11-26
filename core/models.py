from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(blank=True)
    profile_img = models.URLField(default="https://via.placeholder.com/150")

    def __str__(self):
        return self.user.username