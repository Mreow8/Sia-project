from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import datetime

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    bio = models.TextField(blank=True)
    profile_img = models.URLField(default="https://via.placeholder.com/150")

    def __str__(self):
        return self.user.username

class LoginAttempt(models.Model):
    identifier = models.CharField(max_length=100) # Email or Phone
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.identifier} - {self.timestamp}"