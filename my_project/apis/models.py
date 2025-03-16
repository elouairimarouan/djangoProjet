from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone



class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    role = models.IntegerField(default=0)
    date_joined = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)  # Required for Django admin

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.username

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    # @classmethod
    # def authenticate(cls, email, password):
    #     try:
    #         user = cls.objects.get(email=email)
    #         if user.check_password(password):
    #             return user
    #         return None
    #     except cls.DoesNotExist:
    #         return None
        
        
class PasswordResetCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)  
    created_at = models.DateTimeField(auto_now_add=True)
    expired_at = models.DateTimeField()  

    def is_expired(self):
        return timezone.now() > self.expired_at

    def __str__(self):
        return f"Reset code for {self.user.username} (expires at {self.expired_at})"

