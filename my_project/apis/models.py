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
    profile_image = models.ImageField(upload_to='profile_images/',default='profile_images/default.png',null=True, blank=True)


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
    

class Ticket(models.Model):
    # Champs existants
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(
        max_length=50, 
        choices=[('ouvert', 'Ouvert'), 
                 ('ferme', 'Fermé'), 
                 ('en_cours', 'En cours')],default='ouvert')
    name = models.CharField(max_length=100, blank=False, null=False)
    service = models.CharField(max_length=100, blank=False, null=False)
    description = models.TextField(blank=False, null=False)
    personne_declarer = models.CharField(max_length=50, blank=False, null=False)

    def __str__(self):
        return f"Ticket {self.name} - {self.get_status_display()}"


    


