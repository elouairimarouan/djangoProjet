from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from cloudinary.models import CloudinaryField





class User(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=150)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    role = models.IntegerField(default=0)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)

    profile_image = CloudinaryField('profile_image', null=True, blank=True,default='https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png')

    USERNAME_FIELD = 'email'

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)
        
        
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
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    STATUS_CHOICES = [
        ('en_attent', 'En attent'),
        ('resolu', 'Résolu'),
        ('en_cours', 'En cours'),
        ('annuler', 'Annuler'),
    ]

    SERVICE_CHOICES = [
        ('service1', 'service1'),
        ('service2', 'service2'),
        ('service3', 'service3')
    ]

    status = models.CharField(
        max_length=50, 
        choices=STATUS_CHOICES, 
        default='en_attent'
    )
    service = models.CharField(
        null=True,
        max_length=100,
        choices=SERVICE_CHOICES
    )

    name = models.CharField(max_length=100, blank=False, null=False)
    description = models.TextField(blank=False, null=False)
    is_deleted = models.BooleanField(default=False)
    ticket_owner = models.ForeignKey(User, on_delete=models.CASCADE,related_name='assigned_tickets' )


    def __str__(self):
        return f"Ticket {self.name} - {self.get_status_display()}"
    
class Notification(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    ticket=models.ForeignKey(Ticket,on_delete=models.CASCADE)
    message = models.TextField()
    is_read = models.BooleanField(default=False)

    created_at=models.DateTimeField(auto_now_add=True)
    



    


