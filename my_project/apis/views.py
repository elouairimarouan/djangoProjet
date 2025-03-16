from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
# from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
from django.conf import settings
from .models import User,PasswordResetCode
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import User
from rest_framework import status
from datetime import timedelta
from django.utils import timezone
import random
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator




class RegisterView(APIView):
    def post(self, request):
        data = request.data  

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        password_ver = data.get('password_ver')

        if not username:
            return Response({'error': "Le nom d'utilisateur est obligatoire."}, status=400)
        if not email:
            return Response({'error': "L'adresse e-mail est obligatoire."}, status=400)
        if not password:
            return Response({'error': "Le mot de passe est obligatoire."}, status=400)
        if not password_ver:
            return Response({'error': "La confirmation du mot de passe est obligatoire."}, status=400)
        if password != password_ver:
            return Response({'error': "Les mots de passe ne correspondent pas."}, status=400)
        
        try:
            validate_email(email)  # Validate the email format
        except ValidationError:
            return Response({'error': "L'adresse e-mail n'est pas valide."}, status=400)
        
        if User.objects.filter(username=username).exists():
            return Response({'error': "Le nom d'utilisateur est déjà pris."}, status=400)
        if User.objects.filter(email=email).exists():
            return Response({'error': "L'adresse e-mail est déjà enregistrée."}, status=400)

        # Create and save user
        user = User(username=username, email=email)
        user.set_password(password)  # Set the password properly
        user.save()
        return Response({'message': "Compte créé avec succès !"
                         ,'role' : user.role
                         }, status=201)




class LoginView(APIView):
    def post(self, request):
        data = request.data 

        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return Response({'error': "L'adresse e-mail et le mot de passe sont obligatoires."}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': "Adresse e-mail ou mot de passe incorrect."}, status=400)

        if not user.check_password(password):
            return Response({'error': "Adresse e-mail ou mot de passe incorrect."}, status=400)

        
        # token = default_token_generator.make_token(user)

        refresh = RefreshToken.for_user(user)
        refresh['role'] = user.role
        # Add custom claims
        access_token = refresh.access_token
        access_token['role'] = user.role
        

        # authtoken_token.objects.create(user=user, refresh_token=str(refresh))


        return Response({
            'message': "Connexion réussie !",
            'role':user.role,
            'access_token': str(access_token),  # JWT access token
            'refresh_token': str(refresh),  # Refresh token
        }, status=200)


class ProtectedView(APIView):
    authentication_classes = [JWTAuthentication]  # Use JWT authentication
    permission_classes = [IsAuthenticated]  # Only authenticated users can access this view

    def get(self, request):
        # You can access the user's role from the request object
        role = request.user.role
        return Response({
            "message": "This is a protected view, you're authenticated!",
            "role": role
        })


class PasswordResetView(APIView):
    def post(self, request):
        data = request.data
        email = data.get('email')
        
        if not email:
            return Response({'error': "L'adresse e-mail est obligatoire."}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': "Aucun utilisateur trouvé avec cet e-mail."}, status=404)

        code = str(random.randint(100000, 999999))

        expired_at = timezone.now() + timedelta(minutes=10)

        reset_code = PasswordResetCode.objects.create(
            user=user,
            code=code,
            expired_at=expired_at
        )
        
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        subject = "Réinitialisation de votre mot de passe"
        message = (
            f"Bonjour {user.username},\n\n"
            "Nous avons reçu une demande de réinitialisation de votre mot de passe. "
            f"Voici votre code de réinitialisation : {code}\n\n"
            "Ce code est valide pendant 10 minutes.\n\n"
        )
        sender_email = settings.EMAIL_HOST_USER
        receiver = [user.email]
        

        try:
            send_mail(subject, message, sender_email, receiver, fail_silently=False)
        except Exception as e:
            return Response({'error': "Erreur lors de l'envoi de l'e-mail.", 'details': str(e)}, status=500)

        return Response({'message': "Le code de réinitialisation a été envoyé.",'acess_Token': str(access_token),}, status=200)
    
class EmailCodeView(APIView):
    uthentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated] 
    def post(self, request):
        data = request.data
        code = data.get('code')

        if not code:
            return Response({'error': 'Le code de réinitialisation est obligatoire.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            reset_entry = PasswordResetCode.objects.get(code=code)
        except PasswordResetCode.DoesNotExist:
            return Response({'error': "Code de réinitialisation invalide ou e-mail incorrect."}, status=status.HTTP_400_BAD_REQUEST)

        if reset_entry.is_expired():
            return Response({'error': "Le code de réinitialisation a expiré."}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({'success':True,'message': "Code valide."}, status=status.HTTP_200_OK)

class PasswordConfirmationView(APIView):
    authentication_classes = [JWTAuthentication] 
    permission_classes = [IsAuthenticated]  

    def post(self, request):

        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        if not new_password or not confirm_password :
            return Response({'error': "Tous les champs sont obligatoires."}, status=400)
        
        # Check if the passwords match
        if new_password != confirm_password:
            return Response({'error': "Les mots de passe ne correspondent pas."}, status=400)

        user = request.user  # Get the authenticated user

        user.set_password(new_password)
        user.save()

        # Optionally, delete the reset entry after using the code

        return Response({'success': "Mot de passe réinitialisé avec succès."}, status=200)