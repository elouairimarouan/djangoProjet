from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password
import json
from django.core.mail import send_mail
from django.conf import settings
from .models import User
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication


from rest_framework.views import APIView
from rest_framework.response import Response
from .models import User

class RegisterView(APIView):
    def post(self, request):
        data = request.data  # Using request.data for easy parsing in DRF

        # Retrieve data
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        password_ver = data.get('password_ver')

        # Validations
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

        # Check if user exists
        if User.objects.filter(username=username).exists():
            return Response({'error': "Le nom d'utilisateur est déjà pris."}, status=400)
        if User.objects.filter(email=email).exists():
            return Response({'error': "L'adresse e-mail est déjà enregistrée."}, status=400)

        # Create and save user
        user = User(username=username, email=email)
        user.set_password(password)  # Set the password properly
        user.save()

        return Response({'message': "Compte créé avec succès !"}, status=201)



class LoginView(APIView):
    def post(self, request):
        data = request.data  # Using request.data for easy parsing in DRF

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

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)

        # Store the tokens in the User model
        user.access_token = str(refresh.access_token)
        user.refresh_token = str(refresh)
        user.save()

        return Response({
            'message': "Connexion réussie !",
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
        }, status=200)



class ProtectedView(APIView):
    authentication_classes = [JWTAuthentication]  # Use JWT authentication
    permission_classes = [IsAuthenticated]  # Only authenticated users can access this view

    def get(self, request):
        return Response({"message": "This is a protected view, you're authenticated!"})


class RequestPasswordResetView(APIView):
    def post(self, request):
        data = request.data  # Using request.data for easy parsing in DRF

        email = data.get('email')
        if not email:
            return Response({'error': "L'adresse e-mail est obligatoire."}, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'message': "Si l'adresse e-mail existe, un lien de réinitialisation a été envoyé."}, status=200)

        reset_url = f"Réinitialisation"

        subject = "Réinitialisation de votre mot de passe"
        message = (
            f"Bonjour {user.username},\n\n"
            "Nous avons reçu une demande de réinitialisation de votre mot de passe. "
            "Cliquez sur le lien ci-dessous pour le réinitialiser :\n\n"
            f"{reset_url}\n\n"
        )
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]

        try:
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
        except Exception as e:
            return Response({'error': "Erreur lors de l'envoi de l'e-mail.", 'details': str(e)}, status=500)

        return Response({'message': "Le lien de réinitialisation a été envoyé."}, status=200)
