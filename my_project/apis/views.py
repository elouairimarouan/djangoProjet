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
from .models import Ticket





class RegisterView(APIView):
    def post(self, request):
        data = request.data  

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        password_ver = data.get('password_ver')
        profile_image = request.FILES.get('profile_image')  # Get the profile image from the request


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

        user = User(username=username, email=email)
        if profile_image:
            user.profile_image = profile_image  
        user.set_password(password)  
        user.save()
        return Response({'message': "Compte créé avec succès !"
                         ,'role' : user.role,
                         'profile_image_url': user.profile_image.url if user.profile_image else None
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

        
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        access_token['role'] = user.role
        

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

        return Response({'message': "Le code de réinitialisation a été envoyé."}, status=200)
    
class PasswordConfirmationView(APIView):

    def post(self, request):
        data = request.data
        code = data.get('code')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        if not code or not new_password or not confirm_password:
            return Response({'error': 'tous les champs sont obligatoire.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            reset_entry = PasswordResetCode.objects.get(code=code)
        except PasswordResetCode.DoesNotExist:
            return Response({'error': "Code de réinitialisation invalide ou e-mail incorrect."}, status=status.HTTP_400_BAD_REQUEST)

        if reset_entry.is_expired():
            return Response({'error': "Le code de réinitialisation a expiré."}, status=status.HTTP_400_BAD_REQUEST)
        
        if new_password != confirm_password:
            return Response({'error': "Les mots de passe ne correspondent pas."}, status=400)

        
        user = reset_entry.user  
        
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        access_token['user_id'] = user.id

        return Response({'success':True,
                         'message': "Code valide.",
                         "access_token":str(access_token),
                         "refresh":str(refresh),
                        }, status=status.HTTP_200_OK)

# class PasswordConfirmationView(APIView):
    # authentication_classes = [JWTAuthentication] 
    # permission_classes = [IsAuthenticated]  

    # def post(self, request):
    #     new_password = request.data.get('new_password')
    #     confirm_password = request.data.get('confirm_password')

    #     if not new_password or not confirm_password :
    #         return Response({'error': "Tous les champs sont obligatoires."}, status=400)
        
    #     # Check if the passwords match
    #     if new_password != confirm_password:
    #         return Response({'error': "Les mots de passe ne correspondent pas."}, status=400)


    #     user = request.user  

    #     user.set_password(new_password)
    #     user.save()


    #     return Response({'success': "Mot de passe réinitialisé avec succès."}, status=200)
    
    
class TicketCreateView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access

    def post(self, request):
        data = request.data
        personne_declarer = data.get('personne_declarer')
        name = data.get('name')
        service = data.get('service')
        description = data.get('description')

        if not personne_declarer or not name or not service or not description:
            return Response({'error': 'Tous les champs sont obligatoires.'}, status=400)

        ticket = Ticket(
            personne_declarer=personne_declarer,
            name=name,
            service=service,
            description=description,
            created_by=request.user  
        )

        ticket.save()

        return Response({'message': 'Ticket créé avec succès.', 'ticket_id': ticket.id}, status=status.HTTP_201_CREATED)
    
class TicketListView(APIView):
    permission_classes = [IsAuthenticated]  
    def get(self, request):
        user = request.user
        print(vars(user))


        if request.user.role == 1:
            tickets = Ticket.objects.all().values("id", "personne_declarer", "name", "service", "description", "created_at", "created_by","status")

        else :
            tickets = Ticket.objects.filter(created_by=request.user).values("id", "personne_declarer", "name", "service", "description", "created_at","created_by","status")
            if not tickets:
                return Response({"message": "No tickets found for this user."}, status=status.HTTP_404_NOT_FOUND)
            

        
    
        return Response(list(tickets),status=status.HTTP_200_OK)  
        
    

    

class UpdateTicketView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, ticket_id):
        user = request.user 

        try:
            ticket = Ticket.objects.get(id=ticket_id)
        except Ticket.DoesNotExist:
            return Response({"error": "Ticket non trouvé"}, status=status.HTTP_404_NOT_FOUND)

        if ticket.created_by != user:
            return Response({"error": "Permission refusée. Vous n'êtes pas autorisé à modifier ce ticket."}, status=status.HTTP_403_FORBIDDEN)

        data = request.data
        personne_declarer = data.get('personne_declarer')
        name = data.get('name')
        service = data.get('service')
        description = data.get('description')

        if not personne_declarer or not name or not service or not description:
            return Response({'error': 'Tous les champs sont obligatoires.'}, status=status.HTTP_400_BAD_REQUEST)
        
        if 'status' in data:
            return Response({"error":"vous pouvez pas Modifier le status"},status=status.HTTP_403_FORBIDDEN)

        ticket.personne_declarer = personne_declarer
        ticket.name = name
        ticket.service = service
        ticket.description = description

        try:
            ticket.save()  
            return Response({'message': 'Ticket mis à jour avec succès.', 'ticket_id': ticket.id}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

class UpdateTicketStatus(APIView):
    permission_classes = [IsAuthenticated]  # Correction de la syntaxe

    def patch(self, request, ticket_id):
        user = request.user  # Correction ici

        try:
            ticket = Ticket.objects.get(id=ticket_id)
        except Ticket.DoesNotExist:
            return Response({"error": "Ticket non trouvé"}, status=status.HTTP_404_NOT_FOUND)

        if user.role != 1:
            return Response({'error': "Permission refusée. vous pouvez pas modifier le status."},
                            status=status.HTTP_403_FORBIDDEN)

        new_status = request.data.get('status')

        # Vérification si le statut est valide
        valid_status = dict(Ticket.STATUS_CHOICES).keys()
        if new_status not in valid_status:
            return Response({"error": f"Statut invalide. Choisissez parmi : {', '.join(valid_status)}"},
                            status=status.HTTP_400_BAD_REQUEST)

        ticket.status = new_status
        ticket.save()  

        return Response({"message": "Statut modifié avec succès"}, status=status.HTTP_200_OK)

class DeleteTicketView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self,request,ticket_id):
        user = request.user

        try:
            ticket = Ticket.objects.get(id=ticket_id)
        except Ticket.DoesNotExist:
            return Response({"error": "Ticket non trouvé"}, status=status.HTTP_404_NOT_FOUND)
        
        if user.role == 1:
            ticket.delete()
            return Response({"message": "Ticket supprimé avec succès"}, status=status.HTTP_200_OK)
        
        if ticket.created_by != user:
            return Response({'error': "Permission refusée. Vous ne pouvez supprimer que vos propres tickets."},
                            status=status.HTTP_403_FORBIDDEN,)
        if ticket.status != 'ouvert':
                return Response({"error":"Vous ne pouvez supprimer un ticket que s'il est encore ouvert."},
                            status=status.HTTP_403_FORBIDDEN)
        ticket.delete()
        return Response({"message":"ticket supprimé avec succès"},status=status.HTTP_200_OK)
    
class TicketDetailsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self,request,ticket_id):
        user = request.user

        try :
            ticket = Ticket.objects.get(id = ticket_id)
        except Ticket.DoesNotExist:
            return Response({"error": "Ticket non trouvé"}, status=status.HTTP_404_NOT_FOUND)
        
        if user.role == 1 or ticket.created_by==user:
            ticket_data = {
            "id": ticket.id,
            "name": ticket.name,
            "service": ticket.service,
            "description": ticket.description,
            "status": ticket.status,
            "created_at": ticket.created_at,
            "updated_at": ticket.updated_at,
            "personne_declarer": ticket.personne_declarer,
            "created_by": ticket.created_by.username,  
            }
            return Response({"details":ticket_data}, status=status.HTTP_200_OK)
        
        return Response({'error': "Permission refusée. Vous ne pouvez voir que vos propres tickets."},
                        status=status.HTTP_403_FORBIDDEN)
        
        




            

        




        

        

