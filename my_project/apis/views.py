from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
# from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
from django.conf import settings
from .models import User,PasswordResetCode
from rest_framework.permissions import IsAuthenticated
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
from .models import Ticket
from django.contrib.auth import authenticate
from django.db.models import Q


# from channels.layers import get_channel_layer


class RegisterView(APIView):
    def post(self, request):
        data = request.data  

        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')
        password_ver = data.get('password_ver')
        profile_image = request.FILES.get('profile_image')  

        if not first_name:
            return Response({"message": "Le prenom d'utilisateur est obligatoire."}, status=status.HTTP_400_BAD_REQUEST)
        if not last_name:
            return Response({"message": "Le nom d'utilisateur est obligatoire."}, status=status.HTTP_400_BAD_REQUEST)
        if not email:
            return Response({"message": "L'adresse e-mail est obligatoire."}, status=status.HTTP_400_BAD_REQUEST)
        if not password:
            return Response({"message": "Le mot de passe est obligatoire."}, status=status.HTTP_400_BAD_REQUEST)
        if not password_ver:
            return Response({"message": "La confirmation du mot de passe est obligatoire."}, status=status.HTTP_400_BAD_REQUEST)
        if password != password_ver:
            return Response({"message": "Les mots de passe ne correspondent pas."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_email(email)  
        except ValidationError:
            return Response({"message": "L'adresse e-mail n'est pas valide."}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(email=email).exists():
            return Response({"message": "L'adresse e-mail est déjà enregistrée."}, status=status.HTTP_400_BAD_REQUEST)

        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            profile_image=profile_image
        )
 
        user.set_password(password)  
        user.save()
        return Response({'success':True,
                         'first_name':user.first_name,
                         'first_name':user.last_name,
                          'role' : user.role,
                         'profile_image_url':user.profile_image if user.profile_image else None 

                         }, status=201)




class LoginView(APIView):
    def post(self, request):
        data = request.data 
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return Response({"message": "L'adresse e-mail et le mot de passe sont obligatoires."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)  
        except User.DoesNotExist:
            return Response({"message": "Adresse e-mail ou mot de passe incorrect."}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(password):  
            return Response({"message": "Adresse e-mail ou mot de passe incorrect."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not user.is_active:
            return Response({"message":'Votre compte a été suspendu.'},status=403)
     
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        access_token['role'] = user.role
        
        return Response({
            'success':True,
            'role':user.role,
            'first_name':user.first_name,
            'last_name':user.last_name,
            'email':user.email,
            "id":user.id,
            'profile_image':user.profile_image,
            'access_token': str(access_token),  
            'refresh_token': str(refresh), 
        }, status=200)


class ProtectedView(APIView):
    authentication_classes = [JWTAuthentication]  
    permission_classes = [IsAuthenticated]  
        
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
            return Response({"message": "L'adresse e-mail est obligatoire."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": "Aucun utilisateur trouvé avec cet e-mail."}, status=404)

        code = str(random.randint(100000, 999999))

        expired_at = timezone.now() + timedelta(minutes=10)

        reset_code = PasswordResetCode.objects.create(
            user=user,
            code=code,
            expired_at=expired_at
        )
        
        subject = "Réinitialisation de votre mot de passe"
        message = (
            f"Bonjour {user.last_name} {user.first_name},\n\n"
            "Nous avons reçu une demande de réinitialisation de votre mot de passe. "
            f"Voici votre code de réinitialisation : {code}\n\n"
            "Ce code est valide pendant 10 minutes.\n\n"
        )
        sender_email = settings.EMAIL_HOST_USER
        receiver = [user.email]
        
        try:
            send_mail(subject, message, sender_email, receiver, fail_silently=False)
        except Exception as e:
            return Response({"message": "Erreur lors de l'envoi de l'e-mail.", 'details': str(e)}, status=500)

        return Response({'message': "Le code de réinitialisation a été envoyé."}, status=200)
    
class PasswordConfirmationView(APIView):
    def post(self, request):
        data = request.data
        code = data.get('code')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        if not code or not new_password or not confirm_password:
            return Response({"message": 'tous les champs sont obligatoire.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            reset_entry = PasswordResetCode.objects.get(code=code)
        except PasswordResetCode.DoesNotExist:
            return Response({"message": "Code de réinitialisation invalide ou e-mail incorrect."}, status=status.HTTP_400_BAD_REQUEST)

        if reset_entry.is_expired():
            return Response({"message": "Le code de réinitialisation a expiré."}, status=status.HTTP_400_BAD_REQUEST)
        reset_entry.delete()

        if new_password != confirm_password:
            return Response({"message": "Les mots de passe ne correspondent pas."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'success':True,
                         'message': "Code valide.",
                        }, status=status.HTTP_200_OK)

    
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .models import Ticket, User

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from .models import Ticket, User

class TicketCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data

        if request.user.role == 0:  
            name = data.get('name')
            service = data.get('service')
            description = data.get('description')
            created_by = request.user
            assigned_to = request.user  

            if not all([name, service, description]):
                return Response({'message': 'Tous les champs sont obligatoires.'}, status=status.HTTP_400_BAD_REQUEST)

            valid_service = list(dict(Ticket.SERVICE_CHOICES).keys())
            if service not in valid_service:
                return Response({"message": f"Service invalide. Choisissez parmi : {', '.join(valid_service)}"},
                                status=status.HTTP_400_BAD_REQUEST)

        elif request.user.role == 1:  
            name = data.get('name')
            service = data.get('service')
            description = data.get('description')
            user_id = data.get('user_id') 

            if not all([name, service, description, user_id]):
                return Response({'message': 'Tous les champs sont obligatoires.'}, status=status.HTTP_400_BAD_REQUEST)

            valid_service = list(dict(Ticket.SERVICE_CHOICES).keys())
            if service not in valid_service:
                return Response({"message": f"Service invalide. Choisissez parmi : {', '.join(valid_service)}"},
                                status=status.HTTP_400_BAD_REQUEST)

            try:
                ticket_owner = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({"message": "Utilisateur non trouvé."}, status=status.HTTP_404_NOT_FOUND)

            created_by = request.user  
            assigned_to = ticket_owner  

        ticket = Ticket(
            name=name,
            service=service,
            description=description,
            created_by=created_by,  
            ticket_owner=assigned_to 
        )

        ticket.save()

        return Response({'message': 'Ticket créé avec succès.', 'ticket_id': ticket.id}, status=status.HTTP_201_CREATED)

    
class TicketListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        search_param = request.query_params.get('search', '').strip()  # Get the search parameter

        try :
            tickets = Ticket.objects.filter(is_deleted=False)
        except tickets.DoesNotExist:
            return Response({"message":"aucun ticket trouve"},status=status.HTTP_404_NOT_FOUND)
        
        if search_param:
             tickets = tickets.filter(
            Q(name__icontains=search_param) | 
            Q(service__icontains=search_param) | 
            Q(status__icontains=search_param) 
            # Q(description_icontains=search_param)
            )

        
        if request.user.role == 1:  
            tickets = tickets.order_by('-created_at').values("id","name", "service", "description", "created_at", "ticket_owner","status")
        else:  
            tickets = tickets.filter(ticket_owner=request.user).order_by('-created_at').values("id", "name", "service", "description", "created_at", "ticket_owner", "status")
            if not tickets:
                return Response({"message": "No tickets found for this user."}, status=status.HTTP_404_NOT_FOUND)

        tickets_list = list(tickets) 

        return Response({"count":len(tickets_list),"tickets":tickets_list}, status=status.HTTP_200_OK)

class UpdateTicketView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, ticket_id):
        user = request.user

        try:
            ticket = Ticket.objects.get(id=ticket_id)
        except Ticket.DoesNotExist:
            return Response({'message': "Ticket non trouvé"}, status=status.HTTP_404_NOT_FOUND)

        if ticket.ticket_owner != user:
            return Response({'message': "Permission refusée. Vous n'êtes pas autorisé à modifier ce ticket."}, status=status.HTTP_403_FORBIDDEN)

        data = request.data
        name = data.get('name')
        service = data.get('service')
        description = data.get('description')
        status_value = data.get('status')

        if not name or not service or not description or not status_value:
            return Response({"message": 'Tous les champs sont obligatoires.'}, status=status.HTTP_400_BAD_REQUEST)
        
        
        valid_service = dict(Ticket.SERVICE_CHOICES).keys()
        if service not in valid_service:
            return Response({'message': f"service invalide. Choisissez parmi : {', '.join(valid_service)}"},
                            status=status.HTTP_400_BAD_REQUEST)

        ticket.name = name
        ticket.service = service
        ticket.description = description
        ticket.status = status_value

        try:
            ticket.save()  
            return Response({'message': 'Ticket mis à jour avec succès.', 'ticket_id': ticket.id}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

class UpdateTicketStatus(APIView):
    permission_classes = [IsAuthenticated] 

    def patch(self, request, ticket_id):
        user = request.user  

        try:
            ticket = Ticket.objects.get(id=ticket_id)
        except Ticket.DoesNotExist:
            return Response({'message': "Ticket non trouvé"}, status=status.HTTP_404_NOT_FOUND)

        if user.role != 1:
            return Response({"message": "Permission refusée. vous pouvez pas modifier le status."},
                            status=status.HTTP_403_FORBIDDEN)

        new_status = request.data.get('status')

        valid_status = dict(Ticket.STATUS_CHOICES).keys()
        if new_status not in valid_status:
            return Response({'message': f"Statut invalide. Choisissez parmi : {', '.join(valid_status)}"},
                            status=status.HTTP_400_BAD_REQUEST)

        ticket.status = new_status
        ticket.save()  

        return Response({"message": "Statut modifié avec succès"}, status=status.HTTP_200_OK)

class DeleteTicketView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, ticket_id):
        user = request.user

        try:
            ticket = Ticket.objects.get(id=ticket_id)
        except Ticket.DoesNotExist:
            return Response({'message': "Ticket non trouvé"}, status=status.HTTP_404_NOT_FOUND)

        if user.role == 1:
            if ticket.ticket_owner == user:
                ticket.is_deleted = True  
                ticket.save()
                return Response({"message": "Votre ticket a été marqué comme supprimé"}, status=status.HTTP_200_OK)
            else:
                ticket.is_deleted = True
                ticket.save()
                return Response({"message": "Ticket marqué comme supprimé"}, status=status.HTTP_200_OK)

        if ticket.ticket_owner != user:
            return Response({"message": "Permission refusée. Vous ne pouvez supprimer que vos propres tickets."},
                            status=status.HTTP_403_FORBIDDEN)


        ticket.is_deleted = True  
        ticket.status = "Annuler"
        ticket.save()
        return Response({"message": "Ticket marqué comme supprimé"}, status=status.HTTP_200_OK)

    
class TicketDetailsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self,request,ticket_id):
        user = request.user

        try :
            ticket = Ticket.objects.get(id = ticket_id)
        except Ticket.DoesNotExist:
            return Response({'message': "Ticket non trouvé"}, status=status.HTTP_404_NOT_FOUND)
        
        if user.role == 1 or ticket.created_by == user:
            ticket_data = {
            "id": ticket.id,
            "name": ticket.name,
            "service": ticket.service,
            "description": ticket.description,
            "status": ticket.status,
            "created_at": ticket.created_at,
            "updated_at": ticket.updated_at,
            "personne_declarer": ticket.personne_declarer,
            "created_by": ticket.created_by.email,  
            }
            return Response({"details":ticket_data}, status=status.HTTP_200_OK)
        
        return Response({"message": "Permission refusée. Vous ne pouvez voir que vos propres tickets."},
                        status=status.HTTP_403_FORBIDDEN)
    
class UsersListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self,request):
        user=request.user

        if user.role == 1 :
            users = User.objects.all().values('id','first_name')
        else :
            return Response({'message': "Permission refusée"},status=status.HTTP_403_FORBIDDEN)

        users_list = list(users)

        return Response({'users':users_list},status=status.HTTP_302_FOUND)
    
class CreateUser(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request):
        if request.user.role == 1:
            data = request.data
            first_name = data.get('first_name')
            last_name = data.get('last_name')
            email = data.get('email')
            password = data.get('password')
            password_ver = data.get('password_ver')
            profile_image = request.FILES.get('profile_image')

            if not first_name or not last_name or not email or not password or not password_ver:
                return Response({'message':"tous les champs sont obligatoires"},status=status.HTTP_400_BAD_REQUEST)
            
            user = User()
        
        

            

        




        

        

