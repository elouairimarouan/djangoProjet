from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
# from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
from django.conf import settings
from .models import User,PasswordResetCode
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
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
from .models import Ticket, User
from rest_framework.pagination import PageNumberPagination
from rest_framework.exceptions import NotFound
from cloudinary.uploader import upload,destroy
from cloudinary.exceptions import Error as CloudinaryError

from django.db.models import Count, Avg, F, ExpressionWrapper, DurationField
from django.utils.timezone import now, timedelta
from django.db.models.functions import TruncMonth




class RegisterView(APIView):
    def post(self, request):
        data = request.data  

        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')
        password_ver = data.get('password_ver')
        profile_image = request.FILES.get('profile_image')  

        # Validate required fields
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
        
        # Upload profile image to Cloudinary (if provided)
        if profile_image:
            try:
                upload_result = upload(profile_image)  # Upload image to Cloudinary
                profile_image_url = upload_result.get('secure_url')  # Get the URL of the uploaded image
            except CloudinaryError as e:
                return Response({"message": f"Erreur lors du téléchargement de l'image: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            # Default profile image URL
            profile_image_url = "https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png"

        # Create user object
        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            profile_image=profile_image_url
        )
        user.set_password(password)  
        user.save()

        return Response({
            'success': True,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role,
            'profile_image': user.profile_image
        }, status=status.HTTP_201_CREATED)

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
            return Response({"message": "Adresse e-mail introuvable."}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(password):
            return Response({"message": "Mot de passe incorrect."}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_deleted:
            return Response({"message": "Compte non trouvé"}, status=status.HTTP_403_FORBIDDEN)

        if not user.is_active:
            return Response({"message": "Votre compte a été suspendu."}, status=status.HTTP_403_FORBIDDEN)

        # Extract profile image URL (if exists)
        profile_image_url = user.profile_image.url if user.profile_image else None 

        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        access_token['role'] = user.role

        return Response({
            'success': True,
            'role': user.role,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            "id": user.id,
            "is_deleted": user.is_deleted,
            'profile_image': profile_image_url,  # Return the profile image URL
            'access_token': str(access_token),
            'refresh_token': str(refresh),
        }, status=status.HTTP_200_OK)

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
            user_id = data.get('assigned_to') 

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

    class TicketPagination(PageNumberPagination):
        page_size = 6  # Default number of tickets per page
        page_size_query_param = 'page_size'  # The query parameter for page size
        max_page_size = 50  # Maximum number of tickets per page

    def get(self, request):
        user = request.user
        search_param = request.GET.get('search_param', None)
        search_status = request.GET.get('status', None)
        search_service = request.GET.get('service', None)

        tickets = Ticket.objects.filter(is_deleted=False)

        # Apply filters based on search parameters
        if search_status:
            tickets = tickets.filter(status__icontains=search_status)

        if search_service:
            tickets = tickets.filter(service__icontains=search_service)

        if search_param:
            tickets = tickets.filter(
                Q(name__icontains=search_param) | 
                Q(description__icontains=search_param)
            )

        if user.role != 1:
            tickets = tickets.filter(ticket_owner=user)

        if search_status or search_service or search_param:
            page_number = 1  # Reset to page 1 if filters are applied
        else:
            page_number = request.GET.get('page', 1)  # Default page is 1 if no filter is applied


        paginator = self.TicketPagination()

        # Paginate the filtered tickets and handle invalid page numbers
        paginated_tickets = paginator.paginate_queryset(tickets.order_by('-created_at'), request, view=self)

        if not paginated_tickets:
            return Response({"message": "Aucun ticket trouvé sur cette page."}, status=status.HTTP_200_OK)

        tickets_list = []
        for ticket in paginated_tickets:
            profile_image = ticket.ticket_owner.profile_image
            profile_image_url = str(profile_image) if profile_image else None
            ticket_owner_info = {
                "id": ticket.ticket_owner.id,
                "email": ticket.ticket_owner.email,
                "first_name": ticket.ticket_owner.first_name,
                "last_name": ticket.ticket_owner.last_name,
                "date_joined": ticket.ticket_owner.date_joined,
                "role": ticket.ticket_owner.role,
                "profile_image": profile_image_url
            }

            tickets_list.append({
                "id": ticket.id,
                "name": ticket.name,
                "service": ticket.service,
                "description": ticket.description,
                "created_at": ticket.created_at,
                "status": ticket.status,
                "ticket_owner": ticket_owner_info  
            })

        return paginator.get_paginated_response(tickets_list)
    
class UpdateTicketView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, ticket_id):
        user = request.user

        try:
            ticket = Ticket.objects.get(id=ticket_id)
        except Ticket.DoesNotExist:
            return Response({'message': "Ticket non trouvé"}, status=status.HTTP_404_NOT_FOUND)
        
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
            return Response({'message': 'Ticket mis à jour avec succès.', 'name': ticket.name,"service":ticket.service,"description":ticket.description,"status":ticket.status}, status=status.HTTP_200_OK)
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

    def get(self, request):
        user = request.user

        if user.role == 1:
            users = User.objects.filter(is_deleted=False).values() .order_by('-date_joined')
        else:
            return Response({'message': "Permission refusée"}, status=status.HTTP_403_FORBIDDEN)
        
        
        users_list = [
            {
                **user,
                'profile_image': str(user['profile_image']) if user['profile_image'] else None
            }
            for user in users
        ]

        return Response({'users': users_list}, status=status.HTTP_200_OK)
    
class DeleteUser(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"message": "Aucun utilisateur trouvé"}, status=status.HTTP_404_NOT_FOUND)

        # Vérifier si l'utilisateur qui effectue la requête est un administrateur
        if request.user.role != 1:
            return Response({'message': "Accès refusé"}, status=status.HTTP_403_FORBIDDEN)
        
        if user.role == 1:
            return Response({"message":"tu ne peut pas le droit de supprimer un admin"},status=status.HTTP_403_FORBIDDEN)

        user.is_deleted = True
        user.save()

        return Response({"message": "Utilisateur supprimé avec supprimer"}, status=status.HTTP_200_OK)
    
class ToggleUserStatus(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self,request,user_id):

        try :
            user = User.objects.get(id=user_id)
        except user.DoesNotExist:
            return Response({"message":"utilisateur introuvable"},status=status.HTTP_404_NOT_FOUND)
        
        if request.user.role != 1:
            return Response({"message": "Permission refusée"}, status=status.HTTP_403_FORBIDDEN)

        user.is_active = not user.is_active
        user.save()

        message="Utilisateur activé" if user.is_active else "Utilisateur désactivé"
        return Response({"message":message},status=status.HTTP_200_OK)

class UpdateUser(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, user_id):
        if request.user.role != 1:
            return Response(
                {"message": "Accès refusé, vous n'êtes pas administrateur."}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"message": "Utilisateur non trouvé."}, 
                status=status.HTTP_404_NOT_FOUND)
        
        data = request.data

        if 'first_name' in data:
            user.first_name = data['first_name']
        if 'last_name' in data:
            user.last_name = data['last_name']
        if 'email' in data:
            if data['email'] != user.email:
                try:
                    validate_email(data['email'])
                    if User.objects.exclude(id=user.id).filter(email=data['email']).exists():
                        return Response(
                            {"message": "Cet email est déjà utilisé."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    user.email = data['email']
                except ValidationError:
                    return Response(
                        {"message": "Email invalide."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
        if 'role' in data:
            user.role = data['role']

        # Handle password separately
        if 'password' in data and data['password']:
            user.set_password(data['password']) 

        try:
            user.save()
            return Response({
                'message': 'Utilisateur mis à jour avec succès.',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'role': user.role,
                    'profile_image': str(user.profile_image) if user.profile_image else None,
                    'date_joined': user.date_joined,
                    'last_login': user.last_login,
                    'is_active': user.is_active,
                }
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"message": f"Erreur: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

class CreateUser(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request):
        if request.user.role != 1:
            return Response({"message":"accesrefuser"},status=status.HTTP_403_FORBIDDEN)
        
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
        
        try :
            validate_email(email)
        except ValidationError :
            return Response({"message": "L'adresse e-mail n'est pas valide."},status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(email=email).exists():
            return Response({"message": "L'adresse e-mail est déjà enregistrée."},status=status.HTTP_400_BAD_REQUEST)
        
        if profile_image:
            try:
                upload_result = upload(profile_image)
                profile_image_url = upload_result.get('secure_url')  # Ensure this is a string
            except CloudinaryError as e:
                return Response({"message": f"Error uploading image: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            profile_image_url = "https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png"

        # Create and save the user
        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            profile_image=profile_image_url  # Ensure this is stored as a string
        )
        user.set_password(password)
        user.save()

        # Fetch all users sorted by `date_joined` (newest first)
        sorted_users = User.objects.all().order_by('-date_joined')
        users_data = []


        profile_image_url = str(user.profile_image) if user.profile_image else None


            

        return Response(        {
            'id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'role': user.role,
            'date_joined': user.date_joined,
            'profile_image': str(user.profile_image) if user.profile_image else None
        }, status=status.HTTP_201_CREATED)
    
class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self,request):

        user =request.user 
        return Response({
        'id': user.id,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email,
        'role': user.role,
        'date_joined': user.date_joined,
        'profile_image': str(user.profile_image) if user.profile_image else None},status=status.HTTP_200_OK)
    
class ProfileImageView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request,user_id):
        user = request.user

        if request.user.id != user_id and not request.user == 1:
            return Response(
                {"message": "You do not have permission to update this profile image"},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            user = User.objects.get(id = user_id)
        except User.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # if not request.FILES.get('profile_image'):
        #     return Response(
        #         {"message": "No image provided"}, 
        #         status=status.HTTP_400_BAD_REQUEST
        #     )

        if user.profile_image:
            try:
                if 'res.cloudinary.com' in str(user.profile_image):
                    public_id = str(user.profile_image).split('/')[-1].split('.')[0]
                    destroy(public_id)
            except Exception as e:
                print(f"Error supprission old image: {str(e)}")

        try:
            upload_result = upload(request.FILES['profile_image'])
            user.profile_image = upload_result['secure_url']
            user.save()

            return Response({
                'profile_image': user.profile_image,
                'message': 'Profile image updated successfully',
                'user_id':user.id
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"message": f"Image upload failed: {str(e)}"},status=status.HTTP_500_INTERNAL_SERVER_ERROR) 
        
class ProfileUpdate(APIView) :
    permission_classes = [IsAuthenticated]

    def put(self,request,user_id):
        
        if request.user.id != user_id:
            return Response({"message": "tu pas le droit de moddifer le profile"},status=status.HTTP_403_FORBIDDEN)
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"message": "Utilisateur non trouvé."}, status=status.HTTP_404_NOT_FOUND)
        
        data = request.data

        if 'first_name' in data:
            user.first_name = data['first_name']
        if 'last_name' in data:
            user.last_name = data['last_name']
        if 'email' in data:
            if data['email'] != user.email:
                try:
                    validate_email(data['email'])
                    if User.objects.exclude(id=user.id).filter(email=data['email']).exists():
                        return Response({"message": "Cet email est déjà utilisé."},status=status.HTTP_400_BAD_REQUEST)
                    user.email = data['email']
                except ValidationError:
                    return Response({"message": "Email invalide."},status=status.HTTP_400_BAD_REQUEST)

        if 'password' in data and data['password']:
            user.set_password(data['password']) 

        try:
            user.save()
            return Response({
                'message': 'profile mis à jour avec succès.',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'role': user.role,
                    'profile_image': str(user.profile_image) if user.profile_image else None,
                    'date_joined': user.date_joined,
                    'last_login': user.last_login,
                    'is_active': user.is_active,
                }
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response(
                {"message": f"Erreur: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
class StaticsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request):
        if request.user.role !=1 :
            return Response({"message": "Accès refusé"},status=status.HTTP_403_FORBIDDEN)
        
        total_ticket = Ticket.objects.count()
        ticket_by_status = Ticket.objects.values('status').annotate(count=Count('id'))
        ticket_by_user = Ticket.objects.values('ticket_owner').annotate(count=Count('id'))

        last_year_start = now() - timedelta(days=365)

        tickets_per_month = Ticket.objects.filter(created_at__gte=last_year_start).annotate(month=TruncMonth('created_at')).values('month','status').annotate(count=Count('id'))



        return Response({"total_ticket":total_ticket,
                         "ticket_by_status":ticket_by_status,
                         "ticket_by_user":ticket_by_user,
                         "tickets_per_month":tickets_per_month
                         },status=status.HTTP_200_OK)




    


            
        
        

            

        




        

        

