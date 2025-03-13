# from rest_framework import serializers
# from django.core.validators import validate_email
# from django.contrib.auth.password_validation import validate_password
# from django.contrib.auth.models import User
# from django.contrib.auth import authenticate
# from rest_framework_simplejwt.tokens import RefreshToken
# from django.http import HttpResponse
# from django.core.mail import send_mail
# from django.contrib.auth.tokens import default_token_generator
# from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode


# from rest_framework import serializers
# from django.core.validators import validate_email
# from django.contrib.auth.password_validation import validate_password
# from django.contrib.auth.models import User

# class RegisterSerializer(serializers.Serializer):
#     username = serializers.CharField(required=True)
#     email = serializers.EmailField(required=True)
#     password = serializers.CharField(write_only=True, required=True)
#     password_ver = serializers.CharField(write_only=True, required=True)
#     role = serializers.IntegerField(default=0)  # This is NOT stored in DB, only returned in response
    

#     def validate_username(self, value):
#         if User.objects.filter(username=value).exists():
#             raise serializers.ValidationError("Ce nom d'utilisateur est déjà pris. Veuillez en choisir un autre.")
#         return value

#     def validate_email(self, value):
#         value = value.lower().strip()
#         try:
#             validate_email(value)
#         except serializers.ValidationError:
#             raise serializers.ValidationError("Veuillez fournir une adresse e-mail valide.")
#         if User.objects.filter(email=value).exists():
#             raise serializers.ValidationError("Cette adresse e-mail est déjà enregistrée.")
#         return value

#     def validate_password(self, value):
#         validate_password(value)
#         return value

#     def validate(self, data):
#         if data['password'] != data['password_ver']:
#             raise serializers.ValidationError({"password_ver": "Les mots de passe ne correspondent pas."})
#         return data

#     def create(self, validated_data):
#         validated_data.pop('password_ver')  # Remove unnecessary field
#         # user_type = validated_data.pop('type', 0)  # Store type separately (not in DB)

#         # Create the user without 'type'
#         user = User.objects.create_user(**validated_data)

#         # Return response with user information and 'type' as separate
#         return {
#             "message": "Utilisateur créé avec succès",
#             "user": {
#                 "id": user.id,
#                 "username": user.username,
#                 "email": user.email,
#                 "role": user.role , # Returning 'type' without storing it in DB
#             }
#         }



# class LoginSerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     password = serializers.CharField(write_only=True)
#     role = serializers.IntegerField()

#     def validate(self, data):
#         email = data.get("email")
#         password = data.get("password")

#         user = User.objects.filter(email=email).first()
#         if not user:
#             raise serializers.ValidationError("Nom d'utilisateur ou mot de passe invalide.")

#         user = authenticate(username=user.username, password=password)
#         if not user:
#             raise serializers.ValidationError("Nom d'utilisateur ou mot de passe invalide.")

#         token = RefreshToken.for_user(user)
#         return {
#             "user_id": user.id,
#             "username": user.username,
#             "email": user.email,
#             "access_token": str(token.access_token),
#             "refresh_token": str(token),
#             "role":user.role,
#         }
    
# class PasswordResetRequestSerializer(serializers.Serializer):
#     email = serializers.EmailField()

#     def validate_email(self, value):
#         if not User.objects.filter(email=value).exists():
#             raise serializers.ValidationError("No account found with this email address.")
#         return value
    
