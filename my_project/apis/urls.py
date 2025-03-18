from django.urls import path
from .views import (
    RegisterView, 
    LoginView, 
    PasswordResetView, 
    ProtectedView, 
    PasswordConfirmationView,
    TicketCreateView,
   
)

urlpatterns = [
    path('api/register/', RegisterView.as_view(), name='register_user'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/protected-view/', ProtectedView.as_view(), name='protected_view'),  # Protected endpoint (JWT authentication required)
    path('api/email-code/', PasswordResetView.as_view(), name='password_reset_request'),
    path('api/update-password/', PasswordConfirmationView.as_view(), name='confirm_password'),
    path('api/createticket/', TicketCreateView.as_view(), name='create_ticket'),
    # path('api/updateticket/', UpdateTicketView.as_view(), name='update_ticket'),
    
    # Uncomment if you have these views
    # path('api/logout/', LogoutView.as_view(), name='logout'),
    # path('api/hello/', hello, name='hello'),
]
