from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    RegisterView, 
    LoginView, 
    PasswordResetView, 
    ProtectedView, 
    PasswordConfirmationView,
    TicketCreateView,
    TicketListView,
    UpdateTicketView,
    UpdateTicketStatus,
    DeleteTicketView,
    TicketDetailsView,
    UsersListView
)

urlpatterns = [
    path('api/register/', RegisterView.as_view(), name='register_user'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/protected-view/', ProtectedView.as_view(), name='protected_view'),  
    path('api/email-code/', PasswordResetView.as_view(), name='password_reset_request'),
    path('api/update-password/', PasswordConfirmationView.as_view(), name='confirm_password'),
    path('api/create-ticket/', TicketCreateView.as_view(), name='create_ticket'),
    path('api/tickets/', TicketListView.as_view(), name='my-tickets'),
    path('api/update-ticket/<int:ticket_id>/', UpdateTicketView.as_view(), name='update_ticket'),
    path('api/update-Statusticket/<int:ticket_id>/', UpdateTicketStatus.as_view(), name='update_ticket'),
    path('api/delete-ticket/<int:ticket_id>/', DeleteTicketView.as_view(), name='delete-ticket'),
    path('api/details-ticket/<int:ticket_id>/', TicketDetailsView.as_view(), name='details-ticket'),
    path('api/users-list/', UsersListView.as_view(), name='users-list'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    
    # Uncomment if you have these views
    # path('api/logout/', LogoutView.as_view(), name='logout'),
    # path('api/hello/', hello, name='hello'),
]
