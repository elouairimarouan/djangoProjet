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
    UsersListView,
    DeleteUser,
    ToggleUserStatus,
    UpdateUser,
    CreateUser,
    ProfileView,
    ProfileImageView,
    ProfileUpdate,
    StaticsView
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
    path('api/delete-user/<int:user_id>/', DeleteUser.as_view(), name='users-list'),
    path('api/change-account-status/<int:user_id>/', ToggleUserStatus.as_view(), name='users-list'),
    path('api/update-user/<int:user_id>/', UpdateUser.as_view(), name='update-user'),
    path('api/create-user/', CreateUser.as_view(), name='create-user'),
    path('api/profile-user/', ProfileView.as_view(), name='profile-user'),
    path('api/statics/', StaticsView.as_view(), name='StaticView'),
    path('api/update-profile-image/<int:user_id>/', ProfileImageView.as_view(), name='update-profile-image'),
    path('api/update-profile/<int:user_id>/', ProfileUpdate.as_view(), name='update-profile'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),   
]
