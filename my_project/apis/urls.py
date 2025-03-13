from django.urls import path
# from .views import RegisterView,LoginView,PasswordResetRequestView
from .views import RegisterView,LoginView,RequestPasswordResetView,ProtectedView

urlpatterns = [
    # path('api/register/', RegisterView.as_view(), name='registering'),
    path("api/login/", LoginView.as_view(), name="login"),
    path('api/password-reset/', RequestPasswordResetView.as_view(), name='password_reset_request'),
    path('api/protected-view/', ProtectedView.as_view(), name='protected-view'),  # Protected endpoint (JWT authentication required)

    # path('api/reset-password/', PasswordConfirmView.as_view(), name='password_reset_request'),
    path('api/register/', RegisterView.as_view(), name='register_user'),



    # path('api/hello/', hello, name='hello'),
]
