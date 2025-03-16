from django.urls import path
# from .views import RegisterView,LoginView,PasswordResetRequestView
from .views import RegisterView,LoginView,PasswordResetView,ProtectedView,EmailCodeView,PasswordConfirmationView

urlpatterns = [
    path('api/register/', RegisterView.as_view(), name='register_user'),
    path("api/login/", LoginView.as_view(), name="login"),
    path('api/protected-view/', ProtectedView.as_view(), name='protected-view'),  # Protected endpoint (JWT authentication required)
    path('api/email-code/', PasswordResetView.as_view(), name='password_reset_request'),
    path('api/code-verify/', EmailCodeView.as_view(), name='password_reset_request'),
    path('api/update-password/', PasswordConfirmationView.as_view(), name='confirm_password'),



    # path('api/hello/', hello, name='hello'),
]
