from django.urls import path
from student.views import RegistrationView, LoginView, ProfileView, ChangePasswordView, SendPasswordResetEmailView, PasswordResetView, SendConfirmationEmail, VerifyEmailView, UpdateProfileView, GetUserView, LogoutView
from rest_framework_simplejwt.views import TokenRefreshView, TokenBlacklistView

urlpatterns = [
    path('register/', RegistrationView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', TokenBlacklistView.as_view(), name='logout'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('send-password-reset-email/', SendPasswordResetEmailView.as_view(), name='send-password-reset-email'),
    path('reset-password/<uid>/<token>/', PasswordResetView.as_view(), name='reset-password'),
    path('send-confirmation-email/', SendConfirmationEmail.as_view(), name='send-confirmation-email'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('update-profile/', UpdateProfileView.as_view(), name='update-profile'),
    path('get-user/', GetUserView.as_view(), name='get-user'),
]
