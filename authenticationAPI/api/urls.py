from django.urls import path

from authenticationAPI.api.views import RegisterView, LoginApiView, VerifyEmailView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginApiView.as_view(), name='login'),
    path('verify_email', VerifyEmailView.as_view(), name='verify-email')
]
