import jwt
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework_simplejwt.tokens import RefreshToken

from authenticationAPI.api.serializer import RegistrationSerializer, LoginSerializer
from authenticationAPI.api.utils import Util
from authentication_system import settings

User = get_user_model()


class RegisterView(generics.GenericAPIView):
    serializer_class = RegistrationSerializer

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        data = {}
        if serializer.is_valid():
            user = serializer.save()
            data['response'] = 'User was registered successfully'
            data['email'] = user.email
            data['username'] = user.username

            token = RefreshToken.for_user(user).access_token
            domain_name = get_current_site(request).domain
            relative_link = reverse('verify-email')
            absolute_link = 'https://' + domain_name + relative_link + f'?token={token}'

            email_body = f'Hi {user.username}, use the link below to verify your account \n {absolute_link}'
            pay_load = {'email_body': email_body, 'email_subject': 'Verify your email', 'to_email': [user.email]}
            Util.send_email(pay_load)

            return Response(data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(generics.GenericAPIView):

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Email successfully verified'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({'Error': 'Token expired'}, status=status.HTTP_226_IM_USED)
        except jwt.exceptions.DecodeError:
            return Response({'Error': 'Invalid token'}, status=status.HTTP_406_NOT_ACCEPTABLE)


class LoginApiView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_202_ACCEPTED)
