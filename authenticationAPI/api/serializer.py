from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()
'''If you reference User directly (for example, by referring to it in a foreign key), 
    your code will not work in projects where the AUTH_USER_MODEL setting has been changed
    to a different user model. 
    Instead of referring to User directly, you should reference the user model using 
    django.contrib.auth.get_user_model(). This method will return the currently active user model – 
    the custom user model if one is specified, or User otherwise.
 '''


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

    def validate(self, attrs):
        email = attrs.get('email')
        user = get_object_or_404(User, email=email)
        if user:
            raise serializers.ValidationError({'User': 'user already exist'})
        return super().validate(attrs)

    def create(self, validated_data):
        return User.objects.create(**validated_data)


class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    # write _only makes sure the  password isn't sent back to the user

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True, 'input_type': 'password'}
        }

    def save(self):
        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if password != password2:
            raise serializers.ValidationError({'password': 'Passwords must match'})
        user = User.objects.create(email=self.validated_data['email'],
                                   username=self.validated_data['username'])
        user.set_password(password)
        user.save()
        return user


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(max_length=15, write_only=True)
    tokens = serializers.CharField(read_only=True)
    username = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'tokens', 'username']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials, please try again')
        if not user.is_active:
            raise AuthenticationFailed('Account is disabled, contact the site admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email not verified')

        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens()
        }


class LogOutSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs.get('refresh')  # set the token as the token from the attrs from the view request

        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()  # login logic is implemented by blacklisting
            # refresh token so that the user has to revalidate by logging in again

        except TokenError:
            self.fail('bad token')
