import jwt

from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

from django.contrib.auth import authenticate
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.shortcuts import render
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser

from student.serializers import RegistrationSerializer, LoginSerializer, ProfileSerializer, ChangePasswordSerializer, \
    SendPasswordResetEmailSerializer, PasswordResetSerializer, UpdateProfileSerializer
from student.renderer import UserRenderer
from student.utils import Util
from student.models import User
from student.forms import PasswordResetForm


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class RegistrationView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_tokens_for_user(user)

        current_site = get_current_site(request).domain
        relative_link = reverse('verify-email')
        abs_url = 'https://' + str(current_site) + str(relative_link) + "?token=" + str(token['access'])

        html_content = render_to_string('confirmation_mail.html', {'url': abs_url})
        text_content = strip_tags(html_content)

        data = {
            'subject': 'Verify your email',
            'html_content': html_content,
            'text_content': text_content,
            'to_email': user.email
        }

        try:
            Util.send_mail(data)
        except Exception as e:
            print("-> ", e)
            raise ValueError('Something went wrong while sending email. Please try later.')

        data = {'message': 'User successfully registered.', 'token': token}
        return Response({'data': data}, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = authenticate(email=email, password=password)
        if user is not None:
            token = get_tokens_for_user(user=user)
            profile_serializer = ProfileSerializer(user)
            data = {'message': 'Login success.', 'token': token, 'user': profile_serializer.data}
            return Response({'data': data}, status=status.HTTP_200_OK)
        else:
            return Response({'errors': {'non_field_errors': ['Incorrect email or password.']}}, status=status.HTTP_404_NOT_FOUND)


class LogoutView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class ProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serializer = ProfileSerializer(request.user)
        return Response({'data': serializer.data}, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = ChangePasswordSerializer(data=request.data, context={'user': request.user})
        serializer.is_valid(raise_exception=True)
        data = {'message': 'Password changed successfully.'}
        return Response({'data': data}, status=status.HTTP_200_OK)


class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        current_site = get_current_site(request)
        serializer = SendPasswordResetEmailSerializer(data=request.data, context={'current_site': str(current_site)})

        serializer.is_valid(raise_exception=True)
        data = {'message': 'Password reset mail has been sent. Please Check your email.'}
        return Response({'data': data}, status=status.HTTP_200_OK)


class PasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token, format=None):
        form = PasswordResetForm(request.data)
        if form.is_valid():
            password = form.cleaned_data['password']
            password2 = form.cleaned_data['password2']
            if password != password2:
                form = PasswordResetForm()
                return render(request, 'reset_pass.html', {'form': form, 'error': 'Password and confirm password does not match!'})

        serializer = PasswordResetSerializer(data=request.data, context={'uid':uid, 'token': token})
        serializer.is_valid(raise_exception=True)
        return render(request, 'success.html',
                      {'title': 'Password changed', 'message': 'Your password has been changed successfully.'})

    def get(self, request, uid, token, format=None):
        try:
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return render(request, 'error_page.html', {'error': 'Url is not valid, request for new one.'})

            form = PasswordResetForm()
            return render(request, 'reset_pass.html', {'form': form})

        except DjangoUnicodeDecodeError as e:
            return render(request, 'error_page.html', {'error': str(e)})

        except Exception as e:
            return render(request, 'error_page.html', {'error': str(e)})


class SendConfirmationEmail(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        user = request.user
        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request)
        relative_link = reverse('verify-email')
        abs_url = 'https://' + str(current_site) + str(relative_link) + "?token=" + str(token)
        print(abs_url)

        html_content = render_to_string('confirmation_mail.html', {'url': abs_url})
        text_content = strip_tags(html_content)

        data = {
            'subject': 'Verify your email',
            'html_content': html_content,
            'text_content': text_content,
            'to_email': user.email
        }

        try:
            Util.send_mail(data)
        except:
            raise ValueError('Something went wrong while sending email. Please try later.')

        response = {
            'message': 'Confirmation mail sent successfully.',
        }
        return Response({'data': response}, status=status.HTTP_200_OK)


class VerifyEmailView(APIView):
    renderer_classes = [UserRenderer]

    def get(self, request, format=None):
        token = request.GET.get('token')
        try:
            print(token)
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            print(payload)
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return render(request, 'success.html',
                          {'title': 'Email verified', 'message': 'Your email has been verified successfully.'})
        except Exception as e:
            print(e)
            return render(request, 'error_page.html', {'error': 'Something went wrong.'})


class UpdateProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def put(self, request, format=None):
        serializer = UpdateProfileSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.update(instance=request.user, validated_data=request.data)
        data = {
            'message': 'Profile updated successfully.'
        }
        return Response({'data': data}, status=status.HTTP_200_OK)


class GetUserView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user_id = request.data.get('id')
        user = User.objects.get(id=user_id)
        serializer = ProfileSerializer(user)
        return Response({'data': serializer.data}, status=status.HTTP_200_OK)

