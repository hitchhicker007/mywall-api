import os
from rest_framework import serializers

from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from student.models import User
from student.utils import Util


class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError('Password and confirm password does not match!')
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ['email', 'password']


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'student_id', 'is_verified', 'profile_picture']


class ChangePasswordSerializer(serializers.Serializer):
    # old_password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')

        if password != password2:
            raise serializers.ValidationError('Password and confirm password does not match!')
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = self.context.get('current_site')
            link = 'http://' + current_site + '/api/user/reset-password/' + uid + '/' + token + '/'
            print('Password reset link : ', link)
            html_content = render_to_string('password_reset_mail.html', {'name': user.name, 'url': link})
            text_content = strip_tags(html_content)

            data = {
                'subject': 'Reset your password',
                'html_content': html_content,
                'text_content': text_content,
                'to_email': user.email,
            }

            try:
                Util.send_mail(data)
            except:
                raise serializers.ValidationError('Something went wrong while sending email. Please try later.')
            return attrs
        else:
            raise serializers.ValidationError('User with this email does not exists!')


class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError('Password and confirm password does not match!')
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Token is not valid or expired!')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not valid or expired!')


class UpdateProfileSerializer(serializers.ModelSerializer):
    name = serializers.CharField(max_length=200, required=False)
    profile_picture = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = ['name', 'profile_picture']
        extra_kwargs = {
            'name': {'required': False},
            'profile_picture': {'required': False},
        }

    def update(self, instance, validated_data):
        path = ''
        if validated_data.get('name'):
            instance.name = validated_data['name']
        if validated_data.get('profile_picture'):
            try:
                path = instance.profile_picture.path
                print('path = ', instance.profile_picture.path)
                instance.profile_picture = validated_data['profile_picture']
            except ValueError as e:
                instance.profile_picture = validated_data['profile_picture']
        instance.save()
        if os.path.exists(path):
            os.remove(path)
        return instance
