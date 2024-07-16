from rest_framework import serializers
from annotations.models import VogonUser
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import GithubToken, CitesphereToken

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    def create(self, validated_data):
        for k,v in validated_data.items():
            print(k,v)
        user = VogonUser.objects.create(
            email=validated_data['email'],
            username=validated_data['username'],
            full_name=validated_data['full_name'],
            affiliation=validated_data['affiliation'],
        )
        user.set_password(validated_data['password'])
        user.save()

        return user

    class Meta:
        model = get_user_model()
        fields = ('id','email', 'password', 'full_name', 'username', 'affiliation')
        ref_name = "user accounts"


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        try:
            GithubToken.objects.get(user=user)
            token['github_token'] = True
        except GithubToken.DoesNotExist:
            token['github_token'] = False
        try:
            CitesphereToken.objects.get(user=user)
            token['citesphere_token'] = True
        except CitesphereToken.DoesNotExist:
            token['citesphere_token'] = False
        return token
    
    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.user)

        data['is_admin'] = str(self.user.is_admin)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        return data
    
class ResetPasswordSerializer(serializers.Serializer):
	username = serializers.CharField(required=True)
	password1 = serializers.CharField(required=True)
	password2 = serializers.CharField(required=True)
	token = serializers.CharField(required=True)