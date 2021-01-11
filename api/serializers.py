from datetime import datetime

from rest_framework import serializers
from .models import Profile, Friends, Challenge
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'password',
        ]
        extra_kwargs = {'password': {'write_only': True}, 'email': {'required': True}, "username": {"min_length": 5}}

    def validate_email(self, value):
        norm_email = value.lower()
        if User.objects.filter(email=norm_email).exists():
            raise serializers.ValidationError("A user with that email already exists.")
        return norm_email

    def create(self, validated_data):

        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
        )

        user.set_password(validated_data['password'])
        user.save()

        return user


class SearchSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'username']

class FriendSerializer(serializers.Serializer):
    def valid_user(value):
        if not User.objects.filter(username=value).exists():
            raise serializers.ValidationError('User with this username doesn`t exist')

    def valid_status(value):
        if not value in list(map(lambda x: x[1], Friends.STATUS_CHOICES[1:])):
            raise serializers.ValidationError('Unknown status')

    from_user = serializers.CharField(max_length=30, validators=[valid_user], required=True)
    to_user = serializers.CharField(max_length=30, validators=[valid_user])
    status = serializers.CharField(max_length=30, validators=[valid_status], required=False)

    def create(self, validated_data):

        if validated_data.get('from_user') == validated_data.get('to_user'):
            raise ValidationError('you cant request friendship from yourself')

        check1 = Friends.objects.filter(from_user=User.objects.get(username=validated_data.get('from_user')),
                                        to_user=User.objects.get(username=validated_data.get('to_user')))

        check2 = Friends.objects.filter(from_user=User.objects.get(username=validated_data.get('to_user')),
                                        to_user=User.objects.get(username=validated_data.get('from_user')))

        if check1.exists():
            raise ValidationError('this friends request already exist')

        if check2.exists():

            instace = Friends.objects.get(from_user=User.objects.get(username=validated_data.get('to_user')),
                                          to_user=User.objects.get(username=validated_data.get('from_user')))

            if instace.status == Friends.ACCEPTED:
                raise ValidationError(f'you and {validated_data.get("to_user")} already friends!')

            instace.status = Friends.ACCEPTED
            instace.save()
            return instace

        tu = User.objects.get(username=validated_data.get('to_user'))
        fu = User.objects.get(username=validated_data.get('from_user'))
        return Friends.objects.create(from_user=fu, to_user=tu)

    def update(self, instance, validated_data):
        if instance.status == Friends.WAITING:
            status = list(filter(lambda x: x[1] == validated_data.get('status', "WAITING"), Friends.STATUS_CHOICES))[0][
                0]
            instance.status = status
            instance.save()
        return instance


class ChallengeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Challenge
        exclude = ['status']
