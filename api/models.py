from datetime import datetime, timezone

from django.db import models
from django.contrib.auth.models import User
from cloudinary.models import CloudinaryField
import cloudinary.uploader
import cloudinary
from django.core.exceptions import ValidationError

from django.db.models.signals import post_save, post_delete, pre_delete
from django.dispatch import receiver
from rest_framework.authtoken.models import Token


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, blank=False)
    challenges = models.ManyToManyField('Challenge', through='ProfileToChallenge', blank=True)


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        profile = Profile.objects.create(user=instance)
        Statistic.objects.create(owner=profile)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, created=False, **kwargs):
    if created:
        instance.profile.save()


@receiver(post_save, sender=User)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


class Statistic(models.Model):
    owner = models.OneToOneField(Profile, on_delete=models.CASCADE)
    highest_rate = models.PositiveIntegerField(default=0)
    won = models.PositiveIntegerField(default=0)
    lost = models.PositiveIntegerField(default=0)
    tied = models.PositiveIntegerField(default=0)
    resigned = models.PositiveIntegerField(default=0)


def image_count_validator(value):
    if not 0 < value <= 3:
        raise ValidationError(
            "too many photos/user in this Challenge!!!"
        )


def expire_validator(value):
    if value < datetime.now(timezone.utc):
        raise ValidationError(
            "incorrect date !"
        )


class Challenge(models.Model):
    STARTED = 1
    VOTING = 2
    FINISHED = 3
    STATUS_CHOICES = [
        (STARTED, 'STARTED'),
        (VOTING, 'VOTING'),
        (FINISHED, 'FINISHED'),
    ]
    image_count = models.PositiveIntegerField(validators=[image_count_validator])
    expire = models.DateTimeField(validators=[expire_validator])
    voting = models.DateTimeField()
    status = models.SmallIntegerField(choices=STATUS_CHOICES, default=STARTED)
    theme = models.CharField(max_length=50)
    reward = models.CharField(max_length=50)


class ProfileToChallenge(models.Model):
    p = models.ForeignKey(Profile, related_name='ptc', on_delete=models.CASCADE)
    c = models.ForeignKey(Challenge, related_name='ctp', on_delete=models.CASCADE)
    voted = models.BooleanField(default=False)

    class Meta:
        unique_together = (('c', 'p'),)


class Photo(models.Model):
    image = CloudinaryField('image', transformation={"quality": "auto"})
    likes = models.SmallIntegerField(default=0)
    ptc = models.ForeignKey('ProfileToChallenge', on_delete=models.CASCADE)


@receiver(pre_delete, sender=Photo)
def delete_cloudinary(sender, instance, **kwargs):
    cloudinary.uploader.destroy(instance.image.public_id, invalidate=True)


class Like(models.Model):
    photo = models.ForeignKey('Photo', on_delete=models.CASCADE)
    ptc = models.ForeignKey('ProfileToChallenge', on_delete=models.CASCADE)


@receiver(post_delete, sender=Like)
@receiver(post_save, sender=Like)
def update_likes(sender, instance, **kwargs):
    instance.photo.likes = Like.objects.filter(photo=instance.photo).count()
    instance.photo.save()

class Friends(models.Model):
    WAITING = 1
    ACCEPTED = 2
    REJECTED = 3
    STATUS_CHOICES = [
        (WAITING, 'WAITING'),
        (ACCEPTED, 'ACCEPTED'),
        (REJECTED, 'REJECTED'),
    ]
    to_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='friendship_requests_received')
    from_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='friendship_requests_sent')
    status = models.SmallIntegerField(choices=STATUS_CHOICES, default=WAITING)

    class Meta:
        verbose_name = 'Friend'
        unique_together = (('to_user', 'from_user'),)

class Problem(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.TextField()

class Proposal(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    approved = models.BooleanField(default=False)
    message = models.TextField()