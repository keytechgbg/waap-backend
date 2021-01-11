from django.contrib import admin
from .models import Profile, Challenge, Photo, Friends, ProfileToChallenge, Statistic, Like, Problem, Proposal
# Register your models here.


admin.site.register(Profile)
admin.site.register(Challenge)
admin.site.register(Photo)
admin.site.register(Friends)
admin.site.register(Statistic)
admin.site.register(ProfileToChallenge)
admin.site.register(Like)
admin.site.register(Problem)
admin.site.register(Proposal)