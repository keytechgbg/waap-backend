import json
from datetime import datetime, timedelta, timezone

from rest_framework import status, filters, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .serializers import UserSerializer, FriendSerializer, ChallengeSerializer, SearchSerializer
from rest_framework.authtoken.models import Token
from django.db.models import Q
from rest_framework.authentication import TokenAuthentication
from .models import Friends, ProfileToChallenge, Challenge, Photo, Like, Problem, Proposal
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.contrib.auth.models import User


# Registration

@api_view(['POST'])
def user_registration(request):
    if request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            data = serializer.data
            data['token'] = Token.objects.get(user=user).key
            return Response(data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def friends_handler(request):
    user = request.user
    data = request.data.copy() if not request.data == {} else {}
    data['from_user'] = user.username

    if request.method == 'GET':

        friends = Friends.objects.filter(Q(from_user=user) | (Q(to_user=user) & ~Q(status=Friends.REJECTED)))
        if friends.exists():
            friends = list(
                map(lambda x: {
                    'username': x.to_user.username if x.from_user.username == user.username else x.from_user.username
                    , 'status': dict(Friends.STATUS_CHOICES)[x.status],
                    'from_user': 1 if x.from_user.username == user.username else 0},
                    friends))
            return Response(friends)
        return Response([{'error': 'friends not found'}], status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'POST':
        serializer = FriendSerializer(data=data)
        if serializer.is_valid():
            try:
                serializer.save()
            except ValidationError as e:
                return Response({'error': e}, status=status.HTTP_400_BAD_REQUEST)

            return Response([{'success': 'friend request successful'}])
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'PUT':

        from_user = request.data['to_user']

        try:
            instance = Friends.objects.get(to_user=user, status=Friends.WAITING,
                                           from_user=User.objects.get(username=from_user))
        except ObjectDoesNotExist:
            return Response({'error': 'this friend request does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = FriendSerializer(instance, data=data)
        if serializer.is_valid():
            serializer.save()
            return Response([{'success': 'update successful'}])
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':

        try:
            to_user = data["to_user"]
        except Exception:
            return Response({
                "to_user": [
                    "This field is required."
                ]
            }, status=status.HTTP_400_BAD_REQUEST)

        if not User.objects.filter(username=to_user).exists():
            return Response({
                "to_user": [
                    "User with this username doesn`t exist"
                ]
            }, status=status.HTTP_400_BAD_REQUEST)
        to_user = User.objects.get(username=to_user)

        friends = Friends.objects.filter(
            (Q(from_user=user) & Q(to_user=to_user)) | (
                    Q(from_user=to_user) & Q(to_user=user) & Q(status=Friends.ACCEPTED)))
        if friends.exists():
            friends.delete()
            return Response([{'success': 'delete successful'}])
        return Response([{'error': 'friend request not found'}], status=status.HTTP_400_BAD_REQUEST)


class FriendSearch(generics.ListAPIView):
    serializer_class = SearchSerializer
    authentication_class = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    filter_backends = [filters.SearchFilter]

    search_fields = ['^username']

    def get_queryset(self):
        user = self.request.user
        query = User.objects.all()
        friends = Friends.objects.filter((Q(from_user=user) | Q(to_user=user)) & Q(status=Friends.ACCEPTED))
        if friends.exists():
            bad_names = set(map(lambda x: x.to_user.username, friends)).union(
                set(map(lambda x: x.from_user.username, friends)))
        else:

            bad_names = set([user.username])

        bad_names = bad_names.union(
            set(map(lambda x: x.username, User.objects.filter(is_staff=True))))

        for i in bad_names:
            query = query.exclude(username=i)
        query = query.order_by("username")
        return query


def updateStats(c: Challenge):
    ptc = c.ctp.all()
    photos = list(map(lambda x: list(map(lambda p: p.likes, list(x.photo_set.order_by('likes')))), ptc))
    best = list(map(lambda x: max(x) if not x == [] else 0, photos))
    most_likes = max(best)
    winners = []
    for i in range(len(best)):
        if (best[i] == most_likes):
            winners.append(ptc[i].p)
    if len(winners) == 1:
        stats = winners[0].statistic
        stats.won = stats.won + 1
        stats.save()
    elif len(winners) > 1:
        for w in winners:
            stats = w.statistic
            stats.tied = stats.tied + 1
            stats.save()

    players = list(map(lambda x: x.p, ptc))
    for i in range(len(players)):
        stats = players[i].statistic

        if best[i] > stats.highest_rate:
            stats.highest_rate = best[i]

        if not players[i] in winners:
            stats.lost = stats.lost + 1
        stats.save()


@api_view(['GET', 'POST', 'DELETE'])
@permission_classes([IsAuthenticated])
def challenge_handler(request):
    user = request.user
    profile = user.profile
    data = request.data.copy() if not request.data == {} else {}
    data['from_user'] = user.username
    statuses = dict(Challenge.STATUS_CHOICES)

    if request.method == 'GET':

        p_challenges = ProfileToChallenge.objects.filter(p=profile)
        if p_challenges.exists():
            challenges = []

            for x in p_challenges:
                now = datetime.now(timezone.utc)
                d = {}
                d['id'] = x.c.id
                d['image_count'] = x.c.image_count

                if (not x.c.status == Challenge.FINISHED) and x.c.voting < now:
                    x.c.status = Challenge.FINISHED
                    updateStats(x.c)
                    x.c.save()
                elif (x.c.status == Challenge.STARTED) and x.c.expire < now:
                    x.c.status = Challenge.VOTING
                    x.c.save()

                d["status"] = statuses[x.c.status]
                d["expire"] = int(x.c.expire.timestamp() * 1000)
                d["voting"] = int(x.c.voting.timestamp() * 1000)
                d["theme"] = x.c.theme
                d["reward"] = x.c.reward
                d["users"] = list(map(lambda ptc: ptc.p.user.username, ProfileToChallenge.objects.filter(c=x.c)))

                challenges.append(d)

            return Response({"challenges": challenges})
        return Response([{'error': 'challenges not found'}], status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'POST':
        try:
            expire = int(data["expire"])
            expire = datetime.now(timezone.utc) + timedelta(seconds=expire)
            data["expire"] = expire

        except Exception:
            return Response({
                "expire": [
                    "This field is required."
                ]
            }, status=status.HTTP_400_BAD_REQUEST)
        try:
            voting = int(data["voting"])
            voting = expire + timedelta(seconds=voting)
            data["voting"] = voting
        except Exception:
            return Response({
                "voting": [
                    "This field is required."
                ]
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = ChallengeSerializer(data=data)
        if serializer.is_valid():
            try:
                challenge = serializer.save()
            except ValidationError as e:
                return Response({'error': e}, status=status.HTTP_400_BAD_REQUEST)

            ProfileToChallenge.objects.create(p=profile, c=challenge)

            if "users" in data.keys():

                for u in map(lambda x: x.strip(), data["users"].strip('][').split()):

                    if User.objects.filter(username=u).exists():
                        friend = User.objects.get(username=u)
                        if Friends.objects.filter(
                                (Q(from_user=user) & Q(to_user=friend)) | (Q(from_user=friend) & Q(to_user=user)),
                                status=Friends.ACCEPTED).exists():
                            try:
                                ProfileToChallenge.objects.create(p=friend.profile, c=challenge)
                            except Exception:
                                pass

            return Response([{'success': 'challenge created successfully'}])
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':

        try:
            c_id = int(data["id"])
        except Exception:
            return Response({
                "id": [
                    "This field is required."
                ]
            }, status=status.HTTP_400_BAD_REQUEST)

        if not Challenge.objects.filter(id=c_id).exists():
            return Response({
                "id": [
                    "Challenge with this id doesn`t exist"
                ]
            }, status=status.HTTP_400_BAD_REQUEST)
        challenge = Challenge.objects.get(id=c_id)
        if not ProfileToChallenge.objects.filter(p=profile, c=challenge).exists():
            return Response({
                "error": "You are not participating in this challenge"
            }, status=status.HTTP_400_BAD_REQUEST)

        challenge.ctp.filter(p=profile).delete()
        if challenge.ctp.count() == 0:
            challenge.delete()

        stats = profile.statistic
        stats.resigned = stats.resigned + 1
        stats.save()

        return Response([{'success': 'delete successful'}])


@api_view(['GET', ])
@permission_classes([IsAuthenticated])
def statistic_handler(request):
    user = request.user
    profile = user.profile

    if request.method == 'GET':
        stats = profile.statistic
        ststistics = {"highest_rate": stats.highest_rate, "won": stats.won, "lost": stats.lost, "tied": stats.tied,
                      "resigned": stats.resigned}
        print(stats)

        return Response(ststistics)

@api_view(['POST', ])
@permission_classes([IsAuthenticated])
def change_username_password(request):
    user = request.user
    profile = user.profile
    data = request.data.copy() if not request.data == {} else {}

    uchange =True;
    pchange= True;

    try:
        username = data["username"]
    except Exception:
        uchange=False

    try:
        old_password = data["old_password"]
        new_password = data["new_password"]
    except Exception:
        pchange=False;
        if not uchange:
            return Response({
                "error": [
                    "old_password & new_password or username fields are required"
                ]
            }, status=status.HTTP_400_BAD_REQUEST)
        if old_password=="":
            return Response({
                "old_password":
                    "old_password is required"
            }, status=status.HTTP_400_BAD_REQUEST)

        if new_password=="":
            return Response({
                "new_password":
                    "new_password is required"
            }, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'POST':
        if uchange:
            if User.objects.filter(username=username).exists():
                return Response({
                "error":
                    "User with this username already exists."

            }, status=status.HTTP_400_BAD_REQUEST)
            user.username=username;
        if pchange:
            print(new_password)
            if user.check_password(old_password):
                user.set_password(new_password)
            else:
                return Response({
                    "old_password":
                        "old_password does not match"

                }, status=status.HTTP_400_BAD_REQUEST)


        user.save()


        return Response({"success": "changes applied"})

@api_view(['POST', ])
@permission_classes([IsAuthenticated])
def problem_handler(request):
    user = request.user
    data = request.data.copy() if not request.data == {} else {}

    try:
        message = data["message"]
    except Exception:
        return Response({
            "message": [
                "message field is required"
            ]
        }, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'POST':
        Problem.objects.create(owner=user, message=message)


        return Response({"success": "changes applied"})

@api_view(['POST', 'GET', ])
@permission_classes([IsAuthenticated])
def proposal_handler(request):
    user = request.user
    data = request.data.copy() if not request.data == {} else {}

    if request.method == 'POST':
        try:
            message = data["message"]
        except Exception:
            return Response({
                "message": [
                    "message field is required"
                ]
            }, status=status.HTTP_400_BAD_REQUEST)

        Proposal.objects.create(owner=user, message=message)

        return Response({"success": "changes applied"})

    if request.method == 'GET':

        proposals = list(map(lambda x: x.message, Proposal.objects.filter(approved=True)))

        return Response(proposals)

@api_view(['GET', 'POST', 'DELETE'])
@permission_classes([IsAuthenticated])
def photo_handler(request):
    user = request.user
    profile = user.profile
    data = request.data.copy() if not request.data == {} else {}
    data['from_user'] = user.username
    statuses = dict(Challenge.STATUS_CHOICES)

    try:
        challengeId = int(request.GET.get("challenge_id"))
    except Exception:
        return Response({
            "challenge_id": [
                "This field is required."
            ]
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        PTC = ProfileToChallenge.objects.get(p=profile, c=Challenge.objects.get(id=challengeId))
    except Exception:
        return Response({
            "challenge_id": [
                "No challenge found"
            ]
        }, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        res = []
        if PTC.c.status == Challenge.STARTED:
            photos = list(map(lambda e: {"url": e.image.url}, Photo.objects.filter(ptc=PTC)))
            res = [{'user': user.username, 'photos': photos}]
        else:
            for p in list(map(lambda e: e.p, ProfileToChallenge.objects.filter(c=PTC.c))):
                photos = list(map(lambda e: {"url": e.image.url, "likes": e.likes},
                                  Photo.objects.filter(ptc=ProfileToChallenge.objects.get(c=PTC.c, p=p))))
                res.append({'user': p.user.username, 'photos': photos})

        return Response(res)

    elif request.method == 'POST':
        try:
            file = request.FILES["photo"]
        except Exception:
            return Response({
                "photo": [
                    "This field is required."
                ]
            }, status=status.HTTP_400_BAD_REQUEST)

        if PTC.c.status == Challenge.STARTED:
            if Photo.objects.filter(ptc=PTC).count() < PTC.c.image_count:
                photo = Photo.objects.create(image=file, ptc=PTC)
                return Response({"url": photo.image.url})
            else:
                return Response({"error": "too many photos for this challenge"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"error": "challenge expired"}, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':

        try:
            url = data["url"]
        except Exception:
            return Response({
                "url": [
                    "This field is required."
                ]
            }, status=status.HTTP_400_BAD_REQUEST)

        photos = list(Photo.objects.filter(ptc=PTC))
        urls = list(map(lambda e: e.image.url, photos))
        if url in urls:
            if PTC.c.status == Challenge.STARTED:
                photos[urls.index(url)].delete()
                return Response({"success": "delete successful"})
            return Response({"error": "challenge expired"}, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            "url": [
                "url not found"
            ]
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST', 'DELETE'])
@permission_classes([IsAuthenticated])
def like_handler(request):
    user = request.user
    profile = user.profile
    data = request.data.copy() if not request.data == {} else {}
    data['from_user'] = user.username

    try:
        challengeId = int(request.GET.get("challenge_id"))
    except Exception:
        return Response({
            "challenge_id": [
                "This field is required."
            ]
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        PTC = ProfileToChallenge.objects.get(p=profile, c=Challenge.objects.get(id=challengeId))
    except Exception:
        return Response({
            "challenge_id": [
                "No challenge found"
            ]
        }, status=status.HTTP_400_BAD_REQUEST)

    if PTC.c.status == Challenge.STARTED:
        return Response({"error": "voting is not started yet"}, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        photos = list(map(lambda e: e.photo.image.url, Like.objects.filter(ptc=PTC)))
        res = [{'photos': photos}]
        return Response(res)

    elif request.method == 'POST':
        try:
            url = data["url"]
        except Exception:
            return Response({
                "url": [
                    "This field is required."
                ]
            }, status=status.HTTP_400_BAD_REQUEST)

        photos = []
        for ptc in ProfileToChallenge.objects.filter(c=PTC.c):
            photos.extend(list(Photo.objects.filter(ptc=ptc)))
        urls = list(map(lambda e: e.image.url, photos))
        if url in urls:
            if PTC.c.status == Challenge.VOTING:
                Like.objects.get_or_create(ptc=PTC, photo=photos[urls.index(url)])
                return Response({"success": "liked successful"})
            return Response({"error": "challenge finished"}, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            "url": [
                "url not found"
            ]
        }, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':

        try:
            url = data["url"]
        except Exception:
            return Response({
                "url": [
                    "This field is required."
                ]
            }, status=status.HTTP_400_BAD_REQUEST)

        photos = []
        for ptc in ProfileToChallenge.objects.filter(c=PTC.c):
            photos.extend(list(Photo.objects.filter(ptc=ptc)))
        urls = list(map(lambda e: e.image.url, photos))
        if url in urls:
            if PTC.c.status == Challenge.VOTING:
                Like.objects.filter(ptc=PTC, photo=photos[urls.index(url)]).delete()
                return Response({"success": "like removed"})
            return Response({"error": "challenge finished"}, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            "url": [
                "url not found"
            ]
        }, status=status.HTTP_400_BAD_REQUEST)
