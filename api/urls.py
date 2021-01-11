from django.urls import path
from .views import user_registration, friends_handler, challenge_handler, FriendSearch, photo_handler, like_handler, statistic_handler, change_username_password, problem_handler, proposal_handler
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [
    path('registration/', user_registration),
    path('login/', obtain_auth_token),
    path('changepass/', change_username_password),
    path('friends/', friends_handler),
    path('challenges/', challenge_handler),
    path('search/', FriendSearch.as_view()),
    path('photos/', photo_handler),
    path('likes/', like_handler),
    path('statistics/', statistic_handler),
    path('problems/', problem_handler),
    path('proposals/', proposal_handler),

]
