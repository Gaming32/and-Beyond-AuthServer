from django.urls import path

from auth.views import (create_user_route, login_route, logout_route,
                        profile_route, username_route, uuid_route)

urlpatterns = [
    path('login', login_route),
    path('logout/<token>', logout_route),
    path('create-user', create_user_route),
    path('profile/<token>', profile_route), # This is the *authenticated* profile route (use /auth/uuid for unauthenticated requests)
    path('uuid/<id_str>', uuid_route), # Not using Django's builtin uuid converter for API reasons
    path('username/<username>', username_route),
]
