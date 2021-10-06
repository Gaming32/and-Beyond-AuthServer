from django.urls import path

from auth.views import login_route, token_route, uuid_route

urlpatterns = [
    path('login', login_route),
    path('token/<token>', token_route),
    path('uuid/<id_str>', uuid_route), # Not using Django's builtin uuid converter for API reasons
]
