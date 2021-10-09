from django.urls import path

from sessions.views import new_session_route, retrieve_session_route

urlpatterns = [
    path('new', new_session_route),
    path('retrieve/<session_token>', retrieve_session_route),
]
