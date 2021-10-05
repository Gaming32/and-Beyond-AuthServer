"""ab_auth URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.http.request import HttpRequest
from django.urls import path
from django.urls.conf import include
from django.urls.exceptions import Resolver404

from ab_auth.base_views import ping_route, teapot_route
from ab_auth.errors import NOT_FOUND, error_response

handler404 = 'ab_auth.urls.page_not_found'

urlpatterns = [
    path('ping', ping_route),
    path('teapot', teapot_route),
    path('auth/', include('auth.urls')),
]


def page_not_found(request: HttpRequest, exception: Exception):
    if isinstance(exception, Resolver404):
        path = exception.args[0]['path']
        return error_response(NOT_FOUND, {
            'path': path
        }, f'The path "{path}" was not found')
    return error_response(NOT_FOUND, exception.args, str(exception))
