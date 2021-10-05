from django.http.request import HttpRequest
from django.http.response import HttpResponse


def ping_route(request: HttpRequest) -> HttpResponse:
    return HttpResponse('pong', content_type='text/plain')


def teapot_route(request: HttpRequest) -> HttpResponse:
    return HttpResponse("I'm a teapot", status=418, content_type='text/plain')
