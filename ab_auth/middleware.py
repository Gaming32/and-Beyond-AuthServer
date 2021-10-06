import logging
from typing import Callable

from django.http.request import HttpRequest
from django.http.response import HttpResponse

from ab_auth.errors import INTERNAL_ERROR, error_response

GetResponse = Callable[[HttpRequest], HttpResponse]


class ProductionMiddleware:
    func: GetResponse

    def __init__(self, get_response: GetResponse) -> None:
        self.func = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        return self.func(request)

    def process_exception(self, request: HttpRequest, exception: Exception) -> HttpResponse:
        logging.error('An internal error occurred in %s.%s', self.func.__module__, self.func.__qualname__, exc_info=exception)
        exc_str = str(exception)
        exc_text = exception.__class__.__qualname__ + (f': {exc_str}' if exc_str else '')
        return error_response(INTERNAL_ERROR, {
            'type': exception.__class__.__qualname__,
            'args': exception.args,
        }, exc_text)
