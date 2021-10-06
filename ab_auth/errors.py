import functools
import json
import re
import typing
from typing import Any, AnyStr, Iterable, Optional, Union

from django.http import JsonResponse
from django.http.request import HttpRequest

KEY_ERROR = 'KeyError'
FORMAT_ERROR = 'FormatError'
TYPE_ERROR = 'TypeError'
UNAUTHORIZED = 'Unauthorized'
NO_SUCH_USER = 'NoSuchUserError'
NOT_FOUND = 'NotFound'
METHOD_NOT_ALLOWED = 'MethodNotAllowed'
INTERNAL_ERROR = 'InternalError'

ERROR_TYPES = {
    KEY_ERROR: 400,
    FORMAT_ERROR: 400,
    TYPE_ERROR: 400,
    UNAUTHORIZED: 401,
    NO_SUCH_USER: 404,
    NOT_FOUND: 404,
    METHOD_NOT_ALLOWED: 405,
    INTERNAL_ERROR: 500,
}


def get_type_name(value) -> str:
    if isinstance(value, type):
        return value.__qualname__
    elif isinstance(value, typing._UnionGenericAlias): # type: ignore
        return ' | '.join(get_type_name(sub) for sub in typing.get_args(value))
    return str(value)


def error_response(type: str, args: Any = None, human: Optional[AnyStr] = None, status: int = None):
    if status is None:
        status = ERROR_TYPES.get(type, 400)
    return JsonResponse({
        'human': human,
        'type': type,
        'args': args,
    }, status=status, json_dumps_params=dict(
        indent=3, default=str
    ))


def format_error(value: AnyStr, message: Optional[str] = None, **kwargs: Any):
    return error_response(FORMAT_ERROR, dict(value=value, **kwargs), message)


def validate_regex(value: str, regex: str):
    if re.fullmatch(regex, value) is None:
        return format_error(value, f'The specified value did not match the regex "{regex}"', regex=regex)


def ensure_json(request: HttpRequest):
    try:
        return json.loads(request.body)
    except ValueError:
        encoding = 'utf-8' if request.encoding is None else request.encoding
        text = request.body.decode(encoding, 'replace')
        return format_error(text, f'Invalid JSON: {text}')


def type_error(name: str, expected: Union[type, str], got: Union[type, str]):
    if isinstance(expected, type):
        expected = get_type_name(expected)
    if isinstance(got, type):
        got = get_type_name(got)
    return error_response(TYPE_ERROR, {
            'arg': 'username',
            'expected': expected,
            'got': got,
        }, f'{name} is of type {got}, but was expected to be {expected}')


def method_not_allowed(method: str, allowed_methods: Iterable[str] = ('GET',)) -> JsonResponse:
    allowed_methods = list(allowed_methods)
    return error_response(METHOD_NOT_ALLOWED, {
        'method': method,
        'allowed': allowed_methods
    }, f'Request used method {method}, but this route only allows the following methods: {", ".join(allowed_methods)}')
