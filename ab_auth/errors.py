import json
import re
import typing
from typing import Any, AnyStr, Iterable, Optional, TypedDict, Union

import zxcvbn
from django.http import JsonResponse
from django.http.request import HttpRequest

KEY_ERROR = 'KeyError'
FORMAT_ERROR = 'FormatError'
TYPE_ERROR = 'TypeError'
UNAUTHORIZED = 'Unauthorized'
INSECURITY = 'InsecurityError'
NO_SUCH_USER = 'NoSuchUserError'
NOT_FOUND = 'NotFound'
METHOD_NOT_ALLOWED = 'MethodNotAllowed'
CONFLICT = 'Conflict'
RATELIMIT = 'Ratelimited'
INTERNAL_ERROR = 'InternalError'

ERROR_TYPES = {
    KEY_ERROR: 400,
    FORMAT_ERROR: 400,
    TYPE_ERROR: 400,
    UNAUTHORIZED: 401,
    INSECURITY: 401,
    NO_SUCH_USER: 404,
    NOT_FOUND: 404,
    METHOD_NOT_ALLOWED: 405,
    CONFLICT: 409,
    RATELIMIT: 429,
    INTERNAL_ERROR: 500,
}


class _RatelimitDict(TypedDict):
    count: int
    limit: int
    should_limit: bool
    time_left: int


def get_type_name(value) -> str:
    if isinstance(value, type):
        return value.__qualname__
    elif isinstance(value, typing._UnionGenericAlias): # type: ignore
        return ' | '.join(get_type_name(sub) for sub in typing.get_args(value))
    return str(value)


def error_response(type: str, args: Any = None, human: Optional[AnyStr] = None, status: int = None, headers=None):
    if status is None:
        status = ERROR_TYPES.get(type, 400)
    return JsonResponse({
        'human': human,
        'type': type,
        'args': args,
    }, status=status, json_dumps_params=dict(
        indent=3, default=str
    ), headers=headers)


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


def ratelimit_error(ratelimit_info: Optional[_RatelimitDict]) -> JsonResponse:
    if ratelimit_info is None:
        return error_response(RATELIMIT)
    return error_response(
        RATELIMIT, {
            'count': ratelimit_info['count'],
            'limit': ratelimit_info['limit'],
            'retry_after': ratelimit_info['time_left'],
        },
        f'You have encountered a ratelimit! Please try again in {ratelimit_info["time_left"]} seconds.',
        headers={
            'Retry-After': ratelimit_info['time_left'],
        }
    )


def verify_password_security(password: str, username: Optional[str] = None) -> Optional[JsonResponse]:
    user_info = []
    if username is not None:
        user_info.append(username)
    zxcvbn_info = zxcvbn.zxcvbn(password, None if user_info is None else user_info)
    if zxcvbn_info['score'] < 2: # Not secure enough
        human = (f"Your password had a score of {zxcvbn_info['score']}, "
                  "but a minimum of 2 is required.")
        if warning := zxcvbn_info['feedback']['warning']:
            human += '\nWarning: ' + warning
        if suggestions := zxcvbn_info['feedback']['suggestions']:
            human += "\nHere's a list of suggestions to make your password stronger:"
            for suggestion in suggestions:
                human += '\n  + ' + suggestion
        zxcvbn_info.pop('password', None) # Don't send the password back over the network
        return error_response(INSECURITY, zxcvbn_info, human)
    return None
