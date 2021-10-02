import functools
import json
import re
import typing
from typing import Any, Optional, Union

from aiohttp.web import json_response

KEY_ERROR = 'KeyError'
FORMAT_ERROR = 'FormatError'
TYPE_ERROR = 'TypeError'
NO_SUCH_USER = 'NoSuchUserError'
UNAUTHORIZED = 'Unauthorized'
INTERNAL_ERROR = 'InternalError'

ERROR_TYPES = {
    KEY_ERROR: 400,
    FORMAT_ERROR: 400,
    TYPE_ERROR: 400,
    NO_SUCH_USER: 404,
    UNAUTHORIZED: 401,
    INTERNAL_ERROR: 500,
}


def get_type_name(value) -> str:
    if isinstance(value, type):
        return value.__qualname__
    elif isinstance(value, typing._UnionGenericAlias): # type: ignore
        return ' | '.join(get_type_name(sub) for sub in typing.get_args(value))
    return str(value)


def error_repsonse(type: str, args: Any = None, human: Optional[str] = None, status: int = None):
    if status is None:
        status = ERROR_TYPES.get(type, 400)
    return json_response({
        'human': human,
        'type': type,
        'args': args,
    }, status=status, dumps=functools.partial(
        json.dumps, indent=3
    ))


def format_error(value: str, message: Optional[str] = None, **kwargs: Any):
    return error_repsonse(FORMAT_ERROR, dict(value=value, **kwargs), message)


def validate_regex(value: str, regex: str):
    if re.match(regex, value) is None:
        return format_error(value, f'The specified value did not match the regex "{regex}"', regex=regex)


def type_error(name: str, expected: Union[type, str], got: Union[type, str]):
    if isinstance(expected, type):
        expected = get_type_name(expected)
    if isinstance(got, type):
        got = get_type_name(got)
    return error_repsonse(TYPE_ERROR, {
            'arg': 'username',
            'expected': expected,
            'got': got,
        }, f'{name} is of type {got}, but was expected to be {expected}')
