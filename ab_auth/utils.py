import binascii
import hashlib
from typing import Any, Union

from django.http.request import HttpRequest
from django.http.response import HttpResponse

from ab_auth.errors import KEY_ERROR, ensure_json, error_response, type_error


def hash_token(token: bytes) -> bytes:
    return hashlib.sha256(token, usedforsecurity=True).digest()


def stringify_token(token: bytes) -> str:
    return binascii.b2a_hex(token).decode('ascii')


def get_keys(request: HttpRequest, **keys: type) -> Union[dict[str, Any], HttpResponse]:
    if isinstance(info := ensure_json(request), HttpResponse):
        return info
    missing = []
    for key in keys:
        if key not in info:
            missing.append(key)
    if missing:
        return error_response(KEY_ERROR, missing, f'Missing the following parameters: {", ".join(missing)}')
    for (key, key_type) in keys.items():
        key_value = info.get(key)
        if not isinstance(key_value, key_type):
            return type_error(key, key_type, type(key_value))
    return info
    # if not isinstance(username, str):
    #     return type_error('username', str, type(username))
    # if not isinstance(password, str):
    #     return type_error('password', str, type(password))
