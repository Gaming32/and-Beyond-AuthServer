import hashlib
from typing import Any, Union

from django.http.request import HttpRequest
from django.http.response import HttpResponse

from ab_auth.errors import ensure_json, key_error, type_error


def hash_token(token: bytes) -> bytes:
    return hashlib.sha256(token, usedforsecurity=True).digest()


def get_keys(request: HttpRequest, **keys: type) -> Union[dict[str, Any], HttpResponse]:
    if isinstance(info := ensure_json(request), HttpResponse):
        return info
    missing = []
    for key in keys:
        if key not in info:
            missing.append(key)
    if missing:
        return key_error(missing)
    for (key, key_type) in keys.items():
        key_value = info.get(key)
        if not isinstance(key_value, key_type):
            return type_error(key, key_type, type(key_value))
    return info
