import json
import secrets
import uuid

from ab_auth.errors import (KEY_ERROR, NO_SUCH_USER, UNAUTHORIZED,
                            error_response, format_error, type_error,
                            validate_regex)
from django.db.utils import IntegrityError
from django.http.request import HttpRequest
from django.http.response import HttpResponse, JsonResponse
from werkzeug.security import check_password_hash

from auth import TOKEN_REGEX
from auth.models import User


def login_route(request: HttpRequest) -> HttpResponse:
    try:
        info = json.loads(request.body)
    except ValueError:
        encoding = 'utf-8' if request.encoding is None else request.encoding
        text = request.body.decode(encoding, 'replace')
        return format_error(text, f'Invalid JSON: {text}')
    missing = []
    for key in ('username', 'password'):
        if key not in info:
            missing.append(key)
    if missing:
        return error_response(KEY_ERROR, missing, f'Missing the following login parameters: {", ".join(missing)}')
    username = info.get('username')
    password = info.get('password')
    if not isinstance(username, str):
        return type_error('username', str, type(username))
    if not isinstance(password, str):
        return type_error('password', str, type(password))
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return error_response(UNAUTHORIZED, 'username', 'The specified user does not exist')
    if not check_password_hash(user.password, password):
        return error_response(UNAUTHORIZED, 'password', 'The specified password is incorrect')
    for _ in range(8): # Eight attempts (we should never hit this limit)
        token = secrets.token_hex(16)
        user.token = token
        try:
            user.save()
        except IntegrityError:
            continue
        break
    else:
        raise RuntimeError('Failed to find unique token (tried 8 times)')
    return JsonResponse({
        'token': token,
        'uuid': str(user.unique_id),
    })


def get_user_response(user: User) -> HttpResponse:
    return JsonResponse({
        'uuid': str(user.unique_id),
        'username': user.username,
    })


def token_route(request: HttpRequest, token: str) -> HttpResponse:
    if (error := validate_regex(token, TOKEN_REGEX)) is not None:
        return error
    try:
        user = User.objects.get(token=token)
    except User.DoesNotExist:
        return error_response(NO_SUCH_USER, {'token': token}, f'No user with token "{token}"')
    return get_user_response(user)


def uuid_route(request: HttpRequest, id_str: str) -> HttpResponse:
    try:
        user_id = uuid.UUID(id_str)
    except ValueError:
        return format_error(id_str, f'Invalid UUID "{id_str}"')
    id_str = str(user_id) # Normalize ID format
    try:
        user = User.objects.get(unique_id=user_id)
    except User.DoesNotExist:
        return error_response(NO_SUCH_USER, {'uuid': id_str}, f'No user with uuid "{id_str}"')
    return get_user_response(user)
