import binascii
import hashlib
import secrets
import uuid
from typing import Union

from ab_auth.decorators import custom_ratelimit
from ab_auth.errors import (CONFLICT, KEY_ERROR, NO_SUCH_USER, UNAUTHORIZED,
                            ensure_json, error_response, format_error,
                            method_not_allowed, type_error, validate_regex,
                            verify_password_security)
from django.db.utils import IntegrityError
from django.http.request import HttpRequest
from django.http.response import HttpResponse, JsonResponse
from werkzeug.security import check_password_hash, generate_password_hash

from auth import TOKEN_REGEX, USERNAME_REGEX
from auth.models import User


def hash_token(token: bytes) -> bytes:
    return hashlib.sha256(token, usedforsecurity=True).digest()


def user_by_token(token: Union[str, bytes]) -> User:
    if isinstance(token, str):
        token = binascii.a2b_hex(token)
    return User.objects.get(token=hash_token(token))


def login(user: User) -> dict:
    for _ in range(8): # Eight attempts (we should never hit this limit)
        token = secrets.token_bytes(16)
        user.token = hash_token(token)
        try:
            user.save()
        except IntegrityError:
            continue
        break
    else:
        raise RuntimeError('Failed to find unique token (tried 8 times)')
    return {
        'token': binascii.b2a_hex(token).decode('ascii'),
    } | jsonify_user(user)


@custom_ratelimit(key='ip', rate='25/s')
@custom_ratelimit(key='post:username', rate='12/m')
def login_route(request: HttpRequest) -> HttpResponse:
    if isinstance(info := ensure_json(request), HttpResponse):
        return info
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
        user: User = User.objects.get(username=username)
    except User.DoesNotExist:
        return error_response(UNAUTHORIZED, 'username', 'The specified user does not exist')
    if not check_password_hash(user.password, password):
        return error_response(UNAUTHORIZED, 'password', 'The specified password is incorrect')
    return JsonResponse(login(user))


@custom_ratelimit(key='ip', rate='25/s')
def logout_route(request: HttpRequest, token: str) -> HttpResponse:
    if (error := validate_regex(token, TOKEN_REGEX)) is not None:
        return error
    try:
        user = user_by_token(token)
    except User.DoesNotExist:
        return error_response(UNAUTHORIZED, {'token': token}, f'The token "{token}" is invalid')
    user.token = None
    user.save()
    return HttpResponse(status=204)


def jsonify_user(user: User):
    return {
        'uuid': str(user.unique_id),
        'username': user.username,
    }


def get_user_response(user: User) -> HttpResponse:
    return JsonResponse(jsonify_user(user))


@custom_ratelimit(key='ip', rate='25/s')
@custom_ratelimit(key='post:username', rate='3/m')
def profile_route(request: HttpRequest, token: str) -> HttpResponse:
    if (error := validate_regex(token, TOKEN_REGEX)) is not None:
        return error
    try:
        user = user_by_token(token)
    except User.DoesNotExist:
        return error_response(UNAUTHORIZED, {'token': token}, f'No user with the token "{token}"')
    method = 'GET' if request.method is None else request.method
    if method == 'GET':
        return get_user_response(user)
    elif method == 'POST':
        if isinstance(info := ensure_json(request), HttpResponse):
            return info
        changes = 0
        change_username = None
        if 'username' in info:
            username = info.pop('username')
            if not isinstance(username, str):
                return type_error('username', str, type(username))
            change_username = username
            changes += 1
        change_password = None
        if 'password' in info:
            password = info.pop('password')
            if not isinstance(password, str):
                return type_error('password', str, type(password))
            if (error := verify_password_security(password, change_username or user.username)) is not None:
                return error
            change_password = generate_password_hash(password)
            changes += 1
        if changes:
            if change_username is not None:
                user.username = change_username
            if change_password is not None:
                user.password = change_password
            try:
                user.save()
            except IntegrityError:
                return error_response(CONFLICT, 'username', 'That username is already in use')
        return JsonResponse({'changes': changes})
    elif method == 'DELETE':
        user_data = jsonify_user(user)
        user.delete()
        return JsonResponse({'deleted': user_data})
    else:
        return method_not_allowed(method, ['GET', 'POST', 'DELETE'])


@custom_ratelimit(key='ip', rate='50/s')
def uuid_route(request: HttpRequest, id_str: str) -> HttpResponse:
    try:
        user_id = uuid.UUID(id_str)
    except ValueError:
        return format_error(id_str, f'Invalid UUID "{id_str}"')
    id_str = str(user_id) # Normalize ID format
    try:
        user = User.objects.get(unique_id=user_id)
    except User.DoesNotExist:
        return error_response(NO_SUCH_USER, {'uuid': id_str}, f'No user exists with the uuid "{id_str}"')
    return get_user_response(user)


@custom_ratelimit(key='ip', rate='50/s')
def username_route(request: HttpRequest, username: str) -> HttpResponse:
    if (error := validate_regex(username, USERNAME_REGEX)) is not None:
        return error
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return error_response(NO_SUCH_USER, {'username': username}, f'No user exists with the username "{username}"')
    return get_user_response(user)


@custom_ratelimit(key='ip', rate='25/s')
@custom_ratelimit(key='post:username', rate='12/m')
def create_user_route(request: HttpRequest) -> HttpResponse:
    if isinstance(info := ensure_json(request), HttpResponse):
        return info
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
    if (error := verify_password_security(password, username)) is not None:
        return error
    password_hash = generate_password_hash(password)
    unique_id = uuid.uuid4()
    user = User(unique_id=unique_id, username=username, password=password_hash)
    try:
        user.save()
    except IntegrityError:
        return error_response(CONFLICT, 'username', 'That username is already in use')
    return JsonResponse(login(user))
