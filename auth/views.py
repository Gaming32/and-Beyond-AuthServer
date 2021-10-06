import json
import secrets
import uuid

from ab_auth.errors import (KEY_ERROR, METHOD_NOT_ALLOWED, NO_SUCH_USER,
                            UNAUTHORIZED, ensure_json, error_response,
                            format_error, method_not_allowed, type_error,
                            validate_regex)
from django.db.utils import IntegrityError
from django.http.request import HttpRequest
from django.http.response import HttpResponse, JsonResponse
from werkzeug.security import check_password_hash, generate_password_hash

from auth import TOKEN_REGEX
from auth.models import User


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


def logout_route(request: HttpRequest, token: str) -> HttpResponse:
    if (error := validate_regex(token, TOKEN_REGEX)) is not None:
        return error
    try:
        user = User.objects.get(token=token)
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


def profile_route(request: HttpRequest, token: str) -> HttpResponse:
    if (error := validate_regex(token, TOKEN_REGEX)) is not None:
        return error
    try:
        user = User.objects.get(token=token)
    except User.DoesNotExist:
        return error_response(UNAUTHORIZED, {'token': token}, f'No user with the token "{token}"')
    method = 'GET' if request.method is None else request.method
    if method == 'GET':
        return get_user_response(user)
    elif method == 'POST':
        if isinstance(info := ensure_json(request), HttpResponse):
            return info
        changes = 0
        if 'username' in info:
            username = info.pop('username')
            if not isinstance(username, str):
                return type_error('username', str, type(username))
            user.username = username
            changes += 1
        if 'password' in info:
            password = info.pop('password')
            if not isinstance(password, str):
                return type_error('password', str, type(password))
            user.password = generate_password_hash(password)
            changes += 1
        if changes:
            user.save()
        return JsonResponse({'changes': changes})
    elif method == 'DELETE':
        user_data = jsonify_user(user)
        user.delete()
        return JsonResponse({'deleted': user_data})
    else:
        return method_not_allowed(method, ['GET', 'POST', 'DELETE'])


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
