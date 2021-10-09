import secrets

from ab_auth.decorators import custom_ratelimit
from ab_auth.errors import (NO_SUCH_SESSION, UNAUTHORIZED, ensure_json,
                            error_response, format_error, validate_regex)
from ab_auth.utils import get_keys, hash_token, stringify_token
from auth import TOKEN_REGEX
from auth.models import User
from django.http.request import HttpRequest
from django.http.response import HttpResponse, JsonResponse

from sessions.models import Session


def get_session_response(session: Session) -> HttpResponse:
    return JsonResponse(session.dictify())


@custom_ratelimit(key='ip', rate='25/s')
def new_session_route(request: HttpRequest) -> HttpResponse:
    if isinstance(info := get_keys(request, user_token=str, server_address=str), HttpResponse):
        return info
    from_token = info['user_token']
    with_address = info['server_address']
    if len(with_address) > 259:
        return format_error(with_address, 'The server address must be 259 characters or less')
    if (error := validate_regex(from_token, TOKEN_REGEX)) is not None:
        return error
    try:
        user = User.by_token(from_token)
    except User.DoesNotExist:
        return error_response(UNAUTHORIZED, {'token': from_token}, f'No user with the token "{from_token}"')
    session_token = secrets.token_bytes(16)
    session = Session(
        token=hash_token(session_token),
        server_address=with_address,
        user=user,
    )
    session.save()
    return JsonResponse({
        'session_token': stringify_token(session_token),
    } | session.dictify())


@custom_ratelimit(key='ip', rate='25/s')
def retrieve_session_route(request: HttpRequest, session_token: str) -> HttpResponse:
    if (error := validate_regex(session_token, TOKEN_REGEX)) is not None:
        return error
    try:
        session = Session.by_token(session_token)
    except Session.DoesNotExist:
        return error_response(NO_SUCH_SESSION, {'token': session_token}, f'No session exists with the token "{session_token}"')
    session.delete()
    return get_session_response(session)
