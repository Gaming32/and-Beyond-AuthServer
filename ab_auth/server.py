import asyncio
import logging
import secrets
import uuid
from typing import TYPE_CHECKING, Any, Optional

from aiohttp import web
from aiohttp.web_exceptions import HTTPException
from aiohttp.web_middlewares import middleware
from aiohttp.web_response import json_response
from peewee import DoesNotExist, IntegrityError
from werkzeug.security import check_password_hash

from ab_auth.db import TOKEN_REGEX, User, db, regexp
from ab_auth.errors import (FORMAT_ERROR, INTERNAL_ERROR, KEY_ERROR,
                            NO_SUCH_USER, TYPE_ERROR, UNAUTHORIZED,
                            error_repsonse, format_error, type_error,
                            validate_regex)

if TYPE_CHECKING:
    from aiohttp.web_app import _Handler


class AuthServer:
    app: web.Application

    def __init__(self) -> None:
        self.app = web.Application(middlewares=[
            self.middleware,
        ])
        self.app.add_routes([
            web.get('/ping', self.ping_route),
            web.get('/teapot', self.teapot_route),
            web.post('/login', self.login_route),
            web.get('/token/{token}', self.token_route),
            web.get('/uuid/{uuid}', self.uuid_route),
        ])
        User.create_table()

    @middleware
    async def middleware(self, request: web.Request, handler: '_Handler') -> web.StreamResponse:
        try:
            resp = await handler(request)
        except Exception as e:
            if isinstance(e, HTTPException):
                raise
            logging.error('An internal error occurred in %s.%s', handler.__module__, handler.__qualname__, exc_info=e)
            resp = error_repsonse(INTERNAL_ERROR, {
                'type': e.__class__.__qualname__,
                'args': e.args,
            }, f'{e.__class__.__qualname__}: {e}')
        return resp

    async def ping_route(self, request: web.Request) -> web.Response:
        return web.Response(text='pong')

    async def teapot_route(self, request: web.Request) -> web.Response:
        return web.Response(text="I'm a teapot", status=418)

    async def login_route(self, request: web.Request) -> web.Response:
        info: dict[str, Any] = await request.json()
        missing = []
        for key in ('username', 'password'):
            if key not in info:
                missing.append(key)
        if missing:
            return error_repsonse(KEY_ERROR, missing, f'Missing the following login parameters: {", ".join(missing)}')
        username = info.get('username')
        password = info.get('password')
        if not isinstance(username, str):
            return type_error('username', str, type(username))
        if not isinstance(password, str):
            return type_error('password', str, type(password))
        asyncio.sleep(0)
        try:
            user: User = User.get(User.username == username)
        except DoesNotExist:
            return error_repsonse(UNAUTHORIZED, 'username', 'The specified user does not exist')
        await asyncio.sleep(0)
        user_password: str = user.password # type: ignore
        if not check_password_hash(user_password, password):
            return error_repsonse(UNAUTHORIZED, 'password', 'The specified password is incorrect')
        for _ in range(8): # Eight attempts (we should never hit this limit)
            token = secrets.token_hex(16)
            user.token = token # type: ignore
            await asyncio.sleep(0)
            try:
                user.save()
            except IntegrityError:
                continue
            await asyncio.sleep(0)
            break
        else:
            raise RuntimeError('Failed to find unique token (tried 8 times)')
        return json_response({
            'token': token,
            'uuid': str(user.unique_id),
        })

    def get_user_response(self, user: User) -> web.Response:
        return json_response({
            'uuid': str(user.unique_id),
            'username': user.username,
        })

    async def token_route(self, request: web.Request) -> web.Response:
        token = request.match_info['token']
        if (error := validate_regex(token, TOKEN_REGEX)) is not None:
            return error
        await asyncio.sleep(0)
        try:
            user: User = User.get(User.token == token)
        except DoesNotExist:
            return error_repsonse(NO_SUCH_USER, {'token': token}, f'No user with token "{token}"')
        return self.get_user_response(user)

    async def uuid_route(self, request: web.Request) -> web.Response:
        id_str = request.match_info['uuid']
        try:
            id = uuid.UUID(id_str)
        except ValueError:
            return format_error(id_str, f'Invalid UUID "{id_str}"')
        id_str = str(id)
        await asyncio.sleep(0)
        try:
            user: User = User.get(User.unique_id == id)
        except DoesNotExist:
            return error_repsonse(NO_SUCH_USER, {'uuid': id_str}, f'No user with uuid "{id_str}"')
        return self.get_user_response(user)
