from typing import TYPE_CHECKING, Any, Optional

from aiohttp import web

from ab_auth.db import User, db

if TYPE_CHECKING:
    from aiohttp.web_routedef import RouteDef, _HandlerType


class AuthServer:
    app: web.Application

    def __init__(self) -> None:
        self.app = web.Application()
        self.app.add_routes([
            web.get('/ping', self.ping_route),
            web.get('/teapot', self.teapot_route),
        ])
        User.create_table()

    async def ping_route(self, request: web.Request):
        return web.Response(text='pong')

    async def teapot_route(self, request: web.Request):
        return web.Response(text="I'm a teapot", status=418)
