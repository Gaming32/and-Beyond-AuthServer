from aiohttp.web import run_app

from ab_auth.server import AuthServer
from ab_auth.util import init_logger


def main():
    init_logger('auth_server.log')
    server = AuthServer()
    run_app(server.app, port=8932)
