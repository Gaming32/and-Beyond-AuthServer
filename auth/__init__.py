import re

USERNAME_REGEX = '[_a-zA-Z][_a-zA-Z0-9]{0,15}'
_TOKEN_REGEX = '[a-f0-9]{32}'
TOKEN_REGEX = re.compile(_TOKEN_REGEX)
