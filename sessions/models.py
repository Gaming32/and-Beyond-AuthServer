import binascii
from typing import TypedDict, Union

from ab_auth.utils import hash_token
from auth.models import User, _UserDict
from django.db import models
from django.db.models.deletion import CASCADE
from django.db.models.fields import BinaryField, CharField
from django.db.models.fields.related import ForeignKey


class _SessionDict(TypedDict):
    server_address: str
    user: _UserDict


class Session(models.Model):
    token = BinaryField(max_length=32, primary_key=True, unique=True)
    server_address = CharField(max_length=259) # address[253] + ":" + port[5]
    user = ForeignKey(User, on_delete=CASCADE)

    @staticmethod
    def by_token(token: Union[str, bytes]) -> 'Session':
        if isinstance(token, str):
            token = binascii.a2b_hex(token)
        return Session.objects.get(token=hash_token(token))

    def dictify(self) -> _SessionDict:
        return {
            'server_address': self.server_address,
            'user': self.user.dictify(),
        } # type: ignore
