import binascii
from datetime import datetime, timezone
from typing import TypedDict, Union

from ab_auth.utils import hash_token
from auth.models import User, _UserDict
from django.db import models
from django.db.models.deletion import CASCADE
from django.db.models.fields import BinaryField, DateTimeField
from django.db.models.fields.related import ForeignKey


class _SessionDict(TypedDict):
    public_key: str
    expiry: str
    user: _UserDict


class Session(models.Model):
    token = BinaryField(max_length=32, primary_key=True, unique=True)
    public_key = BinaryField(max_length=255)
    expiry = DateTimeField()
    user = ForeignKey(User, on_delete=CASCADE)

    @staticmethod
    def by_token(token: Union[str, bytes]) -> 'Session':
        if isinstance(token, str):
            token = binascii.a2b_hex(token)
        session = Session.objects.get(token=hash_token(token))
        if session.expiry <= datetime.now(timezone.utc):
            session.delete()
            raise Session.DoesNotExist('deleted')
        return session

    def dictify(self) -> _SessionDict:
        return {
            'public_key': binascii.b2a_base64(self.public_key).decode('ascii'),
            'expiry': self.expiry.isoformat(),
            'user': self.user.dictify(),
        } # type: ignore
