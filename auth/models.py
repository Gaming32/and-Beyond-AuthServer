import binascii
from typing import TypedDict, Union

from ab_auth.utils import hash_token
from django.core.validators import RegexValidator
from django.db import models
from django.db.models.fields import (BinaryField, CharField, DateTimeField,
                                     UUIDField)

from auth import USERNAME_REGEX


class _UserDict(TypedDict):
    uuid: str
    username: str
    join_date: str


class User(models.Model):
    unique_id = UUIDField(primary_key=True, unique=True)
    username = CharField(max_length=16, unique=True, validators=[
        RegexValidator(USERNAME_REGEX),
    ])
    password = CharField(max_length=128)
    join_date = DateTimeField()
    token = BinaryField(max_length=32, unique=True, null=True, default=None)

    @staticmethod
    def by_token(token: Union[str, bytes]) -> 'User':
        if isinstance(token, str):
            token = binascii.a2b_hex(token)
        return User.objects.get(token=hash_token(token))

    def dictify(self) -> _UserDict:
        return {
            'uuid': str(self.unique_id),
            'username': self.username,
            'join_date': self.join_date.isoformat(),
        }
