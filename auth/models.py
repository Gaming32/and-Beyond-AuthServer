from django.core.validators import RegexValidator
from django.db import models
from django.db.models.fields import BinaryField, CharField, UUIDField

from auth import TOKEN_REGEX, USERNAME_REGEX


class User(models.Model):
    unique_id = UUIDField(primary_key=True, unique=True)
    username = CharField(max_length=16, unique=True, validators=[
        RegexValidator(USERNAME_REGEX),
    ])
    password = CharField(max_length=128)
    token = BinaryField(max_length=16, unique=True, null=True, default=None)
