import re

from peewee import CharField, Check, Model, SqliteDatabase, UUIDField

DB_PATH = 'db.sqlite3'
USERNAME_REGEX = '[_a-zA-Z][_a-zA-Z0-9]*'
TOKEN_REGEX = '[a-f0-9]{32}'


def regexp(pattern: str, value: str) -> bool:
    if value is None or pattern is None:
        return True
    return re.match(pattern, value) is not None


db = SqliteDatabase(DB_PATH)
db.register_function(regexp)


class BaseModel(Model):
    class Meta:
        database = db


class User(BaseModel):
    unique_id = UUIDField(unique=True, primary_key=True)
    username = CharField(unique=True)
    password = CharField()
    token = CharField(unique=True, null=True, default=None)

    class Meta:
        constraints = [
            Check(f"username REGEXP '{USERNAME_REGEX}'"),
            Check(f"token REGEXP '{TOKEN_REGEX}'"),
        ]
