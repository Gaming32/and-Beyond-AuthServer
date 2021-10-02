import re

from peewee import CharField, Check, Model, SqliteDatabase, UUIDField

DB_PATH = 'db.sqlite3'


def regexp(pattern: str, value: str) -> bool:
    return re.match(pattern, value) is not None


db = SqliteDatabase(DB_PATH)
db.register_function(regexp)


class BaseModel(Model):
    class Meta:
        database = db


class User(BaseModel):
    unique_id = UUIDField(unique=True, primary_key=True)
    username = CharField(constraints=[
        Check("username REGEXP '[_a-zA-Z][_a-zA-Z0-9]*'"),
    ])
    password = CharField()
