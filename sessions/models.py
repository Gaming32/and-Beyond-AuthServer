from auth.models import User
from django.db import models
from django.db.models.deletion import CASCADE
from django.db.models.fields import BinaryField, CharField
from django.db.models.fields.related import ForeignKey


class Session(models.Model):
    token = BinaryField(max_length=32, primary_key=True, unique=True)
    server_address = CharField(max_length=259) # address[253] + ":" + port[5]
    user = ForeignKey(User, on_delete=CASCADE)
