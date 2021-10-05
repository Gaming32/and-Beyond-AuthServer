# Generated by Django 3.2.7 on 2021-10-04 20:22

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('unique_id', models.UUIDField(primary_key=True, serialize=False, unique=True)),
                ('username', models.CharField(max_length=16, unique=True, validators=[django.core.validators.RegexValidator('[_a-zA-Z][_a-zA-Z0-9]*')])),
                ('password', models.CharField(max_length=128)),
                ('token', models.CharField(default=None, max_length=32, null=True, unique=True, validators=[django.core.validators.RegexValidator('[a-f0-9]{32}')])),
            ],
        ),
    ]