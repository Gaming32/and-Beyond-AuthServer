# Generated by Django 3.2.8 on 2021-10-06 19:25

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0002_alter_user_token'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='username',
            field=models.CharField(max_length=16, unique=True, validators=[django.core.validators.RegexValidator('[_a-zA-Z][_a-zA-Z0-9]{0,15}')]),
        ),
    ]
