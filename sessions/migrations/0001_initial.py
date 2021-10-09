# Generated by Django 3.2.8 on 2021-10-09 15:49

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0004_alter_user_token'),
    ]

    operations = [
        migrations.CreateModel(
            name='Session',
            fields=[
                ('token', models.BinaryField(max_length=32, primary_key=True, serialize=False, unique=True)),
                ('server_address', models.CharField(max_length=259)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='auth.user')),
            ],
        ),
    ]