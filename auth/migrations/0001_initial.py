# Generated by Django 3.0.6 on 2020-05-16 15:17

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('userId', models.CharField(max_length=100)),
                ('accessToken', models.CharField(max_length=2048)),
                ('lastUpdateTime', models.DateTimeField(auto_now=True)),
                ('expiresAt', models.IntegerField()),
                ('refreshToken', models.CharField(max_length=512)),
            ],
        ),
    ]
