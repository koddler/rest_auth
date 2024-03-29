# Generated by Django 2.1.1 on 2018-09-15 13:00

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('blank', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Token',
            fields=[
                ('key', models.CharField(max_length=40, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='auth_token', to='blank.User', verbose_name='User')),
            ],
        ),
    ]
