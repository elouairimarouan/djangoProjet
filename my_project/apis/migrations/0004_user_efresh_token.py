# Generated by Django 5.1.7 on 2025-03-13 12:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('apis', '0003_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='efresh_token',
            field=models.TextField(blank=True, null=True),
        ),
    ]
