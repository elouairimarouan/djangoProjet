# Generated by Django 5.1.7 on 2025-03-17 12:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('apis', '0003_rename_ticketmodel_ticket'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ticket',
            name='status',
            field=models.CharField(choices=[('ouvert', 'Ouvert'), ('ferme', 'Fermé'), ('en_cours', 'En cours')], max_length=50),
        ),
    ]
