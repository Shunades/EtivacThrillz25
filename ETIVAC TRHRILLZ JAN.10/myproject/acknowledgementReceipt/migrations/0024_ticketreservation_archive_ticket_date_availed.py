# Generated by Django 5.1.2 on 2025-01-10 15:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('acknowledgementReceipt', '0023_ticketreservation_ticket_date_availed'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticketreservation_archive',
            name='ticket_date_availed',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
