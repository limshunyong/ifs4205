# Generated by Django 2.1.1 on 2018-11-04 09:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webapp', '0020_add_hash_and_sig'),
    ]

    operations = [
        migrations.AddField(
            model_name='healthdata',
            name='otp_device',
            field=models.CharField(blank=True, default='', max_length=100),
        ),
    ]