# Generated by Django 2.1.1 on 2018-11-02 05:44

import ckeditor.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webapp', '0016_merge_20181102_0056'),
    ]

    operations = [
        migrations.AlterField(
            model_name='healthdata',
            name='description',
            field=ckeditor.fields.RichTextField(),
        ),
        migrations.AlterField(
            model_name='healthdata',
            name='minio_filename',
            field=models.CharField(max_length=100, null=True),
        ),
    ]
