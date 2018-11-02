# Generated by Django 2.1.1 on 2018-11-02 07:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webapp', '0018_merge_20181102_0654'),
    ]

    operations = [
        migrations.AlterField(
            model_name='healthdata',
            name='data_type',
            field=models.IntegerField(choices=[(0, 'Image'), (1, 'Time Series'), (2, 'Movie'), (3, 'Document'), (4, 'Diagnosis'), (5, 'Blood Pressure Reading'), (6, 'Height Reading'), (7, 'Weight Reading')], default=0),
        ),
    ]
