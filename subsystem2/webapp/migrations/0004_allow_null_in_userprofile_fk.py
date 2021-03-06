# Generated by Django 2.1.1 on 2018-09-30 17:14

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('webapp', '0003_auto_20180930_0447'),
    ]

    operations = [
        migrations.AlterField(
            model_name='healthdata',
            name='type',
            field=models.IntegerField(choices=[(3, 'Moive'), (0, 'BP Record'), (1, 'Image'), (4, 'Document'), (2, 'Time-series Record')], default=0),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='patient',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='webapp.Patient'),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='role',
            field=models.IntegerField(choices=[(0, 'patient'), (1, 'therapist'), (2, 'researcher')], default=0),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='therapist',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='webapp.Therapist'),
        ),
    ]
