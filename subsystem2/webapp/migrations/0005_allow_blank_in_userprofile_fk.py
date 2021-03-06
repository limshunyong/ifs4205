# Generated by Django 2.1.1 on 2018-09-30 17:16

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('webapp', '0004_allow_null_in_userprofile_fk'),
    ]

    operations = [
        migrations.AlterField(
            model_name='healthdata',
            name='type',
            field=models.IntegerField(choices=[(2, 'Time-series Record'), (4, 'Document'), (1, 'Image'), (3, 'Moive'), (0, 'BP Record')], default=0),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='patient',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='webapp.Patient'),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='role',
            field=models.IntegerField(choices=[(1, 'therapist'), (0, 'patient'), (2, 'researcher')], default=0),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='therapist',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='webapp.Therapist'),
        ),
    ]
