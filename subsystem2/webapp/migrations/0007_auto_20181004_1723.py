# Generated by Django 2.1.1 on 2018-10-04 17:23

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import webapp.models


class Migration(migrations.Migration):

    dependencies = [
        ('webapp', '0006_add_therapist_to_healthdata'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='healthdata',
            name='type',
        ),
        migrations.RemoveField(
            model_name='healthdatapermission',
            name='has_access',
        ),
        migrations.RemoveField(
            model_name='healthdatapermission',
            name='patients',
        ),
        migrations.RemoveField(
            model_name='ward',
            name='policy',
        ),
        migrations.AddField(
            model_name='healthdata',
            name='data_type',
            field=models.IntegerField(choices=[(0, 'Image'), (1, 'Time Series'), (2, 'Movie'), (3, 'Document')], default=0),
        ),
        migrations.AddField(
            model_name='healthdatapermission',
            name='patient',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='webapp.Patient'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='healthdatapermission',
            name='permission',
            field=models.IntegerField(choices=[(0, 'No Access'), (1, 'Read'), (2, 'Write'), (3, 'Read / Write')], default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='healthdatapermission',
            name='therapist',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='webapp.Therapist'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='isapatientof',
            name='document_access',
            field=models.IntegerField(choices=[(0, 'No Access'), (1, 'Read'), (2, 'Write'), (3, 'Read / Write')], default=1),
        ),
        migrations.AddField(
            model_name='isapatientof',
            name='image_access',
            field=models.IntegerField(choices=[(0, 'No Access'), (1, 'Read'), (2, 'Write'), (3, 'Read / Write')], default=1),
        ),
        migrations.AddField(
            model_name='isapatientof',
            name='movie_access',
            field=models.IntegerField(choices=[(0, 'No Access'), (1, 'Read'), (2, 'Write'), (3, 'Read / Write')], default=1),
        ),
        migrations.AddField(
            model_name='isapatientof',
            name='timeseries_access',
            field=models.IntegerField(choices=[(0, 'No Access'), (1, 'Read'), (2, 'Write'), (3, 'Read / Write')], default=1),
        ),
        migrations.AddField(
            model_name='ward',
            name='document_access',
            field=models.IntegerField(choices=[(0, 'No Access'), (1, 'Read'), (2, 'Write'), (3, 'Read / Write')], default=1),
        ),
        migrations.AddField(
            model_name='ward',
            name='image_access',
            field=models.IntegerField(choices=[(0, 'No Access'), (1, 'Read'), (2, 'Write'), (3, 'Read / Write')], default=1),
        ),
        migrations.AddField(
            model_name='ward',
            name='movie_access',
            field=models.IntegerField(choices=[(0, 'No Access'), (1, 'Read'), (2, 'Write'), (3, 'Read / Write')], default=1),
        ),
        migrations.AddField(
            model_name='ward',
            name='timeseries_access',
            field=models.IntegerField(choices=[(0, 'No Access'), (1, 'Read'), (2, 'Write'), (3, 'Read / Write')], default=1),
        ),
        migrations.AlterField(
            model_name='healthdata',
            name='date',
            field=models.DateTimeField(auto_now_add=True, verbose_name='created on'),
        ),
        migrations.AlterField(
            model_name='healthdata',
            name='description',
            field=models.CharField(max_length=1000),
        ),
        migrations.AlterField(
            model_name='healthdata',
            name='therapist',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='webapp.Therapist'),
        ),
        migrations.AlterField(
            model_name='healthdata',
            name='title',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='healthdatapermission',
            name='date',
            field=models.DateTimeField(auto_now_add=True, verbose_name='last updated on'),
        ),
        migrations.AlterField(
            model_name='patient',
            name='address',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='patient',
            name='contact_number',
            field=models.CharField(max_length=12),
        ),
        migrations.AlterField(
            model_name='patient',
            name='date_of_birth',
            field=models.DateField(validators=[webapp.models.no_future_date], verbose_name='birthday'),
        ),
        migrations.AlterField(
            model_name='patient',
            name='gender',
            field=models.CharField(choices=[('MALE', 'MALE'), ('FEMALE', 'FEMALE')], default='MALE', max_length=6),
        ),
        migrations.AlterField(
            model_name='patient',
            name='name',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='patient',
            name='nric',
            field=models.CharField(max_length=9, validators=[django.core.validators.RegexValidator('^[STFG]\\d{7}[A-Z]$', message='Invalid NRIC')]),
        ),
        migrations.AlterField(
            model_name='researcher',
            name='institution',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='researcher',
            name='name',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='therapist',
            name='contact_number',
            field=models.CharField(max_length=12),
        ),
        migrations.AlterField(
            model_name='therapist',
            name='department',
            field=models.CharField(max_length=45),
        ),
        migrations.AlterField(
            model_name='therapist',
            name='designation',
            field=models.CharField(max_length=45),
        ),
        migrations.AlterField(
            model_name='therapist',
            name='name',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='userprofile',
            name='role',
            field=models.IntegerField(choices=[(0, 'patient'), (1, 'therapist'), (2, 'researcher')], default=0),
        ),
        migrations.AlterField(
            model_name='ward',
            name='name',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='ward',
            name='patients',
            field=models.ManyToManyField(blank=True, to='webapp.Patient'),
        ),
        migrations.AlterField(
            model_name='ward',
            name='therapists',
            field=models.ManyToManyField(blank=True, to='webapp.Therapist'),
        ),
        migrations.RemoveField(
            model_name='isapatientof',
            name='has_read_access',
        ),
        migrations.RemoveField(
            model_name='isapatientof',
            name='has_write_access',
        ),
        migrations.AlterUniqueTogether(
            name='isapatientof',
            unique_together={('patient', 'therapist')},
        ),
    ]
