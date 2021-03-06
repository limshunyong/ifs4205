# Generated by Django 2.1.1 on 2018-09-29 17:49

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Has_Consent_From_Patient',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('date', models.DateTimeField(verbose_name='consent given date')),
            ],
        ),
        migrations.CreateModel(
            name='Health_Data',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('type', models.IntegerField(choices=[(1, 'XRAY Record'), (0, 'BP Record')], default=0)),
                ('title', models.CharField(blank=True, max_length=100)),
                ('content', models.CharField(blank=True, max_length=1000)),
            ],
        ),
        migrations.CreateModel(
            name='Health_Data_Permission',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('has_access', models.BooleanField(default=False)),
                ('date', models.DateTimeField(verbose_name='permission last update')),
                ('health_data', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='webapp.Health_Data')),
            ],
        ),
        migrations.CreateModel(
            name='Patient',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(blank=True, max_length=100)),
                ('nric', models.CharField(blank=True, max_length=9)),
                ('gender', models.CharField(blank=True, max_length=6)),
                ('address', models.CharField(blank=True, max_length=100)),
                ('contact_number', models.CharField(blank=True, max_length=12)),
                ('date_of_birth', models.DateTimeField(verbose_name='birthday')),
            ],
        ),
        migrations.CreateModel(
            name='Researcher',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(blank=True, max_length=100)),
                ('institution', models.CharField(blank=True, max_length=100)),
                ('contact_number', models.CharField(blank=True, max_length=12)),
            ],
        ),
        migrations.CreateModel(
            name='Therapist',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(blank=True, max_length=100)),
                ('designation', models.CharField(blank=True, max_length=45)),
                ('department', models.CharField(blank=True, max_length=45)),
                ('contact_number', models.CharField(blank=True, max_length=12)),
                ('patients', models.ManyToManyField(to='webapp.Patient')),
            ],
        ),
        migrations.CreateModel(
            name='Visit_Record',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('date', models.DateTimeField(verbose_name='visit date')),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='webapp.Patient')),
                ('therapist', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='webapp.Therapist')),
            ],
        ),
        migrations.AddField(
            model_name='health_data_permission',
            name='therapist',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='webapp.Therapist'),
        ),
        migrations.AddField(
            model_name='health_data',
            name='patient',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='webapp.Patient'),
        ),
        migrations.AddField(
            model_name='has_consent_from_patient',
            name='patient',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='webapp.Patient'),
        ),
        migrations.AddField(
            model_name='has_consent_from_patient',
            name='researcher',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='webapp.Researcher'),
        ),
    ]
