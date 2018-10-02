from datetime import date
from django.db import models
from django.contrib.auth.models import User as DjangoUser
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError


def no_future_date(value):
    today = date.today()
    if value > today:
        raise ValidationError('Invalid Date.')


class Patient(models.Model):
    MALE = 'MALE'
    FEMALE = 'FEMALE'
    GENDER = (
        (MALE, 'MALE'),
        (FEMALE, 'FEMALE')
    )
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, blank=False)
    nric = models.CharField(max_length=9, blank=False,
                            validators=[RegexValidator('^[STFG]\d{7}[A-Z]$', message="Invalid NRIC")])
    gender = models.CharField(max_length=6, blank=False, choices=GENDER, default=MALE)
    address = models.CharField(max_length=100, blank=False)
    contact_number = models.CharField(max_length=12, blank=False)
    date_of_birth = models.DateField('birthday', validators=[no_future_date])

    def __str__(self):
        return 'patient id: %d, name: %s' % (self.id, self.name)


class Therapist(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, blank=False)
    designation = models.CharField(max_length=45, blank=False)
    department = models.CharField(max_length=45, blank=False)
    contact_number = models.CharField(max_length=12, blank=False)

    def __str__(self):
        return 'therapist id: %d, name: %s' % (self.id, self.name)


class IsAPatientOf(models.Model):
    id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    therapist = models.ForeignKey(Therapist, on_delete=models.CASCADE)
    has_read_access = models.BooleanField(default=True)
    has_write_access = models.BooleanField(default=True)


class Researcher(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, blank=False)
    institution = models.CharField(max_length=100, blank=False)


class Ward(models.Model):
    POLICY_READ_ONLY = 0
    POLICY_READ_WRITE = 1
    POLICY_CHOICES = {
        (POLICY_READ_ONLY, 'Read Only'),
        (POLICY_READ_WRITE, 'Read/Write')
    }
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, blank=False)
    patients = models.ManyToManyField(Patient)
    therapists = models.ManyToManyField(Therapist)
    policy = models.IntegerField(choices=POLICY_CHOICES, default=POLICY_READ_WRITE)


class VisitRecord(models.Model):
    id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    therapist = models.ForeignKey(Therapist, on_delete=models.CASCADE)
    date = models.DateTimeField('visit date')

    def __str__(self):
        return 'Visit %d: patient %s, therapist %s, %s' % (self.id, self.patient.name, self.therapist.name, str(self.date))


class HealthData(models.Model):
    TYPE_BP = 0
    TYPE_IMAGE = 1
    TYPE_TIMESERIES = 2
    TYPE_MOVIE = 3
    TYPE_DOCUMENT = 4
    TYPE_CHOICES = {
        (TYPE_BP, 'BP Record'),
        (TYPE_IMAGE, 'Image'),
        (TYPE_TIMESERIES, 'Time-series Record'),
        (TYPE_MOVIE, 'Movie'),
        (TYPE_DOCUMENT, 'Document'),
    }
    # TODO add types to categories
    id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    therapist = models.ForeignKey(Therapist, on_delete=models.CASCADE)
    type = models.IntegerField(choices=TYPE_CHOICES, default=TYPE_BP)
    title = models.CharField(max_length=100, blank=False)
    description = models.CharField(max_length=1000, blank=False)
    date = models.DateTimeField('created on')


class HealthDataPermission(models.Model):
    id = models.AutoField(primary_key=True)
    health_data = models.ForeignKey(HealthData, on_delete=models.CASCADE)
    patients = models.ManyToManyField(Patient)
    has_access = models.BooleanField(default=False)
    date = models.DateTimeField('last updated on')

class UserProfile(models.Model):
    """Extends Django's built-in user model"""
    ROLE_PATIENT = 0
    ROLE_THERAPIST = 1
    ROLE_RESEARCHER = 2
    ROLE_CHOICES = {
        (ROLE_PATIENT, 'patient'),
        (ROLE_THERAPIST, 'therapist'),
        (ROLE_RESEARCHER, 'researcher')
    }
    user = models.OneToOneField(DjangoUser, on_delete=models.CASCADE)
    role = models.IntegerField(choices=ROLE_CHOICES, default=ROLE_PATIENT)
    patient = models.ForeignKey(Patient, blank=True, null=True, on_delete=models.CASCADE)
    therapist = models.ForeignKey(Therapist, blank=True, null=True, on_delete=models.CASCADE)
