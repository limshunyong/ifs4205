from django.db import models
from django.contrib.auth.models import User as DjangoUser

class Patient(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, blank=True)
    nric = models.CharField(max_length=9, blank=True)
    gender = models.CharField(max_length=6, blank=True)
    address = models.CharField(max_length=100, blank=True)
    contact_number = models.CharField(max_length=12, blank=True)
    date_of_birth = models.DateTimeField('birthday')

    def __str__(self):
        return 'patient id: %d, name: %s' % (self.id, self.name)


class Therapist(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, blank=True)
    designation = models.CharField(max_length=45, blank=True)
    department = models.CharField(max_length=45, blank=True)
    contact_number = models.CharField(max_length=12, blank=True)
    patients = models.ManyToManyField(Patient)

    def __str__(self):
        return 'therapist id: %d, name: %s' % (self.id, self.name)


class Researcher(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, blank=True)
    institution = models.CharField(max_length=100, blank=True)
    contact_number = models.CharField(max_length=12, blank=True)

    def __str__(self):
        return 'researcher id: %d, name: %s' % (self.id, self.name)


class Has_Consent_From_Patient(models.Model):
    id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    researcher = models.ForeignKey(Researcher, on_delete=models.CASCADE)
    date = models.DateTimeField('consent given date')

    def __str__(self):
        return 'Consent %d: patient %s, therapist %s, %s' % (self.id, self.patient.name, self.researcher.name, str(self.date))


class Visit_Record(models.Model):
    id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    therapist = models.ForeignKey(Therapist, on_delete=models.CASCADE)
    date = models.DateTimeField('visit date')

    def __str__(self):
        return 'Visit %d: patient %s, therapist %s, %s' % (self.id, self.patient.name, self.therapist.name, str(self.date))


class Health_Data(models.Model):
    TYPE_BP = 0
    TYPE_XRAY = 1
    TYPE_CHOICES = {
        (TYPE_BP, 'BP Record'),
        (TYPE_XRAY, 'XRAY Record')
    }
    # TODO add types to categories
    id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    type = models.IntegerField(choices=TYPE_CHOICES, default=TYPE_BP)
    title = models.CharField(max_length=100, blank=True)
    content = models.CharField(max_length=1000, blank=True)


class Health_Data_Permission(models.Model):
    id = models.AutoField(primary_key=True)
    health_data = models.ForeignKey(Health_Data, on_delete=models.CASCADE)
    therapist = models.ForeignKey(Therapist, on_delete=models.CASCADE)
    has_access = models.BooleanField(default=False)
    date = models.DateTimeField('permission last update')