import random
from datetime import date
from binascii import unhexlify
from django.db import models
from django.contrib.auth.models import User as DjangoUser
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.db.models.signals import m2m_changed, post_save
from django.dispatch import receiver
from django_otp.models import Device

NO_ACCESS = 0
READ_ONLY = 1
WRITE_ONLY = 2
FULL_ACCESS = 3


PERMISSION_SCOPES = (
    (NO_ACCESS, 'No Access'),
    (READ_ONLY, 'Read Only'),
    (WRITE_ONLY, 'Write Only'),
    (FULL_ACCESS, 'Read / Write')
)


IMAGE_DATA = 0
TIME_SERIES_DATA = 1
MOVIE_DATA = 2
DOCUMENT_DATA = 3
DATA_TYPES = (
    (IMAGE_DATA, 'Image'),
    (TIME_SERIES_DATA, 'Time Series'),
    (MOVIE_DATA, 'Movie'),
    (DOCUMENT_DATA, 'Document')
)

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
    image_access = models.IntegerField(choices=PERMISSION_SCOPES, default=1)
    timeseries_access = models.IntegerField(choices=PERMISSION_SCOPES, default=1)
    movie_access = models.IntegerField(choices=PERMISSION_SCOPES, default=1)
    document_access = models.IntegerField(choices=PERMISSION_SCOPES, default=1)

    def __str__(self):
        return '%s is patient of %s %s' % (self.patient.name, self.therapist.designation, self.therapist.name)

    class Meta:
        unique_together = ('patient', 'therapist')

class Researcher(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, blank=False)
    institution = models.CharField(max_length=100, blank=False)

    def __str__(self):
        return 'researcher id: %d, name: %s' % (self.id, self.name)


class Ward(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, blank=False)
    patients = models.ManyToManyField(Patient, blank=True)
    therapists = models.ManyToManyField(Therapist, blank=True)
    image_access = models.IntegerField(choices=PERMISSION_SCOPES, default=1)
    timeseries_access = models.IntegerField(choices=PERMISSION_SCOPES, default=1)
    movie_access = models.IntegerField(choices=PERMISSION_SCOPES, default=1)
    document_access = models.IntegerField(choices=PERMISSION_SCOPES, default=1)

    def __str__(self):
        return 'ward id: %d, name: %s' % (self.id, self.name)

@receiver(m2m_changed, sender=Ward.patients.through)
@receiver(m2m_changed, sender=Ward.therapists.through)
def add_IsAPatientOf(sender, instance, **kwargs):
    action = kwargs.pop('action', None)
    pk_set = kwargs.pop('pk_set', None)
    model = kwargs.pop('model', None)

    # Create IsAPatientOf for every (Therapist, Patient) permutation 
    # in a Ward and apply default Ward Policy
    if action == 'post_add':
        patients = instance.patients.all()
        therapists = instance.therapists.all()
        for p in patients:
            for t in therapists:
                print ('%s <----> %s' % (p.name, t.name))
                is_patient_of = IsAPatientOf.objects.filter(patient=p, therapist=t)[:1]
                if is_patient_of:
                    print('Is patient')
                else:
                    # Create patient relationship and apply ward policy
                    print('Not patient, will create')
                    rs = IsAPatientOf(
                        patient=p, therapist=t, 
                        image_access=instance.image_access,
                        movie_access=instance.movie_access,
                        timeseries_access=instance.timeseries_access,
                        document_access=instance.document_access
                        )
                    rs.save()


class VisitRecord(models.Model):
    id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    therapist = models.ForeignKey(Therapist, on_delete=models.CASCADE)
    date = models.DateTimeField('visit date')

    def __str__(self):
        return 'Visit %d: patient %s, therapist %s, %s' % (self.id, self.patient.name, self.therapist.name, str(self.date))


class HealthData(models.Model):
    id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    therapist = models.ForeignKey(Therapist, on_delete=models.CASCADE, blank=False)
    data_type = models.IntegerField(choices=DATA_TYPES, blank=False, default=0)
    title = models.CharField(max_length=100, blank=False)
    minio_filename = models.CharField(max_length=100, blank=False)
    description = models.CharField(max_length=1000, blank=False)
    date = models.DateTimeField('created on', auto_now_add=True)

    def __str__(self):
        return '%s %s, patient: [%d] %s, therapist: [%d] %s' % (
            self.title,
            [item[1] for item in DATA_TYPES if item[0] == self.data_type],
            self.patient.id, self.patient.name, self.therapist.id, self.therapist.name)

# Update permissions for all of Patient X's therapist
@receiver(post_save, sender=HealthData)
def update_permissions(sender, instance, **kwargs):
    list_patient_therapist = IsAPatientOf.objects.filter(patient=instance.patient)

    for rs in list_patient_therapist:
        existing_record = HealthDataPermission.objects.filter(
            health_data=instance, therapist=rs.therapist, patient=instance.patient
            )[:1]

        if not existing_record:
            p = 0
            if instance.therapist == rs.therapist:
                # Creator of health data should have full access
                p = FULL_ACCESS
            elif instance.data_type == '0':
                p = rs.image_access
            elif instance.data_type == '1':
                p = rs.timeseries_access
            elif instance.data_type == '2':
                p = rs.movie_access
            elif instance.data_type == '3':
                p = rs.document_access

            HealthDataPermission(
                    health_data=instance, patient=instance.patient, 
                    therapist=rs.therapist, 
                    permission=p
                    ).save()

            print ('Applied permissions for %s' % rs.therapist.name)


class HealthDataPermission(models.Model):
    id = models.AutoField(primary_key=True)
    health_data = models.ForeignKey(HealthData, on_delete=models.CASCADE)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    therapist = models.ForeignKey(Therapist, on_delete=models.CASCADE)
    permission = models.IntegerField(choices=PERMISSION_SCOPES, blank=False)
    date = models.DateTimeField('last updated on', auto_now_add=True)
    # TODO: On save, modifiy date

    def __str__(self):
        return '%s <-> %s <-> %s' % (self.health_data, self.patient, self.therapist)

class UserProfile(models.Model):
    """Extends Django's built-in user model"""
    ROLE_PATIENT = 0
    ROLE_THERAPIST = 1
    ROLE_RESEARCHER = 2
    ROLE_CHOICES = (
        (ROLE_PATIENT, 'patient'),
        (ROLE_THERAPIST, 'therapist'),
        (ROLE_RESEARCHER, 'researcher')
    )
    user = models.OneToOneField(DjangoUser, on_delete=models.CASCADE)
    role = models.IntegerField(choices=ROLE_CHOICES, default=ROLE_PATIENT)
    patient = models.ForeignKey(Patient, blank=True, null=True, on_delete=models.CASCADE)
    therapist = models.ForeignKey(Therapist, blank=True, null=True, on_delete=models.CASCADE)


class BLEOTPDevice(Device):
    key = models.CharField(max_length=64, default="")
    otp_challenge = models.CharField(max_length=1024, default="")

    class Meta:
        verbose_name = 'BLE OTP Device'
        verbose_name_plural = 'BLE OTP Devices'

    @property
    def bin_key(self):
        return ed25519.VerifyingKey(self.key.encode('ascii'), encoding='hex')

    def verify_token(self, sig):
        """
        Try to verify ``sig`` against the saved otp_challenge
        """
        try:
            verifying_key = self.bin_key
            verifying_key.verify(sig, self.otp_challenge, encoding="base64")
            print("Signature Passed")
        except ed25519.BadSignatureError:
            print("Signature Failed")
            return False
        return True
    
