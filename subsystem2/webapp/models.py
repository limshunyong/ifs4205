import random
import ast
import ed25519
from datetime import date
from binascii import unhexlify
from django.db import models
from django.contrib.auth.models import User as DjangoUser
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.db.models.signals import m2m_changed, post_save
from django.dispatch import receiver
from django_otp.models import Device
from django_otp.plugins.otp_static.models import StaticDevice
from auditlog.registry import auditlog
from ckeditor.fields import RichTextField

def no_future_date(value):
    today = date.today()
    if value > today:
        raise ValidationError('Invalid Date.')


class Patient(models.Model):
    MALE = 'MALE'
    FEMALE = 'FEMALE'
    SEX = (
        (MALE, 'Male'),
        (FEMALE, 'Female')
    )
    O_NEGATIVE = "ON"
    O_POSITIVE = "OP"
    A_NEGATIVE = "AN"
    A_POSITIVE = "AP"
    B_NEGATIVE = "BN"
    B_POSITIVE = "BP"
    AB_NEGATIVE = "ABN"
    AB_POSITIVE = "ABP"
    BLOOD_TYPES = (
        (O_NEGATIVE, "O-"),
        (O_POSITIVE, "O+"),
        (A_NEGATIVE, "A-"),
        (A_POSITIVE, "A+"),
        (B_NEGATIVE, "B-"),
        (B_POSITIVE, "B+"),
        (AB_NEGATIVE, "AB-"),
        (AB_POSITIVE, "AB+"),
    )
    CHINESE = "CHINESE"
    MALAY = "MALAY"
    INDIAN = "INDIAN"
    CAUCASIAN = "CAUCASIAN"
    OTHER = "OTHER"
    RACES = (
        (CHINESE, "Chinese"),
        (MALAY, "Malay"),
        (INDIAN, "Indian"),
        (CAUCASIAN, "Caucasian"),
        (OTHER, "Other"),
    )
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, blank=False)
    nric = models.CharField(max_length=9, blank=False,
                            validators=[RegexValidator('^[STFG]\d{7}[A-Z]$', message="Invalid NRIC")])
    sex = models.CharField(max_length=6, blank=False, choices=SEX, default=MALE)
    address = models.CharField(max_length=100, blank=False)
    contact_number = models.CharField(max_length=12, blank=False)
    date_of_birth = models.DateField('birthday', validators=[no_future_date])
    bloodtype = models.CharField(max_length=4, blank=False, choices=BLOOD_TYPES)
    race = models.CharField(max_length=100, blank=False, choices=RACES)

    # default permission for new (Patient, Therapist) relationship
    read_access = models.BooleanField(default=True)
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
    read_access = models.BooleanField(default=True)

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
                        read_access=instance.read_access,
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
    IMAGE_DATA = 0
    TIME_SERIES_DATA = 1
    MOVIE_DATA = 2
    DOCUMENT_DATA = 3
    DIAGNOSIS_DATA = 4
    BLOOD_PRESSURE = 5
    HEIGHT = 6
    WEIGHT = 7

    DATA_TYPES = (
        (IMAGE_DATA, 'Image'),
        (TIME_SERIES_DATA, 'Time Series'),
        (MOVIE_DATA, 'Movie'),
        (DOCUMENT_DATA, 'Document'),
        (DIAGNOSIS_DATA, 'Diagnosis'),
        (BLOOD_PRESSURE, 'Blood Pressure Reading'),
        (HEIGHT, 'Height Reading'),
        (WEIGHT, 'Weight Reading'),
    )

    id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    therapist = models.ForeignKey(Therapist, on_delete=models.CASCADE, blank=True, null=True)
    data_type = models.IntegerField(choices=DATA_TYPES, blank=False, default=0)
    title = models.CharField(max_length=100, blank=False)
    minio_filename = models.CharField(max_length=100, blank=False, null=True)
    description = RichTextField()
    date = models.DateTimeField('created on', auto_now_add=True)
    file_hash = models.CharField(max_length=100, blank=True, default='')
    signature = models.CharField(max_length=100, blank=True, default='')
    otp_device = models.CharField(max_length=100, blank=True, default='')
    is_verified = models.BooleanField(blank=True, null=True, default=None)

    def __str__(self):
        if self.therapist:
            return '%s %s, patient: [%d] %s, therapist: [%d] %s' % (
                self.title,
                [item[1] for item in self.DATA_TYPES if item[0] == self.data_type],
                self.patient.id, self.patient.name, self.therapist.id, self.therapist.name)
        else:
            return '%s %s, patient: [%d] %s' % (
                self.title,
                [item[1] for item in self.DATA_TYPES if item[0] == self.data_type],
                self.patient.id, self.patient.name)


class HealthDataPermission(models.Model):
    id = models.AutoField(primary_key=True)
    health_data = models.ForeignKey(HealthData, on_delete=models.CASCADE)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    therapist = models.ForeignKey(Therapist, on_delete=models.CASCADE)
    read_access = models.BooleanField(default=True)
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
    researcher = models.ForeignKey(Researcher, blank=True, null=True, on_delete=models.CASCADE)


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
            challenge_byte = bytes(ast.literal_eval(self.otp_challenge))
            print("========= BLEOPTDevice:verify_token() ============")
            print("Using verifying key", str(verifying_key.to_ascii(encoding="hex")))
            print("Using signature:", sig)
            print("Original challenge:", self.otp_challenge)
            print("Challenge string:", challenge_byte)
            print("Encoding: base64")
            verifying_key.verify(sig, challenge_byte, encoding="base64")
            print("Signature Passed")
        except ed25519.BadSignatureError:
            print("Signature Failed")
            return False
        except Exception as e:
            print("Signature Failed", str(e))
            return False
        return True


auditlog.register(Patient)
auditlog.register(Therapist)
auditlog.register(IsAPatientOf)
auditlog.register(Researcher)
auditlog.register(Ward)
auditlog.register(VisitRecord)
auditlog.register(HealthData)
auditlog.register(HealthDataPermission)
auditlog.register(UserProfile)
auditlog.register(BLEOTPDevice)
auditlog.register(StaticDevice)
