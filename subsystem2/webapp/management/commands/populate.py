from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from webapp.models import UserProfile, Patient, Therapist, IsAPatientOf, HealthData

import binascii
import os
import random
import string
import time

from datetime import datetime

def random_hex():
    return str(binascii.hexlify(os.urandom(16)), 'ascii')

def random_datetime():
    randate = randomDate("1/1/1970 12:00 AM", "1/1/2010 12:00 AM", random.random())
    return datetime.strptime(randate, '%m/%d/%Y %I:%M %p')

def create_full_patient(username, password, name, nric, sex,
                        date_of_birth, address, contact_number,
                        bloodtype, race):
    newuser = User.objects.create_user(username=username, password=password)
    userprofile = UserProfile.objects.create(user=newuser)
    newuser.userprofile = userprofile
    userprofile.role = UserProfile.ROLE_PATIENT
    newpatient = Patient.objects.create(name=name, nric=nric, sex=sex, date_of_birth=date_of_birth,
                                        address=address, contact_number=contact_number, race=race,
                                        bloodtype=bloodtype)
    userprofile.patient = newpatient
    userprofile.save()
    newpatient.save()
    newuser.save()
    return newuser

def create_random_patient():
    password = random_hex()
    name = "{} {}".format(random.choice(FIRST_NAMES), random.choice(LAST_NAMES))
    username = name.replace(" ", "_") + str(random.randint(0, 99999))
    nric = ("S" + str(random.randint(7, 9)) + "".join(str(random.randint(0, 9)) for i in range(6))
            + random.choice(string.ascii_uppercase))
    sex = random.choice(Patient.SEX)[0]
    date_of_birth = random_datetime()
    address = "25 Random Address St 14"
    contact_number = "91234567"
    bloodtype = random.choice(Patient.BLOOD_TYPES)[0]
    race = random.choice(Patient.RACES)[0]
    return create_full_patient(username, password, name, nric, sex, date_of_birth, address,
            contact_number, bloodtype, race)

def create_full_therapist(username, password, name, designation, department, contact_number):
    newuser = User.objects.create_user(username=username, password=password)
    userprofile = UserProfile.objects.create(user=newuser)
    newuser.userprofile = userprofile
    userprofile.role = UserProfile.ROLE_THERAPIST
    newtherapist = Therapist.objects.create(name=name, designation=designation,
            department=department, contact_number=contact_number)
    userprofile.therapist = newtherapist
    userprofile.save()
    newtherapist.save()
    newuser.save()
    return newuser

def create_random_therapist():
    password = random_hex()
    name = "{} {}".format(random.choice(FIRST_NAMES), random.choice(LAST_NAMES))
    username = name.replace(" ", "_") + str(random.randint(0, 99999))
    designation = random.choice(DESIGNATIONS)
    department = random.choice(DEPARTMENTS)
    contact_number = "91234567"
    return create_full_therapist(username, password, name, designation, department, contact_number)

def assign_patient(therapist, patient):
    newpair = IsAPatientOf.objects.create(therapist=therapist, patient=patient)
    newpair.save()

def add_random_diagnosis(patient, therapist):
    description = random.choice(DIAGNOSES)
    newobj = HealthData.objects.create(patient=patient, therapist=therapist,
            data_type=HealthData.DIAGNOSIS_DATA, title="Diagnosis", description=description)
    newobj.save()
    return newobj

def add_random_blood_pressure(patient, therapist):
    description = "{}/{}".format(random.randint(70, 190), random.randint(40, 100))
    newobj = HealthData.objects.create(patient=patient, therapist=therapist,
            data_type=HealthData.BLOOD_PRESSURE, title="Blood Pressure", description=description)
    newobj.save()
    return newobj

def add_random_height(patient, therapist):
    description = "{}".format(random.randint(120, 180))
    newobj = HealthData.objects.create(patient=patient, therapist=therapist,
            data_type=HealthData.HEIGHT, title="Height", description=description)
    newobj.save()
    return newobj

def add_random_weight(patient, therapist):
    description = "{}".format(random.randint(30, 90))
    newobj = HealthData.objects.create(patient=patient, therapist=therapist,
            data_type=HealthData.WEIGHT, title="Weight", description=description)
    newobj.save()
    return newobj

def populate():
    # Create 3 therapists first.
    for i in range(3):
        create_random_therapist()
    therapists = list(Therapist.objects.all())

    # Create 100 random patients, assigning them to random therapists.
    tp_pairs = []
    for i in range(100):
        current_patient = create_random_patient()
        assigned_therapist = random.choice(therapists)
        assigned_patient = current_patient.userprofile.patient
        assign_patient(assigned_therapist, assigned_patient)
        tp_pairs.append((assigned_patient, assigned_therapist))

    # For each patient, add a random diagnosis, a blood pressure reading, a height, and weight.
    for patient, therapist in tp_pairs:
        add_random_diagnosis(patient, therapist)
        add_random_blood_pressure(patient, therapist)
        add_random_height(patient, therapist)
        add_random_weight(patient, therapist)


class Command(BaseCommand):
    help = 'Closes the specified poll for voting'

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        populate()
        self.stdout.write(self.style.SUCCESS('Successfully populated.'))

FIRST_NAMES = ['Rowena',
 'Belia',
 'Jess',
 'Foster',
 'Amiee',
 'Mariano',
 'Raye',
 'Rina',
 'Arminda',
 'Holli',
 'Maryland',
 'Trey',
 'Efren',
 'Billie',
 'Emerson',
 'Claude',
 'Ja',
 'Caleb',
 'Keeley',
 'Jannette',
 'Rosalva',
 'Robert',
 'Jeana',
 'George',
 'Dominga',
 'Johnie',
 'Wallace',
 'Ema',
 'Crysta',
 'Phil',
 'Ferdinand',
 'Tammi',
 'Sterling',
 'Brooks',
 'Maryann',
 'Billy',
 'Aide',
 'Audrey',
 'Kelle',
 'Helene',
 'Camilla',
 'Archie',
 'Belinda',
 'Linsey',
 'Verla',
 'Gretchen',
 'Christian',
 'Terrell',
 'Monet',
 'Russell']

LAST_NAMES =  ['Peskin',
 'Hulbert',
 'Counter',
 'Yamaguchi',
 'Cayer',
 'Haughey',
 'Adorno',
 'Quellette',
 'Atherton',
 'Perdomo',
 'Deese',
 'Winn',
 'Reigle',
 'Mclellan',
 'Baily',
 'Storey',
 'Kleinschmidt',
 'Port',
 'Stiles',
 'Malpass',
 'Barriere',
 'Baldwin',
 'Keenan',
 'Hasting',
 'Garn',
 'Buendia',
 'Joshua',
 'Soliman',
 'Machen',
 'Ashcroft',
 'Kukowski',
 'Scicchitano',
 'Degraw',
 'Delapp',
 'Nugent',
 'Schantz',
 'Zackery',
 'Neth',
 'Billington',
 'Landey',
 'Stonecipher',
 'Halper',
 'Garey',
 'Swingle',
 'Lumpkin',
 'Adamson',
 'Bernard',
 'Vanallen',
 'Kaler',
 'Nappi']

DEPARTMENTS = ['Dermatology', 'Radiology', 'Neurology', 'Immunology', 'Gynecology', 'Psychiatry']
DESIGNATIONS = ['Doctor', 'Specialist', 'Technician', 'Department Head', 'Trainee']

DIAGNOSES = ['A00.9: Cholera, unspecified',
 'A01.01: Typhoid meningitis',
 'A01.02: Typhoid fever with heart involvement',
 'A01.03: Typhoid pneumonia',
 'A01.04: Typhoid arthritis',
 'A01.05: Typhoid osteomyelitis',
 'A01.1: Paratyphoid fever A',
 'A01.2: Paratyphoid fever B',
 'A01.3: Paratyphoid fever C',
 'A01.4: Paratyphoid fever, unspecified',
 'A02.1: Salmonella sepsis',
 'A02.21: Salmonella meningitis',
 'A02.22: Salmonella pneumonia',
 'A02.23: Salmonella arthritis',
 'A02.24: Salmonella osteomyelitis',
 'A02.25: Salmonella pyelonephritis',
 'A02.8: Other specified salmonella infections',
 'A02.9: Salmonella infection, unspecified',
 'A03.1: Shigellosis due to Shigella flexneri',
 'A03.2: Shigellosis due to Shigella boydii',
 'A03.3: Shigellosis due to Shigella sonnei',
 'A03.8: Other shigellosis',
 'A03.9: Shigellosis, unspecified',
 'A04.2: Enteroinvasive Escherichia coli infection',
 'A04.5: Campylobacter enteritis',
 'A04.6: Enteritis due to Yersinia enterocolitica',
 'A05.1: Botulism food poisoning',
 'A05.4: Foodborne Bacillus cereus intoxication',
 'A05.5: Foodborne Vibrio vulnificus intoxication',
 'A06.1: Chronic intestinal amebiasis',
 'A06.2: Amebic nondysenteric colitis',
 'A06.3: Ameboma of intestine',
 'A06.4: Amebic liver abscess',
 'A06.5: Amebic lung abscess',
 'A06.6: Amebic brain abscess',
 'A06.7: Cutaneous amebiasis',
 'A06.82: Other amebic genitourinary infections',
 'A06.89: Other amebic infections',
 'A06.9: Amebiasis, unspecified',
 'A07.1: Giardiasis [lambliasis]',
 'A07.2: Cryptosporidiosis',
 'A07.3: Isosporiasis',
 'A07.4: Cyclosporiasis',
 'A08.2: Adenoviral enteritis',
 'A08.32: Astrovirus enteritis',
 'A08.39: Other viral enteritis',
 'A08.4: Viral intestinal infection, unspecified',
 'A08.8: Other specified intestinal infections']

# https://stackoverflow.com/questions/553303/generate-a-random-date-between-two-other-dates
def strTimeProp(start, end, format, prop):
    """Get a time at a proportion of a range of two formatted times.

    start and end should be strings specifying times formated in the
    given format (strftime-style), giving an interval [start, end].
    prop specifies how a proportion of the interval to be taken after
    start.  The returned time will be in the specified format.
    """

    stime = time.mktime(time.strptime(start, format))
    etime = time.mktime(time.strptime(end, format))

    ptime = stime + prop * (etime - stime)

    return time.strftime(format, time.localtime(ptime))


def randomDate(start, end, prop):
    return strTimeProp(start, end, '%m/%d/%Y %I:%M %p', prop)

