import json
import ast
import csv
import io
import codecs
import io
import time
import urllib.parse
import random
import re
import os.path
from itertools import zip_longest
from datetime import datetime
import pytz
import ed25519
import magic
import requests
import base64
from urllib3.exceptions import MaxRetryError
from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponseForbidden, Http404, HttpResponseRedirect, HttpResponse, JsonResponse
from django.utils import timezone
from django.utils.encoding import escape_uri_path
from django.views import View
from django.db import transaction
from django.urls import reverse
from django.db.models import Count, Sum, Q
from django.utils.decorators import method_decorator
from django.core.paginator import Paginator
from django.utils.crypto import get_random_string
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
import django_otp as otp
from django_otp.decorators import otp_required
from django_otp.plugins.otp_static.models import StaticDevice
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings


from .models import Patient, Therapist, IsAPatientOf, Researcher, Ward, VisitRecord, HealthData, \
    HealthDataPermission, UserProfile, BLEOTPDevice
from .forms import PermissionForm, UploadDataForm, UploadPatientDataForm
from .object import put_object, get_object, download_object
from django.contrib import messages
from minio.error import ResponseError

from basic_mondrian.anonymize import Anonymizer
from basic_mondrian.tree import Tree

from dateutil.relativedelta import relativedelta
from datetime import datetime
from statistics import mean

TOKEN = os.environ.get('SEC_TOKEN')
TOKEN_UPLOAD = os.environ.get('SEC_TOKEN_UPLOAD')

MAPPING = {
    'image/jpg': HealthData.IMAGE_DATA,
    'image/jpeg': HealthData.IMAGE_DATA,
    'image/png': HealthData.IMAGE_DATA,
    'video/mp4': HealthData.MOVIE_DATA,
    'video/mpg': HealthData.MOVIE_DATA,
    'application/msword': HealthData.DOCUMENT_DATA,
    'text/plain': HealthData.DOCUMENT_DATA
}

FILE_TYPES = {
    "Image": [
        { "mime": "image/jpeg", "ext": ".jpg" },
        { "mime": "image/png", "ext": ".png" }
    ],
    "Movie": [
        { "mime": "video/mp4", "ext": ".mp4" },
        { "mime": "video/mpg", "ext": ".mpg" }
    ],
    "Document": [
        { "mime": "application/msword", "ext": ".doc" }
    ],
    "Time Series": [
        { "mime": "text/plain", "ext": ".csv" }
    ]
}

MAX_IMAGE_SIZE = 10
MAX_TIME_SERIES_SIZE = 0.1
MAX_MOVIE_SIZE = 100
MAX_DOCUMENT_SIZE = 10

MAPSIZE = {
    HealthData.IMAGE_DATA: MAX_IMAGE_SIZE,
    HealthData.TIME_SERIES_DATA: MAX_TIME_SERIES_SIZE,
    HealthData.MOVIE_DATA: MAX_MOVIE_SIZE,
    HealthData.DOCUMENT_DATA: MAX_DOCUMENT_SIZE
}

# Validation for Time Series Data
MAX_ALLOWED_CSV_LINES = 100
MAX_ALLOWED_CSV_COLUMNS = 11


# user_passes_test helper functions
def is_therapist(user):
    try:
        return user.userprofile.role == UserProfile.ROLE_THERAPIST
    except:
        return False


# user_passes_test helper functions
def is_patient(user):
    try:
        return user.userprofile.role == UserProfile.ROLE_PATIENT
    except:
        return False

# user_passes_test helper functions
def is_researcher(user):
    try:
        return user.userprofile.role == UserProfile.ROLE_RESEARCHER
    except:
        return False

def login_view(request, next=None):
    next_url = request.GET.get('next')
    print(request.user, request.user.is_authenticated, request.user.is_verified())
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            if next_url is not None:
                return redirect(reverse('select_otp'), next=next_url)
            else:
                return redirect(reverse('select_otp'))
        else:
            messages.add_message(request, messages.ERROR, "Invalid username or password.")
            return render(request, "login.html")

    if (request.user.is_authenticated) and (not request.user.is_verified()):
        redirect(reverse('select_otp'))

    return render(request, "login.html")


def otp_view(request, next=None):
    next_url = request.GET.get('next')
    print(request.user, request.user.is_authenticated, request.user.is_verified())
    if not request.user.is_authenticated:
        return redirect(reverse('login'))

    context = {
        'devices': [x for x in otp.devices_for_user(request.user) if isinstance(x, BLEOTPDevice)]
    }
    return render(request, "otp.html", context)


def otp_static_view(request, next=None):
    next_url = request.GET.get('next')
    print(request.user, request.user.is_authenticated, request.user.is_verified())
    if not request.user.is_authenticated:
        return redirect(reverse('login'))

    context = {
        'devices': [x for x in otp.devices_for_user(request.user) if isinstance(x, StaticDevice)]
    }
    return render(request, "otp_static.html", context)


def verify_ble_otp(request):
    if not request.user.is_authenticated:
        return redirect(reverse('login'))

    if request.method == 'POST':
        token = request.POST['otp_token']
        device_id = request.POST['otp_device']
        device = otp.models.Device.from_persistent_id(device_id)
        print(str(type(device)), isinstance(device, otp.plugins.otp_static.models.StaticDevice))
        if token and device:
            if isinstance(device, BLEOTPDevice) and device.verify_token(token):
                print("========ble ok")
                otp.login(request, device)
                if request.user.userprofile.role == UserProfile.ROLE_PATIENT:
                    return redirect(reverse('patient_index'))
                elif request.user.userprofile.role == UserProfile.ROLE_THERAPIST:
                    return redirect(reverse('therapist_index'))
                elif request.user.userprofile.role == UserProfile.ROLE_RESEARCHER:
                    return redirect(reverse('researcher_index'))
            else:
                messages.add_message(request, messages.ERROR, "Invalid token.")
                return redirect(reverse('select_otp'))
        else:
            messages.add_message(request, messages.ERROR, "token or device_id not set.")
            return redirect(reverse('select_otp'))
    return redirect(reverse('select_otp'))


def verify_static_otp(request):
    if not request.user.is_authenticated:
        return redirect(reverse('login'))

    if request.method == 'POST':
        token = request.POST['otp_token']
        device_id = request.POST['otp_device']
        device = otp.models.Device.from_persistent_id(device_id)
        print(str(type(device)), isinstance(device, otp.plugins.otp_static.models.StaticDevice))
        if token and device:
            if isinstance(device, StaticDevice) and otp.match_token(request.user, token):
                print("========static ok")
                # Verify static token
                otp.login(request, device)
                if request.user.userprofile.role == UserProfile.ROLE_PATIENT:
                    return redirect(reverse('patient_index'))
                elif request.user.userprofile.role == UserProfile.ROLE_THERAPIST:
                    return redirect(reverse('therapist_index'))
                elif request.user.userprofile.role == UserProfile.ROLE_RESEARCHER:
                    return redirect(reverse('researcher_index'))
            else:
                messages.add_message(request, messages.ERROR, "Invalid token.")
                return redirect(reverse('select_static_otp'))
        else:
            messages.add_message(request, messages.ERROR, "token or device_id not set.")
            return redirect(reverse('select_static_otp'))
    return redirect(reverse('select_static_otp'))



def otp_ble_view(request):
    device_id = request.POST['device_id']
    device = otp.models.Device.from_persistent_id(device_id)
    error_msg = None
    if not request.user.is_authenticated:
        error_msg = 'not_authenticated'
    if device_id is None or device is None:
        error_msg = 'otp_device_does_not_exist'

    msg_to_be_signed = generate_challenge()
    print(device_id, device)
    device.otp_challenge = str(msg_to_be_signed)
    device.save()

    #TODO remove test code below
    # challenge_byte = bytes(msg_to_be_signed)
    # place the private key array here
    # a = [];
    # signing_key_str = ''.join(["{:02x}".format(x) for x in a])
    # print('verifying_key', device.key)
    # print('signing_key', signing_key_str)
    # verifying_key = ed25519.VerifyingKey(device.key.encode('ascii'), encoding='hex')
    # signing_key = ed25519.SigningKey(signing_key_str.encode('ascii'), encoding="hex")
    # sig = signing_key.sign(challenge_byte, encoding="base64")
    # print('challenge', challenge_byte)
    # print('signature', sig)
    # verifying_key.verify(sig, challenge_byte, encoding="base64")

    context = {
        'error_msg': error_msg,
        'challenge': msg_to_be_signed,
        'device_id': request.POST['device_id']
    }
    return render(request, 'otp_ble.html', context)


def generate_challenge():
    """returns a 160-bit challenge, encode in base64 format"""
    split_hex = lambda x: [x[i:i+8] for i in range(0, len(x), 8)]
    rand_bits = random.getrandbits(160)
    bin_array = split_hex(bin(rand_bits)[2:])
    #challenge = base64.b64encode(''.join([chr(int(x, 2)) for x in bin_array]).encode())
    print('rand_bits', rand_bits)
    print('split_hex', bin_array)
    print('bin', [int(x, 2) for x in bin_array])
    return [int(x, 2) for x in bin_array]


def logout_view(request):
    logout(request)
    return redirect("/web/account/login/")


# TODO only admin can view
def keygen_view(request):
    split_hex = lambda x: [x[i:i+2] for i in range(0, len(x), 2)]
    private_key, public_key = ed25519.create_keypair()
    private_key_str = private_key.to_ascii(encoding="hex").decode('ascii')
    public_key_str = public_key.to_ascii(encoding="hex").decode('ascii')
    print(private_key_str)
    print(split_hex(private_key_str))
    arr_uint8 = [int(x, 16) for x in split_hex(private_key_str)]
    print(arr_uint8)
    private_key_arr = '{' + ','.join([str(x) for x in arr_uint8]) + '}'
    context = {
        'public_key': public_key_str,
        'private_key': private_key_arr
    }
    return render(request, 'keygen.html', context)


@otp_required
@user_passes_test(is_patient)
def patient_index_view(request, type=None):
    r = request.user.userprofile.role

    # TODO add pagination
    patient = request.user.userprofile.patient
    if type:
        records = HealthData.objects.filter(patient=patient, data_type=type)
    else:
        records = HealthData.objects.filter(patient=patient)

    context = {
        'user': request.user,
        'type': type,
        'records': records
    }
    return render(request, 'patient_index.html', context)


@otp_required
@user_passes_test(is_therapist)
def therapist_index_view(request, patient_id=None):
    therapist = request.user.userprofile.therapist
    therapist_patients = Patient.objects.filter(isapatientof__therapist=therapist)
    selected_patient = get_object_or_404(Patient, isapatientof__therapist=therapist,
                                         isapatientof__patient_id=patient_id) if patient_id else None
    context = {
        'therapist_patients': therapist_patients,
        'selected_patient': selected_patient
    }
    return render(request, 'therapist_index.html', context)


@otp_required
@user_passes_test(is_therapist)
def patient_detail_view(request, patient_id):
    therapist = request.user.userprofile.therapist
    therapist_patients = Patient.objects.filter(isapatientof__therapist=therapist)
    selected_patient = get_object_or_404(Patient, isapatientof__therapist=therapist,
                                         isapatientof__patient_id=patient_id)
    context = {
        'therapist_patients': therapist_patients,
        'selected_patient': selected_patient
    }
    return render(request, 'patient_detail.html', context)


@otp_required
@user_passes_test(is_therapist)
def therapist_list_patient_record_view(request, patient_id=None, type=None):
    therapist = request.user.userprofile.therapist
    # Ensure that there is a Therapist <--> Patient relationship
    get_object_or_404(IsAPatientOf, therapist=therapist, patient_id=patient_id)

    if type:
        records = HealthData.objects.filter(patient_id=patient_id, data_type=type)
    else:
        records = HealthData.objects.filter(patient_id=patient_id)
    # verify signature
    for r in records:
        if r.otp_device != '':
            device = otp.models.Device.from_persistent_id(r.otp_device)
            if device is not None:
                verifying_key = device.bin_key
                try:
                    verifying_key.verify(r.signature, r.file_hash.encode('ascii'), encoding="base64")
                    r.is_verified = True
                except:
                    r.is_verified = False
            else:
                r.is_verified = None
        else:
            r.is_verified = None
        r.save()
        

    therapist_patients = Patient.objects.filter(isapatientof__therapist=therapist)
    selected_patient = Patient.objects.get(id=patient_id)
    context = {
        'therapist_patients': therapist_patients,
        'records': records,
        'selected_patient': selected_patient
    }
    return render(request, 'therapist_index.html', context)


@otp_required
def patient_record_view(request, record_id):
    # print(record_id)

    context = {
        'user': request.user,
        'record_id': record_id
    }

    user = request.user.userprofile
    if user.role == UserProfile.ROLE_PATIENT:
        health_data = get_object_or_404(HealthData, Q(pk=record_id, patient=user.patient))
    elif user.role == UserProfile.ROLE_THERAPIST:
        therapist = request.user.userprofile.therapist;
        health_data = get_object_or_404(HealthData, pk=record_id)
        # TODO refactor below as a function

        # Check if therapist has permissions
        # 1. Check explicit permissions
        try:
            p = HealthDataPermission.objects.get(therapist=therapist, health_data_id=record_id)
            if p.read_access == False:
                messages.add_message(request, messages.ERROR, "You do not have the permission to view this record.")
                return render(request, 'therapist_error.html', context)
        except HealthDataPermission.DoesNotExist:
            # 2. Check default permissions
            p = get_object_or_404(IsAPatientOf, therapist=therapist, patient=health_data.patient)
            if p.read_access == False:
                messages.add_message(request, messages.ERROR, "You do not have the permission to view this record.")
                return render(request, 'therapist_error.html', context)
        # for sidebar
        context['therapist_patients'] = Patient.objects.filter(isapatientof__therapist=therapist)

    print("data type: ", health_data.data_type)

    if health_data.minio_filename:
        obj_link = get_object(health_data.minio_filename, 10)
        print("obj link:" , obj_link)

    context['description'] = health_data.description
    if health_data.data_type == HealthData.IMAGE_DATA:
        context['obj_link'] = resolve_minio_link(obj_link)
        return render(request, 'patient_record_image.html', context)
    elif health_data.data_type == HealthData.MOVIE_DATA:
        context['obj_link'] = resolve_minio_link(obj_link)
        return render(request, 'patient_record_movie.html', context)
    elif health_data.data_type == HealthData.TIME_SERIES_DATA:
        obj_contents_stream = download_object(health_data.minio_filename)

        obj_contents = ""
        for data in obj_contents_stream.stream(32*1024):
            obj_contents += data.decode()

        transposed_csv_contents = zip_longest(*csv.reader(obj_contents.splitlines(), delimiter=','))

        chart_lines = []
        for idx, row in enumerate(transposed_csv_contents):
            if idx == 0:
                chart_labels = list(row)
            else:
                r, g, b = (random.randint(0,255), random.randint(0, 255), random.randint(0, 255))
                chart_lines.append({
                    "label": "Column %s" % idx,
                    "backgroundColor": "rgb(%s,%s,%s)" % (r, g, b),
                    "borderColor": "rgb(%s,%s,%s)" % (r, g, b),
                    "data": list(row),
                    "fill": False
                })

        chart_data = {
                          "labels": chart_labels,
                          "datasets": chart_lines
                      }
        context['chart_data'] = json.dumps(chart_data)
        return render(request, 'patient_record_bp.html', context)
    elif health_data.data_type == HealthData.DOCUMENT_DATA or health_data.data_type == HealthData.HEIGHT or health_data.data_type == HealthData.WEIGHT or health_data.data_type == HealthData.DIAGNOSIS_DATA or health_data.data_type==HealthData.BLOOD_PRESSURE:
        return render(request, 'patient_record_document.html', context)
    else:
        return HttpResponseForbidden()


def resolve_minio_link(link):
    MINIO_EXTERNAL_URL = getattr(settings, "MINIO_EXTERNAL_URL", None)
    return link.replace("http://minio:9000/", MINIO_EXTERNAL_URL)


@otp_required
@user_passes_test(is_therapist)
def therapist_upload_data(request):
    therapist = request.user.userprofile.therapist

    if request.method == 'GET':
        context = {
            'user': request.user,
            'upload_data_form': UploadDataForm(therapist_id=therapist.pk),
            'device_id': next(otp.devices_for_user(request.user)).persistent_id
        }
        return render(request, 'therapist_upload.html', context)

    elif request.method == 'POST':
        form = UploadDataForm(request.POST, request.FILES, therapist_id=therapist.pk)
        file_hash = request.POST['file_hash']
        hash_signature = request.POST['hash_signature']
        otp_device = request.POST['otp_device'] if 'otp_device' in request.POST else ''
        print('file hash', file_hash)
        print('signature', hash_signature)
        print('otp_device', otp_device)

        if form.is_valid():
            file = form.cleaned_data['file']
            patient_id = form.cleaned_data['patient'].id
            data_type = form.cleaned_data['data_type']

            if file:
                _, file_extension = os.path.splitext(file.name)
                if file_extension:
                    file_extension = file_extension.lower()

                mime = magic.from_buffer(file.read(), mime=True).lower()
                file.seek(0)

                data_type_name = [x for x in HealthData.DATA_TYPES if int(data_type) in x][0][1]

                wrong_type = True
                for allowed_types in FILE_TYPES.get(data_type_name):
                    if file_extension == allowed_types.get('ext') and mime == allowed_types.get('mime'):
                        wrong_type = False
                        break

                context = {
                            'user': request.user,
                            'upload_data_form': form
                        }

                if wrong_type:
                    messages.error(request, 'Invalid file type. File type should be: '
                                            'IMAGE: \'.jpg\', \'.png\' '
                                            'TIME SERIES: \'.csv\' '
                                            'VIDEO: \'.mp4\', \'.mpg\' '
                                            'DOCUMENT: \'.doc\'')
                    return render(request, 'therapist_upload.html', context)


                size = MAPSIZE[int(data_type)]
                max_size = size*1024*1024

                if file.size > max_size:
                    messages.error(request, 'The maximum file size that can be uploaded is ' + str(size) + ' MB')

                    context = {
                        'user': request.user,
                        'upload_data_form': form
                    }

                    return render(request, 'therapist_upload.html', context)

                if int(data_type) == HealthData.TIME_SERIES_DATA:
                    # Validation for Time Series Data
                    for idx, row in enumerate(csv.reader(file.read().decode().splitlines(), delimiter=',')):
                        if idx >= MAX_ALLOWED_CSV_LINES:
                            messages.error(request, "Exceeded %s allowed lines in CSV" % MAX_ALLOWED_CSV_LINES)
                            return render(request, 'therapist_upload.html', context)
                        for idx, col in enumerate(row):
                            if idx >= MAX_ALLOWED_CSV_COLUMNS:
                                messages.error(request, "Exceeded %s allowed columns in CSV" % MAX_ALLOWED_CSV_COLUMNS)
                                return render(request, 'therapist_upload.html', context)
                            if re.match("^-{0,1}((\d+)|(\d+\.\d+))$", col) == None:
                                messages.error(request, "Invalid characters in CSV file, only numbers allowed")
                                return render(request, 'therapist_upload.html', context)
                    file.seek(0)

                minio_filename = '%s_%s%s' % (patient_id, time.time(), file_extension)
                try:
                    put_object(minio_filename, file.file, file.size)
                except ResponseError as err:
                    print(err)
                    messages.error(request, 'ResponseError: file upload failed')
                    context = {
                        'user': request.user,
                        'upload_data_form': form
                    }
                    return render(request, 'therapist_upload.html', context)
                except MaxRetryError as err:
                    print(err)
                    messages.error(request, 'MaxRetryError: file upload failed')
                    context = {
                        'user': request.user,
                        'upload_data_form': form
                    }
                    return render(request, 'therapist_upload.html', context)

            # No files for Document / Height / Weight / Blood Pressure
            else:
                minio_filename = None
            patient_data = HealthData(
                patient=Patient.objects.get(pk=patient_id),
                therapist=therapist,
                data_type=data_type,
                title=file.name if file else str(datetime.now().strftime("%Y-%m-%d %H:%M")),
                description=form.cleaned_data['description'],
                minio_filename=minio_filename,
                file_hash=file_hash,
                signature=hash_signature,
                otp_device=otp_device
            )

            patient_data.save()

            return redirect(reverse(patient_record_view, kwargs={'record_id': patient_data.id}))
        else:
            context = {
                'upload_data_form': form
            }
            return render(request, 'therapist_upload.html', context)


@otp_required
@user_passes_test(is_patient)
def patient_upload_data(request):
    patient = request.user.userprofile.patient

    if request.method == 'GET':
        context = {
            'user': request.user,
            'upload_data_form': UploadPatientDataForm(),
            'device_id': next(otp.devices_for_user(request.user)).persistent_id
        }
        return render(request, 'patient_upload.html', context)

    elif request.method == 'POST':
        form = UploadPatientDataForm(request.POST, request.FILES)
        file_hash = request.POST['file_hash']
        hash_signature = request.POST['hash_signature']
        otp_device = request.POST['otp_device'] if 'otp_device' in request.POST else ''
        print('file hash', file_hash)
        print('signature', hash_signature)
        print('otp_device', otp_device)

        if form.is_valid():
            file = form.cleaned_data['file']
            patient_id = patient.id
            data_type = form.cleaned_data['data_type']

            if file:
                _, file_extension = os.path.splitext(file.name)
                if file_extension:
                    file_extension = file_extension.lower()

                mime = magic.from_buffer(file.read(), mime=True).lower()
                file.seek(0)
                data_type_name = [x for x in HealthData.DATA_TYPES if int(data_type) in x][0][1]

                wrong_type = True
                for allowed_types in FILE_TYPES.get(data_type_name):
                    if file_extension == allowed_types.get('ext') and mime == allowed_types.get('mime'):
                        wrong_type = False
                        break

                context = {
                        'user': request.user,
                        'upload_data_form': UploadPatientDataForm()
                    }

                if wrong_type:
                    messages.error(request, 'Invalid file type. File type should be: '
                                            'IMAGE: \'.jpg\', \'.png\' '
                                            'TIME SERIES: \'.csv\' '
                                            'VIDEO: \'.mp4\', \'.mpg\' '
                                            'DOCUMENT: \'.doc\'')
                    return render(request, 'patient_upload.html', context)


                size = MAPSIZE[int(data_type)]
                max_size = size*1024*1024

                if file.size > max_size:
                    messages.error(request, 'The maximum file size that can be uploaded is ' + str(size) + ' MB')

                    context = {
                        'user': request.user,
                        'upload_data_form': UploadPatientDataForm()
                    }

                    return render(request, 'patient_upload.html', context)

                 # Validation for Time Series Data
                if int(data_type) == HealthData.TIME_SERIES_DATA:
                    for idx, row in enumerate(csv.reader(file.read().decode().splitlines(), delimiter=',')):
                        if idx >= MAX_ALLOWED_CSV_LINES:
                            messages.error(request, "Exceeded %s allowed lines in CSV" % MAX_ALLOWED_CSV_LINES)
                            return render(request, 'patient_upload.html', context)
                        for idx, col in enumerate(row):
                            if idx >= MAX_ALLOWED_CSV_COLUMNS:
                                messages.error(request, "Exceeded %s allowed columns in CSV" % MAX_ALLOWED_CSV_COLUMNS)
                                return render(request, 'patient_upload.html', context)
                            if re.match("^-{0,1}((\d+)|(\d+\.\d+))$", col) == None:
                                messages.error(request, "Invalid characters in CSV file, only numbers allowed")
                                return render(request, 'patient_upload.html', context)
                    file.seek(0)

                minio_filename = '%s_%s%s' % (patient_id, time.time(), file_extension)

                try:
                    put_object(minio_filename, file.file, file.size)

                except ResponseError as err:
                    print(err)
                    messages.error(request, 'ResponseError: file upload failed')
                except MaxRetryError as err:
                    print(err)
                    messages.error(request, 'MaxRetryError: file upload failed')

            # No file for Document / Diagnosis / Height / Weight
            else:
                minio_filename = None
                patient_data = HealthData(
                    patient=Patient.objects.get(pk=patient_id),
                    data_type=data_type,
                    title=file.name if file else str(datetime.now().strftime("%Y-%m-%d %H:%M")),
                    description=form.cleaned_data['description'],
                    minio_filename=minio_filename,
                    file_hash=file_hash,
                    signature=hash_signature,
                    otp_device=otp_device.persistent_id
                )
            patient_data.save()
            messages.success(request, 'File upload successful')

            context = {
                'user': request.user,
                'upload_data_form': UploadPatientDataForm()
            }
            return render(request, 'patient_upload.html', context)

        else:
            context = {
                'user': request.user,
                'upload_data_form': form
            }
            return render(request, 'patient_upload.html', context)


@otp_required
def patient_permission_view(request):
    patient = request.user.userprofile.patient
    therapists = list(map(lambda x: {
        'id': x.therapist.id,
        'name': x.therapist.name,
        'designation': x.therapist.designation,
        'department': x.therapist.department,
        'contact_number': x.therapist.contact_number,
        'read_access': 'Read Access' if x.read_access else 'No Access'
    }, IsAPatientOf.objects.filter(patient=patient)))

    context = {
        'therapists': therapists
    }
    return render(request, 'patient_permission.html', context)


@otp_required
@user_passes_test(is_patient)
def patient_file_permission_view(request, record_id):
    patient = request.user.userprofile.patient

    def extract_therapists(t):
        therapist = Therapist.objects.get(id=t.therapist.id)
        return {
            'id': therapist.id,
            'name': therapist.name,
            'designation': therapist.designation,
            'department': therapist.department,
            'read_access': 'Read Access' if t.read_access else 'No Access'
        }

    therapists_priority_high = list(map(extract_therapists,
                                        HealthDataPermission.objects.filter(
                                            patient=patient, health_data=record_id)))

    therapists_priority_low = list(map(extract_therapists,
                                       IsAPatientOf.objects.filter(patient=patient)))

    low_priority_ids = [x['id'] for x in therapists_priority_low]
    high_priority_ids = [x['id'] for x in therapists_priority_high]

    for idx, val in enumerate(low_priority_ids):
        if val not in high_priority_ids:
            therapists_priority_high.append(therapists_priority_low[idx])

    context = {
        'therapists': therapists_priority_high,
        'record_id': record_id
    }

    return render(request, 'patient_file_permission.html', context)


@otp_required
@user_passes_test(is_patient)
def patient_file_permisison_detail_view(request, record_id, therapist_id=None):
    patient = request.user.userprofile.patient
    therapist = Therapist.objects.get(id=therapist_id)

    if request.method == 'GET':
        try:
            current_permission = HealthDataPermission.objects.get(patient=patient, therapist=therapist,
                                                                  health_data=record_id).read_access
        except:
            current_permission = IsAPatientOf.objects.get(patient=patient, therapist=therapist).read_access

        context = {
            'therapist': therapist,
            'record_id': record_id,
            'permission_form': PermissionForm(initial={'permission': current_permission})
        }
        return render(request, 'patient_file_permission_detail.html', context)

    elif request.method == 'POST':
        form = PermissionForm(request.POST)
        if form.is_valid():
            print('valid form')
            permission = form.cleaned_data['permission']
            print('permission: %s' % permission)
            # Upsert HealthDataPermission
            try:
                print('record_id: %s' % record_id)
                p = HealthDataPermission.objects.get(patient=patient, therapist=therapist, health_data_id=record_id)
                p.read_access = permission
                p.save()
            except HealthDataPermission.DoesNotExist:
                p = HealthDataPermission(patient=patient, therapist=therapist, health_data_id=record_id,
                                         read_access=permission)
                p.save()
            return redirect('/web/patient/record/%s/permission/' % record_id)


@otp_required
@user_passes_test(is_patient)
def patient_permission_detail_view(request, therapist_id=None):
    patient = request.user.userprofile.patient
    therapist = Therapist.objects.get(id=therapist_id)

    if request.method == 'GET':
        current_permission = get_object_or_404(IsAPatientOf, patient=patient, therapist=therapist).read_access
        explicit_permissions = list(map(lambda x: {
            'title': x.health_data.title,
            'read_access': 'Read Access' if x.read_access else 'No Access',
            'id': x.health_data.id
        }, HealthDataPermission.objects.filter(patient=patient, therapist=therapist)))

        context = {
            'therapist': therapist,
            'permission_form': PermissionForm(initial={'permission': current_permission}),
            'explicit_permissions': explicit_permissions
        }
        return render(request, 'patient_permission_detail.html', context)

    elif request.method == 'POST':
        form = PermissionForm(request.POST)
        if form.is_valid():
            permission = form.cleaned_data['permission']
            # Update Permission
            p = get_object_or_404(IsAPatientOf, patient=patient, therapist=therapist)
            p.read_access = permission
            p.save()
            return redirect('/web/patient/permission/')


@csrf_exempt
def get_patient_data(request):
    if request.method == 'POST':
        # compare the token
        if request.POST['stoken'] == TOKEN:
            nric = request.POST['nric']

            # Create the HttpResponse object with the appropriate CSV header.
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="patientData.csv"'
            writer = csv.writer(response)

            # request for all content

            if nric == 'all':

                writer.writerow(["id", "name", "nric", "sex", "address", "contact_number", "date_of_birth"])

                patients = Patient.objects.all()

                for p in patients:
                    id = p.id
                    pname = p.name
                    pnric = p.nric
                    sex = p.sex
                    address = p.address
                    contact_number = p.contact_number
                    date_of_birth = p.date_of_birth
                    writer.writerow([id, pname, pnric, sex, address, contact_number, date_of_birth])

                writer.writerow(["=" * 80])

                writer.writerow(
                    ["data_id", "title", "description", "date", "patient_id", "data_type", "minio_filename", "therapist_id", "minio link"])

                data = HealthData.objects.all()

                for d in data:
                    id = d.id
                    title = d.title
                    description = d.description
                    date = d.date
                    patient_id = d.patient_id
                    datatype = d.data_type
                    minio_filename = d.minio_filename
                    therapist_id = d.therapist_id

                    if minio_filename is None or minio_filename == "":
                        link = "No minio link associated with the file"
                    else:
                        obj_link = get_object(minio_filename, 86400)
                        link = resolve_minio_link(obj_link)


                    writer.writerow([id, title, description, date, patient_id, datatype, minio_filename, therapist_id,link])
                return response

            else:

                writer.writerow(["id", "name", "nric", "sex", "address", "contact_number", "date_of_birth"])

                nricarray = nric.split(",")

                for each in nricarray:
                    try:
                        p = Patient.objects.get(nric=each)
                        id = p.id
                        pname = p.name
                        pnric = p.nric
                        sex = p.sex
                        address = p.address
                        contact_number = p.contact_number
                        date_of_birth = p.date_of_birth

                        writer.writerow([id, pname, pnric, sex, address, contact_number, date_of_birth])

                    except Exception as e:
                        print("Patient with nric ", each, " does not exist")

                writer.writerow(["=" * 80])

                writer.writerow(["data_id", "title", "description", "date", "patient_id", "data_type", "minio_filename", "therapist_id", "minio_link"])

                for each in nricarray:
                    try:
                        # get patient id
                        patient_id = Patient.objects.get(nric=each).id
                        data = HealthData.objects.filter(patient_id=patient_id)
                        for i in data:
                            data_id = i.id
                            title = i.title
                            description = i.description
                            date = i.date
                            patient_id = i.patient_id
                            datatype = i.data_type
                            minio_filename = i.minio_filename
                            therapist_id = i.therapist_id

                            if minio_filename is None or minio_filename == "":
                                link = "No minio link associated with the file"
                            else:
                                obj_link = get_object(minio_filename, 86400)
                                link = resolve_minio_link(obj_link)

                            writer.writerow(
                                [data_id, title, description, date, patient_id, datatype, minio_filename, therapist_id, link])

                    except Exception as e:

                        print("patient with ", each, "does not exist")

                return response
        else:
            return HttpResponseForbidden("Invalid Token")
    else:
        return HttpResponseForbidden("Invalid HTTP method, Please use HTTPS POST for request")


@csrf_exempt
def upload_ext_patient(request):

    if request.method == 'POST':
        if request.POST['stoken'] != TOKEN_UPLOAD:
            return HttpResponseForbidden("Invalid Token")

        name = request.FILES['file'].name
        response = ""
        ufile = request.FILES['file'].read().decode('utf-8-sig').splitlines()

        if name == "Patients.csv":

            for i in range(1,len(ufile)):
                row = ufile[i].split(",")
                patient_exist = Patient.objects.filter(nric=row[5]).exists()
                if not patient_exist:
                    #add into database
                    p = Patient(name=row[1], nric=row[5], sex=row[2], address=row[4]+row[7], contact_number=row[9],
                                date_of_birth=datetime.today())

                    p.save()
                else:
                    response += "Patient with NRIC " + row[5] + \
                                " is not added into the database as the record is already exist. \n"

        elif name == "Patient Data.csv":

            for i in range(1, len(ufile)):
                row = ufile[i].split(",")

                try:
                    # get patient id
                    patient_id = Patient.objects.get(nric=row[0]).id

                    url = row[2]
                    dfile = requests.get(url)

                    b = io.BytesIO(dfile.content)
                    length = len(dfile.content)

                    # upload the downloaded file into minio
                    _, file_extension = os.path.splitext(row[1])
                    if file_extension:
                        file_extension = file_extension.lower()

                    minio_filename = '%s_%s%s' % (row[0], time.time(), file_extension)

                    try:
                         put_object(minio_filename, b, length)
                    except ResponseError as err:
                         print(err)
                         messages.error(request, 'ResponseError: file upload failed')

                    #insert into healthdata
                    d = HealthData(title="External Database Record", description=row[3],
                                   date=datetime.today(), patient_id=patient_id, data_type=4, minio_filename=minio_filename)
                    d.save()

                except Exception as e:

                    response += "Error uploading data for patient with NRIC " + row[0] + ". \n"

        if response == "":
            return HttpResponse("OK")
        else:
            return HttpResponse(response)

    else:
        return HttpResponseForbidden("Invalid HTTP method, Please use HTTPS POST for request")


ANONYMIZER = Anonymizer()
sex_tree = {}
race_tree = {}
bloodtype_tree = {}
for i in Patient.SEX:
    sex_tree[i[0]] = []
for i in Patient.RACES:
    race_tree[i[0]] = []
for i in Patient.BLOOD_TYPES:
    bloodtype_tree[i[0]] = []
ANONYMIZER.add_tree(Tree.struct_to_tree(sex_tree))
ANONYMIZER.add_numrange(0, 120, 1)
ANONYMIZER.add_tree(Tree.struct_to_tree(race_tree))
ANONYMIZER.add_tree(Tree.struct_to_tree(bloodtype_tree))


def get_diag_rows():
    # For each diagnosis, get psuedo-identifiable data about the patient
    diagnoses = HealthData.objects.filter(data_type=HealthData.DIAGNOSIS_DATA)
    rows = []
    for i in diagnoses:
        current_patient = i.patient
        sex = current_patient.sex
        age = str(relativedelta(datetime.now(), current_patient.date_of_birth).years)
        race = current_patient.race
        bloodtype = current_patient.bloodtype

        try:
            bloodpressure = HealthData.objects.filter(data_type=HealthData.BLOOD_PRESSURE,
                    patient=current_patient).first().description
            heights = HealthData.objects.filter(data_type=HealthData.HEIGHT, patient=current_patient)
            weights = HealthData.objects.filter(data_type=HealthData.WEIGHT, patient=current_patient)
            avg_height = str(int(mean(float(i.description) for i in heights)))
            avg_weight = str(int(mean(float(i.description) for i in weights)))
        except:
            continue

        diagnosis = i.description

        current_row = [sex, age, race, bloodtype, bloodpressure, avg_height, avg_weight, diagnosis]
        rows.append(current_row)
    return rows

def get_anon_rows():
    def retrieve_readable(choice, item):
        for i,v in choice:
            if item == i:
                return v
        return "*"
    rows = get_diag_rows()
    results, _ = ANONYMIZER.process(rows, k=2, qi_num=4)

    for row in results:
        row[0] = retrieve_readable(Patient.SEX, row[0])
        row[1] = row[1].replace(",", "-")
        row[2] = retrieve_readable(Patient.RACES, row[2])
        row[3] = retrieve_readable(Patient.BLOOD_TYPES, row[3])

    return results

@otp_required
@user_passes_test(is_researcher)
def researcher_index_view(request):
    researcher = request.user.userprofile.researcher
    anon_rows = get_anon_rows()

    context = {
        'researcher_profile': researcher,
        'records': anon_rows
    }
    return render(request, 'researcher_index.html', context)


