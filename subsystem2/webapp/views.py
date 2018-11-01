import json
import csv
import codecs
import time
import urllib.parse
import os.path
from datetime import datetime
import pytz
import ed25519
import magic
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
    HealthDataPermission, UserProfile, DATA_TYPES, IMAGE_DATA, TIME_SERIES_DATA, \
    MOVIE_DATA, DOCUMENT_DATA, BLEOTPDevice
from .forms import PermissionForm, UploadDataForm, UploadPatientDataForm
from .object import put_object, get_object
from django.contrib import messages
from minio.error import ResponseError


TOKEN = os.environ.get('SEC_TOKEN')

MAPPING = {
    'image/jpg': IMAGE_DATA,
    'image/jpeg': IMAGE_DATA,
    'image/png': IMAGE_DATA,
    'video/mp4': MOVIE_DATA,
    'video/mpg': MOVIE_DATA,
    'application/msword': DOCUMENT_DATA,
    'text/plain': DOCUMENT_DATA
  
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
        'devices': otp.devices_for_user(request.user)
    }
    return render(request, "otp.html", context)


def verify_otp(request):
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
            elif isinstance(device, BLEOTPDevice) and device.verify_token(token):
                print("========ble ok")
                otp.login(request, device)
                # TODO redirect by account type
                return redirect(reverse('patient_index'))
            else:
                messages.add_message(request, messages.ERROR, "Invalid token.")
                return redirect(reverse('select_otp'))
        else:
            messages.add_message(request, messages.ERROR, "token or device_id not set.")
            return redirect(reverse('select_otp'))
    return redirect(reverse('select_otp'))


def challenge_view(request):
    device_id = request.POST['device_id']
    device = otp.models.Device.from_persistent_id(device_id)
    error_msg = None
    if not request.user.is_authenticated:
        error_msg = 'not_authenticated'
    if device_id is None or device is None:
        error_msg = 'otp_device_does_not_exist'

    msg_to_be_signed = get_random_string(length=1024)
    print(device_id, device)
    device.otp_challenge = msg_to_be_signed
    device.save()

    # TODO remove test code below
    signing_key_str = "b2fac486cbc234ed4558788ad4c1c0420472cf7765a3aefeaeed7de049acb14e"
    print('verifying_key', device.key)
    print('signing_key', signing_key_str)
    verifying_key = ed25519.VerifyingKey(device.key.encode('ascii'), encoding='hex')
    signing_key = ed25519.SigningKey(signing_key_str.encode('ascii'), encoding="hex")
    sig = signing_key.sign(msg_to_be_signed.encode('ascii'), encoding="base64")
    print('challenge', msg_to_be_signed)
    print('signature', sig)
    verifying_key.verify(sig, msg_to_be_signed.encode('ascii'), encoding="base64")

    context = {
        'error_msg': error_msg,
        'challenge': msg_to_be_signed,
        'device_id': request.POST['device_id']
    }
    return render(request, 'challenge.html', context)


def logout_view(request):
    logout(request)
    return redirect("/web/account/login/")


# TODO only admin can view
def keygen_view(request):
    private_key, public_key = ed25519.create_keypair()
    private_key_str = private_key.to_ascii(encoding="hex").decode('ascii')
    public_key_str = public_key.to_ascii(encoding="hex").decode('ascii')
    context = {
        'public_key': public_key_str,
        'private_key': private_key_str
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
    print(record_id)

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

    print(health_data.data_type)
    print(health_data.minio_filename)
    obj_link = get_object(health_data.minio_filename, 10)
    print(obj_link)

    if health_data.data_type == IMAGE_DATA:
        context['obj_link'] = resolve_minio_link(obj_link)
        return render(request, 'patient_record_image.html', context)
    elif health_data.data_type == MOVIE_DATA:
        context['obj_link'] = resolve_minio_link(obj_link)
        return render(request, 'patient_record_movie.html', context)
    elif health_data.data_type == TIME_SERIES_DATA:
        return HttpResponse('To implement.')
    elif health_data.data_type == DOCUMENT_DATA:
        return HttpResponse('To implement.')
    else:
        return HttpResponseForbidden()


def resolve_minio_link(link):
    MINIO_URL = getattr(settings, "MINIO_URL", None)
    return link.replace("http://minio:9000/", MINIO_URL)
    

@otp_required
@user_passes_test(is_therapist)
def therapist_upload_data(request):
    therapist = request.user.userprofile.therapist

    if request.method == 'GET':
        context = {
            'user': request.user,
            'upload_data_form': UploadDataForm(therapist_id=therapist.pk)
        }
        return render(request, 'therapist_upload.html', context)

    elif request.method == 'POST':
        form = UploadDataForm(request.POST, request.FILES, therapist_id=therapist.pk)

        if form.is_valid():
            file = form.cleaned_data['file']
            _, file_extension = os.path.splitext(file.name)
            if file_extension:
                file_extension = file_extension.lower()
            data_type = form.cleaned_data['data_type']

            mime = magic.from_buffer(file.read(), mime=True).lower()
            file.seek(0)

            data_type_name = [x for x in DATA_TYPES if int(data_type) in x][0][1]

            wrong_type = True
            for allowed_types in FILE_TYPES.get(data_type_name):
                if file_extension == allowed_types.get('ext') and mime == allowed_types.get('mime'):
                    wrong_type = False
                    break

            if wrong_type:
                messages.error(request, 'Invalid file type. File type should be: '
                                        'IMAGE: \'.jpg\', \'.png\' '
                                        'TIME SERIES: \'.csv\' '
                                        'VIDEO: \'.mp4\', \'.mpg\' '
                                        'DOCUMENT: \'.doc\'')

                context = {
                    'user': request.user,
                    'upload_data_form': form
                }

                return render(request, 'therapist_upload.html', context)

            patient_id = form.cleaned_data['patient'].id
            minio_filename = '%s_%s%s' % (patient_id, time.time(), file_extension)
            try:
                put_object(minio_filename, file.file, file.size)
            except ResponseError as err:
                print(err)
                messages.error(request, 'ResponseError: file upload failed')
                return render(request, 'therapist_upload.html')
            except MaxRetryError as err:
                print(err)
                messages.error(request, 'MaxRetryError: file upload failed')
                return render(request, 'therapist_upload.html')
            patient_data = HealthData(
                patient=Patient.objects.get(pk=patient_id),
                therapist=therapist,
                data_type=data_type,
                title=file.name,
                description='',
                minio_filename=minio_filename
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
            'upload_data_form': UploadPatientDataForm()
        }
        return render(request, 'patient_upload.html', context)

    elif request.method == 'POST':
        form = UploadPatientDataForm(request.POST, request.FILES)

        if form.is_valid():
            file = form.cleaned_data['file']
            _, file_extension = os.path.splitext(file.name)
            if file_extension:
                file_extension = file_extension.lower()
            data_type=form.cleaned_data['data_type']

            mime = magic.from_buffer(file.read(), mime=True).lower()
            file.seek(0)
            data_type_name = [x for x in DATA_TYPES if int(data_type) in x][0][1]

            wrong_type = True
            for allowed_types in FILE_TYPES.get(data_type_name):
                if file_extension == allowed_types.get('ext') and mime == allowed_types.get('mime'):
                    wrong_type = False
                    break

            if wrong_type:
                messages.error(request, 'Invalid file type. File type should be: '
                                        'IMAGE: \'.jpg\', \'.png\' '
                                        'TIME SERIES: \'.csv\' '
                                        'VIDEO: \'.mp4\', \'.mpg\' '
                                        'DOCUMENT: \'.doc\'')

                context = {
                    'user': request.user,
                    'upload_data_form': UploadPatientDataForm()
                }

                return render(request, 'patient_upload.html', context)

            patient_id = patient.id
            minio_filename = '%s_%s%s' % (patient_id, time.time(), file_extension)

            try:
                put_object(minio_filename, file.file, file.size)
                patient_data = HealthData(
                    patient=Patient.objects.get(pk=patient_id),
                    data_type=data_type,
                    title=file.name,
                    description='',
                    minio_filename=minio_filename
                )
                patient_data.save()
                messages.success(request, 'File upload successful')
            except ResponseError as err:
                print(err)
                messages.error(request, 'ResponseError: file upload failed')
                return render(request, 'patient_upload.html')
            except MaxRetryError as err:
                print(err)
                messages.error(request, 'MaxRetryError: file upload failed')
                return render(request, 'patient_upload.html')

            context = {
                'user': request.user,
                'upload_data_form': UploadPatientDataForm()
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

                    obj_link = get_object(minio_filename, 86400)

                    writer.writerow([id, title, description, date, patient_id, datatype, minio_filename, therapist_id, obj_link])

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

                            obj_link = get_object(minio_filename, 86400)

                            writer.writerow(
                                [data_id, title, description, date, patient_id, datatype, minio_filename, therapist_id, obj_link])

                    except Exception as e:

                        print("patient with ", each, "does not exist")

                return response
        else:
            return HttpResponseForbidden("Invalid Token")
    else:
        return HttpResponseForbidden("Invalid HTTP method, Please use HTTPS POST for request")
