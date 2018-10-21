import json
import csv
import codecs
import time
import urllib.parse
import os.path
from datetime import datetime
import pytz
import ed25519
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
from .models import Patient, Therapist, IsAPatientOf, Researcher, Ward, VisitRecord, HealthData,\
HealthDataPermission, UserProfile, DATA_TYPES, IMAGE_DATA, TIME_SERIES_DATA,\
MOVIE_DATA, DOCUMENT_DATA, BLEOTPDevice
from .forms import UploadDataForm
from .object import put_object, get_object


# user_passes_test helper functions
def is_therapist(user):
    try:
        return user.userprofile.role == UserProfile.ROLE_THERAPIST
    except:
        return False

def login_view(request, next=None):
    next_url = request.GET.get('next')
    print(request.user, request.user.is_authenticated ,request.user.is_verified())
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
    print(request.user, request.user.is_authenticated ,request.user.is_verified())
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
                # TODO redirect by account type
                return redirect(reverse('patient_index'))
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
    signing_key =  ed25519.SigningKey(signing_key_str.encode('ascii'), encoding="hex")
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
def patient_index_view(request, type=None):
    # TODO add pagination
    patient = request.user.userprofile.patient
    records = HealthData.objects.filter(patient=patient, data_type=type)
    print(records)
    context = {
        'user': request.user,
        'type': type,
        'records': records
    }
    return render(request, 'patient_index.html', context)


@otp_required
def patient_record_view(request, record_id):
    print(record_id)

    context = {
        'user': request.user,
        'record_id':  record_id
    }

    user = request.user.userprofile
    if user.role == UserProfile.ROLE_PATIENT:
        print(user.patient)
        health_data = get_object_or_404(HealthData, Q(pk=record_id, patient=user.patient))
    elif user.role == UserProfile.ROLE_THERAPIST:
        print(user.therapist)
        health_data = get_object_or_404(HealthData, pk=record_id)
        # verify permission
        # TODO refactor below as a function
        is_a_patient_of = get_object_or_404(IsAPatientOf, patient=health_data.patient, therapist=user.therapist)
        health_data_permission = HealthDataPermission.objects.get(health_data__id=record_id, therapist=user.therapist)
        if (health_data_permission and not health_data_permission.read_access) or \
            (not is_a_patient_of.read_access):
            messages.add_message(request, messages.ERROR, "You do not have the permission to view this record.")
            return render(request, 'therapist_error.html', context)


    print(health_data.data_type)
    print(health_data.minio_filename)

    obj_link = get_object(health_data.minio_filename)
    print(obj_link)

    if health_data.data_type == IMAGE_DATA:
        context['obj_link'] = obj_link
        return render(request, 'patient_record_image.html', context)
    elif health_data.data_type == MOVIE_DATA:
        context['obj_link'] = obj_link
        return render(request, 'patient_record_movie.html', context)
    elif health_data.data_type == TIME_SERIES_DATA:
        return HttpResponse('To implement.')
    elif health_data.data_type == DOCUMENT_DATA:
        return HttpResponse('To implement.')
    else:
        return HttpResponseForbidden()


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
        form = UploadDataForm(request.POST, therapist_id=therapist.pk)

        # TODO: Implement Form Validation, Clean Up
        # if form.isValid():

        file = request.FILES['file']
        _, file_extension = os.path.splitext(file.name)
        patient_id = request.POST['patient']
        minio_filename = '%s_%s%s' % (patient_id, time.time(), file_extension)
        put_object(minio_filename, file.file, file.size)

        patient_data = HealthData(
            patient=Patient.objects.get(pk=patient_id),
            creator=therapist,
            data_type=request.POST['data_type'],
            title=file.name,
            description='',
            minio_filename=minio_filename
            )

        patient_data.save()

        return HttpResponse("Posted")


@otp_required
def patient_permission_view(request):
    patient = request.user.userprofile.patient
    context = {
        'therapists': Therapist.objects.filter(isapatientof__patient=patient)
    }
    return render(request, 'patient_permission.html', context)

@otp_required
def patient_file_permission_view(request, record_id):
    print('in')
    patient = request.user.userprofile.patient
    context = {
        'therapists': Therapist.objects.filter(healthdatapermission__patient=patient, healthdatapermission__id=record_id),
        'record_id': record_id
    }
    return render(request, 'patient_file_permission.html', context)

@otp_required
def patient_file_permisison_detail_view(request, record_id, therapist_id=None):
    patient = request.user.userprofile.patient
    therapist = Therapist.objects.get(id=therapist_id)
    context = {
        'file_permission_set' : get_object_or_404(HealthDataPermission, patient=patient, therapist=therapist, id=record_id),
        'record_id' : record_id
    }
    return render(request, 'patient_file_permission_detail.html', context)

@otp_required
def patient_permission_detail_view(request, therapist_id=None):
    patient = request.user.userprofile.patient
    therapist = Therapist.objects.get(id=therapist_id)
    context = {
        'permission_set': get_object_or_404(IsAPatientOf, patient=patient, therapist=therapist)
    }
    return render(request, 'patient_permission_detail.html', context)


@otp_required
def patient_update_permission(request, therapist_id=None, data_type=None, choice=None):
    if (therapist_id is None) or (data_type is None) or (choice is None):
        raise Http404
    
    therapist = Therapist.objects.get(id=therapist_id)
    is_a_patient_of = IsAPatientOf.objects.get(therapist=therapist)

    # TODO use url path
    data_type = int(data_type)
    # TODO change numbers to DATA_TYPE
    print('data_type', data_type)
    if data_type == 0:
        is_a_patient_of.image_access = choice
    elif data_type == 1:
        is_a_patient_of.timeseries_access = choice
    elif data_type == 2:
        is_a_patient_of.movie_access = choice
    elif data_type == 3:
        is_a_patient_of.document_access = choice
    is_a_patient_of.save()
    return redirect('/web/patient/permission/'+str(therapist.id))


@otp_required
def patient_update_file_permission(request, record_id, therapist_id=None, data_type=None, choice=None):
    if (therapist_id is None) or (data_type is None) or (choice is None):
        raise Http404

    therapist = Therapist.objects.get(id=therapist_id)
    healthdatapermisison = HealthDataPermission.objects.get(therapist=therapist, id=record_id)

    # TODO use url path
    data_type = int(data_type)
    # TODO change numbers to DATA_TYPE
    print('data_type', data_type)
    if data_type == 0:
        healthdatapermisison.permission = choice
    elif data_type == 1:
        healthdatapermisison.permission = choice
    elif data_type == 2:
        healthdatapermisison.permission = choice
    elif data_type == 3:
        healthdatapermisison.permission = choice
    healthdatapermisison.save()

    return redirect('/web/patient/record/'+ str(record_id)+'/permission/'+ str(therapist.id) +'/')