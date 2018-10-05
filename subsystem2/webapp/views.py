import json
import csv
import codecs
import time
import urllib.parse
import os.path
from datetime import datetime
import pytz
from django.shortcuts import get_object_or_404, render, redirect
from django.http import Http404, HttpResponseRedirect, HttpResponse
from django.utils import timezone
from django.utils.encoding import escape_uri_path
from django.views import View
from django.db import transaction
from django.urls import reverse
from django.db.models import Count, Sum, Q
from django.utils.decorators import method_decorator
from django.core.paginator import Paginator
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages

from .models import Patient, Therapist, IsAPatientOf, Researcher, Ward, VisitRecord, HealthData, HealthDataPermission, UserProfile, DATA_TYPES
from .forms import UploadDataForm
from .object import put_object


# user_passes_test helper functions
def is_therapist(user):
    try:
        return user.userprofile.role == UserProfile.ROLE_THERAPIST
    except:
        return False


def login_view(request, next=None):
    next_url = request.GET.get('next')
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            if next_url is not None:
                return redirect(next_url)
            else:
                return redirect("/web/patient/index/")
        else:
            context = {
                'next': next_url,
                'error_msg': "Wrong username or password."
            }
            return render(request, "login.html", context)
    else:
        context = {
            'next': next_url,
            'error_msg': None
        }
        return render(request, "login.html", context)


def logout_view(request):
    logout(request)
    return redirect("/web/login/")


@login_required
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

@login_required
def patient_record_view(request, record_id):
    print(record_id)

    context = {
        'user': request.user,
        'record_id':  record_id
    }

    # hardcoded value for the first demo. to be removed
    if record_id == "1":
        return render(request, 'patient_record_bp.html', context)
    elif record_id == "2":
        return render(request, 'patient_record_image.html', context)
    elif record_id == "3":
        return render(request, 'patient_record_movie.html', context)
    else:
        return render(request, 'patient_index.html', context)


@login_required
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
            therapist=therapist,
            data_type=request.POST['data_type'],
            title=file.name,
            description='',
            minio_filename=minio_filename
            )

        patient_data.save()

        return HttpResponse("Posted")


@login_required
def patient_permission_view(request):
    patient = request.user.userprofile.patient
    context = {
        'therapists': Therapist.objects.filter(isapatientof__patient=patient)
    }
    return render(request, 'patient_permission.html', context)


@login_required
def patient_permission_detail_view(request, therapist_id=None):
    patient = request.user.userprofile.patient
    therapist = Therapist.objects.get(id=therapist_id)
    context = {
        'permission_set': get_object_or_404(IsAPatientOf, patient=patient, therapist=therapist)
    }
    return render(request, 'patient_permission_detail.html', context)


@login_required
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
