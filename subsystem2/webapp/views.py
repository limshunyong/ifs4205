import json
import csv
import codecs
import time
import urllib.parse
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

from .models import Patient, Therapist, IsAPatientOf, Researcher, Ward, VisitRecord, HealthData, HealthDataPermission, UserProfile

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
def patient_index_view(request):
    record_list = HealthData.objects.all()
    
    print(record_list)
    context = {
        'user': request.user,
        'record_list': record_list
    }
    return render(request, 'patient_index.html', context)

@login_required
def patient_record_view(request, record_id):
    print(record_id)

    context = {
        'user': request.user,
        'record_id':  record_id
    }

    if record_id == "1":
        return render(request, 'patient_record_bp.html', context)
    elif record_id == "2":
        return render(request, 'patient_record_image.html', context)
    elif record_id == "3":
        return render(request, 'patient_record_movie.html', context)
    else:
        return render(request, 'patient_index.html', context)