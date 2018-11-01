from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^account/login/$', views.login_view, name='login'),
    url(r'^account/otp/$', views.otp_view, name='select_otp'),
    url(r'^account/otp/verify/$', views.verify_otp),
    url(r'^account/otp/challenge/$', views.challenge_view),
    url(r'^account/logout/$', views.logout_view),

    # Patient Views
    url(r'^patient/index/$', views.patient_index_view, name='patient_index'),
    url(r'^patient/index/(?P<type>\d+)/$', views.patient_index_view, name='patient_index'),
    url(r'^patient/record/(?P<record_id>\d+)$', views.patient_record_view),
    url(r'^patient/record/(?P<record_id>\d+)/permission/$', views.patient_file_permission_view, name='patient_perm'),
    url(r'^patient/record/(?P<record_id>\d+)/permission/(?P<therapist_id>\d+)/$',
        views.patient_file_permisison_detail_view, name='patient_file_permission_detail'),
    url(r'^patient/permission/$', views.patient_permission_view, name='patient_perm'),
    url(r'^patient/permission/(?P<therapist_id>\d+)/$', views.patient_permission_detail_view, name='patient_perm'),
    url(r'^patient/upload/$', views.patient_upload_data, name='patient_upload_data'),

    # Therapist Views
    url(r'^therapist/index/$', views.therapist_index_view, name='therapist_index'),
    url(r'^therapist/index/(?P<patient_id>\d+)$', views.therapist_index_view),
    url(r'^patient/(?P<patient_id>\d+)/detail$', views.patient_detail_view),
    url(r'^therapist/patient/(?P<patient_id>\d+)/$', views.therapist_list_patient_record_view),
    url(r'^therapist/patient/(?P<patient_id>\d+)/(?P<type>\d+)$', views.therapist_list_patient_record_view),
    url(r'^therapist/upload$', views.therapist_upload_data, name='therapist_upload_data'),

    # Subsystem 4
    url(r'^database/retrieve/patient$', views.get_patient_particulars),
    url(r'^database/retrieve/data$', views.get_patient_data),

    url(r'^keygen/', views.keygen_view),

]
