from django.conf.urls import url
from . import views

urlpatterns = [
	url(r'^login/', views.login_view),
	url(r'^logout/', views.logout_view),
	url(r'^patient/index/$', views.patient_index_view, name='patient_index'),
	url(r'^patient/index/(?P<type>\d+)/$', views.patient_index_view, name='patient_index'),
	url(r'^patient/record/(?P<record_id>\d+)$', views.patient_record_view, name='patient_index'),
	url(r'^patient/permission/$', views.patient_permission_view, name='patient_perm'),
	url(r'^patient/permission/(?P<therapist_id>\d+)/$', views.patient_permission_detail_view, name='patient_perm'),
	url(r'^patient/permission/update/(?P<therapist_id>\d+)/(?P<data_type>\d+)/(?P<choice>\d+)/$', views.patient_update_permission),
	url(r'^therapist/upload$', views.therapist_upload_data, name='therapist_upload_data'),
	url(r'^patient/record/(?P<record_id>\d+)/permission$', views.patient_file_permission_view, name='patient_perm'),
	url(r'^patient/record/(?P<record_id>\d+)/permission/(?P<therapist_id>\d+)/$', views.patient_file_permisison_detail_view, name='patient_file_permission_detail'),
	url(r'^patient/record/(?P<record_id>\d+)/permission/(?P<therapist_id>\d+)/update/(?P<data_type>\d+)/(?P<choice>\d+)/$', views.patient_update_file_permission),
]
