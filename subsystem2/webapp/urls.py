from django.conf.urls import url
from . import views

urlpatterns = [
	url(r'^login/', views.login_view, name='login'),
	url(r'^logout/', views.logout_view, name='login'),
	url(r'^patient/index/$', views.patient_index_view, name='patient_index'),
	url(r'^patient/index/(?P<type>\d+)/$', views.patient_index_view, name='patient_index'),
	url(r'^patient/record/(?P<record_id>\d+)$', views.patient_record_view, name='patient_index'),
	url(r'^patient/permission/$', views.patient_permission_view, name='patient_perm'),
	url(r'^patient/permission/(?P<therapist_id>\d+)/$', views.patient_permission_detail_view, name='patient_perm'),
	url(r'^patient/permission/update/(?P<therapist_id>\d+)/(?P<data_type>\d+)/(?P<choice>\d+)/$', views.patient_update_permission),
	url(r'^therapist/upload$', views.therapist_upload_data, name='therapist_upload_data')
] 