from django.conf.urls import url
from . import views

urlpatterns = [
	url(r'^login/', views.login_view, name='login'),
	url(r'^logout/', views.logout_view, name='login'),
	url(r'^patient/index/$', views.patient_index_view, name='patient_index')	
]