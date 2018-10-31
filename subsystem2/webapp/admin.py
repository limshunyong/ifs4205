from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.forms import ModelForm
from django.contrib.auth.models import User as DjangoUser
from .models import Patient, Therapist, IsAPatientOf, Researcher, Ward, VisitRecord, HealthData, HealthDataPermission, UserProfile, BLEOTPDevice

class UserProfileForm(ModelForm):
	"""Add labels for form fields on AdminUserInline"""
	class Meta:
		model = UserProfile
		fields = ['role', 'patient', 'therapist', 'researcher']
		labels = {
			'role': 'Role',
			'patient': 'Patient Profile',
			'therapist': 'Therapist Profile',
                        'researcher': 'Researcher Profile',
		}


class AdminUserInline(admin.StackedInline):
	model = UserProfile
	form = UserProfileForm
	can_delete = False
	verbose_name_plural = 'User Profile'


class AdminUserModel(UserAdmin):
	"""Replace django's default UserAdmin model"""
	inlines = (AdminUserInline, )
	# columns to be shown (either methods in auth.User or self-defined functions)
	list_display = ('username', 'email', 'get_role','is_staff',)
	# declare extended user model
	list_select_related = ('userprofile', )

	def get_role(self, instance):
		return instance.userprofile.role
	get_role.short_description = 'Role'


class BLEOTPDeviceAdmin(admin.ModelAdmin):
	raw_id_fields = ['user']
	change_form_template = 'bleotpdevice_changeform.html'

# Re-register UserAdmin
admin.site.unregister(DjangoUser)
admin.site.register(DjangoUser, AdminUserModel)

# Register BLE OTP Device
admin.site.register(BLEOTPDevice, BLEOTPDeviceAdmin)

# Register your models here.
admin.site.register(Patient)
admin.site.register(Therapist)
admin.site.register(IsAPatientOf)
admin.site.register(Researcher)
admin.site.register(Ward)
admin.site.register(VisitRecord)
admin.site.register(HealthData)
admin.site.register(HealthDataPermission)
