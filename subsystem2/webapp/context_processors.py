from .models import UserProfile, HealthData
def user_roles(request):
    """
    User roles are used to generate individual navbar designs
    for therapist / patient views with the same template
    """
    return {
    'ROLE_PATIENT': UserProfile.ROLE_PATIENT,
    'ROLE_THERAPIST': UserProfile.ROLE_THERAPIST,
    'ROLE_RESEARCHER': UserProfile.ROLE_RESEARCHER
    }

def data_types(request):
	types = []
	for d in HealthData.DATA_TYPES:
		types.append(d[1])
	return {
		'DATA_TYPES': types
	}
