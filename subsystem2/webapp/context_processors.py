from .models import UserProfile

def user_roles(request):
    """    
    User roles are used to generate individual navbar designs 
    for therapist / patient views with the same template
    """
    return {
    'ROLE_PATIENT': UserProfile.ROLE_PATIENT,
    'ROLE_THERAPIST': UserProfile.ROLE_THERAPIST
    }
