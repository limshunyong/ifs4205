from django import forms
from .models import IsAPatientOf, Patient, DATA_TYPES

class UploadDataForm(forms.Form):
    def __init__(self,*args,**kwargs):
        therapist_id = kwargs.pop('therapist_id')
        super(UploadDataForm,self).__init__(*args,**kwargs)
        if therapist_id:
            self.fields['patient'].queryset = Patient.objects.filter(pk__in=IsAPatientOf.objects.filter(pk=therapist_id))

    patient = forms.ModelChoiceField(queryset=None)
    data_type = forms.ChoiceField(choices=DATA_TYPES)
    file = forms.FileField()

    patient.widget.attrs = {'class':'form-control'}
    data_type.widget.attrs = {'class':'form-control'}
    file.widget.attrs = {'class':'form-control'}
