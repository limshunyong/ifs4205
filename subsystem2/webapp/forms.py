from django import forms
from .models import IsAPatientOf, Patient, HealthData
from django.db.models import Count, Sum, Q
from ckeditor.widgets import CKEditorWidget


class UploadDataForm(forms.Form):
    def __init__(self,*args,**kwargs):
        therapist_id = kwargs.pop('therapist_id')
        super(UploadDataForm,self).__init__(*args,**kwargs)
        if therapist_id:
            self.fields['patient'].queryset = Patient.objects.filter(isapatientof__therapist__id=therapist_id)

    patient = forms.ModelChoiceField(queryset=None)
    data_type = forms.ChoiceField(choices=HealthData.DATA_TYPES)
    description = forms.CharField(widget=CKEditorWidget())
    file = forms.FileField(required=False)

    patient.widget.attrs = {'class':'form-control'}
    data_type.widget.attrs = {'class':'form-control'}
    file.widget.attrs = {'class':'form-control'}

    def clean(self):
        cleaned_data = super().clean()
        data_type = int(cleaned_data.get("data_type"))
        file = cleaned_data.get("file")
        if data_type == HealthData.IMAGE_DATA or data_type == HealthData.MOVIE_DATA or data_type == HealthData.TIME_SERIES_DATA:
            if file == None:
                raise forms.ValidationError(
                    "Missing file"
                )
        if data_type == HealthData.DOCUMENT_DATA or data_type == HealthData.DIAGNOSIS_DATA or data_type == HealthData.BLOOD_PRESSURE or data_type == HealthData.HEIGHT or data_type == HealthData.WEIGHT:
            if file != None:
                raise forms.ValidationError(
                    "This data type does not accept files."
                )

class UploadPatientDataForm(forms.Form):
    data_type = forms.ChoiceField(choices=HealthData.DATA_TYPES)
    file = forms.FileField(required=False)
    description = forms.CharField(widget=CKEditorWidget())

    data_type.widget.attrs = {'class':'form-control'}
    file.widget.attrs = {'class':'form-control'}

    def clean(self):
        cleaned_data = super().clean()
        data_type = int(cleaned_data.get("data_type"))
        file = cleaned_data.get("file")
        if data_type == HealthData.IMAGE_DATA or data_type == HealthData.MOVIE_DATA or data_type == HealthData.TIME_SERIES_DATA:
            if file == None:
                raise forms.ValidationError(
                    "Missing file"
                )
        if data_type == HealthData.DOCUMENT_DATA or data_type == HealthData.DIAGNOSIS_DATA or data_type == HealthData.BLOOD_PRESSURE or data_type == HealthData.HEIGHT or data_type == HealthData.WEIGHT:
            if file != None:
                raise forms.ValidationError(
                    "This data type does not accept files."
                )

class PermissionForm(forms.Form):
    TRUE_FALSE_CHOICES = (
        (True, 'Read Access'),
        (False, 'No Access')
    )

    permission = forms.ChoiceField(choices = TRUE_FALSE_CHOICES, label="Permission", widget=forms.Select(), required=True)
