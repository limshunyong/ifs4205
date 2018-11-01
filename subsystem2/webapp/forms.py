from django import forms
from .models import IsAPatientOf, Patient, DATA_TYPES
from django.db.models import Count, Sum, Q
from ckeditor.widgets import CKEditorWidget
from django.core.exceptions import ValidationError


def validate_file_size(file):
    filesize= file.size

    if filesize > 100*1024*1024:
        raise ValidationError("The maximum file size that can be uploaded is 100MB")
    else:
        return file


class UploadDataForm(forms.Form):
    def __init__(self,*args,**kwargs):
        therapist_id = kwargs.pop('therapist_id')
        super(UploadDataForm,self).__init__(*args,**kwargs)
        if therapist_id:
            self.fields['patient'].queryset = Patient.objects.filter(isapatientof__therapist__id=therapist_id)

    patient = forms.ModelChoiceField(queryset=None)
    data_type = forms.ChoiceField(choices=DATA_TYPES)
    description = forms.CharField(widget=CKEditorWidget())
    file = forms.FileField(validators=[validate_file_size])

    patient.widget.attrs = {'class':'form-control'}
    data_type.widget.attrs = {'class':'form-control'}
    file.widget.attrs = {'class':'form-control'}


class UploadPatientDataForm(forms.Form):
    data_type = forms.ChoiceField(choices=DATA_TYPES)
    file = forms.FileField(validators=[validate_file_size])

    data_type.widget.attrs = {'class':'form-control'}
    file.widget.attrs = {'class':'form-control'}


class PermissionForm(forms.Form):
    TRUE_FALSE_CHOICES = (
        (True, 'Read Access'),
        (False, 'No Access')
    )

    permission = forms.ChoiceField(choices = TRUE_FALSE_CHOICES, label="Permission", widget=forms.Select(), required=True)
