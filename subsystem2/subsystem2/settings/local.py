from subsystem2.settings.base import *
# Database
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'hvq6e3ubr-yu%s=42#o8-oh*)=z5obloiv!o+ij#$q3bb@km2c'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ["192.168.99.100", "127.0.0.1"]


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'OPTIONS': {
            'read_default_file': '/etc/mysql/my.cnf',
        },
    }
}
MINIO_URL = "http://127.0.0.1/"