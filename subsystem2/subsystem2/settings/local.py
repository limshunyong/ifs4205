from subsystem2.settings.base import *
import os

# Database
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'hvq6e3ubr-yu%s=42#o8-oh*)=z5obloiv!o+ij#$q3bb@km2c'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ["192.168.99.100", "127.0.0.1"]

DB_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
DB_PORT = os.getenv("MYSQL_PORT", "3306")
DB_USER = os.getenv("MYSQL_USER", "admin")
DB_PASSWORD = os.getenv("MYSQL_PASSWORD", "admin")
DB_DATABASE = os.getenv("MYSQL_DATABASE", "subsystem2")

print(DB_HOST)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': DB_DATABASE,
        'USER': DB_USER,
        'PASSWORD': DB_PASSWORD,
        'HOST': DB_HOST,
        'PORT': DB_PORT,
    }
}
MINIO_EXTERNAL_URL = "http://127.0.0.1/"
