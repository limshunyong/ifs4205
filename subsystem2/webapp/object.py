from minio import Minio
from minio.error import ResponseError
from datetime import timedelta
import os


ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", default='')
SECRET_KEY = os.getenv("MINIO_SECRET_KEY", default='')

minioClient = Minio('localhost:9000',
                    access_key=ACCESS_KEY,
                    secret_key=ACCESS_KEY,
                    secure=False)

BUCKET_NAME = 'patientdata'

def put_object(object_name, data, length):
    etag = minioClient.put_object(BUCKET_NAME, object_name, data, length)
    return etag

def get_object(object_name):
    timeout = 10
    # if bucket_name == 'images':
    #     timeout = 10
    # elif bucket_name == 'videos':
    #     timeout = 60 * 60
    # else:
    #     timeout = 60
    # presigned get object URL for object name, expires in 2 days.
    # try:
    #     print(minioClient.presigned_get_object(BUCKET_NAME, object_name, expires=timedelta(seconds=timeout)))
    # # Response error is still possible since internally presigned does get bucket location.
    # except ResponseError as err:
    #     print(err)
    return minioClient.presigned_get_object(BUCKET_NAME, object_name, expires=timedelta(seconds=timeout))


def download_object(bucket_name, object_name, path):
    # Get a full object and prints the original object stat information.
    try:
        print(minioClient.fget_object(bucket_name, object_name, path))
    except ResponseError as err:
        print(err)


def remove_object(bucket_name, object_name):
    # Remove an object.
    try:
        minioClient.remove_object(bucket_name, object_name)
    except ResponseError as err:
        print(err)
