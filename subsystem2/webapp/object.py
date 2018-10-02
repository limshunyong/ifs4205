from minio import Minio
from minio.error import ResponseError
from datetime import timedelta

minioClient = Minio('localhost:9000',
                    access_key='',
                    secret_key='',
                    secure=False)


def put_object(bucket_name, object_name, path):
    # Put an object 'objectName' with contents from '/tmp/otherobject',
    # upon success prints the etag identifier computed by server.
    if bucket_name == 'images':
        content_type = 'image/jpg'
    elif bucket_name == 'videos':
        content_type = 'video/mp4'
    else:
        content_type = 'application/csv'
    try:
        print(minioClient.fput_object(bucket_name, object_name, path, content_type))
    except ResponseError as err:
        print(err)


def get_object(bucket_name, object_name):
    if bucket_name == 'images':
        timeout = 10
    elif bucket_name == 'videos':
        timeout = 60 * 60
    else:
        timeout = 60
    # presigned get object URL for object name, expires in 2 days.
    try:
        print(minioClient.presigned_get_object(bucket_name, object_name, expires=timedelta(seconds=timeout)))
    # Response error is still possible since internally presigned does get bucket location.
    except ResponseError as err:
        print(err)


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
