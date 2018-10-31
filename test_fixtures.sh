#!/bin/bash
# get the container id of the django server and create a superuser

cid=$(docker ps -aqf "name=subsystem2")
echo $cid
docker exec -it $cid python manage.py loaddata testdata.json
