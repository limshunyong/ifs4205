# IFS4205 Capstone Project Docker Setup Guide

## Prerequisite 
Make sure docker (version >= 18.06-ce) is installed.
```
> docker -v 
Docker version 18.06.1-ce, build e68fc7a
```

## Deployment
```
# in the project directory, build the dimage
> docker-compose build

# run containers 
# -d: detached mode, remove this tag if you want to see the output message
> docker-compose up -d

# create a django superuser account
> ./create_su.sh

```

## Where is the Database
While the mysql instance is containerised, the data itself is stored on the host machine for persistence.
Currently the data is store in the docker volume named `db-data-volume`, located at `/var/lib/mysql`.


## IMPORTANT: Security Enhancement
Database credentials are read from two config files when building the image, namely:

- subsystem2/my.cnf: settings for django's db connector 
- config/mysql.env: settings for mysql initialisation
For production environment, it is important to change this pair of default credentials before each deployment.

> TODO: one possible solution maybe to create a copy of these files on the server, and use git post-receive hook to overwrite the defaults.
 


## Other Useful Commands
```
# to see what containers are running
> docker container ls

# to shut down all containers
> docker-compose down
```
