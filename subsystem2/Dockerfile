FROM python:3.6
ENV PYTHONUNBUFFERED 1

RUN apt-get update
RUN apt-get install -y vim

RUN mkdir /code
WORKDIR /code
ADD . /code/
ADD my.cnf /etc/mysql/
RUN pip install -r requirements.txt
RUN chmod +x wait-for-it.sh

