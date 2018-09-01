FROM python:3.6
ENV PYTHONUNBUFFERED 1
RUN mkdir /code
WORKDIR /code
ADD ./requirements.txt /code/
RUN pip install -r requirements.txt
ADD ./wait-for-it.sh /code/
RUN chmod +x wait-for-it.sh
ADD . /code/
