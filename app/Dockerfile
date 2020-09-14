FROM python:3.8
ADD . /jwt_app
WORKDIR /jwt_app
RUN pip install -r requirements.txt
#CMD ["flask", "run",  "--host=0.0.0.0", "--cert=adhoc"]
#port should be specified in docker-compose or something like that
CMD ["flask", "run",  "--host=0.0.0.0", "--port=5060"]
