FROM python:3.8
ADD . /jwt_auth
WORKDIR /jwt_auth
RUN pip install -r requirements.txt
#CMD ["flask", "run",  "--host=0.0.0.0", "--cert=adhoc"]
CMD ["flask", "run",  "--host=0.0.0.0", "--port=5050"]
