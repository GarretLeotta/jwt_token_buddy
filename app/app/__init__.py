import base64
import json
import datetime
from functools import wraps

from flask import Flask, abort, jsonify, make_response, request

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

class AuthorizationError(Exception):
    pass

def auth_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            raise AuthorizationError("Authorization Token Required")

        token = auth_header.split("Bearer ")[1]

        #for now, assume RS256, JWT, etc.
        #TODO: support other algos
        try:
            token = token.encode('utf-8')
            header, payload, signature = token.split(b'.')
            message = header + b'.' + payload
        except ValueError:
            #invalid json web token
            raise AuthorizationError("Invalid Authorization Token")

        signature = decode_base64url(signature)

        public_key = load_pem_public_key(open('key.pub', 'rb').read())
        try:
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            #verified
            return f(*args, **kwargs)
        except:
            raise AuthorizationError("Invalid Signature")

    return decorated


@app.errorhandler(AuthorizationError)
def auth_error(error):
    return jsonify(str(error)), 403

@app.route('/')
def index():
    return "Hello, App!"

@app.route('/login')
@auth_token
def get_token():
    return jsonify("verified"), 200


#utils
def decode_base64url(input):
    if isinstance(input, str):
        input = input.encode("ascii")

    rem = len(input) % 4

    if rem > 0:
        input += b"=" * (4 - rem)

    return base64.urlsafe_b64decode(input)
