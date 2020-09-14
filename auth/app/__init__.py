import base64
import datetime
import json

from flask import Flask, abort, jsonify, make_response

from cryptography.hazmat.primitives.asymmetric import utils, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

app = Flask(__name__)

@app.route('/')
def index():

    return "Hello, Auth!"


@app.route('/get_token')
def get_token():
    tok_header = {"alg": "RS256", "typ": "JWT"}
    tok_payload = {"name": "garret"}

    tok_header = base64.urlsafe_b64encode(json.dumps(tok_header, separators=(',', ':')).encode('utf-8')).replace(b'=', b'')
    tok_payload = base64.urlsafe_b64encode(json.dumps(tok_payload, separators=(',', ':')).encode('utf-8')).replace(b'=', b'')

    message = tok_header + b'.' + tok_payload

    private_key = load_pem_private_key(open('key', 'rb').read(), password=None)
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    message = message + b'.' + base64.urlsafe_b64encode(signature).replace(b'=', b'')

    return message
