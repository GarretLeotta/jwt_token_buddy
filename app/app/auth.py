import datetime
import os
import hashlib
import codecs
from functools import wraps

#importing current_app here could be controversial
from flask import current_app, request, jsonify
from bson.objectid import ObjectId
from bson.errors import InvalidId

from app import utils


class AuthorizationError(Exception):
    pass


#Authentication Decorators
"""
HASH( SALT + PASS )
"""
def auth_user(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.authorization:
            raise AuthorizationError("Access Denied")
        if not request.authorization.username or not request.authorization.password:
            raise AuthorizationError("Access Denied")
        try:
            userId = ObjectId(request.authorization.username)
        except InvalidId:
            raise AuthorizationError("Access Denied")
        password = request.authorization.password

        user = current_app.mongo.db.users.find_one({'_id': userId})
        if user == None:
            raise AuthorizationError(f"Access Denied")

        inHash = hashlib.sha256()
        #next line can theoretically fail, but we assume that data in DB is good :)
        inHash.update(bytes.fromhex(user['salt']))
        inHash.update(password.encode('utf-8', errors='ignore'))

        if inHash.digest() != bytes.fromhex(user['password']):
            raise AuthorizationError("Access Denied")
        else:
            return f(*args, **kwargs)
    return decorated


def auth_email(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.authorization:
            raise AuthorizationError("Access Denied")
        email = request.authorization.username
        password = request.authorization.password
        user = current_app.mongo.db.users.find_one({'email': email})
        if user == None:
            raise AuthorizationError(f"Access Denied")

        inHash = hashlib.sha256()
        inHash.update(bytes.fromhex(user['salt']))
        inHash.update(password.encode('utf-8', errors='ignore'))

        if inHash.digest() != bytes.fromhex(user['password']):
            raise AuthorizationError("Access Denied")
        else:
            return f(*args, **kwargs)
    return decorated

"""
New authorization api
auth_wrappers + auth_methods
"""
#Accept any authorization method from a list
def auth_or(*authMethods):
    def decorated(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if any([authM() for authM in authMethods]):
                return f(*args, **kwargs)
            else:
                raise AuthorizationError("Access Denied")
        return wrapper
    return decorated

def user():
    if not request.authorization:
        return False
    userId = ObjectId(request.authorization.username)
    password = request.authorization.password
    user = current_app.mongo.db.users.find_one({'_id': userId})
    if user == None:
        return False

    inHash = hashlib.sha256()
    inHash.update(bytes.fromhex(user['salt']))
    inHash.update(password.encode('utf-8'))

    return inHash.digest() == bytes.fromhex(user['password'])

def email():
    if not request.authorization:
        return False
    email = request.authorization.username
    password = request.authorization.password
    user = current_app.mongo.db.users.find_one({'email': email})
    if user == None:
        return False

    inHash = hashlib.sha256()
    inHash.update(bytes.fromhex(user['salt']))
    inHash.update(password.encode('utf-8'))
    return inHash.digest() == bytes.fromhex(user['password'])



#Generator Utilities
def gen_salt():
    return codecs.encode(os.urandom(16), 'hex').decode()

def genConfToken(userDto):
    """ Hash 16 random bytes + user Email to create the confirmation token """
    inHash = hashlib.sha256()
    inHash.update(os.urandom(16))
    inHash.update(userDto['email'].encode('utf-8'))
    tokenHex = codecs.encode(inHash.digest(), 'hex').decode()
    expiry = datetime.datetime.now()+datetime.timedelta(days=7)
    return {
        "token": tokenHex,
        "expiry": expiry
    }
