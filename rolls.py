import base64
import json

from cryptography.hazmat.primitives.asymmetric import utils, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key



private_key = load_pem_private_key(open('key', 'rb').read(), password=None)
public_key = load_pem_public_key(open('key.pub', 'rb').read())

#print(private_key)


#private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
#public_key = private_key.public_key()


pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
#print(pem)

pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
#print(pem)

tok_header = {'alg': 'RS256', 'typ': 'JWT'}
tok_payload = {'name': 'garret'}

tok_header = base64.urlsafe_b64encode(json.dumps(tok_header, separators=(',', ':')).encode('utf-8')).replace(b'=', b'')
tok_payload = base64.urlsafe_b64encode(json.dumps(tok_payload, separators=(',', ':')).encode('utf-8')).replace(b'=', b'')

message = tok_header + b'.' + tok_payload

print(message)
print()



signature = private_key.sign(
    message,
    padding.PKCS1v15(),
    hashes.SHA256()
)
print(base64.urlsafe_b64encode(signature).replace(b'=', b''))


ver = public_key.verify(
    signature,
    message,
    padding.PKCS1v15(),
    hashes.SHA256()
)
print(ver)
