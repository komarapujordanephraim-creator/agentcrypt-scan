import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def issue(payload):
    return jwt.encode(payload, KEY, algorithm="RS256")
