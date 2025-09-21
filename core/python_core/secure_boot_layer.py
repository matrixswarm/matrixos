import json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


def generate_keypair():
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return priv_key, priv_key.public_key()


def serialize_keys(priv, pub):
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()

    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return priv_pem, pub_pem


def load_private_key(pem):
    return serialization.load_pem_private_key(pem.encode(), password=None, backend=default_backend())


def load_public_key(pem):
    return serialization.load_pem_public_key(pem.encode(), backend=default_backend())


def encrypt_blob(data, pub_key):
    if isinstance(data, str):
        data = data.encode()

    return base64.b64encode(
        pub_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    ).decode()


def decrypt_blob(enc_str, priv_key):
    return priv_key.decrypt(
        base64.b64decode(enc_str),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    ).decode()


def receive_key_blob(args):
    import os
    keyfile = args.get("keyfile")
    if keyfile and isinstance(keyfile, str) and os.path.exists(keyfile):
        with open(args['keyfile'], 'r', encoding="utf-8") as f:
            return json.load(f)
    elif 'key_blob' in args:
        return json.loads(args['key_blob'])
    elif 'keypipe' in args:
        with open(args['keypipe'], 'r', encoding="utf-8") as f:
            return json.load(f)
    return None
