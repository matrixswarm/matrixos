import json
import base64
import time

from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

def generate_aes_key():
    b = get_random_bytes(32)
    return base64.b64encode(b).decode()

def sign_data(payload: dict, priv_key) -> str:
    """
    Signs a payload dictionary using the provided private key object.
    Automatically excludes the 'sig' field from signing.

    Returns:
        Base64-encoded signature string
    """
    payload_to_sign = {k: v for k, v in payload.items() if k != "sig"}
    serialized = json.dumps(payload_to_sign, sort_keys=True, separators=(",", ":")).encode()
    digest = SHA256.new(serialized)

    signature = pkcs1_15.new(priv_key).sign(digest)
    return base64.b64encode(signature).decode()



def build_identity_chain(agent_uid, child_pub_key, parent_priv_key_obj, parent_chain=None):
    chain = []

    if parent_chain:
        chain = list(parent_chain)  # full upstream lineage

    entry = {
        "agent": agent_uid,
        "public_key": child_pub_key,
        "timestamp": int(time.time()),
    }

    payload_to_sign = json.dumps({
        "agent": entry["agent"],
        "public_key": entry["public_key"],
        "timestamp": entry["timestamp"]
    }, sort_keys=True).encode()

    digest = SHA256.new(payload_to_sign)
    signature = pkcs1_15.new(parent_priv_key_obj).sign(digest)
    entry["signature"] = base64.b64encode(signature).decode()

    chain.append(entry)
    return chain

class SignedAgentTreeBuilder:
    def __init__(self, matrix_private_key_obj):
        self.private_key = matrix_private_key_obj

    def sign_tree(self, tree_dict: dict) -> dict:
        signed_time = int(time.time())
        payload = {
            "type": "agent_tree",
            "tree": tree_dict,
            "timestamp": signed_time
        }

        digest = SHA256.new(json.dumps(payload, sort_keys=True).encode())
        signature = pkcs1_15.new(self.private_key).sign(digest)
        payload["sig"] = base64.b64encode(signature).decode()

        return payload

    def write_tree_to_file(self, signed_tree: dict, filepath: str):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(signed_tree, f, indent=2)
        print(f"[TREE-BUILDER] 🧬 Agent tree signed and saved to {filepath}")

def generate_identity_token(agent_uid: str, pub_key_pem: str, matrix_priv_key_obj) -> dict:
    payload = {
        "agent": agent_uid,
        "public_key": pub_key_pem,
        "timestamp": int(time.time())
    }

    digest = SHA256.new(json.dumps(payload, sort_keys=True).encode())
    signature = pkcs1_15.new(matrix_priv_key_obj).sign(digest)
    payload["sig"] = base64.b64encode(signature).decode()

    return payload



def verify_identity_token(token: dict, matrix_pub_key_obj):
    try:
        if not all(k in token for k in ("agent", "public_key", "timestamp", "sig")):
            return False, "Token missing required fields"

        payload = {
            "agent": token["agent"],
            "public_key": token["public_key"],
            "timestamp": token["timestamp"]
        }

        digest = SHA256.new(json.dumps(payload, sort_keys=True).encode())
        signature = base64.b64decode(token["sig"])

        pkcs1_15.new(matrix_pub_key_obj).verify(digest, signature)
        return True, "Valid"
    except Exception as e:
        return False, f"Invalid: {e}"


def encrypt_with_ephemeral_aes(data: dict, remote_pub_pem: str):
    """
    Encrypts a dict with an ephemeral AES key, sealed with remote_pubkey.
    Returns { encrypted_key, payload, nonce, tag } base64-encoded.
    """
    raw = json.dumps(data, sort_keys=True).encode()

    # Ephemeral AES
    aes_key = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(raw)

    # Seal AES key with remote RSA pubkey
    pub_key = RSA.import_key(pem_fix(remote_pub_pem).encode())
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    enc_key = cipher_rsa.encrypt(aes_key)

    return {
        "encrypted_key": base64.b64encode(enc_key).decode(),
        "payload": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher_aes.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def decrypt_with_ephemeral_aes(sealed: dict, local_priv_pem: str) -> dict:
    """
    Decrypts a sealed AES payload produced by encrypt_with_ephemeral_aes.
    Requires the local RSA private key (PEM).
    Returns the original dict.
    """
    # Load RSA privkey
    priv_key = RSA.import_key(pem_fix(local_priv_pem).encode())
    cipher_rsa = PKCS1_OAEP.new(priv_key)

    # Unwrap AES key
    aes_key = cipher_rsa.decrypt(base64.b64decode(sealed["encrypted_key"]))

    # Decrypt AES payload
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=base64.b64decode(sealed["nonce"]))
    plaintext = cipher_aes.decrypt_and_verify(
        base64.b64decode(sealed["payload"]),
        base64.b64decode(sealed["tag"])
    )

    return json.loads(plaintext.decode())

def verify_signed_payload(payload: dict, signature_b64: str, pub_key_obj) -> bool:
    """
    Verifies a payload dict signed with sign_data().
    Automatically excludes the 'sig' field before hashing.
    Raises ValueError if verification fails.
    """
    # strip out "sig" just like sign_data
    payload_to_verify = {k: v for k, v in payload.items() if k != "sig"}
    serialized = json.dumps(payload_to_verify, sort_keys=True, separators=(",", ":")).encode()
    digest = SHA256.new(serialized)

    signature = base64.b64decode(signature_b64)
    pkcs1_15.new(pub_key_obj).verify(digest, signature)

    return True

def generate_signed_payload(payload: dict, priv_key_obj) -> dict:
    """
    Returns a signed payload dictionary.
    Structure:
    {
        "payload": {...},
        "signature": "base64...",
    }
    """
    serialized = json.dumps(payload, sort_keys=True).encode()
    digest = SHA256.new(serialized)
    signature = pkcs1_15.new(priv_key_obj).sign(digest)
    return {
        "payload": payload,
        "signature": base64.b64encode(signature).decode()
    }

#remove \n from certs
def pem_fix(pem_str: str) -> str:
    return pem_str.replace("\\n", "\n") if pem_str else pem_str
