import json
import base64
import rsa

def sign_packet(privkey_pem: str, handler: str, timestamp: float, content: dict) -> str:
    data = json.dumps({"handler": handler, "timestamp": timestamp, "content": content}, sort_keys=True).encode()
    priv = rsa.PrivateKey.load_pkcs1(privkey_pem.encode())
    signature = rsa.sign(data, priv, 'SHA-256')
    return base64.b64encode(signature).decode()


def _load_pubkey_any(pem_str: str) -> rsa.PublicKey:
    s = pem_str.strip()
    if "BEGIN PUBLIC KEY" in s:  # PKCS#8 / SPKI
        return rsa.PublicKey.load_pkcs1_openssl_pem(s.encode())
    # Otherwise assume PKCS#1
    return rsa.PublicKey.load_pkcs1(s.encode())

def verify_packet_signature(pubkey_pem: str, handler: str, timestamp, content, sig_b64: str) -> bool:
    try:
        # Detect and load the key
        s = pubkey_pem.strip()
        if "BEGIN PUBLIC KEY" in s:
            key_type = "PKCS#8"
        elif "BEGIN RSA PUBLIC KEY" in s:
            key_type = "PKCS#1"
        else:
            key_type = "Unknown/Derived"

        pub = _load_pubkey_any(pubkey_pem)

        # Log detected key type for ACL/debug purposes
        print(f"[ACL-VERIFY] Using {key_type} public key for handler '{handler}'")

        # Build the exact same byte string that was signed
        data = json.dumps(
            {"handler": handler, "timestamp": timestamp, "content": content},
            sort_keys=True
        ).encode()

        signature = base64.b64decode(sig_b64)
        rsa.verify(data, signature, pub)
        return True

    except Exception as e:
        print(f"[ACL-VERIFY][ERROR] Verification failed for handler '{handler}': {e}")
        return False