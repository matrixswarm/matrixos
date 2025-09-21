
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from cryptography.hazmat.backends import default_backend
import base64, hashlib, json, os, time, threading, ssl, socket, requests
from typing import Optional, Tuple

# === SPKI (cert pinning) ===
def extract_spki_pin_from_cert(cert_bytes: bytes) -> str:
    # Detect if PEM or DER
    if b"-----BEGIN" in cert_bytes:
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    else:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

    pub_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(pub_der).digest()).decode()

def verify_spki_pin_from_client(
    cert_der: bytes,
    expected_pin: str
) -> Tuple[bool, Optional[str]]:

    try:
        actual = extract_spki_pin_from_cert(cert_der)
        return (actual == expected_pin, actual)
    except Exception:
        return (False, None)

# === Nonce/Replay guard (in-memory per process) ===
class ReplayGuard:
    def __init__(self, window_sec=60, max_entries=2048):
        self.window = window_sec
        self.max_entries = max_entries
        self._seen = {}
        self._lock = threading.Lock()

    def check_and_mark(self, peer_id: str, ts: int, nonce_b64: str) -> bool:
        now = int(time.time())
        if abs(now - int(ts)) > self.window:
            return False
        key = (peer_id, nonce_b64)
        with self._lock:
            if key in self._seen:
                return False
            if len(self._seen) > self.max_entries:
                self._seen.clear()
            self._seen[key] = now
        return True

# === AES-GCM payload ===
def encrypt_payload(payload: dict, recipient_pub_pem: str, sender_priv_pem: str) -> dict:
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    raw = json.dumps(payload, separators=(',', ':')).encode()

    gcm = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = gcm.encrypt_and_digest(raw)

    rpub = RSA.import_key(recipient_pub_pem)
    enc_key = PKCS1_OAEP.new(rpub).encrypt(aes_key)

    signer = pkcs1_15.new(RSA.import_key(sender_priv_pem))
    sig = signer.sign(SHA256.new(raw))

    b64 = lambda b: base64.b64encode(b).decode()
    return {
        "ciphertext": b64(ciphertext),
        "nonce": b64(nonce),
        "tag": b64(tag),
        "encrypted_aes_key": b64(enc_key),
        "signature": b64(sig),
        "ts": int(time.time()),
        "nonce_id": b64(os.urandom(16)),
    }

def decrypt_payload(packet: dict, recipient_priv_pem: str) -> dict:
    b = lambda k: base64.b64decode(packet[k])
    aes_key = PKCS1_OAEP.new(RSA.import_key(recipient_priv_pem)).decrypt(b("encrypted_aes_key"))
    gcm = AES.new(aes_key, AES.MODE_GCM, nonce=b("nonce"))
    raw = gcm.decrypt_and_verify(b("ciphertext"), b("tag"))
    return json.loads(raw.decode())

# === HTTPS helpers (client) with SPKI pin ===
def secure_https_request(host: str, port: int, path: str, method="POST", json_payload=None, expected_spki_pin: str=None, timeout=5.0):
    url = f"https://{host}:{port}{path}"
    ctx = ssl._create_unverified_context()
    s = ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout), server_hostname=host)
    cert_bin = s.getpeercert(binary_form=True); s.close()
    pin = extract_spki_pin_from_cert(cert_bin)
    if pin != expected_spki_pin:
        raise RuntimeError(f"SPKI mismatch: expected {expected_spki_pin}, got {pin}")
    fn = requests.post if method.upper() == "POST" else requests.get
    r = fn(url, json=json_payload, verify=False, timeout=timeout)
    r.raise_for_status()
    return r

# === WSS helper (client) pre-dial pin check ===
def precheck_spki(host: str, port: int, expected_spki_pin: str, timeout=5.0):
    ctx = ssl._create_unverified_context()
    s = ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout), server_hostname=host)
    cert_bin = s.getpeercert(binary_form=True); s.close()
    pin = extract_spki_pin_from_cert(cert_bin)
    if pin != expected_spki_pin:
        raise RuntimeError(f"SPKI mismatch: expected {expected_spki_pin}, got {pin}")
    return True