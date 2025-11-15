# Authored by Daniel F MacDonald and ChatGPT-5 aka The Generals
import base64
import os, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class AESHandlerBytesShim:
    """Shim AESHandler to accept and return bytes like old encrypt/decrypt."""
    def __init__(self, key_b64: str):
        self._handler = AESHandler(key_b64)
    def encrypt(self, raw_bytes: bytes) -> bytes:
        # Take bytes, base64 encode, encrypt as string, store JSON as bytes
        enc = self._handler.encrypt(base64.b64encode(raw_bytes).decode('utf-8'))
        return json.dumps(enc, separators=(",", ":")).encode('utf-8')
    def decrypt(self, enc_bytes: bytes) -> bytes:
        # Load JSON dict, decrypt, base64 decode back to bytes
        enc = json.loads(enc_bytes.decode('utf-8'))
        b64_str = self._handler.decrypt(enc)
        return base64.b64decode(b64_str)


class AESHandler:
    """
    Simple AES-256-GCM compatible encrypt/decrypt handler for agents.
    Uses directive-provided symmetric key from config.symmetric_encryption.key.
    """

    def __init__(self, key_b64: str):
        if not key_b64:
            raise ValueError("AESHandler requires a base64-encoded key.")
        # store 32-byte AES key
        self.key = base64.b64decode(key_b64)
        if len(self.key) not in (16, 24, 32):
            raise ValueError(f"Invalid AES key length: {len(self.key)} bytes")

    def encrypt(self, plaintext: str) -> dict:
        """Encrypt text with AES-CBC and PKCS7 padding; returns dict for JSON storage."""
        try:
            iv = os.urandom(16)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
            return {
                "alg": "AES-CBC",
                "iv": base64.b64encode(iv).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            }
        except Exception as e:
            raise RuntimeError(f"AES encryption failed: {e}")

    def decrypt(self, enc_dict: dict) -> str:
        """Decrypt dict output from encrypt(); returns plaintext string."""
        try:
            iv = base64.b64decode(enc_dict.get("iv", ""))
            ciphertext = base64.b64decode(enc_dict.get("ciphertext", ""))
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return plaintext.decode("utf-8", errors="ignore")
        except Exception as e:
            raise RuntimeError(f"AES decryption failed: {e}")

    def generate_aes_key(self):
        b = get_random_bytes(32)
        return base64.b64encode(b).decode()