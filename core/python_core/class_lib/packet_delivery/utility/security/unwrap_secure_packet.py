import json
import hashlib, time
_replay_cache = {}
_REPLAY_TTL = 314  # seconds for normal transient packets

from Crypto.PublicKey import RSA
from core.python_core.utils.crypto_utils import verify_signed_payload, decrypt_with_ephemeral_aes

def unwrap_secure_packet(outer_packet: dict, remote_pubkey, local_privkey, logger=None):
    """
    Securely unwraps a signed and encrypted packet.

    Options:
        - allow_unsigned: allows packets without a signature (default: False)
        - allow_unencrypted: allows plaintext content (default: True)

    Returns:
        inner_packet (dict) if valid, else False.
    """
    try:

        outer_content = outer_packet.get("content", {})

        if not isinstance(outer_content, dict):
            if logger:
                logger(f"[SECURE][REJECT] outer content not dict: {type(outer_content)}")
            return False

        # Signature check
        sig = outer_content.get("sig")
        try:
            verify_signed_payload({k: v for k, v in outer_content.items() if k != "sig"}, sig, ensure_rsa_key(remote_pubkey))
            timestamp = outer_content.get("timestamp", 0)
            sig = outer_content.get("sig")
            expires = outer_content.get("expires")
            if not _replay_block(sig, timestamp, expires, logger):
                return False

        except Exception as e:
            if logger:
                logger(f"[SECURE][REJECT] Signature verification failed: {type(e).__name__} – {e}")
            return False

        # Decrypt or allow plaintext
        inner = outer_content.get("content")

        # decrypt it
        try:
            inner = decrypt_with_ephemeral_aes(inner, local_privkey)
            if isinstance(inner, str):
                inner = json.loads(inner)

        except Exception as e:

            if logger:
                logger(f"[SECURE][REJECT] AES decrypt failed or malformed JSON: {e}")
            return False

        return inner

    except Exception as e:
        if logger:
            logger(f"[SECURE][FAIL] unwrap failed: {type(e).__name__}: {e}")
        return False

def ensure_rsa_key(key):

    if isinstance(key, str):
        return RSA.import_key(key.encode())
    return key


def _hash_sig(sig: str) -> str:
    return hashlib.sha256(sig.encode()).hexdigest() if sig else None

def _replay_block(sig: str, timestamp: int, expires: int = None, logger=None) -> bool:
    """
    Enforces replay + expiry rules.
    - Normal packets expire after _REPLAY_TTL seconds (default 120)
    - Signed long-lived packets can specify 'expires' timestamp in epoch seconds
    - Rejects duplicates or out-of-window timestamps
    """
    now = int(time.time())
    sig_hash = _hash_sig(sig)

    if not sig_hash:
        if logger:
            logger("[SECURE][REPLAY] Missing or invalid signature hash.")
        return False

    # --- Expiration rule ---
    if expires:  # the packet itself says when it dies
        if now > expires:
            if logger:
                logger(f"[SECURE][EXPIRE] Packet expired at {expires}, now={now}")
            return False
    else:
        # fallback to window rule (too old or future skew)
        if abs(now - timestamp) > _REPLAY_TTL:
            if logger:
                logger(f"[SECURE][REPLAY] Timestamp outside {_REPLAY_TTL}s window (ts={timestamp}, now={now})")
            return False

    # --- Duplicate rule ---
    if sig_hash in _replay_cache:
        if logger:
            logger(f"[SECURE][REPLAY] Duplicate packet hash detected ({sig_hash[:10]}...)")
        return False

    _replay_cache[sig_hash] = now

    # cleanup stale entries
    for h, t in list(_replay_cache.items()):
        if now - t > max(_REPLAY_TTL, 60 * 60 * 24 * 7):  # trim anything older than a week
            _replay_cache.pop(h, None)

    return True
