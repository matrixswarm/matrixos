# matrix.py (or a utils module imported by Matrix)
import json
import base64
import time
import rsa  # pip install rsa

def verify_packet_signature(pk: dict, pubkey_pem: str,
                            *, max_clock_skew_sec: int = 300,
                            require_cmd_prefix: bool = True) -> bool:
    """
    Verify a packet's signature.

    Call site: verify_packet_signature(pk, self._signing_keys["remote_pubkey"])

    Raises:
        ValueError on any failure (bad shape, b64, timestamp skew, handler policy, or verify fail)
    Returns:
        True on success
    """
    if not isinstance(pk, dict):
        raise ValueError("bad_packet_type")

    handler = pk.get("handler")
    timestamp = pk.get("timestamp")
    content = pk.get("content", {})
    sig_b64 = pk.get("sig")

    # Shape checks
    if not isinstance(handler, str) or not handler:
        raise ValueError("bad_handler")
    if require_cmd_prefix and not handler.startswith("cmd_"):
        raise ValueError("handler_not_command")
    if timestamp is None:
        raise ValueError("missing_timestamp")

    # Timestamp skew (optional)
    if max_clock_skew_sec is not None:
        try:
            dt = abs(float(timestamp) - time.time())
        except Exception:
            raise ValueError("bad_timestamp")
        if dt > max_clock_skew_sec:
            raise ValueError(f"timestamp_skew_{int(dt)}s")

    # Canonical bytes (must match signer)
    try:
        data = json.dumps(
            {"handler": handler, "timestamp": timestamp, "content": content},
            sort_keys=True
        ).encode("utf-8")
    except Exception:
        raise ValueError("bad_content_serialization")

    # Fix base64 padding and decode
    if not isinstance(sig_b64, str) or not sig_b64.strip():
        raise ValueError("missing_signature")
    s = sig_b64.strip().replace("\n", "").replace("\r", "")
    missing = len(s) % 4
    if missing:
        s += "=" * (4 - missing)
    try:
        sig = base64.b64decode(s, validate=True)
    except Exception:
        # last chance, non-strict
        try:
            sig = base64.b64decode(s)
        except Exception:
            raise ValueError("bad_signature_b64")

    # Load public key (PKCS#8/SPKI or PKCS#1)
    if not isinstance(pubkey_pem, str) or "BEGIN" not in pubkey_pem:
        raise ValueError("bad_pubkey")
    pem = pubkey_pem.strip().encode()
    try:
        if b"BEGIN PUBLIC KEY" in pem:
            pub = rsa.PublicKey.load_pkcs1_openssl_pem(pem)  # PKCS#8/SPKI
        else:
            pub = rsa.PublicKey.load_pkcs1(pem)              # PKCS#1
    except Exception:
        raise ValueError("bad_pubkey_format")

    # Verify (raises rsa.VerificationError on failure)
    try:
        rsa.verify(data, sig, pub)
    except Exception:
        raise ValueError("verify_failed")

    return True
