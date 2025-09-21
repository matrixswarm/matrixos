import ssl
import io
import tempfile
import os

def load_cert_chain_from_memory(ctx, cert_pem: str, key_pem: str):
    """
    Try loading cert/key from memory. If unsupported, fallback to secure tempfile method.
    """
    try:
        # Preferred: load directly from memory (if OpenSSL/Python supports it)
        ctx.load_cert_chain(
            certfile=io.BytesIO(cert_pem.encode()),
            keyfile=io.BytesIO(key_pem.encode())
        )
        print("[DEBUG] Loaded cert/key from memory")
        return "memory"

    except (TypeError, ssl.SSLError) as mem_err:
        print(f"[WARN] Memory load failed: {mem_err} — falling back to tempfiles")

        # Fallback: write to secure temporary files
        with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as cert_tmp:
            cert_tmp.write(cert_pem.encode())
            cert_tmp.flush()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as key_tmp:
            key_tmp.write(key_pem.encode())
            key_tmp.flush()

        try:
            ctx.load_cert_chain(certfile=cert_tmp.name, keyfile=key_tmp.name)
            print("[DEBUG] Loaded cert/key from tempfile")
            return "tempfile"
        finally:
            os.unlink(cert_tmp.name)
            os.unlink(key_tmp.name)
