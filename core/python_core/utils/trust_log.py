from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import hashlib
import base64

def get_fp(key):
    if not key:
        return "N/A"
    try:
        raw = base64.b64decode(key) if "BEGIN" not in key else key.encode()
        return hashlib.sha256(raw).hexdigest()[:12]
    except Exception:
        return "ERR"

def log_trust_banner(agent_name, logger, pub, matrix_pub=None, swarm_key=None, matrix_priv=None, private_key=None):
    self_fp     = get_fp(pub)
    matrix_fp   = get_fp(matrix_pub)
    swarm_fp    = get_fp(swarm_key)
    matrix_pvfp = get_fp(matrix_priv)
    private_kp  = get_fp(private_key)

    box = [
        "╔════════════════════════════════════════════╗",
        f"║ 🔐 TRUST LINEAGE - {agent_name:<25}       ║",
        f"║ 🧬 SELF:     {self_fp:<12}                ║",
        f"║ 🧠 MATRIX:   {matrix_fp:<12}              ║",
        f"║ 🔑 M-PRIV:   {matrix_pvfp:<12}            ║",
        f"║ 🧊 SWARM:    {swarm_fp:<12}               ║",
        f"║ 🗝️ PRIV-KEY: {private_kp:<12}            ║",
        "╚════════════════════════════════════════════╝"
    ]


    for line in box:
        logger.log(line)
        print(line)  # Optional: always echo to stdout
