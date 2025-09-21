import json
import os
import time

import json
import os
from core.python_core.secure_boot_layer import receive_key_blob, encrypt_blob, decrypt_blob, load_private_key, load_public_key

class GhostRiderUltraMixin:
    def ghost_init(self):
        """
        Secure encrypted memory boot.
        Loads env paths, reads secure key blob, injects args/tree, parent/matrix pubkeys.
        """
        self.path_resolution = {
            "site_root_path": os.getenv("SITE_ROOT"),
            "agent_path": os.getenv("AGENT_PATH")
        }

        self.secure_keys = receive_key_blob({
            "keypipe": os.getenv("KEYPIPE"),
            "keyfile": os.getenv("KEYFILE"),
            "key_blob": os.getenv("KEY_BLOB")
        })

        if not self.secure_keys:
            raise RuntimeError("[GHOST-INIT] No secure keys received. Boot aborted.")

        payload = self.decrypt_blob(self.secure_keys["payload_blob"])
        self.command_line_args = payload.get("args", {})
        self.tree_node = payload.get("tree_node", {})
        self.parent_pub = payload.get("parent_pub")
        self.matrix_pub = payload.get("matrix_pub")

        self.log("[GHOST-INIT] Secure payload and trust tree injected.")

    def encrypt_for(self, blob: dict, pub_key_pem: str) -> str:
        pub_key = load_public_key(pub_key_pem)
        return encrypt_blob(json.dumps(blob), pub_key)

    def decrypt_blob(self, enc_str: str) -> dict:
        priv_key = load_private_key(self.secure_keys["priv"])
        return json.loads(decrypt_blob(enc_str, priv_key))

    def verify_key_chain(self):
        pass

    def rotate_keys(self):
        pass

    def sign_payload(self, payload: dict) -> str:
        return json.dumps(payload)

    def validate_signature(self, signed_blob: str) -> bool:
        return True
