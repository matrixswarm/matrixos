# core_spawner_patch.py

import os
import json
import uuid
import tempfile
from core.python_core.secure_boot_layer import generate_keypair, serialize_keys, encrypt_blob

class CoreSpawnerSecureMixin:
    def __init__(self):
        self._trust_tree = {
            "matrix": None,
            "parent": None
        }

    def set_trust_tree(self, trust_dict):
        """
        Expects: {"matrix": matrix_pubkey_pem, "parent": parent_pubkey_pem}
        """
        if "matrix" in trust_dict:
            self._trust_tree["matrix"] = trust_dict["matrix"]
        if "parent" in trust_dict:
            self._trust_tree["parent"] = trust_dict["parent"]

    def prepare_secure_spawn(self, agent_name, universal_id, spawner, tree_node, site_root_path, agent_path):
        # 🔐 Generate child keypair
        priv_key, pub_key = generate_keypair()
        priv_str, pub_str = serialize_keys(priv_key, pub_key)

        # 🔐 Encrypt payload
        payload = {
            "args": {
                "universal_id": universal_id,
                "agent_name": agent_name,
                "matrix": "matrix",
                "spawner": spawner
            },
            "tree_node": tree_node,
            "parent_pub": self._trust_tree.get("parent"),
            "matrix_pub": self._trust_tree.get("matrix")
        }

        encrypted_blob = encrypt_blob(json.dumps(payload), pub_key)

        secure_key_blob = {
            "priv": priv_str,
            "pub": pub_str,
            "payload_blob": encrypted_blob
        }

        key_file = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix=".key", prefix=f"{universal_id}_")
        key_file.write(json.dumps(secure_key_blob))
        key_file.close()

        env = os.environ.copy()
        env.update({
            "KEYFILE": key_file.name,
            "SITE_ROOT": site_root_path,
            "AGENT_PATH": agent_path
        })

        return env, pub_str
