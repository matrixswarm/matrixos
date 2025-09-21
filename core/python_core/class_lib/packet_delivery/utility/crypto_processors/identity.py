class IdentityObject:
    def __init__(self):
        self._identity = None
        self._identity_sig = None
        self._priv = None
        self._pub = None
        self._sig_verifier_pubkey = None
        self._universal_id = None
        self._verified = False
        self._is_payload_identity = False

    # Setters
    def set_identity(self, identity_dict):
        self._identity = identity_dict
        self._agent = identity_dict.get("agent") if isinstance(identity_dict, dict) else None

    def set_identity_sig(self, sig):
        self._identity_sig = sig

    def set_priv(self, priv_key):
        self._priv = priv_key

    def set_pub(self, pub_key):
        self._pub = pub_key

    def set_sig_verifier_pubkey(self, sig_verifier_pubkey):
        self._sig_verifier_pubkey = sig_verifier_pubkey

    def set_universal_id(self, universal_id):
        self._universal_id = universal_id

    def set_verified(self, status: bool):
        self._verified = bool(status)

    def set_is_payload_identity(self, is_payload_identity: bool):
        self._is_payload_identity = bool(is_payload_identity)

    # Getters
    def get_identity(self):
        return self._identity

    def get_identity_sig(self):
        return self._identity_sig

    def get_priv(self):
        return self._priv

    def get_pub(self):
        return self._pub

    def get_sig_verifier_pubkey(self):
        return self._sig_verifier_pubkey

    def get_universal_id(self):
        return self._universal_id

    def is_verified(self):
        return self._verified

    def is_payload_identity(self):
        return self._is_payload_identity

    # Utilities
    def is_complete(self):
        return all([
            self._identity is not None,
            self._priv is not None,
            self._pub is not None,
            self._sig_verifier_pubkey is not None,
            self._is_payload_identity is not None,
            self._universal_id is not None
        ])

    def to_dict(self):
        return {
            "identity": self._identity,
            'identity_sig': self._identity_sig,
            "priv": self._priv,
            "pub": self._pub,
            "sig_verifier_pubkey": self._sig_verifier_pubkey,
            "universal_id": self._universal_id,
            "verified": self._verified,
            "is_payload_identity": self._is_payload_identity,
        }
