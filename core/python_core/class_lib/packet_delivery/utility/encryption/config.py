from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes, PrivateKeyTypes
class EncryptionConfig:
    _instance = None
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EncryptionConfig, cls).__new__(cls)

            cls._instance._enabled = False
            cls._instance._pub = None
            cls._instance._priv = None
            cls._instance._matrix_pub = None
            cls._instance._matrix_priv = None
            cls._instance._swarm_key = None
            cls._instance._private_key = None

        return cls._instance

    def set_swarm_key(self, key: str):
        self._swarm_key = key

    def get_swarm_key(self):
        return self._swarm_key

    def set_private_key(self, key: str):
        self._private_key = key

    def get_private_key(self):
        return self._private_key

    def set_pub(self, key):
        self._pub = key

    def get_pub(self):
        return self._pub

    def set_priv(self, key):
        self._priv = key

    def get_priv(self):
        return self._priv

    def set_matrix_pub(self, key):
        self._matrix_pub = key

    def get_matrix_pub(self):
        return self._matrix_pub

    def set_matrix_priv(self, key):
        self._matrix_priv = key

    def get_matrix_private_key(self):
        return self._matrix_priv

    def set_enabled(self, enabled: bool=True):
        self._enabled=bool(enabled)

    def is_enabled(self) -> bool:
        return self._enabled


ENCRYPTION_CONFIG = EncryptionConfig()