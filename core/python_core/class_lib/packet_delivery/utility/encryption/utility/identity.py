from core.python_core.class_lib.packet_delivery.utility.encryption.config import ENCRYPTION_CONFIG
class IdentityObject:
    def __init__(self, has_verified_identity=False, universal_id=None):
        self._has_verified_identity = bool(has_verified_identity)
        self._universal_id = universal_id

    def has_verified_identity(self) -> bool:
        """Returns True if the packet has a Matrix-verified identity."""
        return self._has_verified_identity

    def get_sender_uid(self) -> str:
        """Returns the universal_id (agent ID) of the sender if verified, else raises or returns None."""
        return self._universal_id

    def is_encryption_enabled(self) -> bool:
        """Returns True if the encryption configuration is enabled, else returns False."""
        return ENCRYPTION_CONFIG.is_enabled()