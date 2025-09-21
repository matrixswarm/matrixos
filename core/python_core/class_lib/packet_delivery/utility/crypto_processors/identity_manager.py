from core.python_core.class_lib.packet_delivery.utility.crypto_processors.identity import IdentityObject

class IdentityManager:
    def __init__(self):
        self._identities = {}

    def add(self, key: str, identity_obj):
        if not isinstance(identity_obj, IdentityObject):
            raise TypeError(f"[IDENTITY_MANAGER] Entry for '{key}' must be an IdentityObject, not {type(identity_obj)}")
        self._identities[key] = identity_obj

    def get_identity(self, key: str) -> IdentityObject:
        return self._identities.get(key)

    def all(self):
        return self._identities

    def keys(self):
        return self._identities.keys()

    def values(self):
        return self._identities.values()

    def items(self):
        return self._identities.items()

    def __getitem__(self, key):
        return self._identities[key]

    def __setitem__(self, key, value):
        self.add(key, value)

    def __contains__(self, key):
        return key in self._identities

    def __len__(self):
        return len(self._identities)

    def __iter__(self):
        return iter(self._identities)
