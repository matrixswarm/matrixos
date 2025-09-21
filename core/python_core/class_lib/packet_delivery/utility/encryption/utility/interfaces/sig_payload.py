from abc import ABC, abstractmethod
from core.python_core.mixin.log_method import LogMixin
class SigPayload(ABC,LogMixin):
    def __init__(self):
        self._payload = None

    def set_payload(self, payload):
        self._payload = payload

    @abstractmethod
    def get_payload(self) -> bytes:
        pass
