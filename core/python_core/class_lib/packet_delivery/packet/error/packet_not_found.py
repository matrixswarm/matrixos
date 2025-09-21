from core.python_core.class_lib.packet_delivery.interfaces.base_packet import BasePacket

class Packet(BasePacket):
    def __init__(self, reason="Packet type not found."):
        self._reason = reason

    def is_valid(self) -> bool:
        return False

    def set_data(self, data):
        pass  # No-op

    def set_packet(self, packet):
        pass  # No-op

    def get_packet(self) -> dict:
        return {}

    def get_error_success(self) -> int:
        return 1

    def get_error_success_msg(self) -> str:
        return self._reason