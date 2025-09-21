from core.python_core.class_lib.packet_delivery.interfaces.base_packet import BasePacket
import time

class Packet(BasePacket):
    def __init__(self):
        self._data = {}
        self._error = None

    def is_valid(self) -> bool:
        return True

    def set_packet(self, data: dict):
        self._data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "species": data.get("species", "GODZILLA"),
            "threat_level": data.get("threat_level", "OMEGA"),
            "summoned_by": data.get("universal_id", "unknown"),
            "message": f"⚠️ KAIJU PROTOCOL TRIGGERED\n{data.get('msg', 'Unknown seismic anomaly')}"
        }

    def get_packet(self) -> dict:
        return self._data

    def get_error_success(self) -> int:
        return 0

    def get_error_success_msg(self) -> str:
        return "Kaiju packet formed successfully"