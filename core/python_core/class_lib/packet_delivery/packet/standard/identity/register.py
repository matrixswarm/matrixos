import time
from core.python_core.class_lib.packet_delivery.interfaces.base_packet import BasePacket

class Packet(BasePacket):

    def set_data(self, data: dict):
        if self._packet:
            raise RuntimeError("[PACKET][ERROR] set_data() must be called before set_packet()")
        try:
            if not data.get("pubkey") or not data.get("bootsig"):
                raise ValueError("Missing 'pubkey' or 'bootsig' in identity payload.")

            self._payload = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "universal_id": data.get("universal_id", "unknown"),
                "pubkey": data["pubkey"],
                "bootsig": data["bootsig"]
            }

            self._data = data

            self._error_code = 0
            self._error_msg = ""
        except Exception as e:
            self._valid = False
            self._error_code = 1
            self._error_msg = str(e)
