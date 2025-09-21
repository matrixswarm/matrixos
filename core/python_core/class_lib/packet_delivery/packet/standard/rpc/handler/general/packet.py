from core.python_core.class_lib.packet_delivery.interfaces.base_packet import BasePacket
import time
class Packet(BasePacket):

    def set_data(self, data: dict):
        try:
            required = ["handler"]
            for r in required:
                if r not in data:
                    raise ValueError(f"Missing required field: {r}")

            self._payload = {
                "timestamp": int(time.time()),
                "handler": data.get('handler'),
                "origin": data.get('origin', "none"),
                "content": data.get('content'),
                # if set locate the service under core.python_core.* and inject data then inject inside handler
            }
            self._data = data
            self._error_code = 0
            self._error_msg = ""
        except Exception as e:
            self._valid = False
            self._error_code = 1
            self._error_msg = str(e)