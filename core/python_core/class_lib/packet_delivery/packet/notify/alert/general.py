# core/class_lib/packet_delivery/packet/notify/alert/general.py
import time
from core.python_core.class_lib.packet_delivery.interfaces.base_packet import BasePacket

class Packet(BasePacket):

    def set_data(self, data: dict):

        try:
            if not data.get("msg"):
                self._valid = False
                self._error_code = 1
                self._error_msg = "Missing required field: 'msg'"
                print(f"[SET_DATA] ERROR: {self._error_msg}")
                return

            self._payload = {
                "server_ip": data.get("server_ip"),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "universal_id": data.get("universal_id", "unknown"),
                "level": data.get("level", "info"),
                "msg": data["msg"],
                "formatted_msg": f"📣 Swarm Message\n{data['msg']}",
                "cause": data.get("cause", "unspecified"),
                "origin": data.get("origin", data.get("universal_id", "unknown")),
                "embed_data": data.get("embed_data", None)
            }
            self._error_code = 0
            self._error_msg = ""
        except Exception as e:
            self._valid = False
            self._error_code = 1
            self._error_msg = str(e)
            print(f"[SET_DATA][EXCEPTION] {e}")
