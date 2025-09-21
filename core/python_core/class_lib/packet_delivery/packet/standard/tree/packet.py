from core.python_core.class_lib.packet_delivery.interfaces.base_packet import BasePacket

class Packet(BasePacket):

    def set_data(self, data: dict):
        try:

            # Safe defaults
            self._payload = {
                "agent_tree": data.get("agent_tree", {}),
                "services": data.get("services", {}),
            }
            self._data = data
            self._error_code = 0
            self._error_msg = ""
        except Exception as e:
            self._valid = False
            self._error_code = 1
            self._error_msg = str(e)
