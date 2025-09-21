import time
from core.python_core.class_lib.packet_delivery.interfaces.base_packet import BasePacket

class Packet(BasePacket):
    """
    A standardized packet for reporting the status of a monitored service.
    This is intended for machine-to-machine communication.
    """
    def set_data(self, data: dict):
        """
        Sets the structured status data for the event.

        Required fields in data:
        - source_agent (str): The universal_id of the reporting agent.
        - service_name (str): The name of the service being monitored.
        - status (str): A machine-readable status (e.g., "UP", "DOWN").
        - severity (str): The importance of the event (e.g., "INFO", "CRITICAL").
        """
        try:
            required = ["source_agent", "service_name", "status", "severity"]
            for r in required:
                if r not in data:
                    raise ValueError(f"Missing required field: {r}")

            self._payload = {
                "timestamp": int(time.time()),
                "source_agent": data["source_agent"],
                "service_name": data["service_name"],
                "status": data["status"].upper(),
                "details": data.get("details", ""),
                "metrics": data.get("metrics", {}),
                "severity": data["severity"],
            }

            self._data = data
            self._error_code = 0
            self._error_msg = ""
        except Exception as e:
            self._valid = False
            self._error_code = 1
            self._error_msg = str(e)