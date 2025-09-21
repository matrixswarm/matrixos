from abc import ABC, abstractmethod

class BasePacket(ABC):
    def __init__(self):
        self._valid = True
        self._payload = {}
        self._error_code = 0
        self._error_msg = ""
        self._packet = None
        self._packet_field_name = "content"
        self._data = {}
        self._auto_fill_sub_packet = True

    def is_valid(self) -> bool:
        return self._valid

    def set_packet(self, packet, field_name="content"):
        if field_name:
            self._packet_field_name = field_name
        self._packet = packet
        return self

    def set_auto_fill_sub_packet(self, auto_fill_sub_packet: bool = True):
        self._auto_fill_sub_packet = auto_fill_sub_packet
        return self

    def get_packet(self) -> dict:
        base = self._payload
        if self._packet and self._packet.is_valid():
            if self._auto_fill_sub_packet:
                self._packet.set_data(self._data.get(self._packet_field_name, {}))
            base[self._packet_field_name] = self._packet.get_packet()
        return base

    def get_error_success(self) -> int:
        return self._error_code

    def get_error_success_msg(self) -> str:
        return self._error_msg

    def set_payload_item(self, keyword: str, data) -> None:
        """Attach a field under a keyword (overwrite if already exists)."""
        self._payload[keyword] = data

    def has_payload_item(self, keyword: str) -> bool:
        return keyword in self._payload

    def get_payload_item(self, keyword: str):
        return self._payload.get(keyword)

    @abstractmethod
    def set_data(self, data: dict):
        """
        Only this must be implemented in the subclass.
        Should assign to self._payload and self._data, or set error flags.
        """
        pass