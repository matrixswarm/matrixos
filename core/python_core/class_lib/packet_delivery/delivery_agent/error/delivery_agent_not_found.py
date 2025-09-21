from abc import ABC

from core.python_core.class_lib.packet_delivery.interfaces.base_delivery_agent import BaseDeliveryAgent
from core.python_core.class_lib.packet_delivery.interfaces.packet_processor import PacketProcessorBase

class DeliveryAgent(BaseDeliveryAgent, ABC):
    def __init__(self, reason="Delivery agent type not found."):
        self._error = reason

    def set_metadata(self, metadata: dict):
        return self

    def set_crypto_handler(self, crypto_handler: PacketProcessorBase):
        return self

    def set_identifier(self, name: str):
        return self

    def set_location(self, loc):
        return self

    def set_address(self, ids):
        return self

    def set_packet(self, packet):
        return self

    def set_drop_zone(self, drop):
        return self

    def get_agent_type(self):
        return "error"

    def get_error_success(self):
        return 1

    def get_error_success_msg(self):
        return self._error

    def create_loc(self):
        return self

    def deliver(self, create=True):
        return self