from core.python_core.class_lib.packet_delivery.interfaces.packet_processor import PacketProcessorBase
class PlaintextProcessor(PacketProcessorBase):

    def has_verified_identity(self) -> bool:
        """Returns True if the packet has a Matrix-verified identity."""
        return False

    def get_sender_uid(self) -> str:
        """Returns the universal_id (agent ID) of the sender if verified, else raises or returns None."""
        return ""

    def prepare_for_processing(self, file_data):
        return file_data