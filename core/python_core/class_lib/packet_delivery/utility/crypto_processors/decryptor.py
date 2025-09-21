from core.python_core.class_lib.packet_delivery.interfaces.packet_processor import PacketProcessorBase
from core.python_core.class_lib.packet_delivery.utility.crypto_processors.football import Football
from core.python_core.class_lib.packet_delivery.utility.encryption.packet_crypto_mixin import PacketCryptoMixin
from core.python_core.mixin.log_method import LogMixin
class PacketDecryptor(PacketProcessorBase, LogMixin):
    def __init__(self, football:Football):

        self.football=football

        self._packet_crypto_mixin = None

    def prepare_for_processing(self, file_data):

           self._packet_crypto_mixin = PacketCryptoMixin()

           try:
               self._packet_crypto_mixin.set_logger(self.get_logger())
           except Exception as e:
               pass

           return self._packet_crypto_mixin.set_football(self.football).unpack_secure_packet(file_data)

    def has_verified_identity(self) -> bool:
        """Returns True if the packet has a Matrix-verified identity."""
        r = False
        try:
            r = self._packet_crypto_mixin.has_verified_identity()
        except Exception as e:
            pass

        return r

    def get_sender_uid(self) -> str:
        """Returns the universal_id (agent ID) of the sender if verified, else raises or returns None."""
        r = None
        try:

            r = self._packet_crypto_mixin.get_sender_uid()

        except Exception as e:
            pass

        return r