from core.python_core.class_lib.packet_delivery.utility.encryption.packet_crypto_mixin import PacketCryptoMixin
from core.python_core.class_lib.packet_delivery.utility.crypto_processors.football import Football
from core.python_core.class_lib.packet_delivery.interfaces.packet_processor import PacketEncryptorBase
from core.python_core.class_lib.packet_delivery.interfaces.base_packet import BasePacket
from core.python_core.mixin.log_method import LogMixin
class PacketEncryptor(PacketEncryptorBase, LogMixin):
    def __init__(self, football: Football):

        self.football = football
        self._packet_crypto_mixin = None

    def prepare_for_delivery(self, packet_obj:BasePacket):

        self._packet_crypto_mixin = PacketCryptoMixin()

        try:
            self._packet_crypto_mixin.set_logger(self.get_logger())
        except Exception as e:
            pass

        return self._packet_crypto_mixin.set_football(self.football).build_secure_packet(packet_obj.get_packet())
