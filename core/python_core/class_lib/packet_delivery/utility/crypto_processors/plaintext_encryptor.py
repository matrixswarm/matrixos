class PacketEncryptorPlaintext:
    def prepare_for_delivery(self, packet_obj):
        return packet_obj.get_packet()