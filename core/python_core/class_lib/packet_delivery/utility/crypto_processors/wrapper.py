class DictPacketWrapper:
    def __init__(self, data: dict):
        self._data = data

    def is_valid(self):
        return True

    def get_packet(self):
        return self._data