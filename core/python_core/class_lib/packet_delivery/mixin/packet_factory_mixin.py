import importlib
import traceback
from core.python_core.class_lib.packet_delivery.packet.error.packet_not_found import Packet as ErrorPacket

class PacketFactoryMixin:
    def __init__(self):
        self._last_packet = None

    def get_delivery_packet(self, dotted_path: str, new=True):
        """
        Loads packet object from dotted path: 'notify/alert/general'
        Falls back to packet/error/packet_not_found.py
        """
        try:
            full_path = f"core.python_core.class_lib.packet_delivery.packet.{dotted_path}"
            mod = importlib.import_module(full_path)
            packet = mod.Packet()
            if new:
                return packet
            else:
                self._last_packet = packet
                return self._last_packet
        except Exception as e:
            print(f"[PACKET][ERROR] Could not import {dotted_path}: {e}")
            traceback.print_exc()
            try:
                return ErrorPacket(reason=f"Packet '{dotted_path}' not found.")
            except Exception as fallback_err:
                print(f"[PACKET][FAILSAFE] Failed to load error packet: {fallback_err}")
                return None

