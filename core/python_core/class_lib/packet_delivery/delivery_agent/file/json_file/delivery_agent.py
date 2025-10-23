import os
import json
import uuid
import time
import tempfile
from core.python_core.class_lib.packet_delivery.interfaces.base_delivery_agent import BaseDeliveryAgent
from core.python_core.class_lib.packet_delivery.interfaces.packet_processor import PacketProcessorBase
from core.python_core.mixin.log_method import LogMixin
class DeliveryAgent(BaseDeliveryAgent, LogMixin):
    def __init__(self):
        self._location = None
        self._address = []
        self._packet = None
        self._drop_zone = None
        self._error = None
        self._file_ext = ".json"
        self._filename_prefix = "pk"
        self._custom_metadata = {}
        self._crypto=None
        self._filename_override = None
        self._save_filename=""
        self._sent_packet = "PACKET_NOT_SENT"

    def set_crypto_handler(self, crypto_handler: PacketProcessorBase):
        self._crypto = crypto_handler
        return self

    def set_identifier(self, name: str):
        if not name.endswith(self._file_ext):
            name += self._file_ext
        self._filename_override = name
        return self

    def set_metadata(self, metadata: dict):
        self._file_ext = metadata.get("file_ext", self._file_ext)
        self._filename_prefix = metadata.get("prefix", self._filename_prefix)
        self._custom_metadata = metadata
        return self

    def set_location(self, loc):
        self._location = loc.get("path")
        return self

    def set_address(self, ids):
        self._address = ids if isinstance(ids, list) else [ids]
        return self

    def set_packet(self, packet):
        self._packet = packet
        return self

    def set_drop_zone(self, drop):
        self._drop_zone = drop.get("drop")
        return self

    def get_agent_type(self):
        return "filesystem"

    def get_error_success(self):
        return 1 if self._error else 0

    def get_error_success_msg(self):
        return self._error or "OK"

    def create_loc(self):
        try:
            if not self._location:
                self._error = "[JSON_FILE][ERROR] No base location set"
                return self
            for uid in self._address:
                base_path = os.path.join(self._location, uid)
                if self._drop_zone:
                    base_path = os.path.join(base_path, self._drop_zone)
                os.makedirs(base_path, exist_ok=True)
            self._error = None
        except Exception as e:
            self._error = f"[JSON_FILE][CREATE] Failed: {e}"
        return self

    def get_saved_filename(self) -> str:
        return self._save_filename

    def deliver(self, create=True):

        if create:
            self.create_loc()

        if self._error:
            return self

        try:
            if not self._packet:
                self._error = "[JSON_FILE][DELIVER] No packet assigned"

                return self

            data = self._packet.get_packet()

            if not isinstance(data, dict):
                self._error = "[JSON_FILE][DELIVER] Packet data invalid"

                return self

            try:
                self._crypto.set_logger(self.get_logger())
            except Exception as e:
                pass

            uids = self._address if self._address else [None]
            for uid in uids:

                drop_path = os.path.join(self._location, uid) if uid else self._location
                if self._drop_zone:
                    drop_path = os.path.join(drop_path, self._drop_zone)

                timestamp = int(time.time())

                try:

                    data = self._crypto.prepare_for_delivery(self._packet)

                    fname = self._filename_override or f"{self._filename_prefix}_{timestamp}_{uuid.uuid4().hex}{self._file_ext}"
                    full_path = os.path.join(drop_path, fname)

                    # Optional metadata config
                    indent = self._custom_metadata.get("indent", 2)
                    atomic = self._custom_metadata.get("atomic", True)
                    output_dir = os.path.dirname(full_path)

                    if atomic:
                        self._sent_packet = data

                        with tempfile.NamedTemporaryFile("w", delete=False, dir=output_dir,
                                                         suffix=self._file_ext) as temp_file:


                            json.dump(data, temp_file, indent=indent)
                            temp_file.flush()
                            os.fsync(temp_file.fileno())
                            temp_path = temp_file.name

                        os.replace(temp_path, full_path)

                    else:


                        with open(full_path, "w", encoding="utf-8") as f:
                            self._sent_packet=data
                            json.dump(data, f, indent=indent)
                            f.close()

                    self._save_filename = full_path

                except Exception as e:
                    self._error = f"[DELIVER][WRITE] Failed to write packet: {e}"
                    self.log("Failed to write packet", error=e)

                return self

        except Exception as e:

            self._error = f"[JSON_FILE][DELIVER] Failed: {e}"
            self.log("Failed", error=e)
        return self

    def get_sent_packet(self):
        return self._sent_packet