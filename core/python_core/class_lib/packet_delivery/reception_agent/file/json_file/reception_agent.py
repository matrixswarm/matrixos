import os
import json
from core.python_core.class_lib.packet_delivery.interfaces.packet_processor import PacketProcessorBase
from core.python_core.class_lib.packet_delivery.interfaces.base_reception_agent import BaseReceptionAgent
from core.python_core.mixin.log_method import LogMixin
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class ReceptionAgent(BaseReceptionAgent, LogMixin):
    def __init__(self):
        self._location = None
        self._address = []
        self._packet = None
        self._drop_zone = None
        self._error = None
        self._file_ext = ".json"
        self._filename_prefix = "packet"
        self._custom_metadata = {}
        self._crypto = None
        self._filename_override = None

    def set_crypto_handler(self, crypto_handler: PacketProcessorBase):
        self._crypto = crypto_handler
        return self

    def set_identifier(self, name: str):
        # Only accept base filename — strip paths or reject if invalid
        base_name = os.path.basename(name)

        # Optional: strictly enforce no slashes (safer than basename stripping)
        if "/" in name or "\\" in name:
            raise ValueError(f"Invalid identifier: must be filename only, not a path → got '{name}'")

        if not base_name.endswith(self._file_ext):
            base_name += self._file_ext

        self._filename_override = base_name
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
    def get_identity(self):
        try:
            return IdentityObject(self.has_verified_identity(), self.get_sender_uid() )
        except Exception:
            pass

    def has_verified_identity(self) -> bool:
        """Returns True if the packet has a Matrix-verified identity."""
        r = False
        try:
            r = self._crypto.has_verified_identity()
        except Exception as e:
            pass

        return r

    def get_sender_uid(self) -> str:
        """Returns the universal_id (agent ID) of the sender if verified, else raises or returns None."""
        r = None
        try:

            r = self._crypto.get_sender_uid()

        except Exception as e:
            pass

        return r

    def receive(self):
        try:

            if self._error:
                self.log(f"{self._error}")
                return None

            uids = self._address if self._address else [None]

            try:
                self._crypto.set_logger(self.get_logger())
            except Exception as e:
                pass

            for uid in uids:

                drop_path = os.path.join(self._location, uid) if uid else self._location
                if self._drop_zone:
                    drop_path = os.path.join(drop_path, self._drop_zone)


                for fname in os.listdir(drop_path):

                    # Enforce file extension
                    if not fname.endswith(self._file_ext):
                        self.log(f"if not fname.endswith(self._file_ext):{self._file_ext}")
                        continue

                    # Enforce exact filename match if an override is set
                    if self._filename_override and fname != self._filename_override:
                        continue

                    full_path = os.path.join(drop_path, fname)

                    with open(full_path, "r", encoding="utf-8") as f:
                        raw_data = json.load(f)
                        f.close()

                    try:
                        # decrypt and set packet
                        data = self._crypto.prepare_for_processing(raw_data)
                        self._packet.set_data(data)
                        return self._packet

                    except Exception as e:
                        self.log(f"[RECEIVE][DEBUG] Failed to load packet for UID: {uid}, drop: {self._drop_zone}")
                        self.log(f"[RECEIVE][DEBUG] Crypto handler: {self._crypto}")
                        self.log(f"[RECEIVE][DEBUG] Filename override: {self._filename_override}")
                        self.log(f"Exception while decrypting '{fname}'")
                        self.log("", error=e)
                        return None


        except Exception as e:
            self.log(error=e)
            return None