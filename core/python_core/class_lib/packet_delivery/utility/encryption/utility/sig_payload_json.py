import json
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.interfaces.sig_payload import SigPayload

class SigPayloadJson(SigPayload):

    def get_payload(self) -> bytes:

        try:
            return json.dumps(self._payload, sort_keys=True).encode()
        except Exception as e:
            raise ValueError(e)

