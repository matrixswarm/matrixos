import base64
import importlib
import traceback
from core.python_core.class_lib.packet_delivery.utility.encryption.config import ENCRYPTION_CONFIG
from core.python_core.class_lib.packet_delivery.utility.crypto_processors.packet_encryption_factory import packet_encryption_factory
from core.python_core.class_lib.packet_delivery.utility.crypto_processors.football import Football

class PacketReceptionFactoryMixin:

    def get_reception_agent(self, path: str, football:Football, new=True):

        try:
            full_path = f"core.python_core.class_lib.packet_delivery.reception_agent.{path}.reception_agent"
            mod = importlib.import_module(full_path)
            agent = mod.ReceptionAgent()
            if new:
                mode = "decrypt" if ENCRYPTION_CONFIG.is_enabled() else "plaintext"
                agent.set_crypto_handler(packet_encryption_factory(mode, football))
                # 🔧 Attach logger from parent if available
                try:
                    agent.set_logger(self.log)
                except Exception as e:
                    pass

            return agent

        except Exception as e:
            if hasattr(self, "log") and callable(getattr(self, "log", None)):
                self.log(f"[RECEPTION][ERROR] Could not import reception agent '{path}'", error=e)
            else:
                print(f"[RECEPTION][ERROR] Could not import reception agent '{path}': {e}")
                traceback.print_exc()
            try:
                from core.python_core.class_lib.packet_delivery.reception_agent.error.reception_agent_not_found import ReceptionAgent as Fallback
                return Fallback(reason=f"Reception agent '{path}' not found.")
            except Exception as fallback_err:
                print(f"[RECEPTION][FAILSAFE] Failed to load fallback reception agent: {fallback_err}")
                return None