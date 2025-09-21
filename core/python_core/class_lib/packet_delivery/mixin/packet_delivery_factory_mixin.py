import base64
from core.python_core.class_lib.packet_delivery.utility.encryption.config import ENCRYPTION_CONFIG
from core.python_core.class_lib.packet_delivery.utility.crypto_processors.packet_encryption_factory import packet_encryption_factory
from core.python_core.class_lib.packet_delivery.utility.crypto_processors.football import Football
import importlib
import traceback

class PacketDeliveryFactoryMixin:

    def get_delivery_agent(self, path: str, football:Football, new=True):

        try:

            full_path = f"core.python_core.class_lib.packet_delivery.delivery_agent.{path}.delivery_agent"
            mod = importlib.import_module(full_path)
            agent = mod.DeliveryAgent()
            if new:
                mode = "encrypt" if ENCRYPTION_CONFIG.is_enabled() else "plaintext_encrypt"
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
                from core.python_core.class_lib.packet_delivery.delivery_agent.error.delivery_agent_not_found import DeliveryAgent as Fallback
                return Fallback(reason=f"Delivery agent '{path}' not found.")
            except Exception as fallback_err:
                print(f"[DELIVERY][FAILSAFE] Failed to load fallback delivery agent: {fallback_err}")
                return None