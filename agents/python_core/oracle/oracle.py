# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Gemini, code enhancements and Docstrings
import sys
import os
import threading

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))
import time
from core.python_core.utils.swarm_sleep import interruptible_sleep
from openai import OpenAI
from core.python_core.boot_agent import BootAgent
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

MAX_TOKENS = 12000  # safely below the 8k-ish window

class Agent(BootAgent):
    """
    Acts as a gateway to a Large Language Model (LLM) for the swarm.

    This agent receives prompts from other agents, queries the configured
    OpenAI model (e.g., gpt-3.5-turbo), and delivers the AI-generated
    response back to the requesting agent. It enables other agents to leverage
    advanced AI for tasks like reasoning, content generation, and analysis.
    """
    def __init__(self):
        """
        Initializes the Oracle agent and the OpenAI client.

        This method loads the OpenAI API key from the agent's configuration
        or an environment variable and instantiates the OpenAI client used
        to communicate with the LLM API.
        """
        super().__init__()

        try:
            self.AGENT_VERSION = "2.0"

            self._cfg_lock = threading.Lock()

            config = self.tree_node.get("config", {})

            self.api_key = config.get("api_key")
            self.model = config.get("model", "gpt-3.5-turbo")
            self.temperature = config.get("temperature",0)
            self.response_mode = config.get("response_mode", "terse")
            self.client = OpenAI(api_key=self.api_key)

            self.processed_query_ids = set()
            self.outbox_path = os.path.join(self.path_resolution["comm_path_resolved"], "outbox")
            os.makedirs(self.outbox_path, exist_ok=True)
            self.use_dummy_data = False
            self._emit_beacon = self.check_for_thread_poke("worker", timeout=60, emit_to_file_interval=10)
        except Exception as e:
            self.log(error=e, block='main_try', level='ERROR')


    def post_boot(self):
        self.log(f"{self.NAME} v{self.AGENT_VERSION} – have a cookie.")

    def worker_pre(self):
        """
        A one-time setup hook that runs before the main worker loop starts.

        This method performs a critical health check to ensure that an OpenAI
        API key has been successfully loaded. If no key is found, it logs a
        warning, indicating that the agent will not be functional.
        """
        if not self.api_key:
            self.log("[ORACLE][ERROR] No API key detected. Is your .env loaded?")
        else:
            self.log("[ORACLE] Pre-boot hooks initialized.")

    def worker_post(self):
        """A one-time hook that runs after the agent's main loops have exited."""
        self.log("[ORACLE] Oracle shutting down. No more prophecies today.")

    def cmd_msg_prompt(self, content, packet, identity: IdentityObject = None):
        """
        Oracle analysis using NEW multi-message format only.
        Expected content:
          {
            "messages": [...],         # list of chat messages
            "query_id": "...",
            "return_handler": "...",
            "session_id": "...",
            "token": "...",
            "rpc_role": "hive.rpc"    # optional override
          }
        """

        try:

            self.log("[ORACLE] Reflex prompt received.")
            # --- Mode selection ---
            use_callback = bool(content.get("use_callback", False))

            messages = content.get("messages")
            return_handler = content.get("return_handler")
            response_mode = (content.get("response_mode") or self.response_mode or "terse").lower()
            query_id = content.get("query_id", 0)
            session_id = content.get("session_id","")
            token = content.get("token", "")

            # Resolve target uid (for swarm-mode only)
            target_uid = None
            if not use_callback:
                if not self.encryption_enabled:
                    # plaintext swarm – target specified directly
                    target_uid = content.get("target_universal_id", False)
                else:
                    # encrypted swarm – require verified identity
                    if isinstance(identity, IdentityObject) and identity.has_verified_identity():
                        target_uid = identity.get_sender_uid()

            # In swarm mode we require a target to send packet to
            if not use_callback and not target_uid:
                self.log("[ORACLE][ERROR] target_universal_id missing. Cannot respond in swarm mode.")
                return

            if not isinstance(messages, list) or not messages:
                self.log(f"[ORACLE][ERROR] Missing or invalid messages array (query_id={query_id}, universal_id={target_uid}).")
                return

            self.log(f"[ORACLE] Received {len(messages)} chat chunks (query_id={query_id}).")
            self.log(f"[ORACLE] Response mode: {response_mode}")

            # ---- Truncation safeguard ----
            total_chars = sum(len(m.get("content", "")) for m in messages)
            if total_chars > 12000:
                self.log(f"[ORACLE] ✂️ Truncating oversized prompt ({total_chars} chars).")
                messages = messages[:1] + messages[-5:]

            # ---- OpenAI Call ----
            with self._cfg_lock:
                client = self.client
                model = self.model
                temperature = self.temperature

            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature
            ).choices[0].message.content.strip()

            if use_callback:
                self.log(f"[ORACLE] ✅ Completed analysis for Phoenix.")
            else:
                self.log(f"[ORACLE] ✅ Completed analysis for {query_id}.")

            # --- CALLBACK MODE (Phoenix / GUI) ---
            if use_callback:
                payload = {
                    "query_id": query_id,
                    "response": response,
                    "origin": self.command_line_args.get("universal_id", "oracle"),
                    "response_mode": response_mode,
                }

                ok = self.crypto_reply(
                    response_handler=return_handler,
                    payload=payload,
                    session_id=session_id,
                    token=token,
                    rpc_role=self.tree_node.get("config", {}).get("rpc_router_role", "hive.rpc")
                )

                if ok:
                    self.log(f"[ORACLE] Sent callback reply → {return_handler} (session={session_id}, token={token})")
                else:
                    self.log("[ORACLE][ERROR] crypto_reply failed for callback mode.")

            else:

                # --- SWARM MODE (original behavior) ---
                pk_resp = self.get_delivery_packet("standard.command.packet")
                pk_resp.set_data({
                    "handler": return_handler,  # This is what the recipient will process
                    "packet_id": int(time.time()),
                    "content": {
                        "query_id": query_id,
                        "response": response,
                        "origin": self.command_line_args.get("universal_id", "oracle"),
                        "response_mode": response_mode,

                    }
                })

                # Send the response back to the original requester
                self.pass_packet(pk_resp, target_uid)
                self.log(f"[ORACLE] Sent {return_handler} reply to {target_uid} for query_id {query_id}")

        except Exception as e:
            self.log("[ORACLE][FATAL] cmd_msg_prompt crashed.", error=e)

    def cmd_generate_embeddings(self, content, packet, identity: IdentityObject = None):
        """
        Handles embedding requests from TrendScout or other agents.
        Expects:
          content = {
              "text": "string or list of strings",
              "return_handler": "handler_to_call_back",
              "session_id": optional,
              "token": optional
          }
        """
        try:

            target_uid = None

            if not self.encryption_enabled:
                # plaintext swarm – target specified directly
                target_uid = content.get("target_universal_id", False)
            else:
                # encrypted swarm – require verified identity
                if isinstance(identity, IdentityObject) and identity.has_verified_identity():
                    target_uid = identity.get_sender_uid()

            if not target_uid:
                self.log("[ORACLE][ERROR] target_universal_id missing. Cannot respond in swarm mode.")
                return

            #text
            text = content.get("text")

            #ref id
            id = content.get("id", 0)

            return_handler = content.get("return_handler", "cmd_oracle_embedding_response")

            if not text:
                self.log("[ORACLE][ERROR] Empty text for embedding.")
                return

            # Support both string and list inputs
            response = self.client.embeddings.create(
                model="text-embedding-3-small",
                input=text
            )

            embeddings = [d.embedding for d in response.data]

            payload = {
                "response_type": 1,  # marker that it's an embedding
                "embeddings": embeddings,
                "model": "text-embedding-3-small",
                "count": len(embeddings),
                "id": id,
                "text": text
            }

            if target_uid:
                pk_resp = self.get_delivery_packet("standard.command.packet")
                pk_resp.set_data({
                    "handler": return_handler,
                    "content": payload
                })
                self.pass_packet(pk_resp, target_uid)
                self.log(f"[ORACLE] → Sent embeddings back to {target_uid}")
            else:
                self.log("[ORACLE][WARN] No target UID found for swarm callback.")


        except Exception as e:
            self.log("[ORACLE][ERROR] Failed embedding request", error=e)

    def worker(self, config=None, identity=None):
        # Emit beacon for Phoenix heartbeat
        if self.running:
            self._emit_beacon()

            # Detect config changes dynamically
            if isinstance(config, dict) and bool(config.get("push_live_config", 0)):
                self.log(f"[ORACLE] 🔁 Live config update detected: {config}")
                self._apply_live_config(config)

            interruptible_sleep(self, 5)
            return

        self.log("[ORACLE] Shutdown requested, stopping worker.")
        interruptible_sleep(self, 0.5)

    def _apply_live_config(self, cfg: dict):
        try:
            new_key = cfg.get("api_key") or self.api_key
            new_model = cfg.get("model", self.model)
            new_mode = cfg.get("response_mode", "terse")
            new_temperature = cfg.get("temperature", self.temperature)

            if new_key != self.api_key:
                with self._cfg_lock:
                    self.client = OpenAI(api_key=new_key)
                    self.api_key = new_key
                    self.log("[ORACLE] API key updated (reloaded client)")

            if new_model != self.model:
                with self._cfg_lock:
                    self.model = new_model
                    self.log(f"[ORACLE] Model switched → {new_model}")

            if new_mode != self.response_mode:
                with self._cfg_lock:
                    self.response_mode = new_mode
                    self.log(f"[ORACLE] Response mode switched → {new_mode}")

            if new_temperature != self.temperature:
                with self._cfg_lock:
                    self.temperature = new_temperature
                    self.log(f"[ORACLE] Temperature switched → {new_temperature}")

        except Exception as e:
            self.log("[ORACLE][ERROR] Failed to apply live config", error=e)

    def cmd_label_clusters(self, content, packet, identity:IdentityObject =None):

        target_uid = None

        if not self.encryption_enabled:
            # plaintext swarm – target specified directly
            target_uid = content.get("target_universal_id", False)
        else:
            # encrypted swarm – require verified identity
            if isinstance(identity, IdentityObject) and identity.has_verified_identity():
                target_uid = identity.get_sender_uid()

        if not target_uid:
            self.log("[ORACLE][ERROR] target_universal_id missing. Cannot respond in swarm mode.")
            return

        clusters = content.get("clusters", [])

        prompt = "Name each semantic group of tags:\n\n"
        for i, c in enumerate(clusters):
            prompt += f"Cluster {i+1}: {', '.join(c['tags'])}\n"

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        ).choices[0].message.content

        payload = {"labels": response}

        pk_resp = self.get_delivery_packet("standard.command.packet")
        pk_resp.set_data({
            "handler": content.get("return_handler"),
            "content": payload
        })
        self.pass_packet(pk_resp, target_uid)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()