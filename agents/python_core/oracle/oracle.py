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

MAX_CHUNK_TOKENS = 6000  # safely below the 8k-ish window

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
            self.AGENT_VERSION = "1.0.9"

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
            self._last_config = {}
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
        Handles an incoming prompt request from another agent.

        This is the primary command handler for the Oracle. It receives a
        prompt, sends it to the OpenAI API for completion, and then packages
        the response into a command packet. This response packet is then sent
        back to the original requesting agent, instructing it to use the
        specified `return_handler` for processing. This enables a flexible,
        asynchronous request/response pattern within the swarm.

        Args:
            content (dict): The command payload containing the prompt and
                routing information. Expected keys include 'prompt',
                'target_universal_id', 'return_handler', and 'query_id'.
            packet (dict): The raw packet object received by the agent.
            identity (IdentityObject, optional): The verified identity of the
                agent that sent the prompt.
        """

        self.log("[ORACLE] Reflex prompt received.")

        target_uid = None
        if not self.encryption_enabled:
            target_uid = content.get("target_universal_id", False)  # swarm running in plaintext mode

        else:
            # reject invalid or missing identity
            if isinstance(identity, IdentityObject) and identity.has_verified_identity():
                 target_uid = identity.get_sender_uid()


        # Parse request context
        prompt_text = content.get("prompt", "")
        history = content.get("history", [])
        return_handler = content.get("return_handler", "cmd_oracle_response")
        response_mode = (content.get("response_mode") or "terse").lower()
        query_id = content.get("query_id", 0)

        try:


            if not prompt_text:
                self.log("[ORACLE][ERROR] Prompt content is empty.")
                return

            if not (target_uid):
                self.log("[ORACLE][ERROR] target_universal_id. Cannot respond.")
                return

            self.log(f"[ORACLE] Response mode: {response_mode}")

            messages = history + [{"role": "user", "content": prompt_text}]

            with self._cfg_lock:
                client = self.client
                model = self.model
                temperature=self.temperature

            # Call the OpenAI API
            if len(prompt_text) > MAX_CHUNK_TOKENS:
                response = self._process_large_prompt(prompt_text, history)
            else:
                response = client.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature
                ).choices[0].message.content.strip()

            # Construct the response packet
            pk_resp = self.get_delivery_packet("standard.command.packet")
            pk_resp.set_data({
                "handler": return_handler,  # This is what the recipient will process
                "packet_id": int(time.time()),
                "content": {
                    "query_id": query_id,
                    "response": response,
                    "origin": self.command_line_args.get("universal_id", "oracle"),
                    "history": history,
                    "prompt": prompt_text,
                    "response_mode": response_mode,
                }
            })

            # Send the response back to the original requester
            self.pass_packet(pk_resp, target_uid)
            self.log(f"[ORACLE] Sent {return_handler} reply to {target_uid} for query_id {query_id}")

        except Exception as e:
            self.log(error=e, block='main_try', level='ERROR')

    def _split_large_prompt(self, text, max_len=MAX_CHUNK_TOKENS):
        parts = []
        while len(text) > max_len:
            cut = text.rfind("\n", 0, max_len)
            cut = cut if cut != -1 else max_len
            parts.append(text[:cut])
            text = text[cut:]
        parts.append(text)
        return parts

    def _process_large_prompt(self, text, history):


        try:
            merged = "error"
            with self._cfg_lock:
                client = self.client
                model = self.model
                temperature = self.temperature

            chunks = self._split_large_prompt(text)
            summaries = []
            for i, chunk in enumerate(chunks, 1):
                self.log(f"[ORACLE] Processing chunk {i}/{len(chunks)} ({len(chunk)} chars)")
                self._emit_beacon_packet_listener()
                resp = client.chat.completions.create(
                    model=model,
                    messages=history + [{"role": "user", "content": chunk}],
                    temperature=temperature
                ).choices[0].message.content.strip()
                summaries.append(resp)
            merged = "\n---\n".join(summaries)

            if len(merged) > MAX_CHUNK_TOKENS:
                self.log("[ORACLE] Result too large, performing recursive summarization.")
                merged = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": f"Summarize the following analysis:\n{merged}"}],
                    temperature=temperature,
                ).choices[0].message.content.strip()
        except Exception as e:
            self.log(error=e, block='main_try', level='ERROR')
        finally:
            return merged

    def worker(self, config=None, identity=None):
        # Emit beacon for Phoenix heartbeat
        if self.running:
            self._emit_beacon()

            # Detect config changes dynamically
            if isinstance(config, dict) and config != self._last_config:
                self.log(f"[ORACLE] 🔁 Live config update detected: {config}")
                self._apply_live_config(config)
                self._last_config = dict(config)  # cache snapshot

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

if __name__ == "__main__":
    agent = Agent()
    agent.boot()