# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Gemini, code enhancements and Docstrings
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))
import time
from core.python_core.utils.swarm_sleep import interruptible_sleep
from openai import OpenAI
from core.python_core.boot_agent import BootAgent
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

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

            config = self.tree_node.get("config", {})
            self.api_key = config.get("api_key")
            self.model = config.get("model", "gpt-3.5-turbo")
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

        # Parse request context
        prompt_text = content.get("prompt", "")
        history = content.get("history", [])
        target_uid = content.get("target_universal_id") or packet.get("target_universal_id")
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

            # Call the OpenAI API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0,
            ).choices[0].message.content.strip()

            # Construct the response packet
            pk_resp = self.get_delivery_packet("standard.command.packet")
            pk_resp.set_data({
                "handler": return_handler,  # This is what the recipient will process
                "packet_id": int(time.time()),
                "target_universal_id": target_uid,
                "role": "oracle",
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

    def worker(self, config=None, identity=None):
        # emit beacon so Phoenix doesn’t mark it stale
        if self.running:
            self._emit_beacon()
            interruptible_sleep(self, 5)  # responsive sleep
            return

        # shutdown path
        self.log("[ORACLE] Shutdown requested, stopping worker.")
        interruptible_sleep(self, .5)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()