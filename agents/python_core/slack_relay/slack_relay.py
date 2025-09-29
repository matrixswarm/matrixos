# 📡 SlackRelayAgent — Forwards Swarm Logs to Slack
# Authored by Daniel F MacDonald and ChatGPT aka The Generals

import sys
import os
import json
import requests

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from core.python_core.boot_agent import BootAgent
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject
from core.python_core.utils.swarm_sleep import interruptible_sleep

class Agent(BootAgent):
    def __init__(self):
        super().__init__()

        config = self.tree_node.get("config", {})
        self.webhook_url = config.get("webhook_url")  # Slack webhook URL

        comm_path = self.path_resolution["comm_path_resolved"]
        self.watch_path = os.path.join(comm_path, "incoming")
        os.makedirs(self.watch_path, exist_ok=True)

        self._emit_beacon = self.check_for_thread_poke("worker", timeout=60, emit_to_file_interval=10)

    def worker_pre(self):
        self.log("[SLACK] Slack relay active. Monitoring incoming communications...")

    def worker(self, config: dict = None, identity: IdentityObject = None):
        self._emit_beacon()
        interruptible_sleep(self, 20)

    def worker_post(self):
        self.log("[SLACK] Relay shutting down. Comm line is quiet.")

    def cmd_send_alert_msg(self, content, packet, identity: IdentityObject = None):
        try:
            message = self.format_message(content)
            self.send_to_slack(message)
            self.log("[SLACK] Message sent successfully.")
        except Exception as e:
            self.log(f"[SLACK][ERROR] Message relay failed: {e}")

    def format_message(self, data: dict):
        """Create a clean Slack-compatible message."""
        embed = data.get("embed_data")
        if embed:
            title = embed.get("title", "Swarm Alert")
            description = embed.get("description", "No details.")
            footer = embed.get("footer", "")
            return f"*{title}*\n{description}\n_{footer}_"
        else:
            return data.get("formatted_msg") or data.get("msg") or "[SWARM] No content."

    def send_to_slack(self, message: str):
        if not self.webhook_url:
            self.log("[SLACK][ERROR] Missing Slack webhook URL.")
            return
        payload = {"text": message}
        try:
            resp = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            if resp.status_code == 200 and resp.text.strip() == "ok":
                self.log("[SLACK] ✅ Message delivered successfully.")
            else:
                body = resp.text.strip()
                if len(body) > 200:  # prevent giant dumps
                    body = body[:200] + "...[truncated]"
                self.log(f"[SLACK][ERROR] Delivery failed → HTTP {resp.status_code} | Body: {body}")


        except Exception as e:
            self.log(f"[SLACK][ERROR] Slack delivery exception: {e}")


if __name__ == "__main__":
    agent = Agent()
    agent.boot()
