# Authored by Daniel F MacDonald and ChatGPT aka The Generals
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))
import time
import json

from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):
    def __init__(self):
        super().__init__()
        self._emit_beacon = self.check_for_thread_poke("worker", timeout=30, emit_to_file_interval=10)

    def pre_boot(self):
        self.log("[COMMANDER] Pre-boot check passed.")

    def post_boot(self):
        self.log("[COMMANDER] Active swarm dashboard engaged.")

    def worker(self, config:dict = None, identity:IdentityObject = None):
        self.track_agents()
        self.thread_registry["worker"]["timeout"] = 15
        self._emit_beacon()


    def track_agents(self):
        comm_root = self.path_resolution["comm_path"]
        flat = []
        for agent_id in os.listdir(comm_root):
            hello_path = os.path.join(comm_root, agent_id, "hello.moto")

            # Skip phantom routing-only directories (not backed by pod boot.json)
            if not self.is_real_agent(agent_id):
                continue

            if not os.path.isdir(hello_path):
                if agent_id == self.command_line_args.get("universal_id"):
                    continue

            try:
                ping_file = os.path.join(comm_root, agent_id, "hello.moto", "poke.heartbeat")
                if os.path.exists(ping_file):
                    delta = time.time() - os.path.getmtime(ping_file)
                status = "✅" if delta < 20 else "⚠️"
                flat.append((agent_id, round(delta, 1), status))
            except:
                flat.append((agent_id, "ERR", "❌"))

        self.render_table(flat)

    def render_table(self, flat):
        flat.sort(key=lambda x: x[0])
        self.log("\n[COMMANDER] Swarm Agent Status:")
        for agent_id, age, flag in flat:
            self.log(f"   {flag} {agent_id.ljust(28)}  last seen: {age}s ago")

    def is_real_agent(self, universal_id):
        pod_root = self.path_resolution["pod_path"]
        for pod_dir in os.listdir(pod_root):
            boot_path = os.path.join(pod_root, pod_dir, "boot.json")
            try:
                with open(boot_path, encoding="utf-8") as f:
                    data = json.load(f)
                    if data.get("universal_id") == universal_id:
                        return True
            except:
                continue
        return False

if __name__ == "__main__":
    agent = Agent()
    agent.boot()
