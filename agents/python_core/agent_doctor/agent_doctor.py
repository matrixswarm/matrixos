# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Docstrings by Gemini
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

import time
import json
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.time_utils.heartbeat_checker import check_heartbeats
from core.python_core.utils.analyze_spawn_records import analyze_spawn_records


class Agent(BootAgent):
    """
    The AgentDoctor is a diagnostic agent that monitors the health and status of all other agents in the swarm.
    It periodically checks for agent beacons to ensure they are alive and responsive, reporting any anomalies.
    """
    def __init__(self):
        """Initializes the AgentDoctor agent, setting its name and the maximum age for a beacon to be considered valid."""
        super().__init__()
        self.name = "AgentDoctor"
        self.max_allowed_beacon_age = 10  # seconds
        self._emit_beacon = self.check_for_thread_poke("worker", timeout=60, emit_to_file_interval=10)

    def pre_boot(self):
        """Logs a message indicating that the diagnostics module is armed and ready."""
        self.log("[DOCTOR] Swarm-wide diagnostics module armed.")

    def post_boot(self):
        """Logs messages indicating the start of monitoring and registration with the Matrix."""
        self.log("[DOCTOR] Monitoring active threads via intelligent beacon protocol.")
        self.log("[IDENTITY] Registering with Matrix...")
        #self.dispatch_identity_command()

    def is_phantom(self, agent_id):
        """
        Checks if an agent is a 'phantom'—meaning its communication directory exists, but its corresponding
        pod (and boot file) does not.

        Args:
            agent_id (str): The universal ID of the agent to check.

        Returns:
            bool: True if the agent is a phantom, False otherwise.
        """
        pod_root = self.path_resolution["pod_path"]
        for pod_id in os.listdir(pod_root):
            boot_file = os.path.join(pod_root, pod_id, "boot.json")
            try:
                with open(boot_file, encoding="utf-8") as f:
                    boot_data = json.load(f)
                    if boot_data.get("universal_id") == agent_id:
                        return False
            except:
                continue
        return True

    def verify_agent_consciousness(self, agent_id):
        """
        Uses the new beacon filename logic to evaluate heartbeat per thread.
        """
        comm_path = self.path_resolution["comm_path"]
        return check_heartbeats(comm_path, agent_id)

    def worker_pre(self):
        self.log("[DOCTOR] Beginning swarm scan...")

    def worker(self, config: dict = None, identity: IdentityObject = None):
        self.log("[DOCTOR] Beginning swarm scan...")
        self._emit_beacon()

        agents = self.get_agents_list()

        for agent_id in agents:
            if agent_id == self.command_line_args.get("universal_id"):
                continue

            if self.is_phantom(agent_id):
                self.log(f"🩺 {agent_id}\n  • 👻 phantom agent — comm exists, no pod detected")
                continue

            statuses = self.verify_agent_consciousness(agent_id)

            if statuses is None:
                self.log(f"🩺 {agent_id}\n  • 💀 missing beacon directory or unreadable files")
                continue

            log_lines = [f"🩺 {agent_id}"]

            # 🧠 Beacon summary
            for thread, info in statuses.items():
                delta = round(info["delta"], 1)
                state = info["status"]
                if state == "sleeping":
                    report = f"😴 sleep until {info['wake_due']} ({delta}s)"
                elif state == "alive":
                    report = f"✅ {delta}s"
                else:
                    report = f"💥 failed ({delta}s)"
                log_lines.append(f"  • {thread:<16} {report}")

            # 📦 Spawn intel
            spawn_info = analyze_spawn_records(self.path_resolution["comm_path"], agent_id)
            log_lines.append(f"  • spawns: {spawn_info['count']}")
            if spawn_info.get("flip_tripping"):
                log_lines.append("  • 🚨 flip-tripping detected (too many restarts)")

            self.log("\n".join(log_lines))

        interruptible_sleep(self, 30)

    def get_agents_list(self):
        """
        Retrieves a list of all agent IDs from the communication directory.

        Returns:
            list: A list of agent universal IDs.
        """
        comm_path = self.path_resolution.get("comm_path")
        agents = []
        for agent_id in os.listdir(comm_path):
            base = os.path.join(comm_path, agent_id)
            if not os.path.isdir(base):
                continue
            if os.path.isdir(os.path.join(base, "incoming")) or os.path.isdir(os.path.join(base, "hello.moto")):
                agents.append(agent_id)
        return agents


if __name__ == "__main__":
    agent = Agent()
    agent.boot()