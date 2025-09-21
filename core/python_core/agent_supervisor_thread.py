import os
import time
import threading
from pathlib import Path

class AgentSupervisorThread(threading.Thread):
    def __init__(self, agent, comm_root="/matrixline", pod_root="/pod", timeout=10):
        super().__init__(daemon=True)

        self.agent = agent
        self.timeout = timeout
        self.comm_root = comm_root
        self.pod_root = pod_root
        self.running = True

    def run(self):
        delegated = self.agent.directives.get("delegated", [])
        self.agent.log(f"[SUPERVISOR] Monitoring delegated agents: {delegated}")

        while self.running:
            for universal_id in delegated:
                try:
                    token_path = os.path.join(self.comm_root, universal_id, ".hello.token")
                    if not os.path.isdir(token_path):
                        self.agent.log(f"[SUPERVISOR] Missing .hello.token for {universal_id}")
                        self.handle_failure(universal_id)
                        continue

                    latest_pulse = self.find_latest_pulse(token_path)
                    if not latest_pulse or time.time() - latest_pulse.stat().st_mtime > self.timeout:
                        self.agent.log(f"[SUPERVISOR] Stale or missing heartbeat for {universal_id}")
                        self.handle_failure(universal_id)

                except Exception as e:
                    self.agent.log(f"[SUPERVISOR-ERROR] {e}")

            time.sleep(5)

    def find_latest_pulse(self, token_path):
        pulses = list(Path(token_path).glob("hello_*.pulse"))
        return max(pulses, key=lambda p: p.stat().st_mtime, default=None)

    def handle_failure(self, universal_id):
        spawn_dir = os.path.join(self.comm_root, universal_id, "spawns")
        if not os.path.isdir(spawn_dir):
            self.agent.log(f"[SUPERVISOR] No spawns directory for {universal_id}")
            return

        # Find latest spawn record
        spawn_files = sorted(Path(spawn_dir).glob("*.spawn"), reverse=True)
        if not spawn_files:
            self.agent.log(f"[SUPERVISOR] No spawn entries found for {universal_id}")
            return

        latest = spawn_files[0]
        try:
            with open(latest, "r") as f:
                pod_path = f.read().strip()
            uuid = os.path.basename(pod_path)
            full_path = os.path.join(self.pod_root, uuid)
            if os.path.exists(full_path):
                self.agent.log(f"[SUPERVISOR] Nuking dead pod: {uuid}")
                os.system(f"pkill -f {uuid}")  # Replace with PID-safe logic if needed
                self.agent.log(f"[SUPERVISOR] Marking {uuid} for scavenger cleanup")
                # Flag for scavenger agent, e.g., write to /scavenger/queue

        except Exception as e:
            self.agent.log(f"[SUPERVISOR-FAILURE] Failed to process spawn for {universal_id}: {e}")

    def stop(self):
        self.running = False
