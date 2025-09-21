# Matrix: An AI OS System
# Copyright (c) 2025 Daniel MacDonald
# Licensed under the MIT License. See LICENSE file in project root for details.
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))
import json
import psutil
from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

class Agent(BootAgent):
    def __init__(self):
        super().__init__()

        self.orbits = {}

    def worker_pre(self):
        self.log("[WORKER] Booted. WorkerAgent is awake and ready.")

    def worker(self, config:dict = None, identity:IdentityObject = None):
        self.do_task_once()
        interruptible_sleep(self, 10)

    def worker_post(self):
        self.log("[WORKER] WorkerAgent shutting down. Task queue suspended.")

    def do_task_once(self):
        universal_id = self.command_line_args.get("universal_id")

        if universal_id == "worker-backup-2":
            load_averages = os.getloadavg()
            self.log(f"Load averages — 1min: {load_averages[0]}, 5min: {load_averages[1]}, 15min: {load_averages[2]}")

        elif universal_id == "worker-backup-1":
            net_stats = psutil.net_io_counters()
            self.log(f"Network — Bytes Sent: {net_stats.bytes_sent}, Received: {net_stats.bytes_recv}")

        elif universal_id == "worker-backup-3":
            import tracemalloc
            tracemalloc.start()
            snapshot = tracemalloc.take_snapshot()
            top_stats = snapshot.statistics("lineno")
            for stat in top_stats[:10]:
                self.log(f"[TRACE] {stat}")

    def process_command(self, command):
        if command.get("action") == "update_delegates":
            self.log("[COMMAND] Delegate update received. Saving tree and spawning.")

            tree_snapshot = command.get("tree_snapshot")
            if not tree_snapshot:
                self.log("[COMMAND] No tree_snapshot found in command.")
                return

            tree_path = os.path.join(
                self.path_resolution["comm_path"],
                self.command_line_args["universal_id"],
                "agent_tree.json"
            )

            try:
                with open(tree_path, "w", encoding="utf-8") as f:
                    json.dump(tree_snapshot, f, indent=2)
                self.log("[COMMAND] Tree snapshot saved.")
                self.spawn_manager()
            except Exception as e:
                self.log(f"[COMMAND] Failed to save tree: {e}")

if __name__ == "__main__":
    agent = Agent()
    agent.boot()