import json

from pathlib import Path
from core.python_core.class_lib.processes.reaper import Reaper

class DefaultLogger:
    def log(self, message):
        print(message)

class ReaperUniversalHandler:
    def __init__(self, pod_root, comm_root, logger=None):
        self.pod_root = Path(pod_root)
        self.comm_root = Path(comm_root)
        self.logger = logger or DefaultLogger()

    def process_all_universal_ids(self, universal_ids, tombstone_mode=False, wait_seconds=20, tombstone_comm=True, tombstone_pod=True):

        self.logger.log("[REAPER-HANDLER] Starting universal_id reaping...")

        reaper = Reaper(self.pod_root, self.comm_root, timeout_sec=wait_seconds, logger=self.logger.log)
        reaper.mission_targets = set(universal_ids)
        shutdown_success = False
        try:
            agent_paths = []
            for pod_dir in self.pod_root.iterdir():
                boot_file = pod_dir / "boot.json"
                if not boot_file.exists():
                    continue
                try:
                    with open(boot_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if data.get("universal_id") in universal_ids:
                        agent_paths.append(pod_dir)
                except Exception as e:
                    self.logger.log(f"[REAPER-HANDLER][ERROR] Reading {boot_file}: {e}")

            if not agent_paths:
                self.logger.log("[REAPER-HANDLER][WARNING] No matching agents found for universal_ids.")

            else:

                reaper.tombstone_mode = tombstone_mode
                reaper.tombstone_comm = tombstone_comm
                reaper.tombstone_pod = tombstone_pod

                reaper.pass_out_die_cookies(agent_paths)
                self.logger.log(f"[REAPER-HANDLER] Waiting {wait_seconds} seconds for shutdown...")
                shutdown_success = reaper.wait_for_agents_shutdown()

        except Exception as e:
            print(f"[REAPER-UNIVERSAL-HANDLER][ERROR] no agents found in path: {e}")

        if not shutdown_success:
            self.logger.log("[REAPER-HANDLER][WARNING] Agents survived initial shutdown. Escalating...")
            reaper.escalate_shutdown()

        self.logger.log("[REAPER-HANDLER] Universal_id reaping operation complete.")