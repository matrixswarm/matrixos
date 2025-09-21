#Authored by Daniel F MacDonald and ChatGPT 4
# ╔═══════════════════════════════════════════════╗
# ║              ☠ REAPER AGENT ☠                ║
# ║   Tactical Cleanup · Wipe Authority · V2.5    ║
# ║        Forged in the halls of Matrix          ║
# ║  Accepts: .cmd / .json  |  Modes: soft/full   ║
# ╚═══════════════════════════════════════════════╝
import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))
# DisposableReaperAgent.py

import json
import time
import threading
from pathlib import Path

from core.python_core.boot_agent import BootAgent
from core.python_core.class_lib.processes.reaper_universal_id_handler import ReaperUniversalHandler  # PID Handler
from core.python_core.utils.swarm_sleep import interruptible_sleep
class Agent(BootAgent):
    def __init__(self):
        super().__init__()

        # Load targets, kill ID, and initialize paths
        config = self.tree_node.get("config", {})
        self.is_mission = bool(config.get("is_mission", False))
        self.targets = config.get("kill_list", [])
        self.strike_delay = config.get("delay", 0)
        self.tombstone_comm = config.get("tombstone_comm", True)
        self.tombstone_pod = config.get("tombstone_pod", True)
        self.cleanup_die = config.get("cleanup_die", False)
        self._emit_beacon = self.check_for_thread_poke("patrol", timeout=30, emit_to_file_interval=10)

        self.universal_id_handler = ReaperUniversalHandler(self.path_resolution['pod_path'], self.path_resolution['comm_path'], logger=self.logger)

    def post_boot(self):
        """
        Logs the mission details and starts the mission in a separate thread.
        """
        if self.is_mission:
            self.mission()
        else:
            threading.Thread(target=self.patrol_comm_for_hit_cookies, daemon=True).start()

    def worker_pre(self):
        self.log("[REAPER] Agent entering execution mode. Targets loaded. Blades sharp.")

    def worker_post(self):
        self.log("[REAPER] Mission completed. Reaper dissolving into silence.")

    def mission(self):
        """
        Execute the mission using the Permanent ID handler to process shutdown requests for all targets.
        """
        self.log("[INFO] Inserting hit team...")

        if self.strike_delay > 0:
            self.log(f"[REAPER] ⏱ Waiting {self.strike_delay} seconds before executing strike...")
            time.sleep(self.strike_delay)

        # Use self.targets directly
        if not self.targets:
            self.log("[WARNING] No valid targets in kill_list.")
            self.running = False
            return

        try:
            self.universal_id_handler.process_all_universal_ids(
                self.targets,  # pass list of UIDs
                tombstone_mode=True,
                wait_seconds=20,
                tombstone_comm=self.tombstone_comm,
                tombstone_pod=self.tombstone_pod
            )

            if self.cleanup_die:
                for uid in self.targets:
                    try:
                        die_path = os.path.join(self.path_resolution["comm_path"], uid, "incoming", "die")
                        if os.path.exists(die_path):
                            os.remove(die_path)
                            self.log(f"[REAPER] Removed die signal from comm: {uid}")
                    except Exception as e:
                        self.log(f"[REAPER][ERROR] Failed to remove die for {uid}: {e}")

            self.log("[INFO] Mission completed successfully.")

        except Exception as e:
            self.log(f"[ERROR] Failed to complete mission: {str(e)}")

        self.running = False
        self.log("[INFO] Mission completed and the agent is now stopping.")
        self.leave_tombstone_and_die()

    def verify_hit_cookie(self, payload, signature):
        try:
            pass
        except Exception as e:
            #self.log(f"[ERROR] Failed to complete mission: {str(e)}")
            pass

        return True

    def patrol_comm_for_hit_cookies(self):
        self.log("[REAPER] 🛰 Patrol mode active. Scanning for hit cookies...")
        comm_root = Path(self.path_resolution["comm_path"])
        while True:
            self._emit_beacon()
            try:
                for agent_dir in comm_root.iterdir():
                    hello_path = agent_dir / "hello.moto"
                    cookie_path = hello_path / "hit.cookie"
                    self._emit_beacon()
                    if not cookie_path.exists():
                        continue

                    payload = {}
                    uid=None
                    with open(cookie_path, "r", encoding="utf-8") as f:
                        try:
                            payload = json.load(f)
                            uid = payload.get("target")
                        except Exception as e:
                            self.log(f"[REAPER][WARN] Malformed cookie in {cookie_path}: {e}")
                            continue

                    # Optional: verify signature
                    signature = "sig"  # payload.get("signature")
                    if not self.verify_hit_cookie(payload, signature):
                        if not uid:
                            uid = "[not set]"
                        self.log(f"[REAPER][WARN] Invalid or unsigned kill cookie for {uid}, skipping.")
                        continue


                    if not uid:
                        continue

                    self.log(f"[REAPER] ☠ Target marked: {uid} — executing...")

                    # Execute: reuse universal_id handler
                    self.process_universal_id(uid)

                    #cookie_path.unlink()  # Remove cookie after execution - scavenger will do it
            except Exception as e:
                self.log(f"[REAPER][ERROR] Patrol loop failed: {e}")

            interruptible_sleep(self, 15)

    def process_universal_id(self, uid):
        handler = ReaperUniversalHandler(self.path_resolution["pod_path"], self.path_resolution["comm_path"], logger=self.logger)
        handler.process_all_universal_ids(
            [uid],
            tombstone_mode=True,
            wait_seconds=15,
            tombstone_comm=True,
            tombstone_pod=True
        )

    def leave_tombstone_and_die(self):
        """
        Reaper drops his own tombstone and shuts down cleanly.
        """
        try:

            incoming_dir = os.path.join(self.path_resolution["comm_path"], self.command_line_args["universal_id"], "incoming")
            os.makedirs(incoming_dir, exist_ok=True)

            pod_dir = os.path.join(self.path_resolution["pod_path"], self.command_line_args["install_name"])

            # Write tombstone to comm
            die_path = os.path.join(incoming_dir, "die")
            with open(die_path, "w", encoding="utf-8") as f:
                f.write("true")

            # Write tombstone to comm
            tombstone_path = os.path.join(incoming_dir, "tombstone")
            with open(tombstone_path, "w", encoding="utf-8") as f:
                f.write("true")

            # Write tombstone to pod
            tombstone_path = os.path.join(pod_dir, "tombstone")
            with open(tombstone_path, "w", encoding="utf-8") as f:
                f.write("true")

            death_warrant=self.tree_node.get('config',{}).get('death_warrant', False)
            if death_warrant:
                self.deliver_death_warrant(death_warrant)

            self.log(f"[DISPOSABLE-REAPER] Die cookie dropped & Tombstone dropped. Mission complete. Signing off.")

        except Exception as e:
            self.log(f"[DISPOSABLE-REAPER][ERROR] Failed to leave tombstone: {str(e)}")

        finally:
            self.running = False  # Always stop running, even if tombstone writing fails



    def deliver_death_warrant(self, signed_warrant):

        try:

            # request the agent_tree_master from Matrix
            packet = self.get_delivery_packet("standard.command.packet", new=True)
            packet.set_data({
                "handler": "cmd_validate_warrant",
                "agent_id": self.command_line_args["universal_id"],
                "content": {  # ✅ wrap inside content
                    "agent_id": self.command_line_args["universal_id"],
                    "warrant": signed_warrant
                },
                "timestamp": time.time(),
                "origin": self.command_line_args["universal_id"]
            })
            self.pass_packet(packet, "matrix")

            self.log("[REAPER] 🕊 Death warrant dispatched to Matrix for post-mission validation.")

        except Exception as e:
            self.log(f"Sync request failed: {e}")


if __name__ == "__main__":
    agent = Agent()
    agent.boot()