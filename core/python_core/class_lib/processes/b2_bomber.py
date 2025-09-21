import os
import time
import signal
import json
import psutil
import re
from pathlib import Path
from core.python_core.class_lib.logging.logger import Logger
from core.python_core.class_lib.file_system.util.json_safe_write import JsonSafeWrite

class B2Bomber:
    def __init__(self):
        self.agents={}

    def level_it(self, target_paths, check_interval=2, timeout=30):
        """
        Main operation:
          1. Pass out die cookies.
          2. Wait for agents to exit gracefully.
          3. Escalate to SIGTERM or SIGKILL if necessary.
        """
        self.log_info("[CARPET-BOMB][INFO] Initiating universe-wide carpet-bombing...")

        # First Pass: drop the `die` cookies to signal graceful shutdown
        self.pass_out_die_cookies(target_paths)

        # Wait for agents to stop gracefully within timeout
        shutdown_success = self.wait_for_agents_shutdown(target_paths, check_interval=check_interval, timeout=timeout)

        if not shutdown_success:
            # Escalate if agents are still running
            self.log_info("[CARPET-BOMB][WARNING] Some agents failed to terminate gracefully. Escalating...")
            # Find and process matching PIDs
            #matching_pids = self.find_bigbang_agents(global_id)
            self.escalate_shutdown(target_paths) #matching_pids)

        #exit()

        self.log_info("[CARPET-BOMB][INFO] Universe-wide carpet-bombing operation concluded.")

    def log_info(self, message):
        """Helper function for logging with fallback to print."""
        print(message)

    def pass_out_die_cookies(self, agent_paths):
        self.log_info("[CARPET-BOMB][INFO] Distributing `die` cookies to agents...")

        for agent_path in agent_paths:
            try:
                comm_root = agent_path.get("comm_path")
                uid = agent_path.get("universal_id")

                if not comm_root or not os.path.exists(comm_root):
                    continue

                die_path = os.path.join(comm_root, uid, "incoming", "die")

                if not uid or not os.path.exists(os.path.join(comm_root, uid)):
                    print(f"[CARPET-BOMB][SKIP] Missing comm dir for {uid} @ {comm_root}")
                    continue

                JsonSafeWrite.safe_write(die_path, "terminate")
                self.log_info(f"[CARPET-BOMB][INFO] `die` cookie distributed for {uid}.")

            except Exception as e:
                self.log_info(f"[CARPET-BOMB][ERROR] Failed to distribute `die` cookie: {e}")


    def wait_for_agents_shutdown(self, agent_paths, check_interval=10, timeout=30):

        self.log_info("[CARPET-BOMB][INFO] Waiting 10s for agents to ingest die cookie...")

        total_wait_time = 0
        survivors = []

        while total_wait_time <= timeout:

            survivors.clear()

            for agent_path in agent_paths:

                if self.is_pid_alive(agent_path.get("pid")):
                    survivors.append(agent_path.get("universal_id"))
                    self.log_info(f"[CARPET-BOMB][INFO] Agent {agent_path.get("universal_id")} is still breathing...")

            if not survivors:
                self.log_info("[CARPET-BOMB][INFO] All agents have exited cleanly.")
                return True  # shutdown_success = True

            time.sleep(check_interval)
            total_wait_time += check_interval

        self.log_info(f"[CARPET-BOMB][warning] Survivors detected after timeout: {survivors}")
        return False  # shutdown_success = False

    def is_pid_alive(self, pid):
        """
          Checks whether a process with the given PID is alive.
          Accounts for zombie processes.
          """
        try:
            proc = psutil.Process(pid)
            if proc.status() == psutil.STATUS_ZOMBIE:
                return False  # Consider zombie processes as not alive
            return proc.is_running()
        except psutil.NoSuchProcess:
            return False
        except psutil.AccessDenied:
            print(f"[WARNING] Access denied to process {pid}. Assuming it is alive.")
            return True
        except Exception as e:
            print(f"[ERROR] Unexpected error when checking PID {pid}: {e}")
            return False

    def escalate_shutdown(self, target_paths):
        """
        Immediately SIGTERM all matching PIDs. If still alive after short delay, SIGKILL.
        """
        self.log_info("[ESCALATE] Sending SIGTERM to all tracked agents...")

        active_pids = {}

        for target in target_paths:

            for proc in psutil.process_iter(['pid', 'cmdline']):
                try:
                    if proc.info['pid'] == target.get("pid"):
                        pid = proc.info['pid']
                        active_pids[target.get("universal_id")] = pid
                        os.kill(pid, signal.SIGTERM)
                        self.log_info(f"[CARPET-BOMB] SIGTERM → {target.get("universal_id")} (PID {pid})")
                except Exception as e:
                    self.log_info(f"[CARPET-BOMB] Error sending SIGTERM to {target.get("universal_id")}: {e}")

        # Short wait for them to acknowledge and self-terminate
        self.log_info("[ESCALATE] Waiting 1sec before SIGKILL...")
        time.sleep(1)

        # Kill any survivors
        for uid, pid in active_pids.items():
            if self.is_pid_alive(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                    self.log_info(f"[CARPET-BOMB] SIGKILL → {uid} (PID {pid})")
                except Exception as e:
                    self.log_info(f"[CARPET-BOMB] Failed to SIGKILL {uid}: {e}")

