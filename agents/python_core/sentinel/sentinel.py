# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Docstrings by Gemini
# ╔════════════════════════════════════════════════════════╗
# ║                    🛡 SENTINEL AGENT 🛡                 ║
# ║     Heartbeat Monitor · Resurrection Watch · Sentinel  ║
# ║   Forged in the signal of Hive Zero | v2.1 Directive   ║
# ║ Accepts: scan / detect / respawn / delay / confirm     ║
# ╚════════════════════════════════════════════════════════╝
# 🧭 UpdateSentinelAgent — Hardened Battlefield Version

import sys
import os
sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))
import threading

from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.boot_agent import BootAgent

class Agent(BootAgent):
    """
    A high-availability watchdog agent for the MatrixSwarm.

    The Sentinel's purpose is to monitor a single, critical agent (typically
    the root 'matrix' agent) for signs of failure. If the monitored agent's
    heartbeat becomes stale, the Sentinel will use a pre-loaded, secure set of
    credentials (the 'security_box') to automatically respawn it, ensuring
    the swarm's central authority remains operational.
    """
    def __init__(self):
        """
        Initializes the Sentinel agent and its monitoring configuration.

        This method loads settings from the agent's directive, such as the
        timeout period for the agent it is watching. It primarily configures
        the conditions under which it will trigger a resurrection.

        Attributes:
            matrix_secure_verified (bool): A flag indicating if this Sentinel
                is a trusted guardian with special privileges.
            watching (str): A descriptive name for the agent being monitored.
            universal_id_under_watch (str): The universal_id of the agent to
                be monitored.
            target_node (dict): A placeholder for the target's node data.
            time_delta_timeout (int): The number of seconds to wait after the
                last heartbeat before considering the target agent to be down.
        """
        super().__init__()

        config = self.tree_node.get("config", {})
        self.matrix_secure_verified=bool(config.get("matrix_secure_verified",0))
        self.watching = config.get("watching", "the Matrix")
        self.universal_id_under_watch = config.get("universal_id_under_watch", False)
        self.target_node = None
        self._emit_beacon = self.check_for_thread_poke("worker", timeout=30, emit_to_file_interval=10)

    def post_boot(self):
        """
        A one-time setup hook that starts the main monitoring thread.
        """
        self.log(f"[SENTINEL] Sentinel booted. Monitoring: {self.watching}")
        # Start watch thread
        threading.Thread(target=self.watch_cycle, daemon=True).start()

    def worker_pre(self):
        """A lifecycle hook that runs before the main worker loop begins."""
        self.log("[SENTINEL] Sentinel activated. Awaiting signal loss...")

    def worker_post(self):
        """A lifecycle hook that runs after the agent's main loops exit."""
        self.log("[SENTINEL] Sentinel down. Final watch cycle complete.")

    def watch_cycle(self):
        """
        The main monitoring and resurrection loop for the Sentinel.

        This method runs in a background thread for the entire lifecycle of
        the agent. It continuously checks the heartbeat of the target agent
        defined in its 'security_box'. If the heartbeat becomes older than the
        configured timeout and no 'die' file is present, it constructs a
        keychain with the necessary high-privilege credentials and respawns
        the target agent.
        """
        self.log("[SENTINEL] Watch cycle started.")

        try:

            if self.universal_id_under_watch and self.security_box:
                # The security_box contains the credentials needed to resurrect Matrix
                keychain = {}
                node = self.security_box.get('node', {})
                keychain["priv"] = node.get("vault", {}).get("priv", {})
                keychain["pub"] = node.get("vault", {}).get("identity", {}).get('pub', {})
                keychain["swarm_key"] = self.swarm_key
                keychain['private_key'] = node.get("vault", {}).get("private_key")
                keychain["matrix_pub"] = self.matrix_pub
                # Use the real Matrix private key from the security box
                keychain["matrix_priv"] = self.security_box["matrix_priv"]
                keychain["encryption_enabled"] = int(self.encryption_enabled)
                keychain["security_box"] = self.security_box.copy()

                while self.running:

                    try:
                        self._emit_beacon()

                        universal_id = self.security_box.get('node').get("universal_id")

                        self.log(f"[SENTINEL] Watching Universal ID: {universal_id}")

                        if not universal_id:
                            self.log("Target node missing universal_id. Breathing idle.", block="WATCHING")
                            break

                        # Respect intentional shutdown signals
                        die_file = os.path.join(self.path_resolution['comm_path'], universal_id, 'incoming', 'die')
                        if os.path.exists(die_file):
                            self.log(f"{universal_id} has die file. Skipping Loop.", block="WATCHING_DIE_FILE")
                            interruptible_sleep(self, 10)
                            continue

                        # Check if the target's heartbeat is stale
                        if self.clear_to_spawn(self.command_line_args.get("universe"), universal_id):

                            self.log(f"Re-spawning {universal_id}")
                            # If heartbeat is stale, initiate respawn
                            try:

                                self.spawn_agent_direct(
                                    universe=self.command_line_args.get("universe"),
                                    spawner=keychain["security_box"]["spawner"],
                                    universal_id=universal_id,
                                    agent_name=node.get("name"),
                                    tree_node=node,
                                    keychain=keychain
                                )


                                self.log(f"{universal_id} respawned successfully.")

                            except Exception as e:
                                self.log(f"failed to spawn agent", error=e, block="keep_alive", level="error")


                    except Exception as e:
                        self.log(f"failed to spawn agent", error=e, block="main_try", level="error")
                    finally:
                        interruptible_sleep(self, 10)

        except Exception as e:
            self.log(error=e, block="main_try")

if __name__ == "__main__":
    agent = Agent()
    agent.boot()