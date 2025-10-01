# Authored by Daniel F MacDonald and ChatGPT-5 aka The Generals
# Docstrings by Gemini
import os
import sys
import time
import subprocess
import base64
import threading
import hashlib
from Crypto.PublicKey import RSA

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from core.python_core.boot_agent import BootAgent
from core.python_core.class_lib.packet_delivery.utility.encryption.config import ENCRYPTION_CONFIG
from core.python_core.utils.crypto_utils import encrypt_with_ephemeral_aes,  sign_data, pem_fix

"""
Agent: TerminalStreamer — executes Linux commands, streams results.

This agent is designed to execute specified Linux commands, enforce a configurable
whitelist for safety, and stream the results back to a remote handler (like a
terminal panel) via an ephemeral RPC mechanism, using encryption and signing for
security. It also includes session monitoring to clean up stale streams.

The core functionality revolves around:
1.  **Command Execution**: Running OS commands using subprocess.
2.  **Safety**: Optional shell mode with a command whitelist.
3.  **Streaming**: Continuous or single-shot execution with results broadcasted.
4.  **Security**: Encrypting and signing broadcasted output.
5.  **Monitoring**: Removing streams if the remote receiver's "fresh broadcast flag" goes stale.

:inherits: core.python_core.boot_agent.BootAgent
"""
class Agent(BootAgent):
    """
    Initializes the TerminalStreamer Agent.

    Configures settings from the node tree, including:
    - Version, polling interval, heartbeat TTL, and rate limit.
    - Active streams dictionary.
    - RPC role for communication.
    - Command whitelist and the state of `safe_shell_mode`.
    - Decryption keys (if encryption is enabled).
    - RSA signing keys for message integrity.
    - Agent's serial number.

    :raises Exception: Catches and logs any exceptions during initialization.
    """
    def __init__(self):
        super().__init__()
        try:
            self.AGENT_VERSION = "1.0.0"

            cfg = self.tree_node.get("config", {})

            self.interval = int(cfg.get("interval", 2))     # seconds between polls
            self.heartbeat_ttl = int(cfg.get("heartbeat_ttl", 30))
            self.rate_limit = float(cfg.get("rate_limit", 2.0))  # seconds between sends

            self.active_streams = {}  # {session_id: {...}}

            self.rpc_role=self.tree_node.get("rpc_router_role", "hive.rpc")

            # === Command whitelist ===
            # Either load from vault/config, or fallback to safe defaults
            self.whitelist = cfg.get("whitelist", [
                "uptime", "df -h", "top -n 1", "whoami"
            ])
            # Toggle safe shell mode (default = True)
            self.safe_shell_mode = bool(cfg.get("safe_shell_mode", True))
            if not self.safe_shell_mode:
                self.log("⚠️ Safe shell mode is OFF – running unrestricted commands!")

            # decryption
            self.key_bytes = None
            if ENCRYPTION_CONFIG.is_enabled():
                swarm_key = ENCRYPTION_CONFIG.get_swarm_key()
                self.key_bytes = base64.b64decode(swarm_key)

            self._signing_keys = self.tree_node.get('config', {}).get('security', {}).get('signing', {})
            self._has_signing_keys = bool(self._signing_keys.get('privkey')) and bool( self._signing_keys.get('remote_pubkey'))

            if self._has_signing_keys:
                priv_pem = self._signing_keys.get("privkey")
                priv_pem = pem_fix(priv_pem)
                self._signing_key_obj = RSA.import_key(priv_pem.encode() if isinstance(priv_pem, str) else priv_pem)

            self._serial_num = self.tree_node.get('serial', {})
        except Exception as e:
            self.log(error=e, block="main_try")

    def post_boot(self):
        """
        Logs a startup message and initiates the session monitoring thread.
        This is called after the core `BootAgent` has finished its boot sequence.
        """
        self.log(f"{self.NAME} v{self.AGENT_VERSION} – TERMINAL standing guard.")
        threading.Thread(target=self._monitor_sessions, daemon=True).start()

    def _monitor_sessions(self, check_interval: int = 15, threshold: int = 30):
        """
        Removes log streams whose websocket relay broadcast flags
        have gone missing or stale.
        """
        alert_role = self.tree_node.get("rpc_router_role", "hive.rpc")

        while True:
            for sess in list(self.active_streams.keys()):
                if int(time.time()) % 60 == 0:  # every ~60 seconds
                    self.log(f"[DEBUG] Active streams: {len(self.active_streams)}")

                # Assume one relay for now (if multiple, iterate)
                for ep in self.get_nodes_by_role(alert_role):
                    relay_uid = ep.get_universal_id()
                    if not self.has_fresh_broadcast_flag(relay_uid, sess, threshold):
                        self.log(f"[SESSION-MONITOR] 🧹 Removing sess={sess} (relay={relay_uid})")
                        self.cmd_stop_stream_terminal({"session_id": sess}, None)
            time.sleep(check_interval)

    # ========== COMMAND HANDLERS ==========
    def cmd_start_stream_terminal(self, content, packet, identity=None):
        """
         Handles the command to start streaming the output of a Linux command.

         Initializes a new streaming session by setting up a stop flag and starting
         a dedicated thread (`_run_loop`) to execute the command periodically.
         If a stream for the session ID already exists, it is stopped first.

         :param content: Dictionary containing stream parameters.
                         Must include "session_id", "token", and "command".
                         Optional: "refresh_sec" (int, 0 for single run) and
                         "return_handler" (str, the remote handler for results).
         :type content: dict
         :param packet: The incoming delivery packet (unused for return).
         :param identity: Optional identity of the sender (unused).
         :returns: None
         """
        sess = content.get("session_id")
        token = content.get("token")
        cmd = content.get("command")
        refresh = int(content.get("refresh_sec", 0))
        handler = content.get("return_handler", "terminal_panel.update")

        if not (sess and token and cmd):
            self.log("❌ Missing required fields for cmd_stream_terminal")
            return

        # Stop existing stream first
        if sess in self.active_streams:
            self.log(f"[TERMINAL] 🧨 Overwriting stream for sess={sess}")
            self.cmd_stop_stream_terminal({"session_id": sess}, packet)

        stop_flag = threading.Event()
        t = threading.Thread(
            target=self._run_loop,
            args=(sess, token, cmd, refresh, handler, stop_flag),
            daemon=True,
        )
        self.active_streams[sess] = {
            "stop": stop_flag,
            "thread": t,
            "return_handler": handler,
        }
        t.start()
        self.log(f"[TERMINAL] 🎬 Started stream for sess={sess}, cmd={cmd}")

    def cmd_stop_stream_terminal(self, content, packet, identity=None):
        """
        Handles the command to stop an active terminal stream.

        Sets the stream's stop flag and removes the session from `active_streams`.

        :param content: Dictionary containing the "session_id" to stop.
        :type content: dict
        :param packet: The incoming delivery packet (unused).
        :param identity: Optional identity of the sender (unused).
        :returns: None if the session ID is missing or not active.
        """
        sess = content.get("session_id")
        if not sess or sess not in self.active_streams:
            return
        self.active_streams[sess]["stop"].set()
        self.active_streams.pop(sess, None)
        self.log(f"[TERMINAL] 🛑 Stopped stream for sess={sess}")

    def _hash_lines(self, lines: list[str]) -> str:
        """
        Returns a short SHA256 hash of the given log lines.
        """
        blob = "\n".join(lines).encode("utf-8")
        h = hashlib.sha256(blob).hexdigest()
        return h[:12]  # shorten for readability

    def _run_loop(self, sess, token, cmd, refresh, handler, stop_flag):
        while not stop_flag.is_set():
            try:
                # Optional: enforce whitelist
                if getattr(self, "safe_shell_mode", True):
                    if not self._is_safe_command(cmd):
                        output = f"[BLOCKED] Command not allowed: {cmd}"
                    else:
                        output = subprocess.check_output(
                            cmd, shell=True, stderr=subprocess.STDOUT, text=True
                        )
                else:
                    output = subprocess.check_output(
                        cmd, shell=True, stderr=subprocess.STDOUT, text=True
                    )
            except Exception as e:
                output = f"[ERROR] {e}"

            self._broadcast_output(sess, token, output, handler)

            if refresh <= 0:
                break
            time.sleep(refresh)

    def _is_safe_command(self, cmd: str) -> bool:
        return any(cmd.strip().startswith(w) for w in self.whitelist)

    def has_fresh_broadcast_flag(self, relay_uid: str, session_id: str, threshold: int = 30) -> bool:
        """
        Checks whether connected.flag.<session_id> exists and is fresh
        inside the relay agent's broadcast dir.
        """
        base = os.path.join(self.path_resolution["comm_path"], relay_uid, "broadcast")
        flag = os.path.join(base, f"connected.flag.{session_id}")
        if not os.path.exists(flag):
            return False
        age = time.time() - os.path.getmtime(flag)
        if age > threshold:
            self.log(f"[SESSION-MONITOR] ⚠️ Flag stale ({int(age)}s) relay={relay_uid} sess={session_id}")
            return False
        return True

    def _broadcast_output(self, sess, token, output, handler):
        try:
            endpoints = self.get_nodes_by_role(self.rpc_role, return_count=1)
            if not endpoints:
                self.log("[TERMINAL] ❌ No hive.rpc endpoints found")
                return

            remote_pub_pem = self._signing_keys.get("remote_pubkey")
            payload = {
                "handler": handler,
                "content": {
                    "session_id": sess,
                    "token": token,
                    "output": output,
                    "timestamp": int(time.time()),
                }
            }
            sealed = encrypt_with_ephemeral_aes(payload, remote_pub_pem)
            content = {
                "serial": self._serial_num,
                "content": sealed,
                "timestamp": int(time.time()),
            }
            sig = sign_data(content, self._signing_key_obj)
            content["sig"] = sig

            pk = self.get_delivery_packet("standard.command.packet")
            pk.set_data({
                "handler": "dummy_handler",
                "origin": self.command_line_args["universal_id"],
                "session_id": sess,
                "content": content,
            })

            for ep in endpoints:
                pk.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk, ep.get_universal_id())

            self.log(f"[TERMINAL] Broadcasted output for sess={sess}")
        except Exception as e:
            self.log("[TERMINAL][ERROR] Broadcast failed", error=e)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()