# Authored by Daniel F MacDonald and ChatGPT-5 aka The Generals
import os
import sys
import time
import json
import base64
import threading
import hashlib
from Crypto.PublicKey import RSA

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.encryption.config import ENCRYPTION_CONFIG
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject
from core.python_core.class_lib.logging.logger import Logger
from core.python_core.utils.crypto_utils import encrypt_with_ephemeral_aes,  sign_data, pem_fix


class Agent(BootAgent):
    """
    LogSentinel — tails an agent.log, streams lines back to Matrix via
    ephemeral rpc_handler, supports start_line offsets, and handles rotation.
    """

    def __init__(self):
        super().__init__()
        try:
            self.AGENT_VERSION = "1.1.0"
            cfg = self.tree_node.get("config", {})

            self.interval = int(cfg.get("interval", 2))     # seconds between polls
            self.heartbeat_ttl = int(cfg.get("heartbeat_ttl", 30))
            self.rate_limit = float(cfg.get("rate_limit", 2.0))  # seconds between sends

            self.active_streams = {}  # {session_id: {...}}

            self.rpc_role=self.tree_node.get("rpc_router_role", "hive.rpc")

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
        self.log(f"{self.NAME} v{self.AGENT_VERSION} – LogSentinel standing guard.")
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
                        self.cmd_stop_stream_log({"session_id": sess}, None)
            time.sleep(check_interval)

    # ========== COMMAND HANDLERS ==========
    def cmd_stream_log(self, content, packet, identity: IdentityObject = None):
        """Start streaming logs for a session with canonical field names."""
        sess = content.get("session_id")
        token = content.get("token")
        target = content.get("target_agent")
        start_line = int(content.get("start_line", 0))
        follow = bool(content.get("follow", True))

        missing = [k for k, v in {
            "session_id": sess,
            "token": token,
            "target_agent": target,
        }.items() if not v]

        if missing:
            self.log(f"❌ Missing required stream_log fields: {', '.join(missing)}. "
                     f"Got keys={list(content.keys())}")
            return

        log_path = os.path.join(
            self.path_resolution["static_comm_path"],
            target,
            "logs",
            "agent.log"
        )
        if not os.path.exists(log_path):
            self.log(f"[LOGSENTINEL] ❌ No log file for {target} at {log_path}")
            return

        # Stop existing stream for this session if any
        if sess in self.active_streams:
            self.log(f"[STREAM] 🧨 Overwriting stream for sess={sess}")
            self.cmd_stop_stream_log({"session_id": sess}, packet)

        stop_flag = threading.Event()
        t = threading.Thread(
            target=self._stream_loop,
            args=(sess, token, target, start_line, follow, stop_flag),
            daemon=True,
        )
        return_handler = content.get("return_handler", "agent_log_view.update")
        self.active_streams[sess] = {
            "thread": t,
            "stop": stop_flag,
            "token": token,
            "return_handler": return_handler,
            "can_broadcast": False,
            "log_path": log_path,
            "created": time.time()
        }
        t.start()
        self.log(f"[LOGSENTINEL] 🎬 Streaming started for {target}, sess={sess}, start_line={start_line}")

    def cmd_stop_stream_log(self, content, packet, identity: IdentityObject = None):
        """Stop streaming logs for a session."""
        sess = content.get("session_id")
        if not sess or sess not in self.active_streams:
            return
        self.active_streams[sess]["stop"].set()
        self.active_streams.pop(sess, None)
        self.log(f"[LOGSENTINEL] 🛑 Stopped log stream for sess={sess}")



    def _hash_lines(self, lines: list[str]) -> str:
        """
        Returns a short SHA256 hash of the given log lines.
        """
        blob = "\n".join(lines).encode("utf-8")
        h = hashlib.sha256(blob).hexdigest()
        return h[:12]  # shorten for readability

    def _stream_loop(self, sess, token, target, start_line, follow, stop_flag):

        offset = start_line
        last_inode = None

        try:
            stream = self.active_streams.get(sess)
            if not stream:
                return

            log_path = stream.get("log_path")
            if not log_path or not os.path.exists(log_path):
                self.log(f"[LOGSENTINEL] ❌ Missing log_path for stream {sess}")
                return

            f = open(log_path, "r", encoding="utf-8")
            last_inode = os.fstat(f.fileno()).st_ino

            total_lines = sum(1 for _ in open(log_path, "r", encoding="utf-8"))
            if offset > total_lines:
                offset = total_lines

            while not stop_flag.is_set():
                # Exit if session was reaped
                stream = self.active_streams.get(sess)
                if not stream:
                    self.log(f"[STREAM] 🚪 Session {sess} gone, exiting loop gracefully.")
                    break

                # rotation check
                try:
                    st = os.stat(log_path)
                    if st.st_ino != last_inode:
                        self.log("[LOGSENTINEL] 🔄 Log rotated, reopening...")
                        f.close()
                        f = open(log_path, "r", encoding="utf-8")
                        last_inode = st.st_ino
                        offset = 0
                except FileNotFoundError:
                    time.sleep(self.interval)
                    continue

                f.seek(0)
                lines = f.readlines()
                new_lines = lines[offset:]

                # Gate: Don't allow broadcast until broadcast flag appears
                if not stream.get("can_broadcast", False):

                    endpoints = self.get_nodes_by_role(self.rpc_role)
                    if not endpoints:
                        self.log("No hive.rpc-compatible agents found for 'hive.rpc'.", level="ERROR")
                        return

                    for ep in endpoints:
                        relay_uid = ep.get_universal_id()
                        flag_path = os.path.join(
                            self.path_resolution["comm_path"], relay_uid, "broadcast", f"connected.flag.{sess}"
                        )
                        if os.path.exists(flag_path):
                            age = time.time() - os.path.getmtime(flag_path)
                            if age < 30:  # safe freshness check
                                stream["can_broadcast"] = True
                            self.log(f"[STREAM] ✅ Broadcast flag detected for sess={sess} in relay={relay_uid}, enabling stream.")
                            break
                    else:
                        time.sleep(self.interval)
                        continue

                if new_lines:
                    rendered = []
                    for line in new_lines:
                        try:
                            if self.key_bytes:
                                line = Logger.decrypt_log_line(line, self.key_bytes)
                            entry = json.loads(line)
                            rendered.append(Logger.render_log_line(entry))
                        except Exception:
                            rendered.append(f"[MALFORMED] {line.strip()}")

                    if self.debug.is_enabled():
                        h = self._hash_lines(rendered)
                        self.log(f"[LOGSENTINEL] 🚀 Broadcasting {len(rendered)} lines hash={h} sess={sess}")

                    self._broadcast_log_lines(token, target, sess, offset, rendered)
                    offset += len(new_lines)

                if not follow:
                    break

                time.sleep(self.rate_limit)

        except Exception as e:
            self.log(f"Error in stream loop", error=e)

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

    def _broadcast_log_lines(self, token: str, target: str, sess: str, offset: int, lines: list):
        try:


            self.log(f"🚨 ENTERED _broadcast_log_lines: sess={sess}, lines={len(lines)}", level="INFO")

            endpoints = self.get_nodes_by_role(self.rpc_role, return_count=1)
            if not endpoints:
                self.log("No hive.rpc-compatible agents found for 'hive.rpc'.")
                return

            remote_pub_pem = self._signing_keys.get("remote_pubkey")

            #expected matrixswarm/matrix_gui/core/dispatcher/inbound_dispatcher.py
            return_handler = self.active_streams.get(sess, {}).get("return_handler", "agent_log_view.update")
            payload = {
                "handler": return_handler,
                "content":{
                    "universal_id": target,
                    "session_id": sess,
                    "token": token,
                    "start_line": offset,
                    "lines": lines,
                    "next_offset": offset + len(lines),
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

            pk1 = self.get_delivery_packet("standard.command.packet")
            pk1.set_data({
                "handler": "dummy_handler", #if a handler isn't set the packet will not set, without a handler
                "origin": self.command_line_args['universal_id'],
                "session_id": sess,
                "content": content,
            })

            for ep in endpoints:
                pk1.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk1, ep.get_universal_id())

        except Exception as e:
            self.log("[LOGSENTINEL][ERROR] Failed to broadcast log lines", error=e)

if __name__ == "__main__":
    agent = Agent()
    agent.boot()