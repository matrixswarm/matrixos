# Authored by Commander & ChatGPT 5.1 — Victory Always Edition
# MATRIX_EMAIL — Secure IMAP Ingress Agent
import os
import sys

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

import time
import threading
import json
import imaplib
import socket
import base64
from email import policy
from email.parser import BytesParser

from core.python_core.boot_agent import BootAgent
from core.python_core.utils.swarm_sleep import interruptible_sleep
from core.python_core.class_lib.packet_delivery.utility.security.unwrap_secure_packet import unwrap_secure_packet
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject
from core.python_core.class_lib.packet_delivery.utility.security.packet_size import guard_packet_size
class Agent(BootAgent):
    """
    MATRIX_EMAIL — IMAP-based secure ingress agent.
    ------------------------------------------------
    Responsibilities:
      • Poll an IMAP inbox for external packets.
      • Expect Phoenix → Swarm packets in base64 form.
      • Decode → unwrap_secure_packet() → forward to Matrix.
      • Provide full BootAgent lifecycle hooks.
      • Maintain encryption + signature parity with Matrix's cmd_the_source.
    """

    def __init__(self):
        super().__init__()

        try:
            self.AGENT_VERSION = "1.0.0"

            config = self.tree_node.get("config", {})
            mail = config.get("imap", {}) or config.get("mail", {})

            # allow incoming packets (True=Deny, False=Allow)
            self.lockdown_state = config.get('lockdown_state', False)  # whether the agent currently accepts external connections (False=accepting packets, True=not accepting packets)
            self.lockdown_time = config.get('lockdown_time', 0)  # seconds to stay offline before auto-reopen (0 = none)
            self.lockdown_expires = 0  # epoch timestamp when lockdown ends

            # IMAP CONFIG
            self.imap_host = mail.get("host") or mail.get("incoming_server")
            self.imap_port = mail.get("port") or mail.get("incoming_port", 993)
            self.imap_user = mail.get("username") or mail.get("incoming_username")
            self.imap_pass = mail.get("password") or mail.get("incoming_password")
            self.imap_folder = mail.get("folder", "INBOX")

            # Polling frequency
            self.poll_interval = int(config.get("poll_interval", 20))

            # SECURITY KEYS
            signing = config.get("security", {}).get("signing", {})
            # Phoenix → Swarm signing key
            self.remote_pubkey = signing.get("remote_pubkey")
            # Our private key for AES unwrap
            self.local_privkey = signing.get("privkey")

            self._msg_retrieval_limit=int(config.get("msg_retrieval_limit", 10))

            self._cfg_lock = threading.Lock()

            if not self.remote_pubkey or not self.local_privkey:
                self.log("[MATRIX_EMAIL][INIT][ERROR] Missing signing keys for secure ingress.")

            self._emit_beacon = self.check_for_thread_poke("worker", timeout=300, emit_to_file_interval=10)

        except Exception as e:
            self.log("[MATRIX_EMAIL][INIT][FATAL]", error=e)

    # ------------------------------------------------------------
    # IMAP
    # ------------------------------------------------------------
    def _connect_imap(self):
        """Connect to IMAP server using SSL."""
        try:
            socket.setdefaulttimeout(20)
            M = imaplib.IMAP4_SSL(self.imap_host, self.imap_port)
            M.login(self.imap_user, self.imap_pass)
            return M
        except Exception as e:
            self.log("[MATRIX_EMAIL][IMAP][ERROR] Failed IMAP connection", error=e)
            return None

    def _get_unread_messages(self):
        """
        Retrieve the newest N unread messages and delete all others.
        """
        M = self._connect_imap()
        if not M:
            return []

        msgs = []
        try:
            M.select(self.imap_folder)
            typ, data = M.search(None, "UNSEEN")
            mail_ids = data[0].split()

            if not mail_ids:
                return []

            # Select the most recent N emails (sorted by arrival)
            newest = mail_ids[-self._msg_retrieval_limit:]

            for mid in newest:
                typ, parts = M.fetch(mid, "(RFC822)")
                if typ != "OK":
                    continue
                raw_msg = parts[0][1]
                msgs.append(raw_msg)

            # Nuke all messages regardless of success/failure
            for mid in mail_ids:
                M.store(mid, "+FLAGS", "\\Deleted")

            # Check mailbox state and processing flag
            if len(msgs) > 0:
                self.log(f"[MATRIX_EMAIL] 📬 {len(msgs)} unread messages detected — beginning processing.")
            else:
                self.log("[MATRIX_EMAIL] 📭 No unread messages found.")

        except Exception as e:
            self.log("[MATRIX_EMAIL][IMAP][FETCH][ERROR]", error=e)

        finally:
            try:
                M.expunge()
                M.logout()
            except:
                pass

        return msgs

    # ------------------------------------------------------------
    # Parsing packets from email
    # ------------------------------------------------------------
    def _extract_payload_from_email(self, raw_bytes):
        try:
            # Step 1: Parse the email safely
            msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

            # Step 2: Try normal MIME-walk method
            for part in msg.walk():
                cte = part.get("Content-Transfer-Encoding", "").lower()
                if cte == "base64":
                    try:
                        payload_bytes = part.get_payload(decode=True)
                        try:
                            return json.loads(payload_bytes.decode("utf-8"))
                        except:
                            return payload_bytes
                    except Exception as e:
                        self.log("[MATRIX_EMAIL][EXTRACT] Failed base64 decode", error=e)

            # Step 3: Fallback: assume raw base64 string in plain text body
            body = msg.get_body(preferencelist=('plain'))
            if body:
                raw = body.get_content().strip()
            else:
                # fallback to full body
                raw = msg.get_content().strip()

            # Step 4: Try base64 decode directly
            try:
                decoded_bytes = base64.b64decode(raw, validate=True)
                try:
                    return json.loads(decoded_bytes.decode("utf-8"))
                except json.JSONDecodeError:
                    self.log("[MATRIX_EMAIL][EXTRACT] Fallback decode is not JSON.")
                    return decoded_bytes
            except Exception as e:
                self.log("[MATRIX_EMAIL][EXTRACT] Fallback raw decode failed", error=e)

            return None

        except Exception as e:
            self.log("[MATRIX_EMAIL][EXTRACT][FATAL]", error=e)
            return None

    # ------------------------------------------------------------
    # Packet unwrap + forward to Matrix
    # ------------------------------------------------------------
    def _unwrap_and_forward(self, outer_packet):
        """
        Unwrap using the EXACT same unwrap_secure_packet() used by Matrix.
        Then forward the unwrapped dict directly to Matrix as a normal
        standard.command.packet {handler:"cmd_the_source", content:{...}}.

        This preserves swarm crypto lineage 1:1.
        """
        try:

            if not guard_packet_size(outer_packet, log=self.log):
                self.log("bad or oversize payload")
                return False

            unwrapped = unwrap_secure_packet(
                outer_packet,
                self.remote_pubkey,
                self.local_privkey,
                logger=self.log
            )

            if not unwrapped:
                self.log("[MATRIX_EMAIL][UNWRAP] ❌ Packet rejected.")
                return False

            matrix_packet = unwrapped.get("matrix_packet",False)
            if not matrix_packet or not isinstance(matrix_packet, dict):
                self.log("[MATRIX_EMAIL][MALFORMED] ❌ MALFORMED Packet rejected.")
                return False

            # 8) All gates passed — relay to Matrix
            self.log(f"[MATRIX-HTTPS][RELAY] {self.imap_user}:{self.imap_host} → cmd_the_source")
            #self.log(f"[MATRIX-HTTPS][RELAY] {unwrapped}")

            # Forward to Matrix
            pk = self.get_delivery_packet("standard.command.packet")
            pk.set_data({'handler': "cmd_the_source", "content": matrix_packet})  # relay the verified inner command

            self.pass_packet(pk, "matrix")

            return True

        except Exception as e:
            self.log("[MATRIX_EMAIL][FORWARD][ERROR]", error=e)
            return False

    # ------------------------------------------------------------
    # Command Handlers
    # ------------------------------------------------------------
    def cmd_status(self, content, packet, identity: IdentityObject = None):
        try:
            session_id = content.get("session_id")
            token = content.get("token")
            return_handler = content.get("return_handler")
            payload = {
                "lockdown_state": "Lockdown" if self.lockdown_state else "Open",
                "lockdown_time": self.lockdown_time,
                "lockdown_expires": str(bool(self.lockdown_expires)),
                "imap_host": self.imap_host,
                "imap_user": self.imap_user,
                "folder": self.imap_folder,
                "poll_interval": self.poll_interval,
                "retrieval_limit": self._msg_retrieval_limit,
            }

            self.crypto_reply(
                response_handler=return_handler,
                payload=payload,
                session_id=session_id,
                token=token,
                rpc_role=self.tree_node.get("config", {}).get("rpc_router_role", "hive.rpc"),
            )

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    def cmd_toggle_perimeter(self, content, packet, identity: IdentityObject = None):
        """
        Swarm command to raise or lower this agent's perimeter.
        Expects content keys:
            lockdown_state (bool)            -> True=open, False=lockdown
            lockdown_time (int)     -> seconds before auto reopen (optional)
            token (str)             -> optional 2FA token for override
        """
        try:

            lockdown_state = bool(content.get("lockdown_state", True))  #up accepting packets, down rejecting packets
            lockdown_time = int(content.get("lockdown_time", 0)) #how long to lockdown in secs or 0 stay down
            session_id = content.get("session_id")
            token = content.get("token")
            return_handler = content.get("return_handler")

            self.toggle_perimeter(lockdown_state, lockdown_time)

            payload = {
                "lockdown_state": "Lockdown" if self.lockdown_state else "Open",
                "lockdown_time": self.lockdown_time,
                "lockdown_expires": str(bool(self.lockdown_expires)),
            }

            self.crypto_reply(
                response_handler=return_handler,
                payload=payload,
                session_id=session_id,
                token=token,
                rpc_role=self.tree_node.get("config", {}).get("rpc_router_role", "hive.rpc"),
            )

            self.log(f"[LOCKDOWN] Perimeter toggled → {payload}")

        except Exception as e:
            self.log(f"[LOCKDOWN][ERROR] cmd_toggle_perimeter failed: {e}")

    def toggle_perimeter(self, lockdown_state, lockdown_time):
        self.lockdown_time = lockdown_time
        if not lockdown_state:
            self.lockdown_state = False
        else:
            self.lockdown_state = True
            self.lockdown_expires = int(time.time()) + lockdown_time if lockdown_time > 0 else 0

    # ------------------------------------------------------------
    # Worker loop
    # ------------------------------------------------------------
    def worker(self, config=None, identity: IdentityObject=None):
        try:

            self._emit_beacon()

            # Detect config changes dynamically
            if isinstance(config, dict) and bool(config.get("push_live_config", 0)):
                self.log(f"[ORACLE] 🔁 Live config update detected: {config}")
                self._apply_live_config(config)

            if self.lockdown_state and self.lockdown_time > 0:
                now = int(time.time())
                if now >= self.lockdown_expires:
                    self.log("[LOCKDOWN] Time expired. Reopening perimeter.")
                    self.toggle_perimeter(False, 0)  # Reopen and reset

            if not self.lockdown_state:

                msgs = self._get_unread_messages()

                if not msgs:
                    return

                for raw in msgs:
                    outer = self._extract_payload_from_email(raw)
                    if not outer:
                        continue

                    self._unwrap_and_forward(outer)
            else:
              self.log(f"[MATRIX-EMAIL][BLOCKED] Packet Processing is Off.")

        except Exception as e:
            self.log("[MATRIX_EMAIL][WORKER][ERROR]", error=e)

        finally:
            interruptible_sleep(self, self.poll_interval)

    def _apply_live_config(self, cfg: dict):
        """
        Dynamically applies updated configuration pushed from Phoenix.
        Supports process_packets.
        """
        try:

            pass

        except Exception as e:
            self.log("[ORACLE][ERROR] Failed to apply live config", error=e)

    def post_boot(self):
        self.log(f"[MATRIX_EMAIL] All aboard — one-way ticket to the Matrix. Buckle up and enjoy the ride. Version {self.AGENT_VERSION}")

if __name__ == "__main__":
    agent = Agent()
    agent.boot()
