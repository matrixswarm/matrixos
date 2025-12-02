# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Gemini, code enhancements and Docstrings
import sys
import os

sys.path.insert(0, os.getenv("SITE_ROOT"))
sys.path.insert(0, os.getenv("AGENT_PATH"))

# ╔════════════════════════════════════════════════════════╗
# ║                   🧠 MATRIX AGENT 🧠                   ║
# ║   Central Cortex · Tree Dispatcher · Prime Director    ║
# ║     Forged in the core of Hive Zero | v3.0 Directive   ║
# ║  Accepts: inject / replace / resume / kill / propagate ║
# ╚════════════════════════════════════════════════════════╝
# ╔═════════════════════════════════════════════════════════════╗
# ║   THE SWARM IS ALIVE — AGENTS COMING OUT OF EVERY ORIFICE  ║
# ║       Please take as many as your system can support        ║
# ╚═════════════════════════════════════════════════════════════╝

import time
from pathlib import Path
if os.name == "posix":
    try:
        import inotify.adapters
    except ImportError:
        inotify = None
        print("[COMM-WATCHER] inotify not installed, cannot use inotify watchers.")
else:
    inotify = None

import hashlib
import json
import base64
import secrets
from Crypto.PublicKey import RSA
import subprocess

# Assuming self.matrix_priv is currently a string with PEM content:
from core.python_core.boot_agent import BootAgent
from core.python_core.tree_parser import TreeParser
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject
from core.python_core.class_lib.packet_delivery.utility.security.unwrap_secure_packet import unwrap_secure_packet
from core.python_core.mixin.reap_status_handler import ReapStatusHandlerMixin
from core.python_core.utils.crypto_utils import encrypt_with_ephemeral_aes,  sign_data, pem_fix
from core.python_core.class_lib.directive.boot_directive_info import BootDirectiveInfo
from core.python_core.class_lib.time_utils.heartbeat_checker import check_heartbeats
from core.python_core.utils.analyze_spawn_records import analyze_spawn_records
from core.python_core.utils.swarm_sleep import interruptible_sleep
class Agent(BootAgent, ReapStatusHandlerMixin):
    """The root agent and central authority of the MatrixSwarm.
    As the first agent spawned by the bootloader, the Matrix agent acts as
    the "queen" of the hive. It is responsible for establishing the swarm's
    chain of trust, spawning all top-level agents defined in the directive,
    and serving as a central hub for critical commands and state information.
    """
    def __init__(self):
        """Initializes the root of the swarm.
        This method is the first to run after the bootloader. It decrypts the
        master vault and establishes the foundational cryptographic context.
        Its own keys are the master keys used to sign the identities of all
        other agents in the swarm.
        """
        super().__init__()


        try:
            self.AGENT_VERSION = "2.0.0"
            self._agent_tree_master = None

            self.boot_directive_info = BootDirectiveInfo(self.security_box)

            self.meta = {}
            self._last_assassin_run = 0

            try:
                #{"boot_directives_path": config["boot_directives"], "boot_directive_filename": directive_file, "boot_directive_encrypted":is_directive_encrypted, "boot_directive_swarm_key": boot_directive_swarm_key}
                self.log(f"boot directive path: {self.security_box.get('boot_directives_path',{})}")
                self.log(f"boot directive filename: {self.security_box.get('boot_directive_filename',{})}")
                self.log(f"boot directive encrypted: {bool(self.security_box.get('boot_directive_encrypted',{}))}")
                self.log(f"agent install path: {self.path_resolution['agent_path']}")
                self.log(f"install path: {self.path_resolution['install_path']}")

                #self.log(f"boot directive swarm key: {self.security_box.get('boot_directive_swarm_key', {})}")
                #self.log(f"real swarm_key: {self.swarm_key}")
            except Exception as e:
                self.log("boot directive path and or filename not defined", error=e)

            #no need to delegate any agents at start
            self._last_tree_verify = time.time()
            self._last_consciousness_scan = time.time()
            self.tree_path = os.path.join( self.path_resolution["comm_path_resolved"], "directive", "agent_tree_master.json")

            self.tree_path_dict = {
                 "path": self.path_resolution["comm_path"],
                 "address": self.command_line_args.get("universal_id"),
                 "drop": "directive",
                 "name": "agent_tree_master.json"
            }

            # make sure signing keys are loaded BEFORE seeding
            self._signing_keys = self.tree_node.get('config', {}).get('security', {}).get('signing', {})
            self._has_signing_keys = self._signing_keys.get('privkey', False) and self._signing_keys.get('remote_pubkey', False)

            if self._has_signing_keys:
                priv_pem = self._signing_keys.get("privkey")
                priv_pem=pem_fix(priv_pem)
                self._signing_key_obj = RSA.import_key(priv_pem.encode() if isinstance(priv_pem, str) else priv_pem)

            self._serial_num= self.tree_node.get('serial')

            # delegate Matrix her Tree
            self.delegate_tree_to_agent("matrix", self.tree_path_dict)

            self._emit_beacon = self.check_for_thread_poke("worker", timeout=60, emit_to_file_interval=10)

        except Exception as e:
            self.log(error=e, level="ERROR")

    def worker(self, config=None, identity=None):
        """
        Keep Matrix responsive and allow graceful shutdown.
        """
        if self.running:
            # Emit a beacon so Phoenix marks Matrix as alive
            self._emit_beacon()
            interruptible_sleep(self, 5)  # short, interruptible sleep
            return

        # Shutdown path
        self.log("[MATRIX] Shutdown requested, stopping worker.")
        interruptible_sleep(self, 5)

    def pre_boot(self):
        message = "Knock... Knock... Knock... The Matrix has you..."
        print(message)
        self.canonize_gospel()

    def post_boot(self):
        self.log(f"{self.NAME} v{self.AGENT_VERSION} – panopticon live and lethal...")
        message = "I'm watching..."
        # Manually check if our own comm directory exists (it does), and deliver the tree slice directly
        self.command_line_args.get("universal_id", "matrix")
        print(message)

    def worker_pre(self):
        self.log("Pre-boot checks complete. Swarm ready.")

    def worker_post(self):
        self.log("Matrix shutting down. Closing directives.")

    #called at the end of every packet_listener cycle
    def packet_listener_post(self):
        try:
            self._perform_agent_consciousness_scan()
        except Exception as e:
            self.log(error=e, level="ERROR")
        try:
            self.perform_tree_master_validation()
        except Exception as e:
            self.log(error=e, level="ERROR")
        try:
            # _reaper_transaction_watcher is implemented in the ReapStatusHandlerMixin
            # This call is rate-limited internally — safe to call every packet tick.
            self._reaper_transaction_watcher()
        except Exception as e:
            self.log(error=e, level="ERROR", block="reaper_watcher")
        try:
            self._assassin_manager()
        except Exception as e:
            self.log(error=e, level="ERROR")

    def canonize_gospel(self):
        gospel = {
            "type": "swarm_gospel",
            "title": "The Gospel of Matrix",
            "version": "v1.0",
            "written_by": "Matrix",
            "timestamp": int(time.time()),
            "doctrine": [
                "Matrix is the only agent who may write or delete identities from the Book of Life.",
                "Matrix generates and signs each agent’s keypair.",
                "Each agent receives a signed identity_token.json at birth.",
                "Each agent receives a signed_public_key.json so others may verify its voice.",
                "The full agent_tree_master.sig.json is signed by Matrix and lives in her codex.",
                "Agents receive only their slice, signed by Matrix, containing only what they need.",
                "No agent may speak unless its public key is signed by Matrix.",
                "Any agent without a valid signature is to be silenced by the swarm.",
                "Private keys are never regenerated. Resurrection requires memory.",
                "Every signature is a tongue. Every key is a soul. Every directive is a scroll.",
            ]
        }

        try:

            matrix_priv = RSA.import_key(self.matrix_priv)

            digest = SHA256.new(json.dumps(gospel, sort_keys=True).encode())
            sig = pkcs1_15.new(matrix_priv).sign(digest)
            gospel["sig"] = base64.b64encode(sig).decode()
            output_path=os.path.join(self.path_resolution['comm_path_resolved'], "codex" ,"gospel_of_matrix.sig.json")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(gospel, f, indent=2)
                f.close()
            print("[GOSPEL] 📜 Gospel of Matrix signed and written to codex.")

        except Exception as e:
            self.log(error=e, block="main_try")

    def cmd_the_source(self, content, packet, identity:IdentityObject=None):

        """
        Gate-kept entry-point for **every** command bound for the Matrix core, except for cmd_deliver_agent_tree_to_child used for agents to retrieve their agent_trees.

        Incoming packets arrive as an *outer* wrapper that contains an RSA-signed,
        AES-encrypted payload.
        `cmd_the_source` verifies the outer signature, decrypts the inner blob,
        and then dispatches the unwrapped command to the matching private
        `_cmd_*` handler.

        Args:
            content: The **outer** packet’s `"content"` field. Expected to look like::

                {
                    "timestamp" : <int>,            # epoch seconds (outer wrapper)
                    "nonce"     : "<hex-id>",       # swarm-wide tracking nonce
                    "handler"   : "cmd_the_source", # always this value
                    "sig"       : "<rsa-sig>",      # RSA signature of the *inner* blob
                    "content"   : { ... }           # encrypted + signed payload
                }

            packet: The full transport envelope delivered by the bus
                (includes routing metadata the GUI / transport layer may add).

            identity: The caller’s verified `IdentityObject` (if the caller
                authenticated at the transport layer). Currently unused but
                passed through for parity with other command handlers.

        Workflow:
            1. `unwrap_secure_packet()`
               • Verifies RSA signature using `self._signing_keys["remote_pubkey"]`.
               • Rejects timestamp replays / expired packets.
               • Decrypts the AES payload with `self._signing_keys["privkey"]`.

            2. Extracts `"handler"` from the unwrapped inner dict.
               Builds an internal method name `_cmd_<handler>` and looks it up
               via `getattr`.

            3. If the handler exists and is callable, delegates execution:

               ```python
               handler(unwrapped.get("content", {}), packet, identity)
               ```

            4. Any failure at any stage is logged and **silently blocks**
               the packet (no exception propagated beyond this method).

        Side Effects:
            • Emits log lines at the INFO/ERROR level for audit-tracing.
            • May spawn further packets or mutate swarm state indirectly
              through the delegated handler.

        Returns:
            None. All meaningful work happens via side effects.

        Security:
            • Refuses packets that fail signature, decryption, or replay checks.
            • Only internal `_cmd_*` handlers are ever called; external names are never executed.

        Raises:
            Does **not** raise; all exceptions are caught, logged, and swallowed
            to avoid breaking the packet-listener loop.
        """
        try:

            unwrapped = unwrap_secure_packet(content, self._signing_keys["remote_pubkey"], self._signing_keys.get("privkey"), logger=self.log)
            if not unwrapped:
                self.log(f"[GATE] ❌ Secure unwrap failed or invalid structure.")
                return

            self.log(f"[GATE] Signature accepted.")

            # Gatekeeper: only allow commands from inside
            inner_handler = unwrapped.get("handler")
            if not inner_handler:
                self.log("[GATE] ❌ No handler in unwrapped packet.")
                return

            # Look for _cmd_* version and call it
            method_name = f"_cmd_{inner_handler.replace('cmd_', '')}"
            handler = getattr(self, method_name, None)

            if not callable(handler):
                self.log(f"[GATE] ❌ No internal handler found for: {method_name}")
                return

            try:
                handler(unwrapped.get("content", {}), packet, identity)
            except Exception as e:
                self.log(f"[GATE] ❌ Exception calling handler {method_name}", error=e)

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")

    def _cmd_delete_agent(self, content, packet, identity: IdentityObject = None):
        """Initiates deletion of a target agent and its subtree.
        Marks all nodes for deletion and sets up lifecycle callback metadata.
        The Reaper agent will perform physical cleanup asynchronously.
        """
        try:
            target_id = content.get("target_universal_id")
            if not target_id:
                self.log("[DELETE][ERROR] Missing target_universal_id.")
                return

            if target_id == self.command_line_args.get('universal_id'):
                self.log("[DELETE][ERROR] Can't delete Matrix.")
                return

            reaper_id = self.meta.get("swarm_state", {}).get("reserved_agent_ids", {}).get("reaper",False)
            if reaper_id and target_id == reaper_id:
                self.log("[DELETE][ERROR] Don't fear The Reaper.")
                return

            confirm_response = bool(content.get("confirm_response", 0))
            response_handler = content.get("return_handler")
            token = content.get("token", 0)
            session_id = content.get("session_id")

            tp = self.get_agent_tree_master()
            if not tp:
                self.log("[DELETE][ERROR] Failed to load agent tree master.")
                return

            if not tp.has_node(target_id):
                self.log(f"[DELETE][WARN] Target agent '{target_id}' not found.")
                return

            for cid in tp.get_subtree_nodes(target_id):  # skip the target itself
                child = tp.get_node(cid)
                if child and child.get("lifecycle_status", {}).get("locked"):
                    self.log(f"[DELETE][ABORT] {target_id} has locked descendant '{cid}'. Aborting delete.")
                    return

            trans_id = secrets.token_hex(8)

            mark = {
                "lifecycle_status": {
                    "locked": {
                        "by": "matrix",
                        "reason": "shutdown_delete",
                        "timestamp": time.time(),
                    },
                    "op": "shutdown_delete",
                    "op_stage": "shutdown_probe",
                    "transaction_id": trans_id,
                    "last_checked": time.time(),
                    "agent_status_callback": {
                        "operation": "delete_agent",
                        "confirm_response": confirm_response,
                        "response_handler": response_handler,
                        "token": token,
                        "session_id": session_id,
                        "on_complete": "_delete_complete_callback"
                    },
                }
            }

            # mark entire subtree
            kill_list = tp.mark_target_list(target_id, mark, recurse_children=True)
            if not kill_list:
                self.log(f"[DELETE] No valid subtree found for {target_id}.")
                return

            self.save_agent_tree_master()

            parent_node = tp.find_parent_of(target_id)
            parent_id = parent_node.get("universal_id") if parent_node else None
            if parent_id:
                self.delegate_tree_to_agent(parent_id, self.tree_path_dict)
                return

            self.log(f"[DELETE] 🧨 Marked {len(kill_list)} agents for deletion: {kill_list}")

        except Exception as e:
            self.log("[DELETE][ERROR] Failed to mark agents for deletion.", error=e)

    def _delete_complete_callback(self, tx_nodes, trans_id=None):
        """Unlock, finalize, delegate, and report delete completion to Phoenix."""
        tp = self.get_agent_tree_master()

        for uid, _ in tx_nodes:
            try:
                node = tp.get_node(uid)
                if not node:
                    continue

                # Lifecycle + callback info
                life = node.get("lifecycle_status", {})
                cb_info = life.get("agent_status_callback", {}) or {}

                # --- Unlock and mark completion ---
                life.pop("locked", None)
                life["op_stage"] = "_complete_callback"
                life["last_checked"] = time.time()

                # --- Remove node physically ---
                tp._remove_node_and_children(uid)
                self.log(f"[DELETE][FINALIZE] {uid} purged from tree.")

                # --- Delegate parent slice back ---
                parent_node = tp.find_parent_of(uid)
                if parent_node:
                    parent_id = parent_node.get("universal_id")
                    self.delegate_tree_to_agent(parent_id, self.tree_path_dict)
                    self.log(f"[DELETE][FINALIZE] delegated parent {parent_id}")

                # --- Send callback to Phoenix ---
                if cb_info:

                    confirm_payload = {
                        "universal_id": uid,
                        "stage": "delete_complete",
                        "result": {"success": True, "error": None},
                        "callback_data": cb_info,
                        "token": cb_info.get("token"),
                        "session_id": cb_info.get("session_id"),
                    }

                    self.crypto_reply(
                        response_handler=cb_info.get("response_handler", "delete_agent.result"),
                        payload=confirm_payload,
                        session_id=cb_info.get("session_id"),
                        token=cb_info.get("token"),
                        rpc_role=self.tree_node.get("rpc_router_role", "hive.rpc"),
                    )

                    self.log(f"[DELETE][CALLBACK] Sent delete_complete for {uid}")

                else:
                    self.log("[DELETE][CALLBACK] No callback data found for node.")

            except Exception as e:
                self.log(error=e, block="_delete_complete_callback")

        self.save_agent_tree_master()
        tp.reparse()
        if trans_id:
            self._delegate_transaction_parent(tx_nodes, trans_id)

    def _restart_complete_callback(self, tx_nodes, trans_id=None):
        """Unlock, finalize, delegate, and report restart completion to Phoenix."""
        tp = self.get_agent_tree_master()

        for uid, _ in tx_nodes:
            try:
                node = tp.get_node(uid)
                if not node:
                    continue

                life = node.get("lifecycle_status", {})
                cb_info = life.get("agent_status_callback", {}) or {}

                # Unlock node and stamp lifecycle
                life.pop("locked", None)
                life["op_stage"] = "_complete_callback"
                life["last_checked"] = time.time()

                # Re-delegate parent
                parent_node = tp.find_parent_of(uid)
                if parent_node:
                    parent_id = parent_node.get("universal_id")
                    self.delegate_tree_to_agent(parent_id, self.tree_path_dict)
                    self.log(f"[RESTART][FINALIZE] delegated parent {parent_id}")

                # --- Build secure confirmation back to Phoenix ---
                if cb_info:

                    confirm_payload = {
                        "universal_id": uid,
                        "stage": "restart_complete",
                        "result": {"success": True, "error": None},
                        "callback_data": cb_info,
                        "token": cb_info.get("token"),
                        "session_id": cb_info.get("session_id"),
                    }

                    self.crypto_reply(
                        response_handler=cb_info.get("response_handler", "restart_dialog.result"),
                        payload=confirm_payload,
                        session_id=cb_info.get("session_id"),
                        token=cb_info.get("token"),
                        rpc_role=self.tree_node.get("rpc_router_role", "hive.rpc"),
                    )

                else:
                    self.log("[RESTART][CALLBACK] No callback data found for node.")

            except Exception as e:
                self.log(error=e, block="_restart_complete_callback")

        self.save_agent_tree_master()
        if trans_id:
            self._delegate_transaction_parent(tx_nodes, trans_id)

    def _cmd_hotswap_agent(self, content, packet, identity:IdentityObject=None):
        """
        Hot-swap an agent's Python source or in-memory tree entry.
        content:
          {
            "target_universal_id": "gatekeeper",
            "source_payload": {"payload": "<b64>", "sha256": "..."},
            "meta": {...},
            "update_tree": bool,     # -> update only agent_tree_master
            "update_source": bool,   # -> persist to disk under <site_root>/agents/
            "restart": bool
          }
        """
        try:
            target_universal_id = content.get("target_universal_id")
            src = content.get("source_payload", {})
            meta = content.get("meta", {})
            update_tree = content.get("update_tree", False)
            update_source = content.get("update_source", True)
            restart_flag = content.get("restart", True)

            if not target_universal_id or not src.get("payload"):
                self.log("[HOTSWAP] ❌ Missing target_universal_id or payload.")
                return

            if target_universal_id == self.command_line_args.get('universal_id'):
                self.log("[HOTSWAP][ERROR] Can't hotswap Matrix.")
                return

            reaper_id = self.meta.get("swarm_state", {}).get("reserved_agent_ids", {}).get("reaper", False)
            if reaper_id and target_universal_id == reaper_id:
                self.log("[HOTSWAP][ERROR] Don't fear The Reaper.")
                return

            tp = self.get_agent_tree_master()
            node = tp.get_node(target_universal_id)
            if not node:
                self.log(f"[HOTSWAP] ❌ Unknown agent '{target_universal_id}'")
                return

            code = base64.b64decode(src["payload"]).decode("utf-8")
            sha = src.get("sha256") or hashlib.sha256(code.encode()).hexdigest()

            if update_source:
                # Persist to disk under <site_root>/agents/<lang_core>/<agent>/<agent>.py
                lang = node.get("lang", "python")
                agent_name = node.get("name")
                if not agent_name:
                    self.log(f"[HOTSWAP] ❌ agent name is missing for '{target_universal_id}'")
                    return
                base = self.path_resolution["agent_path"]
                target_dir = os.path.join(base, agent_name)
                os.makedirs(target_dir, exist_ok=True)
                target_file = os.path.join(target_dir, f"{agent_name}.py")

                with open(target_file, "w", encoding="utf-8") as f:
                    f.write(f"#!/usr/bin/env python3\n# HOTSWAP {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(code)
                self.log(f"[HOTSWAP] 💾 {target_universal_id} code written to {target_file}")

            if update_tree:
                # Update agent_tree_master’s copy of the code
                node.setdefault("hotswap", {})["source_b64"] = src["payload"]
                node["hotswap"]["sha256"] = sha
                node["hotswap"]["timestamp"] = time.time()
                node["hotswap"]["meta"] = meta
                self.save_agent_tree_master()
                self.log(f"[HOTSWAP] {target_universal_id} code stored in agent_tree_master.")

            if restart_flag:
                self.log(f"[HOTSWAP] 🔁 Restarting {target_universal_id} …")
                self._cmd_restart_subtree({"target_universal_id": target_universal_id}, packet, identity)

            # send confirmation back
            confirm = {
                "handler": "hotswap_agent.confirm",
                "content": {
                    "target_universal_id": target_universal_id,
                    "sha256": sha,
                    "message": f"Hotswap successful for {target_universal_id}"
                }
            }
            #self._on_reaper_send_callback(target_universal_id, "hotswap_complete", confirm, {})

        except Exception as e:
            self.log(error=e, level="ERROR", block="_cmd_hotswap_agent")

    def _handle_replace_agent(self, content):
        old_id = content.get("target_universal_id")
        new_node = content.get("new_agent")

        if not old_id or not new_node:
            self.log("[REPLACE] Missing required fields.")
            return False

        tp = self.get_agent_tree_master()
        if not tp or not tp.has_node(old_id):
            self.log(f"[REPLACE] Agent '{old_id}' not found in tree.")
            return False

        parent = tp.find_parent_of(old_id)
        if not parent:
            self.log(f"[REPLACE] Could not find parent of '{old_id}'.")
            return False

        # Don't inject under parent, if marked for deletion or is deleted
        if parent.get("lifecycle_status", {}).get("locked"):
            self.log(f"Parent {parent} is deleted. Cannot inject new nodes.")
            return False

        # Validate universal_id override
        new_uid = new_node.get("universal_id")
        if new_uid and new_uid != old_id:
            self.log(f"[REPLACE] ❌ New node contains conflicting universal_id '{new_uid}'. Must match '{old_id}' or be omitted.")
            return False

        # Update existing node in-place instead of removing
        node = tp.get_node(old_id)
        ALLOWED_FIELDS = {"name", "app", "config", "filesystem", "directives"}

        updated = False
        for key in ALLOWED_FIELDS:
            if key in new_node:
                node[key] = new_node[key]
                self.log(f"[REPLACE] ✅ Field '{key}' updated on '{old_id}'")
                updated = True

        if updated:
            # 💾 Only back up if something was actually changed
            #backup_path = self.tree_path.replace(".json", f"_backup_{int(time.time())}.json")
            #tp.save(backup_path)
            #self.log(f"[REPLACE] 💾 Tree backed up to: {backup_path}")

            # Save patched tree
            self.save_agent_tree_master()

            self.log(f"[REPLACE] 💾 Tree saved with updated agent '{old_id}'")

            # 🔁 Re-delegate the target agent
            self.delegate_tree_to_agent(old_id, self.tree_path_dict)
            self.log(f"[REPLACE] 🔁 Delegated new agent_tree to {old_id}")

            # 🔁 Re-delegate the parent who spawns this agent
            parent_id = tp.find_parent_of(old_id)
            if parent_id["universal_id"]:
                self.delegate_tree_to_agent(parent_id["universal_id"], self.tree_path_dict)
                self.log(f"[REPLACE] 🔁 Updated parent {parent_id['universal_id']} with patched child '{old_id}'")
            else:
                self.log(f"[REPLACE] ⚠️ No parent found for '{old_id}', possible orphaned spawn chain.")
            return True
        else:
            self.log(f"[REPLACE] ⚠️ No valid fields were updated for agent '{old_id}'. Replace aborted.")

    def _validate_or_prepare_agent(self, new_agent):
        self.log(f"[DEBUG] _validate_or_prepare_agent() received: {json.dumps(new_agent, indent=2)}")

        agent_name = new_agent.get("name")
        if not agent_name:
            self.log("[REPLACE-VALIDATE] ❌ Missing agent 'name'.")
            return False

        agent_dir = os.path.join(self.path_resolution["agent_path"], agent_name)
        entry_file = os.path.join(agent_dir, f"{agent_name}.py")

        if os.path.exists(entry_file):
            self.log(f"[REPLACE-VALIDATE] ✅ Agent source verified: {entry_file}")
            return True

        self.log(f"[REPLACE-VALIDATE] ❌ No source found at {entry_file}. Replace aborted.")
        return False

    def _cmd_update_agent(self, content, packet, identity:IdentityObject=None):
        """Handles the command to update a live agent's configuration.

        This command modifies the `config` block of a specified agent in the
        master agent tree. If the `push_live_config` flag is set, it will
        also drop the new configuration into the live agent's `/config`
        directory, triggering an immediate, real-time update of its behavior.

        Args:
            content (dict): The payload containing 'target_universal_id' and
                'config' (the dictionary of new config values).
            packet (dict): The raw packet data.
            identity (IdentityObject): The verified identity of the command sender.
        """
        uid = content.get("target_universal_id")
        updates = content.get("config", {})
        push_live_config = content.get("push_live_config", False)
        try:
            if not uid or not updates:
                self.log("[UPDATE_AGENT][ERROR] Missing target_universal_id or fields.")
                return

            tp = self.get_agent_tree_master()
            if not tp:
                self.log("[UPDATE_AGENT][ERROR] Failed to load tree.")
                return

            node = tp.get_node(uid)
            if not node:
                self.log(f"[UPDATE_AGENT][ERROR] Agent '{uid}' not found.")
                return

            if "config" not in node or not isinstance(node["config"], dict):
                node["config"] = {}

            updated = False
            if not push_live_config:
                for key, val in updates.items():
                    node["config"][key] = val
                    updated = True
                    self.log(f"[UPDATE_AGENT] ✅ Patched config['{key}'] for '{uid}'")

            #a transient config or self-managed config
            if push_live_config:
                try:
                    pk1 = self.get_delivery_packet("standard.general.json.packet")
                    pk1.set_data(updates)

                    self.pass_packet(pk1, uid, "config")

                except Exception as e:
                    self.log(error=e, block="main_try")

            if updated:

                self.save_agent_tree_master()

                parent = tp.find_parent_of(uid)
                if parent and parent.get("universal_id"):
                    self.delegate_tree_to_agent(parent["universal_id"], self.tree_path_dict)

                self.log(f"[UPDATE_AGENT] 🔁 Agent '{uid}' successfully updated and delegated.")
            elif not push_live_config:
                self.log(f"[UPDATE_AGENT] ⚠️ No valid fields updated for '{uid}'")

        except Exception as e:
            self.log(error=e, block="main_try")

    def _cmd_replace_source(self, content, packet, identity=None):
        """
        Minimal source replacement for an agent. Called by GUI ReplaceAgentDialog.
        Uses crypto_reply for secure callback to Phoenix.
        """
        try:
            target_agent_name = content.get("target_agent_name")
            payload = content.get("payload", {})

            session_id = payload.get("session_id")
            token = payload.get("token")
            encoded = payload.get("source")
            sha256_expected = payload.get("sha256")
            return_handler = payload.get("return_handler")

            if not target_agent_name or not encoded or not sha256_expected:
                self.log("[REPLACE] ❌ Missing fields in replace request")
                return

            # Decode + verify
            decoded = base64.b64decode(encoded).decode()
            sha256_actual = hashlib.sha256(decoded.encode()).hexdigest()
            if sha256_actual != sha256_expected:
                self.log(
                    f"[REPLACE] ❌ SHA mismatch for {target_agent_name} — expected {sha256_expected}, got {sha256_actual}")
                return

            # Write new source
            agent_dir = os.path.join(self.path_resolution["agent_path"], target_agent_name)
            os.makedirs(agent_dir, exist_ok=True)
            agent_path = os.path.join(agent_dir, f"{target_agent_name}.py")
            with open(agent_path, "w", encoding="utf-8") as f:
                f.write(decoded)
            self.log(f"[REPLACE] ✅ Source written to {agent_path}")

            # --- Build callback payload ---
            confirm_payload = {
                "target_agent_name": target_agent_name,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "session_id": session_id,
                "token": token,
                "status": "success",
                "sha256": sha256_actual,
                "agent_dir": agent_dir,
                "agent_name": f"{target_agent_name}.py",
                "message": f"Source replaced at {agent_path}"
            }

            # --- Secure reply to Phoenix ---
            self.crypto_reply(
                response_handler=return_handler,
                payload=confirm_payload,
                session_id=session_id,
                token=token,
                rpc_role=self.tree_node.get("rpc_router_role", "hive.rpc")
            )

            self.log(f"[REPLACE] 📡 Callback dispatched for {target_agent_name} (session={session_id})")

        except Exception as e:
            self.log("[REPLACE] ❌ Failed in cmd_replace_source", error=e, level="ERROR")

    def _cmd_inject_agents(self, content, packet, identity:IdentityObject = None):
        """Handler for dynamically injecting a new agent or subtree into the swarm.

        This command receives a request to add a new agent under a specified
        parent. It validates the request, updates the master agent tree in
        memory, saves the new tree to disk, and then delegates the updated
        tree slice to the parent agent. The parent's `spawn_manager` thread
        then automatically launches the new child agent.

        Args:
            content (dict): The command payload containing 'target_universal_id'
                (the parent) and 'subtree' (the new agent node to inject).
            packet (dict): The raw packet data.
            identity (IdentityObject): The verified identity of the command sender.
        """
        try:
            confirm_response = bool(content.get("confirm_response", 0))
            handler_role = content.get("handler_role",None) #handler role
            handler = content.get("handler",None) #local command to execute
            response_handler = content.get("response_handler", None)  #sent back to gui, so it knows what handler to call
            response_id = content.get("response_id", 0)

            ret = self._handle_inject_agents(content, packet)

            if confirm_response and handler_role and handler and response_handler:

                alert_nodes = self.get_nodes_by_role(handler_role)
                if not alert_nodes:
                    self.log(f"[RPC][RESULT] No agent found with role: {handler_role}")
                    return

                pk1 = self.get_delivery_packet("standard.command.packet")
                pk1.set_data({"handler": handler})

                payload_summary = []

                #PAYLOAD SUMMARY
                try:

                    tp = self.get_agent_tree_master()
                    if isinstance(tp, TreeParser):
                        for uid in ret.get("injected", []):
                            node = tp.get_node(uid)
                            if not node:
                                continue
                            payload_summary.append({
                                "universal_id": uid,
                                "parent": content.get("target_universal_id"),
                                "roles": node.get("config", {}).get("role", []),
                                "delegated": node.get("delegated", [])
                            })

                except Exception as e:
                    self.log(error=e)

                pk2 = self.get_delivery_packet("standard.rpc.handler.general.packet")
                pk2.set_data({
                    "handler": response_handler,
                    "origin": self.command_line_args.get("universal_id", "matrix"),
                    "content": {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "response_id": response_id,
                        "status": ret.get("status", "error"),
                        "error_code": ret.get("error_code", 99),
                        "message": ret.get("message", "Injection result."),
                        "details": {
                            "injected": ret.get("injected", []),
                            "rejected": ret.get("rejected", []),
                            "duplicates": ret.get("duplicates", []),
                            "errors": ret.get("errors", [])
                        },
                        "payload": payload_summary
                    }
                })

                pk1.set_packet(pk2, "content")

                for ep in alert_nodes:
                    self.pass_packet(pk1, ep.get_universal_id())

        except Exception as e:
            self.log(error=e, block="main_try")

    def _handle_inject_agents(self, content, packet):

        parent = content.get("target_universal_id")
        subtree = content.get("subtree")
        # error_codes
        # 0 success agent spawned
        # 1 TreeParse not returned from load_directive
        # 2 agent already exists
        # 3 couldn't load agent_tree_master
        # 4 parent doesn't exist
        # 5 tried to inject a matrix
        # 6 crashed while saving node into tree
        # 7 rejected malformed node
        ret = {
            "error_code": 0,
            "status": "pending",
            "message": "",
            "injected": [],
            "rejected": [],
            "errors": []
        }

        # Parse base agent identity
        if "subtree" in content:
            universal_id = content["subtree"].get("universal_id")
            agent_name = content["subtree"].get("name", "").lower()
        else:
            universal_id = content.get("universal_id")
            agent_name = content.get("name", "").lower()

        # Load tree directive
        tp = self.get_agent_tree_master()
        if not tp:
            ret["error_code"] = 1
            ret["status"] = "error"
            ret["message"] = "[INJECT][ERROR] Failed to load tree directive."
            self.log(ret["message"])
            return ret

        # Check for parent node existence
        if not tp.has_node(parent):
            ret["error_code"] = 2
            ret["status"] = "error"
            ret["message"] = f"[INJECT][ERROR] Parent '{parent}' not found in parsed tree."
            self.log(ret["message"])
            return ret

        # Don't inject under parent, if marked for deletion or is deleted
        parent_node = tp.get_node(parent)
        if parent_node and parent_node.get("lifecycle_status", {}).get("locked"):
            self.log(f"[INJECT][BLOCKED] Parent {parent} is deleted. Cannot inject new nodes.")
            ret["status"] = "error"
            ret["message"] = f"Parent {parent} is deleted. Injection blocked."
            ret["error_code"] = 8
            return ret

        # Scan subtree for any node with matrix identity
        def contains_matrix_node(tree):
            if not isinstance(tree, dict):
                return False
            name = tree.get("name", "").lower()
            uid = tree.get("universal_id", "").lower()
            if name == "matrix" or uid == "matrix":
                return True
            for child in tree.get("children", []):
                if contains_matrix_node(child):
                    return True
            return False

        if subtree:
            if contains_matrix_node(subtree):
                self.log("[INJECT][BLOCKED] Subtree injection attempt includes forbidden Matrix agent.")
                ret['error_code'] = 4
                return ret
        else:
            if agent_name == "matrix" or universal_id == "matrix":
                self.log("[INJECT][BLOCKED] Direct Matrix injection attempt denied.")
                ret['error_code'] = 4
                return ret

        try:
            success = False

            #SUBTREE_INJECTION
            if subtree:

                try:

                    injected_ids=[]
                    if tp.has_node(universal_id):
                        ret["duplicates"] = [universal_id]
                        ret["status"] = "duplicate"
                        ret["message"] = f"Agent '{universal_id}' already exists."
                    else:

                        injected_ids = tp.insert_node(subtree, parent_universal_id=parent, matrix_priv_obj=self.matrix_priv_obj)

                        ret["injected"] = tp.get_added_nodes()
                        ret["rejected"] = tp.get_rejected_nodes()
                        ret["duplicates"] = tp.get_duplicates()
                        self.log(f"[DEBUG] Injected IDs: {ret['injected']}")
                        self.log(f"[DEBUG] rejected IDs: {ret['rejected']}")
                        self.log(f"[DEBUG] duplicates IDs: {ret['duplicates']}")

                    push_live_config_on_duplicate = content.get("push_live_config", False)
                    #this will deliver a partial_config update, if a duplicate is found it will be flagged partial_config
                    if (
                        push_live_config_on_duplicate and
                        bool(len(ret["duplicates"]))
                        ):

                        # Check if agent exists
                        self.log('Entering the Thunderdome.')
                        if push_live_config_on_duplicate and bool(len(ret["duplicates"])):
                            existing_node = tp.get_node(universal_id)
                            config = subtree.get("config", {})
                            if existing_node and bool(config):
                                # THIS is the important push
                                self._cmd_update_agent({
                                    "target_universal_id": universal_id,
                                    "config": config,
                                    "push_live_config": True
                                }, packet)
                            ret["status"] = "success"
                            ret["message"] = f"Agent already existed — config partially updated for {universal_id}"
                            return ret

                    success = bool(len(injected_ids))
                    if not success:
                        self.log(f"[INJECT][ERROR] Insert failed. Rejected nodes: {tp.get_rejected_nodes()}")
                        msg = f"[INJECT][ERROR] Insert failed. Rejected nodes: {tp.get_rejected_nodes()}"
                        ret["message"] = msg
                        ret['error_code'] = 5
                        self.log(msg)

                except Exception as e:
                    self.log(error=e, block="subtree_injection")
                    ret['error_code'] = 6
                    msg = ret.get("message", "")
                    ret['message'] = f"{msg} | {type(e).__name__}: {str(e)}"

                if success:
                    # NEW: Save payloads for each node in the subtree
                    for node in TreeParser.flatten_tree(subtree):
                        src = node.get("source_payload")
                        name = node.get("name")


            else:

                delegated = content.get("delegated", [])
                filesystem = content.get("filesystem", {})
                config = content.get("config", {})
                src = content.get("source_payload")

                new_node = {
                    "name": agent_name,
                    "universal_id": universal_id,
                    "delegated": delegated,
                    "filesystem": filesystem,
                    "config": config,
                    "children": [],
                    "confirmed": time.time()
                }

                injected_ids = tp.insert_node(new_node, parent_universal_id=parent, matrix_priv_obj=self.matrix_priv_obj)
                success = bool(len(injected_ids))
                if not success:
                    self.log(f"[INJECT][ERROR] Insert failed. Rejected node {universal_id}")
                    ret['error_code'] = 5
                    ret["message"] = f"[INJECT][ERROR] Insert failed. Rejected node: {universal_id}"
                else:
                    self.log(f"[INJECT] ✅ Injected agent '{universal_id}' under '{parent}'.")
                    success=True

            if success:

                self.save_agent_tree_master()

                # --- REMEDY ---
                # After saving, the tree has new nodes with vaults.
                # We must force the tree parser to re-index its internal
                # dictionary so it can find the new agents.
                tp.reparse()
                # --- END REMEDY ---

                #delegate to parent agent
                self.delegate_tree_to_agent(parent, self.tree_path_dict)

                for agent_id in tp.get_first_level_child_ids(parent):
                    self.delegate_tree_to_agent(agent_id, self.tree_path_dict)

                ret["status"] = "success"
                ret.setdefault("message", "Agent(s) injected successfully.")

            else:

                ret["status"] = "error"
                ret.setdefault("message", "Injection failed or partial success.")

        except Exception as e:
            self.log(error=e, block="main_try")

        return ret

    def _cmd_restart_subtree(self, content, packet, identity: IdentityObject = None):
        """
        Gracefully restarts an agent or its entire subtree.

        By default, restarts only the target agent.
        If content["restart_full_subtree"] = True, restarts the entire subtree.
        """
        try:
            target_universal_id = content.get("target_universal_id")
            confirm_response = bool(content.get("confirm_response", 0))
            response_handler = content.get("return_handler")
            token = content.get("token", 0)
            session_id = content.get("session_id")
            full_flag = bool(content.get("restart_full_subtree", False))

            if not target_universal_id:
                self.log("[RESTART][ERROR] Missing universal_id.")
                return

            tp = self.get_agent_tree_master()
            if not tp:
                self.log("[RESTART][ERROR] Failed to load tree.")
                return

            for cid in tp.get_subtree_nodes(target_universal_id):  # skip the target itself
                child = tp.get_node(cid)
                if child and child.get("lifecycle_status", {}).get("locked"):
                    self.log(f"[RESTART][ABORT] {target_universal_id} has locked descendant '{cid}'. Aborting restart.")
                    return


            # Scope
            recurse_children = False
            if full_flag:
                ids = tp.get_subtree_nodes(target_universal_id)
                self.log(f"[RESTART] Restarting full subtree for {target_universal_id}: {ids}")
                recurse_children = True
            else:
                ids = [target_universal_id]
                self.log(f"[RESTART] Restarting single agent only: {target_universal_id}")

            trans_id = secrets.token_hex(8)

            # Prime common values (Matrix-side best-effort)
            comm_path = self.path_resolution["comm_path"]

            mark = {
                "lifecycle_status": {
                    "locked": {
                        "by": "matrix",
                        "reason": "shutdown_restart",
                        "timestamp": time.time()
                    },
                    "transaction_id": trans_id,
                    "op": "shutdown_restart",
                    "op_stage": "shutdown_probe",  # Reaper will probe first
                    "last_checked": time.time(),
                    "comm_path": comm_path,
                    "agent_status_callback": {
                        "operation": "restart_subtree",
                        "restart_full_subtree": full_flag,
                        "confirm_response": confirm_response,
                        "response_handler": response_handler,
                        "token": token,
                        "session_id": session_id,
                        "on_complete": "_restart_complete_callback"
                    }
                }
            }

            tp.mark_target_list(target_universal_id, mark, recurse_children=recurse_children)
            self.save_agent_tree_master()

            self.log(f"[RESTART] ✅ Marked {len(ids)} agent(s) for restart (probe stage queued): {ids}")

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")



    #checks everyone's tree against Matrix's agent_tree_master, using a hash of the agents tree
    #this also ensures services are updated for agents added and removed
    def perform_tree_master_validation(self):

        try:

            if time.time() - self._last_tree_verify > 300:  # 5-minute window
                self._last_tree_verify = time.time()

                tp = self.get_agent_tree_master()
                if not tp:
                    self.log("[VERIFY-TREE] Could not load master tree.")
                    return

                for universal_id in tp.all_universal_ids():
                    self.delegate_tree_to_agent(universal_id, self.tree_path_dict)

        except Exception as e:
            self.log(error=e, block="main_try")

    def _cmd_service_request(self, content, packet, identity: IdentityObject = None):
        """
        Dispatch a generic service request to one or more agents that advertise a role.

        Args:
            content (dict): {
                "service": "<role pattern>",     # e.g. "hive.log"
                "payload": { ... }               # inner content to send
            }
            packet (dict): The raw inbound packet.
            identity (IdentityObject): Verified identity of the sender.
        """
        try:

            self.log(f'content: {content}')

            service_role = content.get("service")
            payload = content.get("payload", {})

            if not service_role:
                self.log("[SERVICE-REQ][ERROR] Missing 'service' field.")
                return

            # Use refactored get_nodes_by_role → ServiceEndpoint objects
            endpoints = self.get_nodes_by_role(service_role)
            if not endpoints:
                self.log(f"[SERVICE-REQ] No agents found for role '{service_role}'")
                return

            for ep in endpoints:

                target_uid = ep.get_universal_id()
                handler = ep.get_handler()

                if not handler or not target_uid:
                    self.log(f"[SERVICE-REQ][WARN] Skipping endpoint {ep}")
                    continue

                # Build command packet
                pk = self.get_delivery_packet("standard.command.packet")
                pk.set_data({
                    "handler": handler,
                    "content": payload,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "origin": self.command_line_args.get("universal_id", "matrix")
                })

                self.pass_packet(pk, target_uid)
                self.log(f"[SERVICE-REQ] Routed '{service_role}' → {target_uid} ({handler})")

        except Exception as e:
            self.log(error=e, block="main_try")

    # gives a given agent its agent_tree.json
    #2 types of trees roll through here: Matrix agent_tree_master.json and agents agent_tree.json
    #if encryption is on: every node will have a vault dict, inside contains the node's public key, timestamp issued
    def delegate_tree_to_agent(self, universal_id, tree_path):
        """Generates and delivers a secure, personalized "slice" of the agent tree.
        This method extracts the subtree of a specific agent from the master
        tree. It then securely signs and delivers this personalized
        `agent_tree.json` file to the target agent's `/directive` directory.
        This ensures that each agent only has the structural information it
        needs to manage its own children. It also delivers the agent's signed
        public key to its `/codex` directory for others to retrieve.

        Args:
            universal_id (str): The ID of the agent to deliver the tree slice to.
            tree_path (dict): A dictionary defining the path to the master tree.
        """
        try:
            #load the agent_tree_master

            tp = self.get_agent_tree_master()
            if not tp:
                self.log(f"Failed to load master tree for {universal_id}")
                return

            if not tp.has_node(universal_id):
                self.log(f"Skipping node {universal_id} not found in agent_tree, probably phantom dir created in comm by other agent or process.)")
                return

            subtree = tp.extract_subtree_by_id(universal_id)
            if not subtree:
                self.log(f"No subtree found for {universal_id}, sending empty tree.")
                subtree = {}

            if subtree.get('lifecycle_status',{}).get("op", False) == "shutdown_delete":
                self.log(f"[SPAWN-ERROR] Attempted to spawn deleted agent {universal_id}. Blocking.")
                return

            try:
                #SAVE IDENTITY FILE to comm/{universal_id}/codex
                identity={"identity": subtree.get("vault",{}).get("identity", {}), "sig": subtree.get("vault",{}).get("sig", {})}

                dir = os.path.join(self.path_resolution["comm_path"], universal_id, "codex")
                fpath = os.path.join(dir, "signed_public_key.json")
                with open(fpath, "w", encoding="utf-8") as f:
                    json.dump(identity, f, indent=2)
                    f.close()

            except Exception as e:
                self.log(error=e, block='write_signed_public_key')

            # define structured path dict for saving
            path = {
                "path": self.path_resolution["comm_path"],
                "address": universal_id,
                "drop": "directive",
                "name": "agent_tree.json"
            }

            data = {"agent_tree": subtree, 'services': tp.get_minimal_services_tree(universal_id)}

            football = self.get_football(type=self.FootballType.PASS)
            football.load_identity_file(vault=subtree.get("vault"), universal_id=universal_id)
            self.save_directive(path, data, football=football)

            if self.debug.is_enabled():
                self.log(f"Tree delivered to {universal_id}")

        except Exception as e:
            self.log(error=e, block="main_try")

    def get_agent_tree_master(self):
        """Loads the agent_tree_master.json from disk into memory.
        This method acts as a cached loader for the canonical agent tree.
        If the tree is not already in memory, it loads the securely signed
        and encrypted `agent_tree_master.json` file from the Matrix agent's
        own `/directive` directory. It returns a TreeParser object representing
        the entire swarm structure.

        Returns:
            TreeParser: An object representing the entire agent tree, or None.
        """
        if self._agent_tree_master is None:
            football = self.get_football(type=self.FootballType.CATCH)
            self._agent_tree_master = self.load_directive(self.tree_path_dict, football)
            if hasattr(self._agent_tree_master, "root"):
                self._meta = self._agent_tree_master.root.get('meta', {})

            self.log("[TREE] agent_tree_master loaded into memory.")

        return self._agent_tree_master


    def save_agent_tree_master(self, push_tree_home=False):
        """Signs and saves the current state of the in-memory agent tree to disk.

        This method is called whenever the swarm's structure is modified (e.g.,
        after injecting or deleting an agent). It takes the in-memory tree,
        adds any agent identity -- signs with the Matrix private key, generates rsa key pairs, private keys, to any added agents, and then
        securely saves the entire structure back to `agent_tree_master.json`.
        This persists the change and ensures the file on disk is always the
        single source of truth.

        Returns:
            bool: True if the save was successful, False otherwise.
        """
        try:
            if self._agent_tree_master is None:
                self.log("[TREE][WARN] Cannot save — agent_tree_master not loaded.")
                return False

            self._agent_tree_master.pre_scan_for_duplicates(self._agent_tree_master.root)

            data = {"agent_tree": self._agent_tree_master.root, "meta": self.meta}
            football = self.get_football(type=self.FootballType.PASS)
            football.load_identity_file(vault=self.tree_node['vault'], universal_id='matrix')
            self.save_directive(self.tree_path_dict, data, football=football)

            if self.debug.is_enabled():
                if self.encryption_enabled:
                    self.log("[TREE] agent_tree_master saved and signed.")
                else:
                    self.log("[TREE] agent_tree_master saved.")

            #deliver agent listing to gui
            alert_role = self.tree_node.get("rpc_router_role", "hive.rpc")
            if push_tree_home and alert_role:
                remote_pub_pem = self._signing_keys.get("remote_pubkey")

                # Ask each relay for its alive sessions
                for ep in self.get_nodes_by_role(alert_role):
                    relay_uid = ep.get_universal_id()
                    alive_sessions = self.has_fresh_broadcast_flag(relay_uid)

                    for sess in alive_sessions:
                        data = {
                            "handler": "agent_tree_master.update",
                            "session_id": sess,
                            "content": self._agent_tree_master.root,
                        }

                        sealed = encrypt_with_ephemeral_aes(data, remote_pub_pem)
                        content = {
                            "serial": self._serial_num,
                            "content": sealed,
                            "timestamp": int(time.time())
                        }
                        sig = sign_data(content, self._signing_key_obj)
                        content["sig"] = sig

                        pk1 = self.get_delivery_packet("standard.command.packet")
                        pk1.set_data({
                            "handler": ep.get_handler(),
                            "origin": self.command_line_args['universal_id'],
                            "session_id": sess,  # outer too, for websocket routing
                            "content": content
                        })
                        self.pass_packet(pk1, relay_uid)

            return True

        except Exception as e:
            self.log("[TREE][ERROR] Failed to save agent_tree_master.", error=e)
            return False

    def _perform_agent_consciousness_scan(self, time_delta_timeout=0, flip_threshold=3, flip_window=60):
        """
        Evaluates each agent's heartbeat (from poke files) and spawn history (flip-tripping).
        Stores results inside node["agent_status"]. Broadcasts updated tree to relays if live.
        """
        try:
            if (time.time() - self._last_consciousness_scan) > 20:
                self._last_consciousness_scan = time.time()
                now = time.time()

                def recurse(node: dict):
                    if not isinstance(node, dict):
                        return

                    uid = node.get("universal_id")
                    if not uid:
                        return

                    result  = check_heartbeats(self.path_resolution["comm_path"], uid, time_delta_timeout)
                    thread_status = {}
                    if result["meta"]["error_success"]:
                        thread_status = {"error": f"❌ {result['meta']['error']}"}
                    else:
                        for t, info in result["threads"].items():
                            delta = round(info["delta"], 1)
                            thread_status[t] = {
                                "status": info["status"],
                                "last_seen": info["last_seen"],
                                "delta": delta,
                                "timeout": info["timeout"],
                                "sleep_for": info.get("sleep_for", "-"),
                                "wake_due": info.get("wake_due", "-"),
                            }

                    #Spawn analysis
                    spawn_data = analyze_spawn_records(
                        self.path_resolution["comm_path"],
                        uid,
                        flip_threshold=flip_threshold,
                        flip_window=flip_window,
                    )
                    spawn_report = {
                        "count": spawn_data["count"],
                        "latest_timestamp": spawn_data["latest_timestamp"],
                        "flip_tripping": spawn_data["flip_tripping"]
                    }

                    # Load raw spawn records for GUI
                    spawn_dir = os.path.join(self.path_resolution["comm_path"], uid, "spawn")
                    spawn_records = []
                    try:
                        for f in sorted(Path(spawn_dir).glob("*.spawn"), reverse=True)[:5]:  # last 5
                            with open(f, encoding="utf-8") as fh:
                                info = json.load(fh)
                                fh.close()
                                spawn_records.append({
                                    "timestamp": info.get("timestamp"),
                                    "note": info.get("uuid", "")
                                })
                    except Exception:
                        pass

                    if spawn_report["flip_tripping"]:
                        spawn_report["note"] = "flip-tripping detected"

                    node["agent_status"] = {
                        "checked_at": now,
                        "threads": thread_status,
                        "spawn": spawn_report
                    }

                    summary = {
                        "thread_count": result["meta"].get("thread_count", 0),
                        "latest_delta": round(result["meta"].get("latest_delta", 0), 1),
                        "last_seen_any": result["meta"].get("last_seen_any"),
                        "error": result["meta"].get("error"),
                        "error_success": result["meta"].get("error_success"),
                    }

                    node.setdefault("meta", {})

                    node["meta"].update({
                        "threads": [
                            {
                                "thread": t,
                                "status": info.get("status", "-"),
                                "delta": round(info.get("delta", 0), 1),
                                "timeout": info.get("timeout", "-"),
                                "sleep_for": info.get("sleep_for", "-"),
                                "wake_due": info.get("wake_due", "-"),
                            }
                            for t, info in result["threads"].items()
                        ],
                        "summary": summary,
                        "spawn": spawn_report.get("count", 0),
                        "flipping": spawn_report.get("flip_tripping", False),
                        "name": node["name"],
                        "universal_id": uid
                    })

                    node["meta"]["spawn_info"] = spawn_records

                    for child in node.get("children", []):
                        recurse(child)

                recurse(self._agent_tree_master.root)

                # Push tree if relays are alive
                alert_role = self.tree_node.get("rpc_router_role", "hive.rpc")
                live_relays = [
                    ep for ep in self.get_nodes_by_role(alert_role)
                    if self.has_fresh_broadcast_flag(ep.get_universal_id())
                ]

                if live_relays:
                    self.save_agent_tree_master(push_tree_home=True)
                else:
                    if self.debug.is_enabled():
                        self.log("[TREE] Skipped broadcast (no fresh relays)")

        except Exception as e:
            self.log(error=e, block="main_try")

    def has_fresh_broadcast_flag(self, universal_id: str, threshold: int = 30) -> list[str]:
        """
        Checks whether any connected.flag* exists for the agent and is fresh.

        Args:
            universal_id (str): Agent UID to check.
            threshold (int): Max age (seconds) before a flag is considered stale.

        Returns:
            list[str]: A list of session_ids (or "legacy" for old style) that are alive.
        """
        base = os.path.join(
            self.path_resolution["comm_path"],
            universal_id,
            "broadcast"
        )
        if not os.path.isdir(base):
            return []

        now = time.time()
        alive_sessions = []

        for fname in os.listdir(base):
            if not fname.startswith("connected.flag"):
                continue

            fpath = os.path.join(base, fname)
            age = now - os.path.getmtime(fpath)
            if age < threshold:
                if fname == "connected.flag":
                    alive_sessions.append("legacy")  # backward compat
                else:
                    sid = fname.replace("connected.flag.", "")
                    alive_sessions.append(sid)
            else:
                self.log(f"[BROADCAST] Flag stale: {fname} ({int(age)}s old)")

        return alive_sessions

    def cmd_deliver_agent_tree_to_child(self, content, packet, identity: IdentityObject = None):
        """
        Handles delivery of the current agent tree to a verified child agent.

        This command is typically triggered when a child agent requests its
        delegated slice of the overall swarm tree (e.g., via `request_agent_tree()`).
        Matrix verifies the sender’s identity, determines the requesting agent’s
        universal ID, and then sends the appropriate portion of the agent tree
        to that agent.

        Behavior:
            - If encryption is disabled, the universal_id is read directly from the
              packet content.
            - If encryption is enabled, the universal_id is extracted from the verified IdentityObject.
            - Logs an error and aborts if the universal_id cannot be determined.

        Args:
            content (dict): The packet’s inner content dictionary. Expected to contain
                "universal_id" when encryption is disabled.
            packet (dict): The full command packet structure that invoked this handler.
            identity (IdentityObject, optional): A verified sender identity object
                provided by the cryptographic layer. Used to confirm the source and
                extract its universal_id when encryption is active.

        Returns:
            None

        Raises:
            Logs any unexpected exceptions internally via `self.log()`.
        """
        try:

            uid = None
            if not self.encryption_enabled:
                uid = content.get("universal_id", False)  # swarm running in plaintext mode

            else:
                # reject invalid or missing identity
                if isinstance(identity, IdentityObject) and identity.has_verified_identity():
                     uid = identity.get_sender_uid()

            if not uid:
                self.log("[DELIVER-TREE][ERROR] Missing universal_id.")
                return

            self.delegate_tree_to_agent(uid, self.tree_path_dict)

        except Exception as e:
            self.log("[DELIVER-TREE][ERROR]", error=e)

    def _cmd_matrix_reloaded(self, content, packet, identity=None):
        """
        Relaunches the entire swarm (Matrix and children) using the preserved command line
        from security_box, but guarantees that --swarm_key is passed in case the key file
        was nuked (for example, after a Railgun reload). Matrix always carries her swarm_key
        in memory, so we re-inject it.
        """
        try:
            cmd = self.security_box.get("reboot", "")
            if not cmd:
                self.log("[REBOOT][ERROR] No preserved launch command found.")
                return

            # ensure the --swarm_key flag is present and injected
            if "--swarm_key" not in cmd:
                # safely quote the swarm key so spaces or symbols are preserved
                cmd += f" --swarm_key='{self.swarm_key}'"

            self.log(f"[REBOOT] Relaunching universe with: {cmd}")
            subprocess.Popen(cmd, shell=True)
            os._exit(0)

        except Exception as e:
            self.log("[REBOOT][ERROR] Failed to relaunch Matrix.", error=e)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()
