# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Gemini, code enhancments and Docstrings

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


import re
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
from datetime import datetime
from Crypto.PublicKey import RSA

# Assuming self.matrix_priv is currently a string with PEM content:
from core.python_core.boot_agent import BootAgent
from core.python_core.tree_parser import TreeParser
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject
from core.python_core.agent_factory.reaper.reaper_factory import make_reaper_node
from core.python_core.agent_factory.scavenger.scavenger_factory import make_scavenger_node
from core.python_core.utils.crypto_utils import generate_signed_payload, verify_signed_payload, encrypt_with_ephemeral_aes,  sign_data, pem_fix
from core.python_core.class_lib.directive.boot_directive_info import BootDirectiveInfo
from core.python_core.class_lib.packet_delivery.utility.security.packet_size import guard_packet_size
from core.python_core.class_lib.packet_delivery.utility.encryption.verify_packet_signature import verify_packet_signature
from core.python_core.class_lib.time_utils.heartbeat_checker import check_heartbeats
from core.python_core.utils.analyze_spawn_records import analyze_spawn_records
from core.python_core.utils.swarm_sleep import interruptible_sleep
class Agent(BootAgent):
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
            self.AGENT_VERSION = "1.3.0"
            self._agent_tree_master = None

            self.boot_directive_info = BootDirectiveInfo(self.security_box)


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

            self._acl = {}

            # make sure signing keys are loaded BEFORE seeding
            self._signing_keys = self.tree_node.get('config', {}).get('security', {}).get('signing', {})
            self._has_signing_keys = bool(self._signing_keys.get('privkey')) and bool(
            self._signing_keys.get('remote_pubkey'))

            if self._has_signing_keys:
                priv_pem = self._signing_keys.get("privkey")
                priv_pem=pem_fix(priv_pem)
                self._signing_key_obj = RSA.import_key(priv_pem.encode() if isinstance(priv_pem, str) else priv_pem)

            self._serial_num= self.tree_node.get('serial', {})

            self._seed_acl()  # builds dict-shaped ACL entries for matrix + dominion

            # delegate Matrix her Tree
            self.delegate_tree_to_agent("matrix", self.tree_path_dict)

            self._signing_keys = self.tree_node.get('config',{}).get('security',{}).get('signing',{})
            self._has_signing_keys = self._signing_keys.get('privkey',False) and self._signing_keys.get('remote_pubkey',False)

            # Inject payload_path if it's not already present
            if "payload_path" not in self.path_resolution:
                self.path_resolution["payload_path"] = os.path.join(
                    self.path_resolution["comm_path_resolved"],
                    "payload"
                )

            self._emit_beacon = self.check_for_thread_poke("worker", timeout=60, emit_to_file_interval=10)

        except Exception as e:
            self.log(error=e, level="ERROR")



    PRIVILEGED_MATRIX_HANDLERS = {
        "cmd_deliver_agent_tree_to_child",
    }

    def _keyhash(self, pem_str: str) -> str:
        return hashlib.sha256(pem_str.encode()).hexdigest()

    def _acl_entry(self, pub_pem: str, allow):
        # store canonical ACL entries with pubkey so we can verify later
        return {"pubkey": pub_pem, "allow": set(allow)}

    def _seed_acl(self):
        try:
            self._acl = {}
            # Tier 1: Matrix baseline
            self._acl[self._keyhash(self.matrix_pub)] = self._acl_entry(self.matrix_pub, self.PRIVILEGED_MATRIX_HANDLERS)
            # Tier 0: Dominion key (GUI directive signing key) — allow everything
            dom_pub = self._signing_keys.get('remote_pubkey') if hasattr(self, "_signing_keys") else None
            if dom_pub:
                self._acl[self._keyhash(dom_pub)] = self._acl_entry(dom_pub, {"*"})
        except Exception as e:
            self.log("ACL seed failed", error=e, block="acl-seed")

    def grant_acl(self, pub_pem: str, handlers):
        h = self._keyhash(pub_pem)
        if h in self._acl:
            if "*" in self._acl[h]["allow"]:
                return  # already omnipotent
            self._acl[h]["allow"].update(handlers)
        else:
            self._acl[h] = self._acl_entry(pub_pem, handlers)

    def incoming_packet_acl_check(self, pk: dict, identity=None) -> bool:
        """
        Access model:
          • Beast mode (neo cert): signature verifies with self._signing_keys["remote_pubkey"] ⇒ allow any cmd_*
          • No/invalid signature: goodwill only ⇒ allow cmd_deliver_agent_tree_to_child
        """
        try:
            # 0) Hard size/nesting limits
            if not guard_packet_size(pk, log=self.log):
                self.log("[ACL] Size/nesting guard rejected packet")
                return False

            handler = pk.get("handler")
            timestamp = pk.get("timestamp")
            sig = pk.get("sig")

            # Basic shape
            if not isinstance(handler, str) or timestamp is None:
                self.log("[ACL] Missing/invalid handler or timestamp")
                return False

            # 1) Must have a verified identity object
            if not identity or not getattr(identity, "has_verified_identity", lambda: False)():
                self.log("[ACL] Identity not verified — dropping")
                return False

            # 2) Beast mode: signed by dominion key ⇒ allow any cmd_*
            if sig and self._has_signing_keys and self._signing_keys.get("remote_pubkey"):
                try:
                    # raises ValueError on failure
                    verify_packet_signature(pk, self._signing_keys["remote_pubkey"])
                    if not handler.startswith("cmd_"):
                        self.log(f"[ACL] Signed packet but non-command handler blocked: {handler}")
                        return False
                    return True
                except Exception as e:
                    if self.debug.is_enabled():
                        self.log("[ACL] Signature present but verification failed; falling back to goodwill", error=e)

            # 3) Goodwill token only: permit the Christmas tree delivery, nothing else
            if handler == "cmd_deliver_agent_tree_to_child":
                return True

            self.log(f"[ACL] DENY (goodwill mode) handler={handler}")
            return False

        except Exception as e:
            self.log("[ACL] Pipeline error", error=e)
            return False

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
        interruptible_sleep(self, 0.5)

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
        self.perform_agent_consciousness_scan()
        self.perform_tree_master_validation()

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

            print("[GOSPEL] 📜 Gospel of Matrix signed and written to codex.")

        except Exception as e:
            self.log(error=e, block="main_try")

    def cmd_delete_agent(self, content, packet, identity:IdentityObject = None):
        """Handles the command to delete an agent and its entire subtree.

        This is an orchestrator method. It doesn't delete the agent directly,
        but instead:
        1. Marks the target agent and all its children as "deleted" in the tree.
        2. Saves the updated master agent tree.
        3. Injects a permanent `reaper` agent to terminate the processes.
        4. Injects a permanent `scavenger` agent to clean up the directories.
        5. Optionally sends a response packet back to the caller via an RPC route.

        Args:
            content (dict): The command payload, containing the
                'target_universal_id' of the agent to delete.
            packet (dict): The raw packet data.
            identity (IdentityObject): The verified identity of the command sender.
        """
        try:

            #is a response expected
            confirm_response = bool(content.get("confirm_response", 0))
            #this is the client rpc handler which handles the response
            return_handler = content.get("return_handler")
            token = content.get("token", 0)
            session_id = content.get("session_id")

            result = self._cmd_delete_agent(content, packet)

            #RPC-DELETE
            if (confirm_response and
                return_handler):

                # --- RPC Confirmation ---
                rpc_role = self.tree_node.get("rpc_router_role", "hive.rpc")
                endpoints = self.get_nodes_by_role(rpc_role, return_count=1)
                if not endpoints:
                    self.log("No hive.rpc-compatible agents found for 'hive.rpc'.")
                    return

                remote_pub_pem = self._signing_keys.get("remote_pubkey")

                payload = {
                    "handler": return_handler,
                    "content": {
                        "session_id": session_id,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "token": token,
                        "status": result.get("status", "error"),
                        "error_code": result.get("error_code", 99),
                        "message": result.get("message", "Deletion result."),
                        "details": {
                            "target_universal_id": result.get("target_universal_id"),
                            "kill_list": result.get("kill_list", []),
                            "reaped": result.get("reaped", 0),
                            "existed": result.get("existed", 0),
                            "deleted": result.get("deleted", 0)
                        }
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
                    "handler": "dummy_handler",  # if a handler isn't set the packet will not set, without a handler
                    "origin": self.command_line_args['universal_id'],
                    "session_id": session_id,
                    "content": content,
                })

                for ep in endpoints:
                    pk1.set_payload_item("handler", ep.get_handler())
                    self.pass_packet(pk1, ep.get_universal_id())


        except Exception as e:
            self.log("Failed to process cmd_delete_agent", error=e, block="main-try")


    def _cmd_delete_agent(self, content, packet):
        """Contains the core implementation for decommissioning an agent and its subtree.

        This private method executes the multi-step process for safely and completely
        removing an agent from the swarm. It is called by the public-facing
        `cmd_delete_agent` handler.

        The process includes:
        1. Marking the target node and all its children as "deleted" in the master tree.
        2. Saving the updated tree to persist this change.
        3. Calling `drop_hit_cookies` to signal the live agents to terminate.
        4. Injecting a 'reaper' agent to forcefully terminate any lingering processes.
        5. Injecting a 'scavenger' agent to clean up the pod/comm directories.

        Args:
            content (dict): The command payload, requiring a 'target_universal_id'.
            packet (dict): The raw packet data.

        Returns:
            dict: A result dictionary summarizing the outcome of the operation,
                  including the status, kill list, and error messages.
        """
        result = {
            "status": "error",
            "error_code": 99,
            "message": "",
            "target_universal_id": None,
            "kill_list": [],
            "reaped": 0,
            "existed": 0,
            "deleted": 0,
        }

        try:
            target = content.get("target_universal_id")
            if not target:
                result["message"] = "Missing target_universal_id."
                return result

            result["target_universal_id"] = target

            tp = self.get_agent_tree_master()
            if not tp:
                result["message"] = "Failed to load directive."
                return result

            node_exists = tp.has_node(target)
            result["existed"] = int(node_exists)

            kill_list = tp.mark_deleted_and_get_kill_list(target)
            result["kill_list"] = kill_list

            if kill_list:

                #save the deletions
                self.save_agent_tree_master()

                result["deleted"] = 1

                self.drop_hit_cookies(kill_list)

                #since no mission has been assigned, it will patrol perpetually
                reaper_node = make_reaper_node(mission_name="reaper-guardian")

                # Inject Reaper
                reaper_packet = {
                    "target_universal_id": "matrix",
                    "subtree": reaper_node
                }

                reaper_result = self._cmd_inject_agents(reaper_packet, packet)

                if reaper_result.get("status") == "success":
                    result["reaped"] = 1
                    self.log(f"[DELETE] ✅ Reaper injected: {reaper_node['universal_id']}")
                else:
                    self.log(f"[DELETE] ❌ Reaper injection failed: {reaper_result.get('message')}")

                scavenger_node = make_scavenger_node(mission_name="scavenger-keeper")

                # Inject Scavenger
                scavenger_packet = {
                    "target_universal_id": "matrix",
                    "subtree": scavenger_node
                }

                scavenger_result = self._cmd_inject_agents(scavenger_packet, packet)

                if scavenger_result.get("status") == "success":
                    self.log(f"[DELETE] ✅ Scavenger injected: {scavenger_node['universal_id']}")
                else:
                    self.log(f"[DELETE] ❌ Scavenger injection failed: {scavenger_result.get('message')}")

                result["status"] = "success"
                result["message"] = f"Kill protocol deployed. Reaper + Scavenger set for: {kill_list}"


                self.delegate_tree_to_agent("matrix", self.tree_path_dict)


            else:
                result["message"] = "No kill list generated. Agent might not exist."

        except Exception as e:
            self.log("Error inside _cmd_delete_agent", error=e, block="main_try")
            result["message"] = str(e)

        return result

    def drop_hit_cookies(self, kill_list):

        for agent in kill_list:
            try:
                comm_dir = os.path.join(self.path_resolution["comm_path"], agent, "hello.moto")
                os.makedirs(comm_dir, exist_ok=True)  # ✅ Ensure path exists

                cookie_path = os.path.join(comm_dir, "hit.cookie")

                payload = {
                    "target": agent,
                    "reason": "deleted_by_matrix",
                    "timestamp": datetime.utcnow().isoformat()
                }

                with open(cookie_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)

                self.log(f"[DELETE] Dropped hit.cookie for {agent}")

            except Exception as e:

                self.log(error=e, block="main_try")

    #used to get a copy of the current agent_tree_master, usually sent from
    #matrix-https to send back to gui
    def cmd_deliver_agent_tree(self, content, packet, identity:IdentityObject = None):

        try:
            target = 'matrix-https'

            # any agents that are subscribers of updates to master agent tree, get a copy
            # agents that need the tree. Matrix-Https

            tp = self.get_agent_tree_master()
            if not tp:
                return

            data = {"agent_tree": tp.root}
            football = self.get_football(type=self.FootballType.PASS)
            football.load_identity_file(universal_id=target)

            path = self.tree_path_dict.copy()

            path['address'] = target
            self.save_directive(path, data, football=football)

        except Exception as e:

            self.log(error=e, block="main_try")

    def cmd_deletion_confirmation(self, content, packet, identity: IdentityObject = None):
        """Processes a confirmation that an agent's resources have been cleaned up.

        This handler is typically called by a 'scavenger' agent after it has
        successfully removed the pod and comm directories of a deleted agent.
        Its purpose is to mark the agent as fully decommissioned in the master
        agent tree, providing a final state for forensic and operational history.

        Args:
            content (dict): The command payload, expecting a 'universal_id'
                of the agent whose deletion is being confirmed.
            packet (dict): The raw packet data.
            identity (IdentityObject): The verified identity of the command sender,
                which should be the scavenger agent.
        """
        try:
            uid = content.get("universal_id")
            if not uid:
                self.log("Missing universal_id in confirmation.", block="deletion-confirm")
                return

            # Security check to ensure the confirmation comes from a trusted source
            is_trusted_source = True # Default to true if encryption is off
            if identity and identity.is_encryption_enabled():
                if not identity.has_verified_identity() or identity.get_sender_uid() != 'scavenger-keeper':
                    is_trusted_source = False

            if is_trusted_source:
                self.log(f"[CONFIRM-DELETE] ✅ Confirmed deletion from: {uid}")
                tp = self.get_agent_tree_master()
                if not tp:
                    self.log("[CONFIRM-DELETE][ERROR] Failed to load agent_tree_master")
                    return

                node = tp.get_node(uid)
                if node:
                    node['confirmed_deleted'] = True
                    self.log(f"[CONFIRM-DELETE] ⛔ Node {uid} marked confirmed_deleted")
                    self.save_agent_tree_master()
            else:
                self.log(f"[CONFIRM-DELETE][DENIED] Untrusted source attempted to confirm deletion for {uid}")

        except Exception as e:
            self.log(error=e, block="main_try")

    def cmd_validate_warrant(self, content, packet, identity:IdentityObject = None):
        """Securely validates and executes a "death warrant" for an agent.

        This method serves as the final step for self-terminating, mission-based
        agents like the Reaper. The Reaper, upon completing its mission, sends
        its unique, signed death warrant back to Matrix. This handler performs
        a multi-step verification to ensure the warrant is authentic before
        permanently removing the agent from the master tree.

        The validation process includes:
        1. Verifying the warrant's signature against the master Matrix public key.
        2. Matching the agent ID in the packet with the ID inside the warrant.
        3. Matching the unique 'death_id' in the warrant with the one assigned
           to the agent's config when it was created.

        Args:
            content (dict): The command payload, containing the 'agent_id' and
                the signed 'warrant' object.
            packet (dict): The raw packet data.
            identity (IdentityObject): The verified identity of the command sender.
        """
        try:
            self.log(f"[WARRANT][DEBUG] Received packet content: {json.dumps(content, indent=2)}")
            warrant = content.get("warrant")
            agent_id = content.get("agent_id")

            if not agent_id or not warrant:
                self.log("[WARRANT] ❌ Missing required warrant fields.")
                return

            # Step 1: Verify signature
            payload = warrant.get("payload")
            signature = warrant.get("signature")
            try:
                verify_signed_payload(payload, signature, self.matrix_pub_obj)
            except Exception as e:
                self.log(f"❌ Invalid signature on warrant for {agent_id}", error=e)
                return

            # Step 2: Confirm agent ID match
            if payload.get("universal_id") != agent_id:
                self.log(f"[WARRANT] ❌ Mismatched universal_id in warrant: {payload['universal_id']} != {agent_id}")
                return

            # Step 3: Match against in-memory agent's death_id
            tp = self.get_agent_tree_master()
            if not tp:
                self.log("[UPDATE_AGENT][ERROR] Failed to load tree.")
                return

            tree_node = tp.get_node(agent_id)
            if not tree_node:
                self.log(f"[WARRANT] ⚠️ No agent found in tree for {agent_id}")
                return

            node_warrant = tree_node.get("config", {}).get("death_warrant", {})
            if warrant.get("death_id") != node_warrant.get("death_id"):
                self.log(f"[WARRANT] ❌ Death ID mismatch for {agent_id}")
                return

            # Step 4: Delete from tree if all checks pass
            self.log(f"[WARRANT] ✅ Death warrant validated. Removing node: {agent_id}")
            tp.remove_exact_node(tree_node)
            self.save_agent_tree_master()

        except Exception as e:
            self.log("[WARRANT][ERROR] Warrant processing failed", error=e)


    def cmd_forward_command(self, content, packet, identity:IdentityObject = None):
        try:
            target = content.get("target_universal_id")
            folder = content.get("folder", "incoming")
            inner = content.get("command")

            if not (target and inner and inner.get("handler")):
                self.log("[FORWARD][ERROR] Missing required fields.")
                return

            # Deep copy to preserve structure
            forwarded_packet = inner.copy()

            # 💥 Validate again if needed
            if "handler" not in forwarded_packet:
                self.log("[FORWARD][ERROR] Inner packet missing handler.")
                return

            # 🔍 Check if it's a config intent
            is_config_packet = forwarded_packet.get("handler") == "__config__"

            # 📦 Choose packet type
            packet_type = "standard.general.json.packet" if is_config_packet else "standard.command.packet"
            pk = self.get_delivery_packet(packet_type, new=True)
            pk.set_data(forwarded_packet)

            # 🚚 Deliver to the right place
            self.pass_packet(pk, target)


        except Exception as e:
            self.log(error=e, block="main_try")

    def cmd_hotswap_agent(self, content, packet, identity:IdentityObject = None):
        """Handles the command to replace a live agent with new code.

        This powerful command allows for zero-downtime updates. It performs
        the following sequence:
        1. Validates the `new_agent` payload, which can include new source code.
        2. If new source code is provided, it's installed to the
           `{active instance path}/.matrixswarm/agent/` directory.
        3. The agent's node in the master tree is updated in-memory with the
           new configuration.
        4. The master tree is saved, and the updated directive slice is
           re-delegated to the parent of the target agent.
        5. A `reaper` agent is dispatched to cleanly terminate the old version
           of the agent.
        6. The parent agent's `spawn_manager` will then automatically
           re-spawn the agent using its new source code and configuration.

        Args:
            content (dict): The payload containing 'target_universal_id' and
                'new_agent' (the new agent definition and source code).
            packet (dict): The raw packet data.
            identity (IdentityObject): The verified identity of the command sender.
        """

        try:
            new_agent = content.get("new_agent", {})
            src = new_agent.get("source_payload")

            target_uid = content.get("target_universal_id")

            if not target_uid:
                self.log("[REPLACE] Missing 'target_universal_id'. Cannot dispatch Reaper.")
                return

            if target_uid == "matrix":
                self.log("[REPLACE] Cannot target Matrix for self-replacement. Operation aborted.")
                return

            #REPLACE AGENT
            if src:
                try:
                    decoded = base64.b64decode(src["payload"]).decode()
                    sha_check = hashlib.sha256(decoded.encode()).hexdigest()

                    if sha_check != src["sha256"]:
                        self.log(f"[REPLACE] ❌ SHA-256 mismatch. Payload rejected.")
                        return

                    agent_name = new_agent["name"]
                    #creates the directory of the new agent: {somepath}/.matrixswarm/agent/{agent_name}
                    agent_dir = os.path.join(self.path_resolution["agent_path"], agent_name)
                    os.makedirs(agent_dir, exist_ok=True)

                    agent_path = os.path.join(agent_dir, f"{agent_name}.py")
                    with open(agent_path, "w", encoding="utf-8") as f:
                        f.write(decoded)

                    self.log(f"[REPLACE] ✅ Live agent source written to {agent_path}")

                except Exception as e:
                    self.log(msg="❌ Failed to install source payload", error=e, block="replace-agent")
                    return

            if not self._validate_or_prepare_agent(new_agent):
                self.log("[REPLACE] ❌ Validation or prep failed. Replacement skipped.")
                return

            if not self._handle_replace_agent(content):
                self.log("[REPLACE] ❌ Replacement failed. Tree untouched. Aborting Reaper dispatch.")
                return

            # 🎯 Gather kill list and full field set
            kill_list = [target_uid]

            # 🛠 Create reaper node with full config
            reaper_node = make_reaper_node(
                targets=kill_list,
                tombstone_comm=True,
                tombstone_pod=True,
                delay=4,
                cleanup_die=True,
                is_mission=True,
            )

            #when reaper self-bye-byes, he will drop this in death_warrant.json and Matrix will verify and
            #remove from tree
            death_id = secrets.token_hex(16)  # or uuid4().hex
            warrant_payload = {
                "universal_id": reaper_node["universal_id"],
                "death_id": death_id,
                "timestamp": time.time(),
                "reason": "mission_complete"
            }

            signed_warrant = generate_signed_payload(warrant_payload, self.matrix_priv_obj)

            reaper_node['config']['death_warrant'] = signed_warrant

            # Inject Reaper as a Matrix child
            reaper_packet = {
                "target_universal_id": "matrix",
                "subtree": reaper_node
            }

            reaper_result = self._cmd_inject_agents(reaper_packet, packet)

            if reaper_result.get("status") == "success":
                self.log(f"[DELETE] ✅ Reaper injected: {reaper_node['universal_id']}")
            else:
                self.log(f"[DELETE] ❌ Reaper injection failed: {reaper_result.get('message')}")

            self.delegate_tree_to_agent("matrix", self.tree_path_dict)

            self.log(f"[REPLACE] 🧨 Reaper dispatched for {kill_list}")

        except Exception as e:
            self.log(error=e, block="main_try")

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
        if parent and (parent.get("deleted") or parent.get("confirmed_deleted")):
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

    def cmd_update_agent(self, content, packet, identity:IdentityObject = None):
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
            for key, val in updates.items():
                node["config"][key] = val
                updated = True
                self.log(f"[UPDATE_AGENT] ✅ Patched config['{key}'] for '{uid}'")

            if content.get("push_live_config", False):
                try:
                    pk1 = self.get_delivery_packet("standard.general.json.packet")
                    pk1.set_data(node["config"])

                    self.pass_packet(pk1, uid, "config")

                except Exception as e:
                    self.log(error=e, block="main_try")

            if updated:

                self.save_agent_tree_master()

                parent = tp.find_parent_of(uid)
                if parent and parent.get("universal_id"):
                    self.delegate_tree_to_agent(parent["universal_id"], self.tree_path_dict)

                self.log(f"[UPDATE_AGENT] 🔁 Agent '{uid}' successfully updated and delegated.")
            else:
                self.log(f"[UPDATE_AGENT] ⚠️ No valid fields updated for '{uid}'")

        except Exception as e:
            self.log(error=e, block="main_try")

    def cmd_replace_source(self, content, packet, identity=None):
        """
        Minimal source replacement for an agent. Called by GUI ReplaceAgentDialog.
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
                self.log(f"[REPLACE] ❌ SHA mismatch for {target_agent_name} — expected {sha256_expected}, got {sha256_actual}")
                return

            # Save to agent dir
            agent_dir = os.path.join(self.path_resolution["agent_path"], target_agent_name)
            os.makedirs(agent_dir, exist_ok=True)
            agent_path = os.path.join(agent_dir, f"{target_agent_name}.py")

            with open(agent_path, "w", encoding="utf-8") as f:
                f.write(decoded)

            self.log(f"[REPLACE] ✅ Source written to {agent_path}")

            # --- RPC Confirmation ---
            rpc_role = self.tree_node.get("rpc_router_role", "hive.rpc")
            endpoints = self.get_nodes_by_role(rpc_role, return_count=1)
            if not endpoints:
                self.log("No hive.rpc-compatible agents found for 'hive.rpc'.")
                return

            remote_pub_pem = self._signing_keys.get("remote_pubkey")

            # expected matrixswarm/matrix_gui/core/dispatcher/inbound_dispatcher.py
            payload = {
                "handler": return_handler,
                "content": {
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
                "handler": "dummy_handler",  # if a handler isn't set the packet will not set, without a handler
                "origin": self.command_line_args['universal_id'],
                "session_id": session_id,
                "content": content,
            })

            for ep in endpoints:
                pk1.set_payload_item("handler", ep.get_handler())
                self.pass_packet(pk1, ep.get_universal_id())

            self.log(f"[REPLACE] 📡 Confirmation sent for {target_agent_name} (session={session_id})")

        except Exception as e:
            self.log("[REPLACE] ❌ Failed in cmd_replace_source", error=e, level="ERROR")


    def cmd_inject_agents(self, content, packet, identity:IdentityObject = None):
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

            ret = self._cmd_inject_agents(content, packet)

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

    def _cmd_inject_agents(self, content, packet):

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
        if parent_node and (parent_node.get("deleted") or parent_node.get("confirmed_deleted")):
            self.log(f"[INJECT][BLOCKED] Parent {parent} is deleted. Cannot inject new nodes.")
            ret["status"] = "error"
            ret["message"] = f"Parent {parent} is deleted. Injection blocked."
            ret["error_code"] = 8
            return ret

        # 🔒 Scan subtree for any node with matrix identity
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
                                self.cmd_update_agent({
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
                        if src and name:
                            self._save_payload_to_boot_dir(name, src)

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
                    if src:
                        self._save_payload_to_boot_dir(agent_name, src)

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

    def cmd_restart_subtree(self, content, packet, identity: IdentityObject = None):
        """Gracefully restarts an agent or its entire subtree.

        By default, restarts only the target agent.
        If content["restart_full_subtree"] = True, restarts the entire subtree.
        """

        try:
            target_id = content.get("universal_id")

            # is a response expected
            confirm_response = bool(content.get("confirm_response", 0))
            # this is the client rpc handler which handles the response
            response_handler = content.get("return_handler")
            token = content.get("token", 0)
            session_id = content.get("session_id")


            if not target_id:
                self.log("[RESTART][ERROR] Missing universal_id.")
                return

            tp = self.get_agent_tree_master()
            if not tp:
                self.log("[RESTART][ERROR] Failed to load tree.")
                return

            parent_node = tp.get_node(target_id)
            if parent_node and (parent_node.get("deleted") or parent_node.get("confirmed_deleted")):
                self.log(f"[RESTART][BLOCKED] {target_id} is deleted. Cannot restart.")
                return

            # check flag - restart a single target or the whole branch
            if content.get("restart_full_subtree", False):
                ids = tp.get_subtree_nodes(target_id)  # full family
                self.log(f"[RESTART] Restarting full subtree for {target_id}: {ids}")
            else:
                ids = [target_id]  # just the agent itself
                self.log(f"[RESTART] Restarting single agent only: {target_id}")

            # 🛠 Create reaper node with restart flags
            reaper_node = make_reaper_node(
                targets=ids,
                tombstone_comm=False,
                tombstone_pod=False,
                delay=4,
                cleanup_die=True,
                is_mission=True,
            )

            # Death warrant (temporary agent self-destruct after mission)
            death_id = secrets.token_hex(16)
            death_confirmation = {
                "universal_id": target_id,
                "death_id": death_id,
                "timestamp": time.time(),
                "reason": "mission_complete",
            }

            if content.get("session_id", False):
                return

            if content.get("session_id", False):
                death_confirmation['confirmation']['session_id'] = content["session_id"]

            if content.get("return_handler"):
                death_confirmation['confirmation']['return_handler'] = content["return_handler"]

            signed_warrant = generate_signed_payload(death_confirmation, self.matrix_priv_obj)
            reaper_node['config']['death_confirmation'] = signed_warrant

            # Inject Reaper
            reaper_packet = {
                "target_universal_id": "matrix",
                "subtree": reaper_node,
                "ephemeral_agent": True,
            }

            self._cmd_inject_agents(reaper_packet, packet)
            self.log(f"[RESTART] ✅ Reaper injected, restart initiated for {ids}")

        except Exception as e:
            self.log(error=e, block="main_try", level="ERROR")


    def cmd_shutdown_subtree(self, content, packet, identity:IdentityObject = None):
        """Initiates a graceful shutdown of an agent and its entire subtree.

        This method works by dropping a 'die' file into the `/incoming`
        directory of the target agent and all of its descendants. The agents'
        `enforce_singleton` thread monitors for this file and will trigger a
        clean shutdown of the agent process upon detection.

        Args:
            content (dict): The payload containing the 'universal_id' of the
                root of the subtree to be shut down.
            packet (dict): The raw packet data.
            identity (IdentityObject): The verified identity of the command sender.
        """
        target_id = content.get("universal_id")
        if not target_id:
            self.log("[SHUTDOWN][ERROR] Missing universal_id.")
            return

        tp = self.get_agent_tree_master()
        if not tp:
            self.log("[SHUTDOWN][ERROR] Failed to load tree.")
            return

        # Don't inject under parent, if marked for deletion or is deleted
        parent_node = tp.get_node(target_id)
        if parent_node and (parent_node.get("deleted") or parent_node.get("confirmed_deleted")):
            self.log(f"[INJECT][BLOCKED] Parent {target_id} is deleted. Cannot inject new nodes.")
            return


        ids = tp.get_subtree_nodes(target_id)
        for uid in ids:
            die_path = os.path.join(self.path_resolution["comm_path"], uid, "incoming", "die")
            os.makedirs(os.path.dirname(die_path), exist_ok=True)
            with open(die_path, "w", encoding="utf-8") as f:
                f.write("☠️")
            self.log(f"[SHUTDOWN] Dropped .die for {uid}")

    def cmd_resume_subtree(self, content, packet, identity:IdentityObject = None):
        """Resumes a previously shut-down agent and its subtree.

        This method is the inverse of `cmd_shutdown_subtree`. It removes the
        'die' and 'tombstone' files from the `/incoming` directory of the
        target agent and all of its descendants. Once the 'die' file is gone,
        the parent agent's `spawn_manager` will detect that the agent is down
        (via a stale heartbeat) and automatically resurrect it.

        Args:
            content (dict): The payload containing the 'universal_id' of the
                root of the subtree to be resumed.
            packet (dict): The raw packet data.
            identity (IdentityObject): The verified identity of the command sender.
        """
        target_id = content.get("universal_id")
        if not target_id:
            self.log("[RESUME][ERROR] Missing universal_id.")
            return

        tp = self.get_agent_tree_master()
        if not tp:
            self.log("[RESUME][ERROR] Failed to load tree.")
            return

        # Don't inject under parent, if marked for deletion or is deleted
        parent_node = tp.get_node(target_id)
        if parent_node and (parent_node.get("deleted") or parent_node.get("confirmed_deleted")):
            self.log(f"[INJECT][BLOCKED] Parent {target_id} is deleted. Cannot resume agent.")
            return

        ids = tp.get_subtree_nodes(target_id)
        for uid in ids:
            die = os.path.join(self.path_resolution["comm_path"], uid, "incoming", "die")
            tomb = os.path.join(self.path_resolution["comm_path"], uid, "incoming", "tombstone")

            for path in [die, tomb]:
                if os.path.exists(path):
                    os.remove(path)
                    self.log(f"[RESUME] Removed {os.path.basename(path)} for {uid}")

    def _save_payload_to_boot_dir(self, agent_name, src):
        try:

            decoded = base64.b64decode(src["payload"]).decode()
            sha_check = hashlib.sha256(decoded.encode()).hexdigest()

            if sha_check != src["sha256"]:
                self.log(f"[INJECT][SHA-FAIL] {agent_name} payload hash mismatch.")
                return

            dir_path = os.path.join(self.path_resolution["root_path"], "boot_payload", agent_name)
            os.makedirs(dir_path, exist_ok=True)

            file_path = os.path.join(dir_path, f"{agent_name}.py")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(decoded)

            self.log(f"[INJECT] ✅ Source code installed at {file_path}")

        except Exception as e:
            self.log(error=e, block="main_try")

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

    def cmd_service_request(self, content, packet, identity: IdentityObject = None):
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

            try:
                #SAVE IDENTITY FILE to comm/{universal_id}/codex
                identity={"identity": subtree.get("vault",{}).get("identity", {}), "sig": subtree.get("vault",{}).get("sig", {})}

                dir = os.path.join(self.path_resolution["comm_path"], universal_id, "codex")
                os.makedirs(dir, exist_ok=True)
                fpath = os.path.join(dir, "signed_public_key.json")
                with open(fpath, "w", encoding="utf-8") as f:
                    json.dump(identity, f, indent=2)

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
            self.log(error=e, block="main-try")

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
        if not hasattr(self, "_agent_tree_master") or self._agent_tree_master is None:
            football = self.get_football(type=self.FootballType.CATCH)
            self._agent_tree_master = self.load_directive(self.tree_path_dict, football)
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
            if not hasattr(self, "_agent_tree_master") or self._agent_tree_master is None:
                self.log("[TREE][WARN] Cannot save — agent_tree_master not loaded.")
                return False

            self._agent_tree_master.pre_scan_for_duplicates(self._agent_tree_master.root)

            data = {"agent_tree": self._agent_tree_master.root}
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

    def perform_agent_consciousness_scan(self, time_delta_timeout=0, flip_threshold=3, flip_window=60):
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
        try:
            uid = content.get("universal_id", False)
            if not uid:
                self.log("[DELIVER-TREE][ERROR] Missing universal_id.")
                return

            self.delegate_tree_to_agent(uid, self.tree_path_dict)

        except Exception as e:
            self.log("[DELIVER-TREE][ERROR]", error=e)


if __name__ == "__main__":
    agent = Agent()
    agent.boot()
