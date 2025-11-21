# Authored by Daniel F MacDonald and ChatGPT aka The Generals
# Gemini, code enhancements and Docstrings
import os
import time
import traceback
import threading
import json
import hashlib
import fnmatch
import inspect
import copy
import queue
from enum import Enum
from pathlib import Path
from core.python_core.class_lib.service.service_endpoint import ServiceEndpoint
from core.python_core.class_lib.packet_delivery.interfaces.base_packet import BasePacket
from core.python_core.mixin.ghost_rider_ultra import GhostRiderUltraMixin
from core.python_core.class_lib.time_utils.heartbeat_checker import check_heartbeats
from core.python_core.core_spawner import CoreSpawner
from core.python_core.mixin.identity_registry import IdentityRegistryMixin
from core.python_core.class_lib.file_system.find_files_with_glob import  FileFinderGlob
from core.python_core.class_lib.processes.duplicate_job_check import  DuplicateProcessCheck
from core.python_core.class_lib.logging.logger import Logger
from core.python_core.class_lib.packet_delivery.mixin.packet_factory_mixin import PacketFactoryMixin
from core.python_core.class_lib.packet_delivery.mixin.packet_delivery_factory_mixin import PacketDeliveryFactoryMixin
from core.python_core.class_lib.packet_delivery.mixin.packet_reception_factory_mixin import PacketReceptionFactoryMixin
from core.python_core.class_lib.packet_delivery.utility.encryption.config import ENCRYPTION_CONFIG
from core.python_core.class_lib.packet_delivery.utility.encryption.config import EncryptionConfig
from core.python_core.utils.debug.config import DebugConfig
from cryptography.hazmat.primitives import serialization
from core.python_core.mixin.ghost_vault import decrypt_vault
from core.python_core.utils.trust_log import log_trust_banner
from core.python_core.boot_agent_thread_config import get_default_thread_registry
from core.python_core.trust_templates.matrix_dummy_priv import DUMMY_MATRIX_PRIV
from core.python_core.tree_parser import TreeParser
from core.python_core.class_lib.packet_delivery.utility.crypto_processors.football import Football
from core.python_core.class_lib.packet_delivery.utility.encryption.utility.identity import IdentityObject

from core.python_core.utils.process_utils import find_jobs_by_prefix, reeeeeeebeeeengaaaaa

from Crypto.PublicKey import RSA as PyCryptoRSA
from core.python_core.utils.swarm_sleep import interruptible_sleep


class BootAgent(PacketFactoryMixin, PacketDeliveryFactoryMixin, PacketReceptionFactoryMixin, GhostRiderUltraMixin, IdentityRegistryMixin):
    """The foundational class for all agents in the MatrixSwarm.
    This class provides the core functionality required for an agent to operate
    within the swarm, including secure initialization from a vault, lifecycle
    management through multithreading, and the packet-based communication system.
    All specific agents must inherit from BootAgent.
    """
    if __name__ == "__main__":

        raise RuntimeError("Direct execution of agents is forbidden. Only Matrix may be launched via bootloader.")

    def __init__(self):
        """Initializes the agent by securely decrypting its configuration.
        This method is the entry point for a newly spawned agent. It reads the
        SYMKEY and VAULTFILE from environment variables, decrypts the payload,
        and uses it to set up all core attributes, including security keys,
        path resolutions, and cryptographic handlers ("Footballs") for
        communication.

        Attributes:
            path_resolution (dict): A dictionary of all essential filesystem paths.
            command_line_args (dict): Arguments passed at spawn time, like universal_id.
            tree_node (dict): The agent's specific node from the master directive.
            swarm_key (str): The global AES key used for general packet encryption.
            private_key (str): The agent's personal AES key.
            matrix_pub (str): The PEM-encoded public key of the root Matrix agent.
            matrix_priv (str): The private key of the Matrix agent (often a dummy key).
            public_key_obj: The agent's own public key as a cryptography object.
            private_key_obj: The agent's own private key as a cryptography object.
            logger (Logger): An encrypted logger instance for this agent.
            running (bool): A flag that controls the main loops of the agent's threads.
            _pass_football (Football): A pre-configured crypto handler for sending packets.
            _catch_football (Football): A pre-configured crypto handler for receiving packets.
        """
        print("[BOOT] Matrix waking up...")

        try:
            payload = decrypt_vault()
            print("[VAULT] Decryption succeeded")
        except Exception as e:
            print(f"[FATAL] Vault decryption failed: {e}")
            exit()

        self.path_resolution = payload["path_resolution"]
        self.command_line_args = payload["args"]
        self.tree_node = payload["tree_node"]

        #used by the swarm to encrypt packets
        self.swarm_key = payload.get("swarm_key")  #swarm AES Key
        #this is for Matrix only and maybe a bogus key, only the real Matrix gets this and her Sentinels
        self.private_key = payload.get("private_key") #private AES Key

        #these 2 guys are aux and are created by the parent
        self.matrix_pub = payload.get("matrix_pub")
        self.matrix_priv = payload.get("matrix_priv")  # Fallback already handled by decrypt_vault()

        #these are the same 2 guys that have been converted in the vault
        self.public_key_obj = payload["public_key_obj"]
        self.private_key_obj = payload["private_key_obj"]
        self.pub_fingerprint = payload["pub_fingerprint"]
        self.secure_keys = payload.get("secure_keys", {})
        self.cached_pem = payload.get("cached_pem", {})
        #hold Matrix credentials, encase of her going down
        self.security_box = payload.get("security_box", {})

        config = EncryptionConfig()

        #to be accessed by long packet_listener processes
        self._emit_beacon_packet_listener = self.check_for_thread_poke("packet_listener", timeout=60)

        #automatic throttle
        self.throttle_queue = queue.Queue(maxsize=1)

        self.debug = DebugConfig()

        self.logger = Logger(self.path_resolution["static_comm_path_resolved"], "logs", "agent.log")

        self.encryption_enabled=bool(payload.get("encryption_enabled",0))
        if self.encryption_enabled:
            config.set_swarm_key(self.swarm_key)
            config.set_private_key(self.private_key)
            config.set_enabled(True)
            self.logger.set_encryption_key(self.swarm_key)

        # Optional fingerprint of Matrix public key
        try:
            self.matrix_fingerprint = hashlib.sha256(self.matrix_pub.encode()).hexdigest()[:12]
        except Exception as e:
            self.log(f"[BOOT] matrix_pub is missing. Trust cannot be verified.", error=e, block="optional_fingerprint")


        # Convert to objects

        try:
            self.matrix_pub_obj = serialization.load_pem_public_key(self.matrix_pub.encode())
        except Exception as e:
            self.matrix_pub_obj = None
            self.log(f"[BOOT] matrix_pub is missing. Trust cannot be verified.", error=e, block="serialize_public_key")
            exit()

        try:
            self.matrix_priv_obj = PyCryptoRSA.import_key(self.matrix_priv)
            self.log("[BOOT] 🔐 Matrix private key imported via PyCryptodome for signature operations.")
        except Exception as e:
            self.matrix_priv_obj = None
            self.log("[BOOT] ❌ Failed to convert Matrix private key to PyCrypto-compatible object", error=e)
            exit()

        # 🧬 Chain-of-trust determination
        uid = self.command_line_args.get("universal_id", "")
        log_trust_banner(
            agent_name=uid,
            logger=self.logger,
            pub=self.secure_keys.get("pub"),
            matrix_pub=self.matrix_pub,
            matrix_priv=self.matrix_priv,
            swarm_key=self.swarm_key,
            private_key=self.private_key
        )


        #this option will be pulled from the command line as debug
        #all packets all directives, using the self.swarm_key
        self.packet_encryption=True

        self.boot_time = time.time()
        self.running = False
        self.subordinates = []
        self.thread_registry = get_default_thread_registry()

        if self.encryption_enabled:
            config.set_pub(self.public_key_obj)
            config.set_priv(self.private_key_obj)
            config.set_matrix_pub(self.matrix_pub_obj)
            config.set_matrix_priv(self.matrix_priv_obj)

        self.verbose = bool(self.command_line_args.get('verbose',0))

        debug = bool(self.command_line_args.get('debug',0))

        #don't need to use a singleton
        self.rug_pull = bool(self.command_line_args.get('rug_pull', 0))

        self.debug.set_enabled(enabled = debug)
        if self.debug.is_enabled():
            status="enabled"
        else:
            status="disabled"
        self.log(f"Debugging: {status}")

        if self.encryption_enabled:
            status = "enabled"
        else:
            status = "disabled"
        self.log(f"Encryption: {status}")

        status="disabled"
        if self.rug_pull:
            # kick the chair out
            status = "enabled"
        self.log(f"Rug pull: {status}")

        if self.rug_pull:
            # kick the chair out
            ppath = os.path.join(self.path_resolution["pod_path_resolved"], "run")
            try:
                os.unlink(ppath)
                print(f"[RUG-PULL] 🪓 Deleted {ppath}")
                self.log(f"[RUG-PULL] 🪓 Deleted {ppath}")

            except Exception as e:
                print(f"[RUG-PULL][FAIL] Could not delete {ppath}: {e}")
                self.log(f"[RUG-PULL][FAIL] Could not delete {ppath}", error=e, level="ERROR")

        self._loaded_tree_nodes={}
        self._service_manager_services = {}

        self._outgoing_addins = []  # keep BootAgent skinny

        self.running = False
        self.NAME = self.command_line_args.get("agent_name", "UNKNOWN")

        '''
        fb.add_identity(matrix_node['vault'],
                identity_name="agent_owner",    #owner identity
                verify_universal_id=True,       #make sure the universal_id of the agent is the same as the one in the identity
                universal_id="matrix",          #compare universal_id to the one stored in the identity, sanity check
                is_payload_identity=True,         #yes, this payload is an identity, if identity embedding is turned on this will be the identity that will be embeded, since it will be the identity of the user sending the packet
                sig_verifier_pubkey=matrix_pub,   #this pubkey is used to verify the identity, always Matrix's pubkey
                is_pubkey_for_encryption=False,    #if you turn on asymmetric encryption the pubkey in the identity will encrypt, check payload size
                is_privkey_for_signing=True,       #use the privkey that belongs to the identity pubkey to sign the whole subpacket
                )
        '''

        #cache the identity, no need to do the calculations every instantiation
        #basic identity template to send a packet
        self._pass_football= Football()
        self._pass_football.set_identity_sig_verifier_pubkey(self.matrix_pub)  # this is used to verify the agent's own identity, sanity check
        self._pass_football.add_identity(self.tree_node["vault"],
                                    identity_name="agent_owner",
                                    universal_id=self.command_line_args.get("universal_id"), #verify the agents own universal_id,
                                    is_payload_identity=True,
                                    is_privkey_for_signing=True
                                    )
        self._pass_football.set_pubkey_verifier(self.matrix_pub) #Matrix pubkey to verify the inner-identity
        self._pass_football.set_identity_base_path(self.path_resolution['comm_path'])
        #self._pass_football.set_aes_key(self.swarm_key)
        #self._pass_football.set_aes_encryption_pubkey() #used for sending the aes encryption key using targets, pubkey
        #self._pass_football.set_aes_encryption_privkey() #used by the receiving target to decrypt the aes key and decrypt the payload


        # basic identity template to receive a packet
        self._catch_football = Football()
        self._catch_football.set_identity_sig_verifier_pubkey(self.matrix_pub)  # this is used to verify the agent's own identity, sanity check
        self._catch_football.add_identity(
                                         self.tree_node["vault"],
                                         identity_name="agent_owner",
                                         universal_id=self.command_line_args.get("universal_id"),
                                         )
        self._catch_football.set_pubkey_verifier(self.matrix_pub)  # Matrix pubkey to verify the inner-identity
        self._catch_football.set_aes_encryption_privkey(self.secure_keys.get("priv"))  #used by the receiving agent to decrypt the aes key that wa
        # s encrypted with the paired pubkey, then using the aes key to decrypt the payload
        self._catch_football.set_identity_base_path(self.path_resolution['comm_path'])

        self.last_tree_mtime = 0

    class FootballType(Enum):
        PASS = 1
        CATCH = 2

    def get_football(self, type: FootballType = FootballType.PASS ):

        try:
            if type == self.FootballType.CATCH:
                fb = copy.deepcopy(self._catch_football)
            elif type == self.FootballType.PASS:
                fb = copy.deepcopy(self._pass_football)
            else:
                raise ValueError("Unknown football type or type not provided")

        except Exception as e:
            self.log(error=e, block="main_try")

        return fb

    def log(self, msg="", error: Exception = None, block=None, include_stack=True, level="INFO", custom_tail=None):
        """A custom logging method that automatically injects agent context.

        This wrapper around the standard logger automatically prepends a prefix
        to every log message, including the agent's name, the calling method's
        name, and the line number. This provides rich, contextual logging
        across the entire swarm with zero configuration.

        Args:
            msg (str): The message to log.
            error (Exception, optional): An exception object to log.
            block (str, optional): An optional string to add a custom block name.
            level (str, optional): The log level (e.g., "INFO", "ERROR").
        """
        try:

            if custom_tail:

                agent = self.command_line_args.get("agent_name", "UNKNOWN").upper()

                prefix = f"[{agent}]{custom_tail}"

            else:

                frame = inspect.currentframe()
                outer_frames = inspect.getouterframes(frame)

                if len(outer_frames) > 1:
                    outer = outer_frames[1]
                else:
                    outer = outer_frames[0]

                method_name = outer.function.upper()
                lineno = outer.lineno

                if not isinstance(error, (BaseException, type(None))):
                    raise TypeError(f"'error' must be an Exception, not {type(error).__name__}")

                agent = self.command_line_args.get("agent_name", "UNKNOWN").upper()

                prefix = f"[{agent}][{method_name}][L{lineno}]"

            if block:
                prefix += f"[{block.upper()}]"

            if not msg and error is None:
                return  # no payload to log

            if error:
                err_str = str(error)
                self.logger.log(f"{prefix} {msg} : {err_str}", level=level)
                if include_stack:
                    self.logger.log(traceback.format_exc(), level="DEBUG")
            else:
                self.logger.log(f"{prefix} {msg}", level=level)

        except Exception as fallback:
            print(f"[LOG-FAIL] Logging system failure: {fallback}")

    def log_proto(self, message: str, level: str = "INFO", block: str = None):
        """
        A standardized logging proto for use across agents.

        Args:
            message (str): The message body.
            level (str): One of INFO, WARN, ERROR, CRITICAL, DEBUG.
            block (str): Optional subsystem/block label.
        """
        try:
            prefix = f"[{self.command_line_args.get('agent_name', 'UNKNOWN').upper()}]"
            if block:
                prefix += f"[{block.upper()}]"
            self.log(f"{prefix} {message}", level=level)
        except Exception as e:
            print(f"[LOG-PROTO-FAIL] {e}")

    def send_message(self, message):
        self.log(f"[SEND] {json.dumps(message)}")

    def directive_watcher(self):
        """
        Periodically checks if this agent's agent_tree.json exists or was modified.
        If missing or updated, sends a request to Matrix (or parent) to re-delegate it.
        """
        directive_path = os.path.join(self.path_resolution["comm_path_resolved"], "directive", "agent_tree.json")

        while self.running:
            try:
                if not os.path.exists(directive_path):
                    self.log("[TREE-WATCH] agent_tree.json missing — requesting from parent.")
                    self.request_agent_tree()
                else:
                    current_mtime = os.path.getmtime(directive_path)
                    if current_mtime != self.last_tree_mtime:
                        if self.debug.is_enabled():
                            self.log("[TREE-WATCH] Detected update to agent_tree.json")

                        self.last_tree_mtime = current_mtime

            except Exception as e:
                self.log("[TREE-WATCH][ERROR]", error=e)

            interruptible_sleep(self, 10)

    def request_agent_tree(self):
        """
        Sends a request to Matrix or the parent to receive the agent's tree slice.
        """
        try:
            payload = {
                "handler": "cmd_deliver_agent_tree_to_child",
                "timestamp": time.time(),
                "content": {
                    "universal_id": self.command_line_args.get("universal_id")
                }
                #"sig": sign_packet(
            }

            target = self.command_line_args.get("matrix")

            pk1 = self.get_delivery_packet("standard.command.packet")
            pk1.set_data(payload)
            self.pass_packet(pk1, target, "incoming")
            self.log(f"[TREE-REQUEST] Tree request sent to {target}.")

        except Exception as e:
            self.log("[TREE-REQUEST][ERROR]", error=e)

    def enforce_singleton(self):
        self.log("[ENFORCE] singleton loop starting...")
        try:
            while self.running:
                try:
                    job_label = DuplicateProcessCheck.get_self_job_label()
                    if DuplicateProcessCheck.check_all_duplicate_risks(job_label=job_label, check_path=False):
                        self.running = False
                        self.log(
                            f"[ENFORCE] {self.command_line_args['universal_id']} detected duplicate — standing down.")
                    else:
                        if self.debug.is_enabled():
                            self.log(f"[ENFORCE] {self.command_line_args['universal_id']} is primary for job {job_label}.")

                    path = os.path.join(self.path_resolution["comm_path_resolved"], "incoming")

                    count, _ = FileFinderGlob.find_files_with_glob(path, pattern="die")
                    if count > 0:
                        self.running = False
                        self.log(f"[ENFORCE] die.cookie ingested — going down easy...")

                    if self.running:
                        count, _ = FileFinderGlob.find_files_with_glob(path, pattern="punji")
                        if count > 0:
                            self.running = False
                            self.log(f"[ENFORCE] hit punji — exiting...")

                except Exception as inner:
                    self.log(f"[ENFORCE][ERROR] loop iteration crashed: {inner}", error=inner)

                interruptible_sleep(self, 1.5)

        except Exception as outer:
            self.log(f"[ENFORCE][FATAL] thread crashed: {outer}", error=outer)
        finally:
            self.log("[ENFORCE] loop exited, DONE")

        self.shutdown_now("die.cookie")

    def shutdown_now(self, reason="normal"):
        self.log(f"[SHUTDOWN] agent terminating ({reason})")
        try:
            time.sleep(0.5)
        finally:
            os._exit(0)

    def monitor_threads(self):
        while self.running:
            # Only monitor if worker_thread exists
            if hasattr(self, "worker_thread") and self.worker_thread and not self.worker_thread.is_alive():
                self.log("[WATCHDOG] worker() thread has crashed. Logging beacon death.")
                self.emit_dead_poke("worker", "Worker thread crashed unexpectedly.")
                self.running = False
                os._exit(1)
            interruptible_sleep(self, 3)

    def resolve_factory_injections(self):
        self.log("Starting factory injection from 'factories' block only.")

        config = self.tree_node.get("config", {})
        factories = config.get("factories", {})

        if self.debug.is_enabled():
            self.log(f"Found factories: {list(factories.keys())}")

        for dotted_path, factory_config in factories.items():
            if not isinstance(dotted_path, str) or "." not in dotted_path:
                self.log(f"Invalid factory path: {dotted_path}")
                continue

            try:
                full_module_path = f"agent.{self.command_line_args['agent_name']}.factory.{dotted_path}"
                self.log(f"Attempting: {full_module_path}")
                mod = __import__(full_module_path, fromlist=["attach"])
                mod.attach(self, factory_config)
                self.log(f"Loaded: {full_module_path}")
            except Exception as e:
                self.log(f"{dotted_path} → {e}", error=e, block="main-try")

    def is_worker_overridden(self):
        return self.__class__.worker != BootAgent.worker

    def boot(self):
        """Starts the agent's main operational threads.

       This is the primary entry point to activate the agent after it has been
       initialized. It sets the agent's status to 'running' and launches all
       essential background threads for heartbeat, singleton enforcement,
       inter-agent communication, and the main worker process.
       """
        try:
            self.pre_boot()
            self.running = True
            self.thread_registry["worker"]["active"] = self.is_worker_overridden()
            self.worker_thread = threading.Thread(target=self._throttled_worker_wrapper, name="worker", daemon=False)
            self.worker_thread.start()
            threading.Thread(target=self.enforce_singleton, name="enforce_singleton", daemon=True).start()
            self.thread_registry["enforce_singleton"]["active"] = True
            threading.Thread(target=self.spawn_manager, name="spawn_manager", daemon=True).start()
            self.thread_registry["spawn_manager"]["active"] = True
            threading.Thread(target=self.directive_watcher, name="directive_watcher", daemon=True).start()
            self.thread_registry["directive_watcher"] = {"active": True, "timeout": 30}
            threading.Thread(target=self.packet_listener, name="packet_listener", daemon=True).start()
            self.thread_registry["packet_listener"]["active"] = True
            self.start_dynamic_throttle()
            self.post_boot()
            self.monitor_threads()

            #clear you're own punji file
            punji_file = os.path.join(self.path_resolution['comm_path'], self.command_line_args['universal_id'], 'incoming', 'punji')
            try:
                if os.path.exists(punji_file):
                    os.remove(punji_file)
                    self.log(f"[BOOT] Cleared punji: {punji_file}")
                else:
                    self.log(f"[BOOT] No punji file to remove at: {punji_file}")
            except Exception as e:
                self.log(f"[BOOT] Failed to remove punji: {punji_file}", error=e)

        except Exception as e:
            self.log(error=e, block="main-try")

    """The main operational loop for the agent, intended to be overridden.
    This method is called repeatedly by the _throttled_worker_wrapper.
    Developers should override this method in their own agent classes to
    define the agent's primary logic and tasks. The base implementation
    simply logs a message and sleeps.

    Args:
        config (dict, optional): A dictionary containing the agent's
            most recent configuration, loaded dynamically from the
            /config directory. Defaults to None.
        identity (IdentityObject, optional): An object containing the
            verified identity of the sender if the worker is triggered
            by a packet. Defaults to None.
    """

    def worker(self, config=None, identity=None):
        pass

    def pre_boot(self):
        """A one-time setup hook called before the main threads start.
        This method is intended to be overridden by child agent classes.
        It runs once during the boot() sequence, after initialization but
        before the heartbeat, worker, or listener threads are launched. It is
        ideal for initial health checks or setup that doesn't require threads.
        """
        self.log("[BOOT] Default pre_boot (override me if needed)")

    def post_boot(self):
        """A one-time setup hook called after the main threads have started.
        This method is intended to be overridden by child agent classes.
        It runs once at the end of the boot() sequence after all core
        background threads are active. It is ideal for tasks that should
        run once the agent is fully operational.
        """
        self.log("[BOOT] Default post_boot (override me if needed)")

    def packet_listener(self):
        """Monitors the incoming directory for new command packets.
        This method is the core of inter-agent communication. Running in a
        continuous loop, it watches the agent's `/incoming` directory for new
        `.json` files. When a file appears, it uses a ReceptionAgent to
        securely decrypt and validate the packet. It then dynamically calls the
        appropriate handler method within the agent to process the command.
        After processing, the packet file is deleted.
        """
        self.log("Monitoring incoming packets...")
        incoming_path = os.path.join(self.path_resolution["comm_path_resolved"], "incoming")
        os.makedirs(incoming_path, exist_ok=True)
        last_dir_mtime = os.path.getmtime(incoming_path)
        #TOP TRY
        try:

            football = self.get_football(type=self.FootballType.CATCH)
            ra = self.get_reception_agent("file.json_file", new=True, football=football)
            ra.set_location({"path": self.path_resolution["comm_path"]}) \
                .set_address([self.command_line_args["universal_id"]]) \
                .set_drop_zone({"drop": "incoming"})

        except Exception as e:
            self.log(error=e, block="top_try")

        while self.running:

            #Main Try
            try:

                self._emit_beacon_packet_listener()

                current_dir_mtime = os.path.getmtime(incoming_path)
                if current_dir_mtime != last_dir_mtime:
                    last_dir_mtime = current_dir_mtime

                    for fname in os.listdir(incoming_path):
                        #dynamic config packet
                        try:
                            if not fname.startswith("pk_") or not fname.endswith(".json"):
                                continue

                            pk = self.get_delivery_packet("standard.command.packet", new=True)
                            pk2 = self.get_delivery_packet("standard.general.json.packet", new=True)
                            pk.set_packet(pk2)

                            packet = ra.set_identifier(fname) \
                                       .set_packet(pk) \
                                       .receive()

                            fpath = os.path.join(incoming_path, fname)  # get the file's path

                            try:
                                os.remove(fpath)
                            except Exception as e:
                                pass

                            try:
                                identity=ra.get_identity()
                            except Exception as e:
                                identity=None

                            try:
                                pk = packet.get_packet()
                            except Exception as e:
                                self.log(f"Failed to process {fname} :{pk}", error=e, block="dynamic_config_packet")
                                pk={}

                            if ra.get_error_success() or packet is None:
                                pk={}
                                self.log(f"Failed to receive data from reception agent or error: {ra.get_error_success_msg()}.")

                            if self.debug.is_enabled():
                                self.log(f"processing packet: {fname}")

                            handler = pk.get("handler")
                            if not handler:
                                self.log(f"[UNIFIED][SKIP] No 'call' in: {fname} packet: {pk}")
                                continue

                            handler_name = pk.get("handler")
                            content = pk.get("content", {})

                            # 1. Check if the class has a direct method with this name
                            handler_fn = getattr(self, handler_name, None)
                            #factory handler check

                            if not handler_name.startswith("cmd_"):
                                self.log(f"[INVALID HANDLER NAME]: {handler_name}")
                                continue

                            if callable(handler_fn):
                                try:
                                    handler_fn(content, pk, identity)
                                    if self.debug.is_enabled():
                                        self.log(f"[UNIFIED] ✅ Executed handler: {handler_name}")
                                    continue
                                except Exception as e:
                                    self.log(f"[UNIFIED][ERROR] Handler '{handler_name}' failed: {e}")

                        except Exception as e:
                            self.log(f"Failed to process {fname}", error=e)
                            if fpath and os.path.isfile(fpath):
                                os.remove(fpath)
                            continue

            except Exception as loop_error:

                self.log("Error in loop", error=loop_error, block="main_try")

            #packet_listener_post call
            try:
                handler_fn = getattr(self, "packet_listener_post", None)
                if callable(handler_fn):
                    self.packet_listener_post() #used as hook or cron, so any operation that effects the agent_tree for instance stay on same thread

            except Exception as e:
                self.log(error=e, block="packet_listener_post")

            interruptible_sleep(self, 2)

    def save_directive(self, path: dict, node_tree :dict, football:Football):
        """
        Encrypt and deliver the directive tree using a structured path dictionary.

        path: {
            "path": base communication path (e.g., /comm/data),
            "address": universal_id (e.g., agent ID),
            "drop": drop zone (e.g., 'directive'),
            "name": filename (e.g., 'agent_tree_master.json')
        }
        """
        try:

            pk1 = self.get_delivery_packet("standard.tree.packet", new=True)
            pk1.set_data(node_tree)
            ra = self.get_delivery_agent("file.json_file", new=True, football=football)
            ra.set_location({"path": path["path"]}) \
                .set_identifier(path['name']) \
                .set_metadata({"atomic": True}) \
                .set_address([path["address"]]) \
                .set_drop_zone({"drop": path["drop"]}) \
                .set_packet(pk1) \
                .deliver()

            if self.encryption_enabled:
                if self.debug.is_enabled():
                    self.log(f"[SAVE] ✅ Encrypted directive delivered to {path['address']}/{path['drop']}/{path['name']}")
            else:
                if self.debug.is_enabled():
                    self.log(f"[SAVE] ✅ Directive delivered to {path['address']}/{path['drop']}/{path['name']}")

            return True

        except Exception as e:
            self.log(f"[BOOT][DUMP-TREE-DELIVERY-ERROR] ❌", error=e, block="main_try")
            return False

    def load_directive(self, path :dict, football:Football):
        try:

            if ENCRYPTION_CONFIG.is_enabled():
                football.set_allowed_sender_ids(["matrix"])

            pk1 = self.get_delivery_packet("standard.tree.packet", new=True)

            packet = self.get_reception_agent("file.json_file", football=football) \
                .set_location({"path": path["path"]}) \
                .set_identifier(path["name"]) \
                .set_address(path["address"]) \
                .set_packet(pk1) \
                .set_drop_zone({"drop": path["drop"]}) \
                .receive()

            if packet is None:
                raise ValueError("Failed to receive data from reception agent.")

            data=packet.get_packet()

            return TreeParser.load_tree_direct(data)

        except Exception as e:
            self.log(f"[BOOT][DUMP-TREE-DELIVERY-ERROR] ❌", error=e, block="main_try")
            return TreeParser.load_tree_direct({})


    def _throttled_worker_wrapper(self):
        """A wrapper that manages the execution of the main worker() method.

        This wrapper provides two key features:
        1.  Dynamic Throttling: It monitors the system's load average and
            introduces a delay between worker() loop executions if the load
            is too high, preventing the swarm from overloading the host system.
        2.  Real-Time Configuration: It monitors the agent's /config directory
            for new .json files. If a new config file is dropped, it is
            securely loaded and passed into the next execution of the worker()
            method, allowing for on-the-fly configuration changes.
        """
        self.log("Throttled worker wrapper engaged.")
        config_path = os.path.join(self.path_resolution["comm_path_resolved"], "config")
        os.makedirs(config_path, exist_ok=True)
        fpath=None
        identity=None
        last_dir_mtime = os.path.getmtime(config_path)
        last_worker_cycle_execution = 0
        try:

            football = self.get_football( type = self.FootballType.CATCH)
            ra = self.get_reception_agent("file.json_file", new=True, football=football)
            ra.set_location({"path": self.path_resolution["comm_path"]}) \
                .set_address([self.command_line_args["universal_id"]]) \
                .set_drop_zone({"drop": "config"})

        except Exception as e:
            self.log(f"Failed to process", error=e, block="main_try")

        # Optional pre-hook (called ONCE before loop)
        if hasattr(self, "worker_pre"):
            try:
                self.worker_pre()
                self.resolve_factory_injections()
            except Exception as e:
                self.log(error=e)

        while self.running:

            try:
                # Wait for a signal from the throttler thread before proceeding.
                # This call will block until an item is available in the queue.
                self.throttle_queue.get()

                config={}
                _config = {} #temp config

                try:

                    #ON EXECUTION, THIS WILL SCOOP UP ALL THE CONFIG PACKETS
                    #BUT  ONLY SEND THE LAST ONE TO THE WORKER METHOD
                    #AND DELETE THE REST OF THE PACKETS
                    current_dir_mtime = os.path.getmtime(config_path)
                    if current_dir_mtime != last_dir_mtime:
                        last_dir_mtime = current_dir_mtime

                        for fname in os.listdir(config_path):

                            if not fname.endswith(".json"):
                                continue

                            #get json packet
                            pk1 = self.get_delivery_packet("standard.general.json.packet", new=True)

                            packet = ra.set_identifier(fname) \
                                .set_packet(pk1) \
                                .receive()

                            fpath = os.path.join(config_path, fname)  # get the file's path

                            _config = packet.get_packet()

                            if ra.get_error_success() or packet is None:
                                self.log(f"Failed to receive data from reception agent or error: {ra.get_error_success_msg()}.")

                            if self.debug.is_enabled():
                                self.log(f"config: path: {fpath} {config}")

                            os.remove(fpath)

                            identity = ra.get_identity()

                            if isinstance(_config, dict):
                                config = _config.copy()

                except Exception as e:
                    if fpath and os.path.isfile(fpath):
                        os.remove(fpath)
                    self.log(f"config {config}", error=e)

                #AVOID SPAMMING LOGS
                now = time.time()
                if (last_worker_cycle_execution + 30) < now:
                    last_worker_cycle_execution = now
                    if self.debug.is_enabled():
                        self.log(f"Executing worker cycle...")

                #REMEMBER THIS ISN'T ENTERED LIKE PACKET_LISTENER
                #THERE MAY BE A LARGE TIMEOUT IN WORKER
                if not self.running:
                    break
                self.worker(config, identity)

            except Exception as e:
                self.log(error=e, block="main_try")

            interruptible_sleep(self, 1)

        # Optional post-hook (called ONCE after loop exits)
        if hasattr(self, "worker_post"):
            try:
                self.worker_post()
            except Exception as e:
                self.log(error=e)


    #used to verify and map threads to verify consciousness
    def check_for_thread_poke(self, thread_token="packet_listener", timeout=None, sleep_for=None, emit_to_file_interval=10):
        """
        Returns an emit() function that writes a heartbeat file no more often than
        emit_to_file_interval seconds. File name encodes timeout/sleep info.
        """
        poke_dir = os.path.join(self.path_resolution["comm_path_resolved"], "hello.moto")
        os.makedirs(poke_dir, exist_ok=True)

        wake_due = int(time.time() + sleep_for) if sleep_for else 0
        timeout_val = timeout if timeout else 0
        sleep_val = sleep_for if sleep_for else 0
        last_emit = [0]  # closure storage

        def emit():
            now = time.time()
            if now - last_emit[0] < emit_to_file_interval:
                # too soon since last write, skip
                return

            filename = f"poke.{thread_token}.{timeout_val}.{sleep_val}.{wake_due}"
            poke_path = os.path.join(poke_dir, filename)

            # create/truncate empty file
            with open(poke_path, "w"):
                pass

            last_emit[0] = now
            if self.debug.is_enabled():
                print(f"[BEACON] {thread_token} emitted as {filename} at {now}")

        return emit

    def emit_dead_poke(self, thread_name, error_msg):
        path = os.path.join(self.path_resolution["comm_path_resolved"], "hello.moto", f"poke.{thread_name}")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "status": "dead",
                "last_seen": time.time(),
                "error": error_msg
            }, f, indent=2)

    def get_load(self):
        if hasattr(os, "getloadavg"):
            return os.getloadavg()[0]
        else:
            # Windows: fallback (always return 0 or use psutil.cpu_percent())
            try:
                import psutil
                # Return normalized value, e.g., %CPU / 100
                return psutil.cpu_percent() / 100.0
            except ImportError:
                return 0  # Safe default

    def start_dynamic_throttle(self, min_delay=2, max_delay=10, max_load=2.0):
        def dynamic_throttle_loop():
            last_throttle_cycle_execution = False
            greatest_load = 0
            while self.running:
                try:
                    load_avg = self.get_load()
                    scale = min(1.0, (load_avg - max_load) / max_load) if load_avg > max_load else 0
                    delay = int(min_delay + scale * (max_delay - min_delay))

                    if scale > 0:
                        if not last_throttle_cycle_execution:
                            last_throttle_cycle_execution = True
                            if self.debug.is_enabled():
                                self.log(f"[THROTTLE_STARTED] Load: {load_avg:.2f} → delay: {delay}s")
                        if load_avg > greatest_load:
                            greatest_load = load_avg
                    else:
                        if last_throttle_cycle_execution:
                            last_throttle_cycle_execution = False
                            if self.debug.is_enabled():
                                self.log(f"[THROTTLE_ENDED] Highest Load: {greatest_load:.2f}")
                            greatest_load = 0

                    # Signal the worker thread to proceed.
                    try:
                        self.throttle_queue.put_nowait(True)
                    except queue.Full:
                        # Queue is already full, meaning worker hasn't processed the last signal.
                        # Do nothing and let the queue act as a buffer of size 1.
                        pass

                    interruptible_sleep(self, delay)
                except Exception as e:
                    self.log(error=e)
                    interruptible_sleep(self, min_delay)

        threading.Thread(target=dynamic_throttle_loop, daemon=True).start()

    def get_nodes_by_role_with_priority(self, role, scope='any'):
        nodes = self.get_nodes_by_role(role, scope=scope)
        prioritized = []

        for node in nodes:
            config = node.get('config', {})
            role_priority_map = config.get('priority', {})
            priority = role_priority_map.get(role, role_priority_map.get('default', 1))  # default = 1

            prioritized.append((priority, node))

        prioritized.sort(key=lambda x: x[0])  # lower = higher priority
        return [n for _, n in prioritized]


    def _resolve_scope(self, scope: str):
        """
        Normalize scope string into a depth_limit.
        Returns None for unlimited depth (whole swarm).
        """
        if not scope or scope in ("any", "child(0)"):
            return None  # full swarm
        if scope.startswith("child("):
            try:
                return int(scope.split("(")[1].split(")")[0])
            except Exception:
                return 1
        if scope == "child":
            return 1
        return None

    def get_nodes_by_role(self, role: str, return_count: int = 0):
        """
        Finds agents in the swarm based on advertised roles.
        Expects 'role' to be a string or comma-separated list.
        Returns a list of ServiceEndpoint objects.
        """
        try:
            role_patterns = [r.strip().lower() for r in role.split(",") if r.strip()]
            if not role_patterns:
                return []

            nodes = self.get_cached_service_managers()
            endpoints = []

            for node in nodes:
                uid = node.get("universal_id")
                for svc in node.get("config", {}).get("service-manager", []):
                    for role_entry in svc.get("role", []):  # already a list
                        role_entry = role_entry.strip()
                        if "@" in role_entry:
                            role_name, handler = [x.strip() for x in role_entry.split("@", 1)]
                        else:
                            role_name, handler = role_entry.strip(), None

                        for pattern in role_patterns:
                            if fnmatch.fnmatch(role_name.lower(), pattern):
                                ep = ServiceEndpoint({
                                    "role": role_name,
                                    "handler": handler,
                                    "universal_id": uid,
                                })
                                if ep.is_clear():
                                    endpoints.append(ep)
                                break  # one match is enough per entry

                if return_count > 0 and len(endpoints) >= return_count:
                    break

            return endpoints if return_count <= 0 else endpoints[:return_count]

        except Exception as e:
            self.log(f"[INTEL][ERROR] get_nodes_by_role failed: {e}")
            return []

    def get_nodes_by_subscription(self, topic: str, scope: str = "any", return_count: int = 0):
        """Finds nodes with services subscribed to a specific topic.

        This function queries the agent's cached data to find and return a
        list of nodes that have a service subscribed to a specific topic. It
        iterates through all cached service manager configurations and checks
        their subscriptions, ensuring each matching node is returned only once.

        Note:
            The 'scope' parameter is parsed but not currently used to filter
            the nodes. The search is always performed across all cached nodes.

        Args:
            topic (str): The subscription topic to search for, e.g.,
                "system.health.report".
            scope (str): Defines the intended search scope.
                Defaults to "child".
            return_count (int): The maximum number of matching nodes to return.
                If 0 or less, all matches are returned. Defaults to 0.

        Returns:
            list: A list of node objects that match the subscription topic.
            Returns an empty list if no nodes are found or if an error
            occurs during execution.
        """
        try:
            topic = topic.strip()
            if not topic:
                return []

            # Determine the depth limit from scope
            depth_limit = None
            if scope.startswith("child("):
                try:
                    depth_limit = int(scope.split("(")[1].split(")")[0])
                except:
                    depth_limit = 1
            elif scope == "child":
                depth_limit = 1
            elif scope in ("any", "child(0)"):
                depth_limit = None  # no limit
            else:
                depth_limit = 1

            # BFS to honor depth_limit
            nodes = self.get_cached_service_managers()
            uid_to_node = {n.get("universal_id"): n for n in nodes}

            # Start from this agent's node
            start_uid = self.command_line_args.get("universal_id")
            seen_uids = set()
            matches = []
            queue = [(start_uid, 0)]  # (uid, current_depth)

            while queue:
                uid, cur_depth = queue.pop(0)
                if uid in seen_uids:
                    continue
                seen_uids.add(uid)
                node = uid_to_node.get(uid)
                if not node:
                    continue

                # Check for subscription at this node
                for svc in node.get("config", {}).get("service-manager", []):
                    subscriptions = svc.get("subscribe", [])
                    if isinstance(subscriptions, str):
                        subscriptions = [subscriptions]
                    for sub in subscriptions:
                        if sub.strip() == topic:
                            matches.append(node)
                            break  # Only one match per node

                # Queue children if within depth_limit
                if depth_limit is None or cur_depth < depth_limit:
                    for child in node.get("children", []):
                        cuid = child.get("universal_id")
                        if cuid and cuid not in seen_uids:
                            queue.append((cuid, cur_depth + 1))

                if return_count > 0 and len(matches) >= return_count:
                    break

            return matches if return_count <= 0 else matches[:return_count]

        except Exception as e:
            self.log(f"[INTEL][ERROR] get_nodes_by_subscription failed: {e}")
            return []

    def get_cached_service_managers(self):
        if hasattr(self, "_service_manager_services") and self._service_manager_services:
            return self._service_manager_services
        else:
            return []

    #orginizes level one children by role
    def track_direct_subordinates(self):
        for child in self.tree_node.get("children", []):
            role = child.get("config", {}).get("role")
            uid = child.get("universal_id")
            if role and uid:
                self.subordinates[role] = uid
        self.log(f"[INTEL] Subordinate registry: {self.subordinates}")



    def spawn_manager(self):

        time_delta_timeout = 60

        last_tree_mtime = 0
        tree = None  # Initial tree holder

        tree_path_resolved = os.path.join(self.path_resolution['comm_path'], self.command_line_args["universal_id"], "directive", "agent_tree.json")

        tree_path = {
            "path": self.path_resolution["comm_path"],
            "address": self.command_line_args["universal_id"],
            "drop": "directive",
            "name": "agent_tree.json"
        }

        emit_beacon = self.check_for_thread_poke("spawn_manager", timeout=60)

        while self.running:
            try:

                emit_beacon()

                if self.debug.is_enabled():
                    print(f"[SPAWN] Checking for delegated children of {self.command_line_args['universal_id']}")

                if not os.path.exists(tree_path_resolved):
                    interruptible_sleep(self, 5)
                    continue

                mtime = os.path.getmtime(tree_path_resolved)
                if mtime != last_tree_mtime:

                    football = self.get_football(type=self.FootballType.CATCH)
                    tp = self.load_directive(tree_path, football=football)
                    self._service_manager_services = getattr(tp, "_service_manager_services", [])

                    if not tp or not hasattr(tp, "root") or not isinstance(tp.root, dict):
                        self.log("[SPAWN] Corrupt or invalid tree — deleting and re-requesting.")
                        os.remove(tree_path_resolved)
                        continue  # Will retry in next loop

                    tree = tp.root
                    last_tree_mtime = mtime
                    if self.debug.is_enabled():
                        self.log(f"[SPAWN] Tree updated from disk.")

                if not tree:
                    print(f"[SPAWN][ERROR] Could not load tree for {self.command_line_args['universal_id']}")
                    interruptible_sleep(self, 3)
                    continue

                for child_id in tp.get_first_level_child_ids(self.command_line_args["universal_id"]):

                    node = tp.nodes.get(child_id)
                    if not node:
                        self.log(f"[SPAWN] Could not find node for {child_id}")
                        interruptible_sleep(self, 3)
                        continue

                    # Skip deleted nodes
                    if node.get('lifecycle_status',{}).get("locked", False):
                        if self.debug.is_enabled():
                            self.log(f"[SPAWN-BLOCKED] {node.get('universal_id')} is marked deleted.")
                        interruptible_sleep(self, 3)
                        continue

                    # Skip if die token exists
                    die_file = os.path.join(self.path_resolution['comm_path'], node.get("universal_id"), 'incoming', 'die')
                    if os.path.exists(die_file):
                        self.log(f"[SPAWN-BLOCKED] {node.get('universal_id')} has die file.")
                        interruptible_sleep(self, 3)
                        continue

                    #Go time
                    if self.clear_to_spawn(self.command_line_args.get("universe"), node.get("universal_id")):

                        #check to see if this agent is a cronjob
                        #This block first checks the node for a tag 'is_cron_job'
                        #if it contains that tag, it checks to see if a mission.complete file is in the hello.moto dir
                        #if the file doesn't exist it exits the block and spawns the agent
                        #if the file does exist it gets the interval from the node in secs or defaults 3600(6 min), and then
                        #checks the mtime of the file and calculates if the cron_interval_sec has elapsed since the files creation
                        #if it has the time has elapsed it removes the file and spawns the agent
                        #if not, it goes directly to jail; no pass go.
                        #once the agent carries out it's mission it drops the mission.complete file and the process goes, and continues forever, and ever, and ever.
                        is_cron_job_and_time_to_awake=False
                        if node.get("is_cron_job", False):
                            mission_complete_file= os.path.join(self.path_resolution['comm_path'], node.get("universal_id"), 'hello.moto', 'mission.complete')
                            if os.path.exists(mission_complete_file):
                                last_run_time = os.path.getmtime(mission_complete_file)
                                interval = node.get("cron_interval_sec", 3600)
                                if (time.time() - last_run_time) >= interval:
                                    self.log(f"[CRON] Interval met for {node.get('universal_id')}. Removing die cookie to trigger next run.")
                                    os.remove(mission_complete_file)
                                else:
                                    is_cron_job_and_time_to_awake=True

                        #if not a cronjob, enter; if is a cronjob and it's time to awake from slumber then
                        if not is_cron_job_and_time_to_awake:
                            # Call spawn function
                            self.spawn_agent_direct(
                                universe=self.command_line_args.get("universe"),
                                spawner=self.command_line_args["universal_id"],
                                universal_id=node.get("universal_id"),
                                agent_name=node.get("name"),
                                tree_node=node,
                                keychain=self.ring_keychain(node)
                            )

            except Exception as e:
                self.log(error=e, block="main_try")

            interruptible_sleep(self, 15)

    def clear_to_spawn(self, universe, universal_id)->bool:

        # THIS WHOLE BLOCK IS WHAT CONTROLS REBOOTING BASED ON ANY POKE.* FILE DETECTED AS STALE
        clear_to_spawn = False

        try:

            # Skip if recent heartbeat is alive, all pokes are alive or sleeping
            result = check_heartbeats(self.path_resolution['comm_path'], universal_id)
            meta = result["meta"]
            threads = result["threads"]

            safe_to_continue=True
            if meta["error_success"]:
                self.log(f"[HEARTBEAT] {universal_id} failed: {meta['error']}")
            else:
                # log failed threads with deltas
                for t, s in threads.items():
                    if s["status"] == "failed":
                        self.log(f"[HEARTBEAT] {universal_id}:{t} failed delta={s['delta']}s (timeout={s['timeout']})")

                if all(s["status"] in ("alive", "sleeping") for s in threads.values()):
                    safe_to_continue = False  # healthy, no respawn


            if safe_to_continue:
                # defense, encase stray poke got inside hello.moto directory, which would initiate a phantom status, leading to stale poke file, leading to reboot
                ss = os.path.join(self.path_resolution['comm_path'], universal_id, 'hello.moto')
                for f in Path(ss).glob("poke.*"):
                    try:
                        f.unlink()
                    except Exception as e:
                        pass

                # 1. Check the process list for agent with cmd line --job {universe=universe, defaults to ai}:{spawner=parent agent, obviously this agent}:{universal_id=agent getting spawned}:{agent_name=actual agent being spawned comm/<agent><agent>}
                #   for active propess in memroy
                punji_dir = os.path.join(self.path_resolution['comm_path'], universal_id, 'incoming')
                punji_file = os.path.join(punji_dir, 'punji')
                matches = find_jobs_by_prefix(universe, universal_id, match_mode="exact")
                # job_prefix = f"{universe}:{universal_id}"
                # no matches - assumed no agent in memory
                if not matches:
                    clear_to_spawn = True
                    try:
                        # make sure the punji file is deleted, because if not, and it exists next iteration then it will restart a take-down
                        os.remove(punji_file)
                    except Exception as e:
                        if self.debug.is_enabled():
                            self.log(error=e, block="main_try")

                # 2. If the punji file exists that means singleton_enforcement didn't shut down the agent, it had 20secs(spawn_manager sleep interval * 1) to do so(bottom of this function interruptible_sleep(self, 20))
                elif not os.path.exists(punji_file):
                    try:
                        os.makedirs(punji_dir, exist_ok=True)
                        Path(punji_file).write_text("ouch")
                        self.log(f"[BOOT][PUNJI] Dropped punji for {universal_id}")
                    except Exception as e:
                        self.log(f"[BOOT][PUNJI][WARN] Could not drop punji file for {universal_id}", error=e)

                # 3. we've been locked up for a while now, time we blow the coop, 40secs(spawn_manager sleep interval *2) is long enough
                else:

                    self.log(reeeeeeebeeeengaaaaa(matches))

        except Exception as e:
            self.log(error=e, block="main_try")

        return clear_to_spawn

    def ring_keychain(self, node:dict)->dict:

        try:
            if not isinstance(node, dict):
                return {}

            keychain={}
            keychain["priv"] = node.get("vault",{}).get("priv",{})
            keychain["pub"] = node.get("vault",{}).get("identity",{}).get('pub',{})
            keychain["swarm_key"] = self.swarm_key
            keychain['private_key'] = node.get("vault",{}).get("private_key")
            keychain["matrix_pub"] = self.matrix_pub
            keychain["matrix_priv"]=DUMMY_MATRIX_PRIV
            keychain["encryption_enabled"]=int(self.encryption_enabled)
            keychain["security_box"] = self.security_box.copy()
            #Matrix is running, and currently spawning
            if node.get("universal_id") == 'matrix':
                keychain["matrix_priv"] = self.matrix_priv
                keychain["private_key"] = self.private_key

            cfg = node.get("config", {})
            #these items will be returned to Matrix encase of her early demise
            #this block is basically only given to a sentinel, that's the only one that would need this
            #len of keychain["security_box"] is checked because multiple iterations will cause it
            #to be overridden
            if bool(cfg.get("matrix_secure_verified")) and len(keychain["security_box"])==1:
                self.log("[TRUST] matrix_secure_verified: TRUE → injecting real Matrix private key.")
                keychain["security_box"]["encryption_enabled"] = int(self.encryption_enabled)
                keychain["security_box"]["matrix_priv"] = self.matrix_priv
                keychain["security_box"]["matrix_pub"] = self.matrix_pub
                #keychain["security_box"]["priv"] = self.secure_keys['priv'] in tree_node
                #keychain["security_box"]["pub"] = self.secure_keys['pub']   in tree_node
                #keychain["security_box"]["private_key"] = self.private_key   in tree_node
                keychain["security_box"]["swarm_key"] = self.swarm_key
                keychain["security_box"]["node"] = self.tree_node.copy()
                keychain["security_box"]["spawner"] = self.command_line_args["spawner"]

            return keychain

        except Exception as e:
            self.log(error=e, block="main_try")

        return {}

    def spawn_agent_direct(self, universe, spawner, universal_id, agent_name, tree_node, keychain=None):

        try:

            if tree_node.get('lifecycle_status',{}).get("locked", False):
                self.log(f"[SPAWN-ERROR] Attempted to spawn locked agent {universal_id}. Blocking.")
                return

            cp = CoreSpawner(
                self.command_line_args.get("universe"),
                self.path_resolution["install_path"],
                self.path_resolution["reboot_uuid"],
                python_site=self.path_resolution["python_site"],
                detected_python=self.path_resolution["python_exec"],
            )

            if keychain and len(keychain) > 0:
                cp.set_keys(keychain)

            comm_file_spec = []
            cp.ensure_comm_channel(universal_id, comm_file_spec, tree_node.get("filesystem", {}))
            new_uuid, pod_path = cp.create_runtime()

            cp.set_verbose(self.verbose)
            cp.set_debug(self.debug.is_enabled())
            cp.set_rug_pull(self.rug_pull)

            try:
                #SAVE IDENTITY FILE to comm/{universal_id}/codex
                identity={"identity": tree_node.get("vault",{}).get("identity", {}), "sig": tree_node.get("vault",{}).get("sig", {})}

                dir = os.path.join(self.path_resolution["comm_path"], universal_id, "codex")

                os.makedirs(dir, exist_ok=True)
                fpath = os.path.join(dir, "signed_public_key.json")
                with open(fpath, "w", encoding="utf-8") as f:
                    json.dump(identity, f, indent=2)
                    f.close()

            except Exception as e:
                self.log(error=e, block='write_signed_public_key')


            try:
                result = cp.spawn_agent(
                    universe=universe,
                    spawner=spawner,
                    universal_id=universal_id,
                    agent_name=agent_name,
                    spawn_uuid=new_uuid,
                    tree_node=tree_node,
                )

            except Exception as e:
                self.log(f"Failed to spawn agent {universal_id}.", error=e, level="CRITICAL",  block="agent_spawn")
                return None

            return result

        except Exception as e:

            self.log(error=e, block="main_try")

    def pass_packet(self, packet:BasePacket, target_uid:str, drop_zone:str="incoming"):
        """
        A high-level helper method to securely prepare and deliver a packet.

        This method encapsulates the entire delivery process: creating a Football,
        loading the target's identity, getting a DeliveryAgent, and delivering
        the packet.

        Args:
            packet (BasePacket): The packet object to be sent.
            target_uid (str): The universal_id of the recipient agent.
            drop_zone (str): The sub-directory to deliver to (e.g., "incoming").

        Returns:
            bool: True if delivery was successful, False otherwise.
        """
        try:

            codex_path = os.path.join(self.path_resolution["comm_path"], target_uid, "codex", "signed_public_key.json")
            if not os.path.exists(codex_path):
                self.log(f"[PASS-PACKET] ❌ No public key found for {target_uid}. Aborting send.")
                return False

            football = self.get_football(type=self.FootballType.PASS)
            football.load_identity_file(universal_id=target_uid)
            da = self.get_delivery_agent("file.json_file", football=football, new=True)
            da.set_location({"path": self.path_resolution["comm_path"]}) \
                .set_address([target_uid]) \
                .set_drop_zone({"drop": drop_zone}) \
                .set_packet(packet) \
                .deliver()

            if da.get_error_success() != 0:
                self.log(f"[PASS-PACKET][FAIL] to {target_uid}: {da.get_error_success_msg()}", level="ERROR")
                return False
            else:
                if self.debug.is_enabled():
                    self.log(f"Packet passed to {target_uid} successfully.")

                return True
        except Exception as e:
            self.log(f"Failed during pass_packet to {target_uid}", error=e, level="ERROR")
            return False

    def catch_packet(self, filename, drop_zone="incoming"):
        """
        A high-level helper method to securely receive and decrypt a packet.

        This encapsulates the process of setting up a Football and ReceptionAgent
        to process a single file from a drop zone.

        Args:
            filename (str): The name of the packet file to be processed.
            drop_zone (str): The sub-directory the file is in (e.g., "incoming").

        Returns:
            dict: The decrypted packet content, or None on failure.
        """
        try:
            football = self.get_football(type=self.FootballType.CATCH)
            ra = self.get_reception_agent("file.json_file", new=True, football=football)

            packet_obj = self.get_delivery_packet("standard.command.packet")  # A generic packet to hold the data

            packet = ra.set_location({"path": self.path_resolution["comm_path"]}) \
                .set_address([self.command_line_args["universal_id"]]) \
                .set_drop_zone({"drop": drop_zone}) \
                .set_identifier(filename) \
                .set_packet(packet_obj) \
                .receive()

            if packet is None or ra.get_error_success() != 0:
                self.log(f"Failed to receive packet {filename}: {ra.get_error_success_msg()}", level="ERROR")
                return None

            return packet.get_packet()

        except Exception as e:
            self.log(f"Failed during catch_packet for {filename}", error=e, level="ERROR")
            return None

    def verify_identity(self, identity: IdentityObject, allowed_uids: list[str]) -> bool:
        """Centralized identity gatekeeper for secure handlers."""
        if not self.encryption_enabled:
            return True  # swarm running in plaintext mode

        # reject invalid or missing identity
        if not isinstance(identity, IdentityObject) or not identity.has_verified_identity():
            self.log("[AUTH] Unauthorized access attempt: no valid IdentityObject")
            return False

        sender = identity.get_sender_uid()
        if sender not in allowed_uids:
            self.log(f"[AUTH] Unauthorized access attempt from {sender} (allowed: {allowed_uids})")
            return False

        return True