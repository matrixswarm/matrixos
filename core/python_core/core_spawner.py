"""
Core Spawner for the MatrixSwarm Framework.
Authored by Daniel F MacDonald and ChatGPT aka The Generals
Gemini, code enhancements and Docstrings
This module defines the CoreSpawner class, which is the central engine for
instantiating, managing, and terminating agents within the MatrixSwarm. It handles
the entire lifecycle of an agent, from setting up its dedicated communication
channels and runtime environment to launching it as a secure, isolated process.

Key Responsibilities:
-   **Filesystem Scaffolding**: Creates the necessary directory structures for
    inter-agent communication (`comm` channels) and temporary runtime execution
    (`pod` directories).
-   **Secure Environment Preparation**: Utilizes mixins to handle the creation
    of a secure, encrypted environment for each agent, passing sensitive data
    like cryptographic keys through environment variables.
-   **Agent Lifecycle Management**: Spawns agents from source files, verifies
    their integrity via hash checking, logs their creation, and provides
    mechanisms for their graceful or forceful termination.
-   **Configuration and Trust Management**: Ingests path configurations, trust
    assets (keys), and agent-specific directives to ensure each agent is
-   spawned with the correct context and permissions.
"""
import os
import sys
import hashlib
from pathlib import Path
# Add the directory containing this script to the PYTHONPATH
current_directory = os.path.dirname(os.path.abspath(__file__))  # Directory of the current script
if current_directory not in sys.path:
    sys.path.insert(0, current_directory)

import json
import base64
import uuid
import shutil
import subprocess
import traceback
from datetime import datetime
from class_lib.file_system.file_system_builder import FileSystemBuilder
from core.python_core.path_manager import PathManager
from core.python_core.class_lib.logging.logger import Logger
from core.python_core.mixin.core_spawn_secure import CoreSpawnerSecureMixin
from core.python_core.mixin.ghost_vault import build_encrypted_spawn_env

class CoreSpawner(CoreSpawnerSecureMixin):
    """
    Manages the creation, lifecycle, and termination of MatrixSwarm agents.

    This class orchestrates the entire process of bringing an agent online.
    It prepares the agent's filesystem, sets up secure communication channels,
    and launches the agent process with a secure, encrypted environment.
    """
    def __init__(self, universe, base_path, reboot_uuid=None, python_site=None, detected_python=None):
        """
        Initializes the CoreSpawner instance.

        Args:
            path_manager (PathManager, optional): An instance of PathManager for
                resolving framework paths. If not provided, a new one is created.
                Defaults to None.
            site_root_path (str, optional): The root path of the website or
                application being managed by the swarm. Defaults to
                '/site/your_site_fallback_path'.
            python_site (str, optional): The path to the Python site-packages
                directory. Defaults to None.
            detected_python (str, optional): The path to the Python executable
                to be used for spawning agents. Defaults to None.
            install_path (str, optional): The root installation path of the
                MatrixSwarm framework. Defaults to None.
        """
        super().__init__()

        self.verbose=False
        self.debug = False
        self.rug_pull = False

        self.python_site=python_site
        self.python_exec= detected_python

        # Defines the default directory structure for an agent's communication channel.
        self.default_comm_file_spec = [
            {"name": "directive", "type": "d", "content": None},
            {"name": "hello.moto", "type": "d", "content": None},
            {"name": "payload", "type": "d", "content": None},
            {"name": "incoming", "type": "d", "content": None},
            {"name": "codex", "type": "d", "content": None},
            {"name": "queue", "type": "d", "content": None},
            {"name": "stack", "type": "d", "content": None, "meta": "Long - term mission chaining"},
            {"name": "replies", "type": "d", "content": None, "meta": "stack / Long - term mission chaining"},
            {"name": "broadcast", "type": "d", "content": None, "meta": "Shared folder for swarms with listeners"},
            {"name": "config", "type": "d", "content": None, "meta": "Updated configs go here"},
        ]

        self.pm = PathManager(universe, base_path, reboot_uuid)



        self._keychain={}

    def set_keys(self, key_dict: dict):
        """
        Injects multiple cryptographic keys and trust assets at once.

        Args:
            key_dict (dict): A dictionary containing key names and their values
                             (e.g., matrix_pub, swarm_key, security_box).
        """
        self._keychain = key_dict

    def set_key(self, name: str, key):
        """
        Sets a single cryptographic key or trust asset by name.

        Args:
            name (str): The name of the key (e.g., 'swarm_key', 'matrix_pub').
            key: The key material.
        """
        if not hasattr(self, "_keychain"):
            self._keychain = {}
        self._keychain[name] = key

    def set_verbose(self, verbose):
        """
        Enables or disables verbose output for spawned processes.

        Args:
            verbose (bool): If True, spawned agents will print to stdout/stderr.
        """
        self.verbose = bool(verbose)

    def set_rug_pull(self, rug_pull:bool=True):

        self.rug_pull = bool(rug_pull)

    def set_debug(self, debug):
        """
        Enables or disables debug mode for spawned agents.

        Args:
            debug (bool): If True, agents may run with additional debugging logic.
        """
        self.debug = bool(debug)

    def reset_hard(self):
        """
        Performs a hard reset, wiping all agent communication and runtime directories.

        Warning: This is a destructive operation that deletes all transient agent
        data.
        """
        #NEED TO WAIT UNTIL ALL PROCESSES HAVE COMPLETED
        for root in [self.pm.resolve('runtime_comm'), self.pm.resolve("runtime_pod")]:
            for folder in os.listdir(root):
                folder_path = os.path.join(root, folder)
                if os.path.isdir(folder_path):
                    shutil.rmtree(folder_path)

        print("[SPAWNER] Hard reset complete.")

    def verify_soft(self):
        """
        Ensures that the base communication and runtime directories exist.
        """
        for root in [self.pm.resolve('runtime_comm'), self.pm.resolve("runtime_pod")]:
            os.makedirs(root, exist_ok=True)
            print(f"[SPAWNER] Verified structure: {root}")

    def ensure_comm_channel(self, universal_id, file_spec, agent_directive=None):
        """
        Creates or verifies the communication directory structure for a given agent.

        It uses a FileSystemBuilder to create the default folder layout and then
        merges any additional filesystem specifications from the agent's directive.

        Args:
            universal_id (str): The unique identifier for the agent.
            file_spec (list): A list of file/folder specifications for the agent.
            agent_directive (dict, optional): The agent's directive, which may
                                              contain additional 'folders' or 'files'
                                              to create. Defaults to None.

        Returns:
            str: The absolute path to the agent's base communication directory.
        """
        base = ""
        try:
            base = os.path.join(self.pm.resolve("runtime_comm"), universal_id)

            os.makedirs(base, exist_ok=True)

            fsb = FileSystemBuilder()
            # Always process the default file_spec
            fsb.process_selection(base, self.default_comm_file_spec)

            # Process any special requirements from the agent's directive
            if file_spec:
                fsb.process_selection(base, file_spec)
            if agent_directive:
                fs_node = agent_directive if isinstance(agent_directive, dict) else {}
                folders = fs_node.get("folders", [])
                if folders:
                    fsb.process_selection(base, folders)

                files = fs_node.get("files", {})
                for name, content in files.items():
                    item = {"name": name, "type": "f", "content": content}
                    fsb.process_item(base, item)

            print('comm_channel creation: end')
        except Exception as e:
            tb = traceback.format_exc()
            print(f"[ensure_comm_channel] Unhandled exception during spawn of {tb}: {e}")
        return base

    def create_runtime(self):
        """
        Creates a new, temporary runtime directory (pod) for an agent instance.

        Args:
            universal_id (str): The unique identifier of the agent for which to
                                create the runtime. (Note: This is unused, the
                                pod is globally unique).

        Returns:
            tuple: A tuple containing the new UUID for the pod and the absolute
                   path to the pod directory.
        """
        new_uuid = f"{str(uuid.uuid4())}"
        pod_path = os.path.join(self.pm.resolve("runtime_pod"), new_uuid)
        os.makedirs(pod_path, exist_ok=True)
        return new_uuid, pod_path

    def destroy_runtime(self, uuid):
        """
        Deletes a runtime directory (pod) and all its contents.

        Args:
            uuid (str): The UUID of the runtime pod to destroy.

        Returns:
            bool: True if the directory was found and deleted, False otherwise.
        """
        target = os.path.join(self.pm.resolve("runtime_pod"), uuid)
        if os.path.exists(target):
            shutil.rmtree(target)
            print(f"[SPAWNER] Destroyed runtime pod: {uuid}")
            return True
        return False

    def get_boot_log(self, path):
        """
        Reads the boot.json file from a given pod path.

        Args:
            path (str): The path to the runtime pod directory.

        Returns:
            tuple: A tuple containing a boolean success flag and the JSON content
                   of the boot log as a dictionary, or None on failure.
        """
        boot_file_path = os.path.join(path, 'boot.json')
        try:
            with open(boot_file_path, "r", encoding="utf-8") as f:
                content = json.load(f)
            return True, content
        except (FileNotFoundError, json.JSONDecodeError):
            return False, None

    def spawn_agent(self, universe, spawner, universal_id, agent_name, spawn_uuid, tree_node=None):
        """
        The main method to spawn a new agent process.

        This method performs the following steps:
        1.  Sets up a logger for the agent.
        2.  Resolves the path to the agent's source code.
        3.  Verifies the source code's integrity using a hash if provided.
        4.  Prepares a secure payload with paths, args, and keys.
        5.  Builds an encrypted environment for the process using Ghost Vault.
        6.  Launches the agent as a detached subprocess.
        7.  Records the spawn event and boot information.

        Args:
            spawn_uuid (str): The unique ID for this specific spawn instance (pod ID).
            agent_name (str): The name of the agent to spawn.
            universal_id (str): The persistent, unique identifier for the agent.
            spawner (str): The universal_id of the agent performing the spawn.
            tree_node (dict, optional): The configuration node for this agent from
                                      the directive. Defaults to None.
            universe (str, optional): The ID of the universe or session this
                                       spawn belongs to. Defaults to None.

        Returns:
            tuple: A tuple containing the new process ID (int) and the command (list)
                   used to launch the agent.

        Raises:
            RuntimeError: If the agent source code cannot be found or if the
                          hash verification fails.
        """

        logger=None
        try:

            lang = tree_node.get("lang", "python") if tree_node else "python"
            ext_map = {
                "python": "py",
                "go": "go",
                "javascript": "js",
                "bash": "sh",
                "rust": "rs"
            }
            ext = ext_map.get(lang, "py")

            site_paths= self.pm.full_resolution(universal_id, spawn_uuid, lang=lang, ext=ext)
            logger = Logger(site_paths["static_comm_resolved"], "logs", "agent.log")

            if self._keychain.get("encryption_enabled"):
                logger.set_encryption_key(self._keychain["swarm_key"])

            with open("/matrix/spawn.log", "a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat()} :: {universal_id} → {agent_name}\n")

            #ensure the runtime pod path is created
            spawn_path = site_paths["runtime_pod_resolved"]
            os.makedirs(spawn_path, exist_ok=True)

            site_root_path = self.pm.resolve("site_root")
            source_path = self.pm.resolve("agent_resolved", lang=lang, agent_name=agent_name, ext=ext)

            # Integrity Check: Use embedded source or load from file and verify hash
            if tree_node and "src_embed" in tree_node:
                src_bytes = base64.b64decode(tree_node["src_embed"])
                logger.log(f"[SPAWN] Using embedded agent source for {agent_name}.")
            elif os.path.exists(source_path):
                 with open(source_path, "rb") as f:
                    src_bytes = f.read()
                 logger.log(f"[SPAWN] ✅ Found source for {agent_name} at {source_path}")
            else:
                logger.log(f"[SPAWN-FAIL] Agent source not found at expected path: {source_path}")
                raise RuntimeError(f"[SPAWN-FAIL] Missing agent source: {source_path}")

            real_hash = hashlib.sha256(src_bytes).hexdigest()
            expected_hash = tree_node.get("hash_bang") if tree_node else None

            #INTEGRITY DETECTION
            if expected_hash:
                if real_hash != expected_hash:
                    msg = (
                        f"HASH MISMATCH for agent '{agent_name}'\n"
                        f"  Source: {spawn_path}\n"
                        f"  Expected: {expected_hash}\n"
                        f"  Got:      {real_hash}\n"
                        f"  (Prefix: expected {expected_hash[:8]}... got {real_hash[:8]}...)\n"
                        "Aborting spawn."
                    )
                    logger.log(f"[SPAWN-FAIL] {msg}")
                    raise RuntimeError(f"Agent source hash mismatch:\n{msg}")
                else:
                    msg = (
                        f"HASH OK for agent '{agent_name}'\n"
                        f"  Source: {source_path}\n"
                        f"  hash_bang: {expected_hash}\n"
                        f"  Passed:    {real_hash[:12]}... (matched)"
                    )
                    logger.log(f"[SPAWN-HASH] {msg}")
            elif not expected_hash:
                logger.log(f"[SPAWN-HASH] No hash_bang provided for agent '{agent_name}' — spawn continues without integrity check.")

            # Write the verified source to a runnable file in the pod
            run_path = os.path.join(spawn_path, "run")
            vault_path = os.path.join(spawn_path, "vault")
            file_content = src_bytes.decode("utf-8")  # Now a string
            with open(run_path, "w", encoding="utf-8") as f:
                f.write(file_content)

            timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
            logger.log(f"[SPAWN-MGR] Spawning: {universal_id} ({agent_name})")
            print(f"[SPAWN-MGR] Spawning: {universal_id} ({agent_name})")

            # --- Prepare Secure Payload and Environment ---
            payload = {
                "path_resolution": {
                    "root_path": site_root_path,
                    "pod_path": site_paths["runtime_pod"],
                    "comm_path":  site_paths["runtime_comm"],
                    "static_comm_path": self.pm.resolve("static_comm"),
                    "static_comm_path_resolved": site_paths["static_comm_resolved"],
                    "reboot_uuid": self.pm.resolve("reboot_uuid"),
                    "agent_path": self.pm.resolve("agent"),
                    "incoming_path_template": os.path.join(site_paths["runtime_comm"], "$universal_id", "incoming"),
                    "comm_path_resolved": site_paths["runtime_comm_resolved"],
                    "pod_path_resolved": site_paths["runtime_pod_resolved"],
                    "poke_worker_file": os.path.join(site_paths["runtime_comm"], universal_id, "hello.moto", "poke.worker"),
                    "site_root_path": site_root_path,
                    "install_path": site_root_path,
                    # path of .matrixswarm dir - where session agent, boot_directive, and certs live
                    "python_site": self.python_site,
                    "python_exec": self.python_exec or "python3"
                },
                "args": {
                    "install_name": spawn_uuid,
                    "matrix": "matrix",
                    "spawner": spawner,
                    "universal_id": universal_id,
                    "agent_name": agent_name,
                    "universe": universe,
                    "site_root_path": site_root_path,
                    "verbose": int(self.verbose),
                    "debug": int(self.debug),
                    "rug_pull": int(self.rug_pull),
                },
                "tree_node": tree_node,
                "secure_keys": {
                    "pub": self._keychain["pub"],
                    "priv": self._keychain["priv"]
                },
                "swarm_key": self._keychain["swarm_key"],
                "private_key": self._keychain["private_key"],
                "matrix_pub": self._keychain["matrix_pub"],
                "matrix_priv": self._keychain["matrix_priv"],
                "security_box": self._keychain["security_box"],
                "encryption_enabled": self._keychain["encryption_enabled"],
            }

            def sanitize_for_json(obj):
                if isinstance(obj, dict):
                    return {k: sanitize_for_json(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [sanitize_for_json(i) for i in obj]
                elif isinstance(obj, Path):
                    return str(obj)
                else:
                    return obj

            payload = sanitize_for_json(payload)
            env = build_encrypted_spawn_env(payload, vault_path)


            env.update({
                "SITE_ROOT": site_root_path,
                "AGENT_PATH": self.pm.resolve("agent"),
                "PYTHON_SITE": self.python_site,
                "PYTHONPATH": os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            })

            # --- Launch Process ---
            cmd = [self.python_exec or "python3", run_path, "--job", f"{universe}:{universal_id}"]
            kwargs = {"preexec_fn": os.setsid} if os.name == "posix" else {}
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL if not self.verbose else None,
                stderr=subprocess.DEVNULL if not self.verbose else None,
                stdin=subprocess.DEVNULL,
                env=env,
                **kwargs
            )

            # --- Record Keeping ---
            spawn_record = {
                "uuid": spawn_uuid, "universal_id": universal_id, "agent_name": agent_name,
                "parent": spawner, "timestamp": timestamp, "pid": process.pid
            }
            spawn_dir = os.path.join(site_paths["runtime_comm_resolved"], "spawn")
            os.makedirs(spawn_dir, exist_ok=True)
            with open(os.path.join(spawn_dir, f"{timestamp}_{spawn_uuid}.spawn"), "w", encoding="utf-8") as f:
                json.dump(spawn_record, f, indent=2)
            with open(os.path.join(spawn_path, "boot.json"), "w", encoding="utf-8") as f:
                json.dump({"universal_id": universal_id, "boot_time": timestamp, "pid": process.pid, "cmd": cmd}, f, indent=4)

            logger.log(f"[SPAWN-LOG] Spawn recorded for PID {process.pid}")

        except Exception as e:
            raise RuntimeError(f"[SPAWN-FAIL] Unhandled exception during spawn of {agent_name}: {e}")

        return process.pid, cmd